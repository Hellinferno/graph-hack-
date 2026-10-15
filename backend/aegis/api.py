"""FastAPI backend: REST + Server-Sent Events over the agent, the MCP toolbox and the graphs (docs/DESIGN.md §6).

Run: ``python -m aegis api`` (or ``uvicorn aegis.api:app --port 8000`` from backend/).
"""
from __future__ import annotations

import asyncio
import json
import threading
import logging
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from . import graph as g
from . import memory, seed, tools
from .agent import AgentRunner, Mode
from .config import settings
from .mcp_client import MCPToolbox

log = logging.getLogger("aegis.api")


@dataclass
class RunRecord:
    run_id: str
    incident_id: str
    mode: str
    status: str = "running"
    created_at: float = field(default_factory=time.time)
    events: list[dict[str, Any]] = field(default_factory=list)
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    task: asyncio.Task | None = None


class RunRequest(BaseModel):
    incident_id: str
    alert_text: str | None = None
    mode: Mode = "auto"


class SeedRequest(BaseModel):
    reset_memory: bool = False


class _ToolboxOwner:
    """Runs one MCPToolbox inside a dedicated task.

    The MCP stdio client uses anyio task groups, whose cancel scopes must be entered and exited by the same task.
    Starting and stopping the toolbox here (never from a request task) keeps that true, and a crashing server
    subprocess only ends this task instead of cancelling whichever request or lifespan task happened to start it.
    """

    def __init__(self) -> None:
        self.box = MCPToolbox()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    @property
    def alive(self) -> bool:
        return self._task is not None and not self._task.done() and self.box.started and not self.box.dead

    async def start(self) -> MCPToolbox:
        ready: asyncio.Future = asyncio.get_running_loop().create_future()

        async def own() -> None:
            try:
                async with self.box:
                    ready.set_result(None)
                    await self._stop.wait()
            except asyncio.CancelledError:
                self.box.dead = True
                if not ready.done():
                    ready.set_exception(RuntimeError("MCP toolbox start was cancelled"))
                raise
            except Exception as exc:  # noqa: BLE001 - the server died or failed to start
                self.box.dead = True
                if not ready.done():
                    ready.set_exception(exc)
                else:
                    log.warning("MCP toolbox stopped unexpectedly: %s", exc)

        self._task = asyncio.create_task(own(), name="mcp-toolbox-owner")
        await ready
        return self.box

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None and not self._task.done():
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=15)
            except Exception as exc:  # noqa: BLE001 - teardown must never mask the caller's work
                log.warning("MCP toolbox did not stop cleanly: %s", exc)


class AppState:
    def __init__(self) -> None:
        self._owner: _ToolboxOwner | None = None
        self.runs: dict[str, RunRecord] = {}
        self.toolbox_error: str | None = None
        self._toolbox_lock = asyncio.Lock()
        # reseeding and starting runs are mutually exclusive (a run must never see the graph rebuilt under it)
        self.lock = threading.Lock()
        self.reseeding = False

    @property
    def toolbox(self) -> MCPToolbox | None:
        return self._owner.box if self._owner is not None else None

    async def get_toolbox(self) -> MCPToolbox:
        """The shared MCP toolbox, started on first use and respawned if its server subprocess died."""
        async with self._toolbox_lock:
            if self._owner is not None and not self._owner.alive:
                log.warning("MCP toolbox is not alive; restarting it")
                await self._owner.stop()
                self._owner = None
            if self._owner is None:
                owner = _ToolboxOwner()
                try:
                    await owner.start()
                except Exception as exc:  # noqa: BLE001 - surfaced as 503 with the real reason
                    self.toolbox_error = f"{type(exc).__name__}: {exc}"
                    raise HTTPException(status_code=503, detail=f"MCP toolbox unavailable: {self.toolbox_error}") from exc
                self._owner = owner
                self.toolbox_error = None
            return self._owner.box

    async def shutdown(self) -> None:
        async with self._toolbox_lock:
            if self._owner is not None:
                await self._owner.stop()
                self._owner = None

    def run_in_progress(self) -> bool:
        return any(r.status == "running" for r in self.runs.values())


state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if g.ping():
        try:
            await state.get_toolbox()
        except HTTPException as exc:
            log.warning("MCP toolbox not started at boot: %s", exc.detail)
    else:
        log.warning("FalkorDB is not reachable at %s:%s - the API will answer 503 until it is", settings.falkordb_host, settings.falkordb_port)
    try:
        yield
    finally:
        await state.shutdown()


app = FastAPI(title="AegisGraph API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["*"], allow_headers=["*"])

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@app.middleware("http")
async def reject_cross_site_writes(request: Request, call_next):
    """State-changing requests from a browser page on another origin are refused (a form POST to /api/seed would
    otherwise wipe the graph). Same-origin console requests and non-browser clients (no Origin header) pass."""
    if request.method not in _SAFE_METHODS:
        origin = request.headers.get("origin")
        if origin is not None and "*" not in settings.cors_origins and origin not in settings.cors_origins:
            return JSONResponse({"detail": f"cross-site request from origin '{origin}' rejected"}, status_code=403)
    return await call_next(request)


def _require_falkordb(seeded: bool = True) -> None:
    if not g.ping():
        raise HTTPException(status_code=503, detail="FalkorDB is unreachable; AegisGraph cannot run without its graph (start it with `docker compose up -d`)")
    if seeded and not g.graph_exists(settings.prod_graph_name):
        raise HTTPException(status_code=409, detail=f"graph '{settings.prod_graph_name}' is not seeded yet; POST /api/seed or run `python -m aegis seed`")


# ---------------------------------------------------------------------------- health / graph

@app.get("/api/health")
def health() -> JSONResponse:
    ok = g.ping()
    body: dict[str, Any] = {
        "status": "ok" if ok else "degraded",
        "falkordb": ok,
        "falkordb_host": f"{settings.falkordb_host}:{settings.falkordb_port}",
        "falkordb_browser_url": settings.falkordb_browser_url,
        "prod_graph": settings.prod_graph_name,
        "memory_graph": settings.memory_graph_name,
        "llm_configured": settings.llm_configured,
        "model": settings.active_llm_model if settings.llm_configured else None,
        "llm_provider": settings.llm_provider if settings.llm_configured else None,
        "llm_fallback_models": settings.openrouter_models[1:] if settings.llm_configured and settings.llm_provider == "openrouter" else [],
        "mcp_servers": state.toolbox.servers if state.toolbox and state.toolbox.started else [],
        "mcp_error": state.toolbox_error or ("MCP server subprocess died; it is restarted on the next tool call" if state.toolbox and state.toolbox.dead else None),
    }
    if ok:
        try:
            overview = tools.graph_overview()
            body["graphs"] = overview["graphs"]
            body["label_counts"] = overview["label_counts"]
            body["seeded"] = bool(overview["label_counts"])
        except Exception as exc:  # noqa: BLE001
            body["graphs"], body["label_counts"], body["seeded"], body["graph_error"] = [], {}, False, str(exc)
    return JSONResponse(body, status_code=200 if ok else 503)


@app.post("/api/seed")
def reseed(req: SeedRequest | None = None) -> dict[str, Any]:
    _require_falkordb(seeded=False)
    with state.lock:
        if state.run_in_progress():
            raise HTTPException(status_code=409, detail="a run is in progress; wait for it to finish before reseeding")
        if state.reseeding:
            raise HTTPException(status_code=409, detail="a reseed is already in progress")
        state.reseeding = True
    try:
        return seed.seed_all(reset_memory=bool(req and req.reset_memory))
    finally:
        with state.lock:
            state.reseeding = False


@app.get("/api/graph")
def graph_prod() -> dict[str, Any]:
    _require_falkordb()
    return g.graph_snapshot(g.prod_graph())


@app.get("/api/graphs")
def graphs() -> dict[str, Any]:
    _require_falkordb()
    return tools.graph_overview()


@app.get("/api/graph/{name}")
def graph_named(name: str) -> dict[str, Any]:
    _require_falkordb()
    if not name.startswith(settings.graph_prefix):
        raise HTTPException(status_code=400, detail=f"graph name must start with '{settings.graph_prefix}'")
    if not g.graph_exists(name):
        raise HTTPException(status_code=404, detail=f"graph '{name}' does not exist")
    return g.graph_snapshot(g.get_db().select_graph(name))


# ---------------------------------------------------------------------------- incidents / proof / memory

@app.get("/api/incidents")
def incidents() -> list[dict[str, Any]]:
    _require_falkordb()
    return tools.list_incidents()


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str) -> dict[str, Any]:
    _require_falkordb()
    try:
        return tools.get_decision_proof(incident_id)
    except tools.ToolError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/memory")
def memory_view() -> dict[str, Any]:
    _require_falkordb(seeded=False)
    return memory.memory_overview()


@app.post("/api/rollback/{audit_id}")
async def rollback(audit_id: str) -> dict[str, Any]:
    await asyncio.to_thread(_require_falkordb)
    box = await state.get_toolbox()
    res = await box.call_tool("rollback_remediation", {"audit_id": audit_id})
    if res.is_error:
        raise HTTPException(status_code=400, detail=res.result.get("error") if isinstance(res.result, dict) else str(res.result))
    return res.result


# ---------------------------------------------------------------------------- MCP tools

@app.get("/api/tools")
async def list_tools() -> list[dict[str, Any]]:
    await asyncio.to_thread(_require_falkordb)
    box = await state.get_toolbox()
    return [t.as_dict() for t in box.list_tools()]


@app.post("/api/tools/{name}")
async def call_tool(name: str, args: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    await asyncio.to_thread(_require_falkordb)
    box = await state.get_toolbox()
    if not box.has_tool(name):
        raise HTTPException(status_code=404, detail=f"unknown tool '{name}'")
    res = await box.call_tool(name, args)
    return {"name": name, "args": args, "result": res.result, "is_error": res.is_error, "duration_ms": round(res.duration_ms, 2), "server": res.server}


# ---------------------------------------------------------------------------- agent runs

async def _drive(record: RunRecord, req: RunRequest) -> None:
    box = await state.get_toolbox()
    runner = AgentRunner(toolbox=box)
    try:
        async for ev in runner.run(req.incident_id, req.alert_text, req.mode, run_id=record.run_id):
            record.events.append(ev)
            for q in list(record.subscribers):
                q.put_nowait(ev)
        last = record.events[-1]["type"] if record.events else "error"
        record.status = "completed" if last == "run_completed" else "error"
    except Exception as exc:  # noqa: BLE001 - never leave a run stuck in "running"
        log.exception("run %s crashed", record.run_id)
        ev = {"type": "error", "ts": time.time(), "run_id": record.run_id, "message": f"{type(exc).__name__}: {exc}", "recoverable": False}
        record.events.append(ev)
        for q in list(record.subscribers):
            q.put_nowait(ev)
        record.status = "error"
    finally:
        for q in list(record.subscribers):
            q.put_nowait(None)


@app.post("/api/runs")
async def create_run(req: RunRequest) -> dict[str, Any]:
    await asyncio.to_thread(_require_falkordb)
    await state.get_toolbox()
    mode = req.mode if req.mode != "auto" else ("llm" if settings.llm_configured else "deterministic")
    if mode == "llm" and not settings.llm_configured:
        raise HTTPException(status_code=400, detail="LLM mode requires ANTHROPIC_API_KEY or OPENROUTER_API_KEY; use deterministic mode")
    record = RunRecord(run_id=f"run-{uuid.uuid4().hex[:10]}", incident_id=req.incident_id, mode=mode)
    with state.lock:  # registered as running atomically with the reseed check
        if state.reseeding:
            raise HTTPException(status_code=409, detail="the graph is being reseeded; start the run when it finishes")
        state.runs[record.run_id] = record
    record.task = asyncio.create_task(_drive(record, req))
    return {"run_id": record.run_id, "incident_id": req.incident_id, "mode": mode, "status": record.status}


@app.get("/api/runs")
def list_runs() -> list[dict[str, Any]]:
    return [{"run_id": r.run_id, "incident_id": r.incident_id, "mode": r.mode, "status": r.status, "created_at": r.created_at, "events": len(r.events)}
            for r in sorted(state.runs.values(), key=lambda r: r.created_at, reverse=True)]


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    record = state.runs.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return {"run_id": record.run_id, "incident_id": record.incident_id, "mode": record.mode, "status": record.status,
            "created_at": record.created_at, "events": record.events}


def _sse(event: dict[str, Any]) -> str:
    return f"event: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"


@app.get("/api/runs/{run_id}/events")
async def stream_events(run_id: str) -> StreamingResponse:
    record = state.runs.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown run")

    async def gen() -> AsyncIterator[str]:
        queue: asyncio.Queue = asyncio.Queue()
        record.subscribers.append(queue)
        try:
            for ev in list(record.events):
                yield _sse(ev)
            # Events emitted during the replay are waiting in the queue. Once the run is no longer running,
            # _drive has already queued all of them (and a None sentinel for subscribers it knew about), so
            # draining until None or empty is complete; a late subscriber simply finds the queue empty.
            while True:
                if record.status != "running" and queue.empty():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                if ev is None:
                    break
                yield _sse(ev)
            yield "event: done\ndata: {}\n\n"
        finally:
            if queue in record.subscribers:
                record.subscribers.remove(queue)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
