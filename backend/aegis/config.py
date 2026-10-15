"""Runtime configuration, loaded from environment variables (and the project-root .env file).

Every process that touches the graph (API server, MCP server subprocess, CLI, tests) reads the same
settings, so the graph prefix and FalkorDB connection are consistent across processes.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent  # .../backend
PROJECT_ROOT = BACKEND_DIR.parent  # .../aegisgraph
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | None, default: int) -> int:
    try:
        return int(value) if value not in (None, "") else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    falkordb_host: str
    falkordb_port: int
    falkordb_username: str | None
    falkordb_password: str | None
    falkordb_browser_url: str
    graph_prefix: str
    anthropic_api_key: str | None
    llm_model: str
    llm_effort: str
    llm_provider: str  # "anthropic", "openrouter" or "none" (resolved at load time)
    openrouter_api_key: str | None
    openrouter_model: str
    openrouter_fallbacks: tuple[str, ...]
    openrouter_base_url: str
    openrouter_reasoning: str
    openrouter_allow_paid: bool
    max_tool_iterations: int
    sim_ttl_minutes: int
    keep_sandbox: bool
    api_port: int
    cors_origins: tuple[str, ...]
    enable_falkordb_mcp: bool
    mcp_python: str
    embed_dim: int

    @property
    def prod_graph_name(self) -> str:
        return f"{self.graph_prefix}prod_graph"

    @property
    def memory_graph_name(self) -> str:
        return f"{self.graph_prefix}memory_graph"

    @property
    def llm_configured(self) -> bool:
        if self.llm_provider == "anthropic":
            return bool(self.anthropic_api_key)
        if self.llm_provider == "openrouter":
            return bool(self.openrouter_api_key)
        return False

    @property
    def active_llm_model(self) -> str | None:
        """The model LLM mode will request (the primary one, for OpenRouter)."""
        if self.llm_provider == "anthropic":
            return self.llm_model
        if self.llm_provider == "openrouter":
            return self.openrouter_model
        return None

    @property
    def openrouter_models(self) -> list[str]:
        """Primary + fallbacks, de-duplicated, in priority order."""
        out: list[str] = []
        for m in (self.openrouter_model, *self.openrouter_fallbacks):
            if m and m not in out:
                out.append(m)
        return out

    def env_for_subprocess(self) -> dict[str, str]:
        """Environment variables a spawned MCP server needs to see the same FalkorDB + graph prefix.

        The MCP stdio client only forwards a minimal default environment, so these must be passed explicitly.
        """
        env = {
            "FALKORDB_HOST": self.falkordb_host,
            "FALKORDB_PORT": str(self.falkordb_port),
            "AEGIS_GRAPH_PREFIX": self.graph_prefix,
            "AEGIS_SIM_TTL_MINUTES": str(self.sim_ttl_minutes),
            "AEGIS_KEEP_SANDBOX": "true" if self.keep_sandbox else "false",
            "AEGIS_EMBED_DIM": str(self.embed_dim),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
        }
        if self.falkordb_username:
            env["FALKORDB_USERNAME"] = self.falkordb_username
        if self.falkordb_password:
            env["FALKORDB_PASSWORD"] = self.falkordb_password
        return env


DEFAULT_OPENROUTER_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
DEFAULT_OPENROUTER_FALLBACKS = "google/gemma-4-31b-it:free,openrouter/free"


def _resolve_provider(env: os._Environ[str] | dict[str, str]) -> str:
    explicit = (env.get("AEGIS_LLM_PROVIDER") or "").strip().lower()
    if explicit in {"anthropic", "openrouter"}:
        return explicit
    if env.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if env.get("OPENROUTER_API_KEY"):
        return "openrouter"
    return "none"


def load_settings() -> Settings:
    env = os.environ
    configured = [o.strip().rstrip("/") for o in env.get("AEGIS_CORS_ORIGINS", "http://localhost:5173,http://localhost:4173").split(",") if o.strip()]
    # localhost and 127.0.0.1 are the same console; accept both spellings of every configured origin
    aliases = [o.replace("://localhost", "://127.0.0.1") if "://localhost" in o else o.replace("://127.0.0.1", "://localhost") for o in configured]
    origins = tuple(dict.fromkeys(configured + aliases))
    return Settings(
        falkordb_host=env.get("FALKORDB_HOST", "localhost"),
        falkordb_port=_int(env.get("FALKORDB_PORT"), 6379),
        falkordb_username=env.get("FALKORDB_USERNAME") or None,
        falkordb_password=env.get("FALKORDB_PASSWORD") or None,
        falkordb_browser_url=env.get("AEGIS_FALKORDB_BROWSER_URL")
        or f"http://localhost:{_int(env.get('FALKORDB_BROWSER_PORT'), 3000)}",
        graph_prefix=env.get("AEGIS_GRAPH_PREFIX", "aegis_"),
        anthropic_api_key=env.get("ANTHROPIC_API_KEY") or None,
        llm_model=env.get("AEGIS_LLM_MODEL", "claude-opus-5-5"),
        llm_effort=env.get("AEGIS_LLM_EFFORT", "high"),
        llm_provider=_resolve_provider(env),
        openrouter_api_key=env.get("OPENROUTER_API_KEY") or None,
        openrouter_model=env.get("AEGIS_OPENROUTER_MODEL") or DEFAULT_OPENROUTER_MODEL,
        openrouter_fallbacks=tuple(
            m.strip() for m in (env.get("AEGIS_OPENROUTER_FALLBACKS", DEFAULT_OPENROUTER_FALLBACKS)).split(",") if m.strip()
        ),
        openrouter_base_url=(env.get("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1").rstrip("/"),
        openrouter_reasoning=(env.get("AEGIS_OPENROUTER_REASONING") or "medium").strip().lower(),
        openrouter_allow_paid=_bool(env.get("AEGIS_OPENROUTER_ALLOW_PAID"), False),
        max_tool_iterations=_int(env.get("AEGIS_MAX_TOOL_ITERATIONS"), 25),
        sim_ttl_minutes=_int(env.get("AEGIS_SIM_TTL_MINUTES"), 30),
        keep_sandbox=_bool(env.get("AEGIS_KEEP_SANDBOX"), True),
        api_port=_int(env.get("AEGIS_API_PORT"), 8000),
        cors_origins=origins,
        enable_falkordb_mcp=_bool(env.get("AEGIS_ENABLE_FALKORDB_MCP"), False),
        mcp_python=env.get("AEGIS_MCP_PYTHON") or sys.executable,
        embed_dim=_int(env.get("AEGIS_EMBED_DIM"), 384),
    )


settings = load_settings()
