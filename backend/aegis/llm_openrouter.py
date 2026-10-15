"""OpenRouter chat-completions client for LLM mode, restricted to free models.

AegisGraph's LLM mode can run on OpenRouter (https://openrouter.ai) instead of the Anthropic API. This module talks
to the OpenAI-compatible `POST /api/v1/chat/completions` endpoint directly with httpx:

* tools are sent as OpenAI function tools built from the MCP tool list (name, description, JSON schema);
* `models` carries the primary model plus fallbacks: OpenRouter tries the next one when a model errors, is rate
  limited or is down, and the response `model` field names the one that answered;
* free-only is enforced: every configured model must be priced at zero by OpenRouter's public `/models` endpoint
  (falling back to the `:free` suffix rule when that endpoint is unreachable), otherwise the run is refused;
* HTTP 429 / transient 5xx responses are retried with backoff (free models allow 20 requests per minute).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

from .config import settings

log = logging.getLogger("aegis.openrouter")

RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4
FREE_ROUTER = "openrouter/free"

# test hook: tests replace this with a factory returning an AsyncClient backed by httpx.MockTransport
client_factory = None

_free_cache: dict[str, Any] = {"checked_at": 0.0, "free_ids": None}


class OpenRouterError(Exception):
    def __init__(self, message: str, status: int | None = None, retryable: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable


def make_client() -> httpx.AsyncClient:
    if client_factory is not None:
        return client_factory()
    return httpx.AsyncClient(timeout=httpx.Timeout(180.0, connect=15.0))


def headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.openrouter_api_key}",
        "Content-Type": "application/json",
        # optional attribution headers recommended by OpenRouter
        "HTTP-Referer": "https://github.com/aegisgraph",
        "X-Title": "AegisGraph",
    }


def is_free_id(model_id: str) -> bool:
    return model_id == FREE_ROUTER or model_id.endswith(":free")


async def free_model_ids(client: httpx.AsyncClient) -> set[str] | None:
    """IDs OpenRouter prices at zero for prompt and completion (cached for an hour); None if unreachable."""
    if _free_cache["free_ids"] is not None and time.time() - _free_cache["checked_at"] < 3600:
        return _free_cache["free_ids"]
    try:
        resp = await client.get(f"{settings.openrouter_base_url}/models", timeout=30.0)
        resp.raise_for_status()
        ids: set[str] = set()
        for m in resp.json().get("data", []):
            pricing = m.get("pricing") or {}
            try:
                if float(pricing.get("prompt", 1)) == 0 and float(pricing.get("completion", 1)) == 0:
                    ids.add(m["id"])
            except (TypeError, ValueError):
                continue
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        log.warning("could not fetch OpenRouter model list (%s); using the ':free' suffix rule", exc)
        return None
    _free_cache.update(checked_at=time.time(), free_ids=ids)
    return ids


async def ensure_free(client: httpx.AsyncClient, models: list[str]) -> None:
    """Refuse to run unless every configured model is free (the user asked for free models only)."""
    if settings.openrouter_allow_paid:
        return
    free = await free_model_ids(client)
    paid = [m for m in models if (m not in free if free is not None else not is_free_id(m))]
    if paid:
        raise OpenRouterError(
            f"refusing non-free OpenRouter model(s) {paid}: AegisGraph is configured for free models only "
            f"(pick IDs ending in ':free' or '{FREE_ROUTER}'; set AEGIS_OPENROUTER_ALLOW_PAID=true to override)"
        )


def tools_from_mcp(specs: list[Any]) -> list[dict[str, Any]]:
    """MCP tool specs -> OpenAI function tools."""
    out = []
    for spec in specs:
        schema = dict(spec.input_schema or {"type": "object", "properties": {}})
        schema.setdefault("type", "object")
        schema.setdefault("properties", {})
        out.append({"type": "function", "function": {"name": spec.name, "description": spec.description, "parameters": schema}})
    return out


MAX_SERVER_WAIT_S = 60.0


def _server_wait(resp: httpx.Response | None) -> float | None:
    """Seconds the server asked us to wait (Retry-After, or X-RateLimit-Reset in epoch ms), if it said."""
    if resp is None:
        return None
    retry_after = resp.headers.get("retry-after")
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass
    reset = resp.headers.get("x-ratelimit-reset")
    if reset:
        try:
            return max(0.0, float(reset) / 1000.0 - time.time())
        except ValueError:
            pass
    return None


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    wait = _server_wait(resp)
    if wait is not None:
        return max(1.0, wait + 0.5)
    return min(30.0, 2.0 * (2 ** attempt))


def error_hint(status: int | None) -> str:
    """A short, accurate pointer for the operator, by HTTP status."""
    return {
        401: " (check OPENROUTER_API_KEY in .env)",
        402: " (the OpenRouter account balance is negative; free models need a non-negative balance)",
        403: " (the input was flagged by the model's moderation; try another model in AEGIS_OPENROUTER_MODEL / AEGIS_OPENROUTER_FALLBACKS)",
        429: " (free-model rate limit: 20 requests/minute, 50/day without credits)",
    }.get(status or 0, "")


def _error_message(resp: httpx.Response) -> str:
    try:
        err = resp.json().get("error") or {}
        meta = err.get("metadata") or {}
        raw = meta.get("raw")
        detail = f" ({raw})" if isinstance(raw, str) and raw else ""
        return f"{err.get('message') or resp.text[:300]}{detail}"
    except ValueError:
        return resp.text[:300]


async def chat(
    client: httpx.AsyncClient,
    *,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    models: list[str],
    reasoning_effort: str | None,
    max_tokens: int = 8000,
) -> dict[str, Any]:
    """One chat-completions round trip with fallbacks and retries. Returns the parsed JSON body."""
    body: dict[str, Any] = {"messages": messages, "tools": tools, "tool_choice": "auto", "max_completion_tokens": max_tokens}
    if len(models) > 1:
        body["models"] = models
    else:
        body["model"] = models[0]
    if reasoning_effort and reasoning_effort != "omit":
        body["reasoning"] = {"effort": reasoning_effort}
    last_error: OpenRouterError | None = None
    for attempt in range(MAX_ATTEMPTS):
        resp: httpx.Response | None = None
        try:
            resp = await client.post(f"{settings.openrouter_base_url}/chat/completions", headers=headers(), json=body)
        except httpx.TransportError as exc:
            last_error = OpenRouterError(f"cannot reach OpenRouter: {exc}", retryable=True)
        else:
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    data = None
                if not isinstance(data, dict):
                    last_error = OpenRouterError("OpenRouter returned an unreadable body", retryable=True)
                elif isinstance(data.get("error"), dict):  # provider errors can arrive with HTTP 200
                    err = data["error"]
                    code = err.get("code")
                    last_error = OpenRouterError(f"OpenRouter error {code}: {err.get('message')}", status=code if isinstance(code, int) else None,
                                                 retryable=code in RETRYABLE_STATUS)
                elif not data.get("choices"):
                    last_error = OpenRouterError("OpenRouter returned no choices", retryable=True)
                else:
                    return data
            else:
                last_error = OpenRouterError(f"OpenRouter HTTP {resp.status_code}: {_error_message(resp)}", status=resp.status_code,
                                             retryable=resp.status_code in RETRYABLE_STATUS)
        if not last_error.retryable or attempt == MAX_ATTEMPTS - 1:
            break
        wait = _server_wait(resp)
        if wait is not None and wait > MAX_SERVER_WAIT_S:
            # e.g. the daily free-model quota: waiting minutes inside a run helps nobody
            raise OpenRouterError(f"{last_error}; the limit resets in about {max(1, round(wait / 60))} min, try again later",
                                  status=last_error.status, retryable=False)
        delay = _retry_delay(resp, attempt)
        log.warning("%s - retrying in %.1fs (attempt %d/%d)", last_error, delay, attempt + 2, MAX_ATTEMPTS)
        await asyncio.sleep(delay)
    assert last_error is not None
    raise last_error


def parse_arguments(raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Tool-call arguments arrive as a JSON string; returns (args, error)."""
    if isinstance(raw, dict):
        return raw, None
    if raw in (None, ""):
        return {}, None
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        return None, f"arguments are not valid JSON ({exc.msg if hasattr(exc, 'msg') else exc})"
    if not isinstance(parsed, dict):
        return None, "arguments must be a JSON object"
    return parsed, None
