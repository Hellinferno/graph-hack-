"""Test configuration: every test runs against a live FalkorDB using isolated ``test_aegis_*`` graphs.

The environment is pinned BEFORE ``aegis`` is imported so the settings singleton (and the MCP server
subprocesses it spawns) use the test prefix and never touch the demo graphs.
"""
from __future__ import annotations

import os
from typing import Any

os.environ["AEGIS_GRAPH_PREFIX"] = "test_aegis_"
os.environ["AEGIS_KEEP_SANDBOX"] = "false"
os.environ["AEGIS_SIM_TTL_MINUTES"] = "30"
os.environ["AEGIS_ENABLE_FALKORDB_MCP"] = "false"
os.environ["AEGIS_CORS_ORIGINS"] = "http://localhost:5173,http://localhost:4173"  # independent of the local .env
# Tests never call a real LLM. Empty values (not pop) also stop aegis.config's load_dotenv(override=False)
# from re-adding keys from the project's .env file.
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["OPENROUTER_API_KEY"] = ""
os.environ["AEGIS_LLM_PROVIDER"] = ""

import pytest  # noqa: E402

from aegis import graph as g  # noqa: E402
from aegis.config import settings  # noqa: E402
from aegis.seed import seed_all  # noqa: E402


def _cleanup() -> None:
    for name in g.list_graphs():
        if name.startswith(settings.graph_prefix):
            g.delete_graph_if_exists(name)


@pytest.fixture(scope="session", autouse=True)
def falkordb_session():
    if not g.ping():
        pytest.exit("FalkorDB is not reachable on %s:%s - start it with `docker compose up -d`" % (settings.falkordb_host, settings.falkordb_port), returncode=3)
    assert settings.graph_prefix == "test_aegis_"
    _cleanup()
    seed_all(reset_memory=True)
    yield
    _cleanup()


@pytest.fixture
def fresh_graphs():
    """Reseed both graphs (used by tests that mutate production or memory state)."""
    seed_all(reset_memory=True)
    yield
    seed_all(reset_memory=True)


@pytest.fixture
def openrouter(monkeypatch):
    """Install a scripted OpenRouter (free models) as the LLM provider; returns an installer taking the replies."""
    import dataclasses

    import httpx

    from aegis import agent as agent_mod
    from aegis import llm_openrouter as orc

    from .openrouter_fake import FREE_MODELS, FakeOpenRouter

    def install(replies: list[Any], **overrides: Any) -> FakeOpenRouter:
        fake = FakeOpenRouter(replies)
        fields = {"llm_provider": "openrouter", "openrouter_api_key": "sk-or-test", "openrouter_model": FREE_MODELS[0],
                  "openrouter_fallbacks": tuple(FREE_MODELS[1:]), **overrides}
        cfg = dataclasses.replace(agent_mod.settings, **fields)
        monkeypatch.setattr(agent_mod, "settings", cfg)
        monkeypatch.setattr(orc, "settings", cfg)
        monkeypatch.setattr(orc, "client_factory", lambda: httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)))
        monkeypatch.setattr(orc, "_free_cache", {"checked_at": 0.0, "free_ids": None})
        return fake
    return install
