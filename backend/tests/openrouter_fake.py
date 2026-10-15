"""Shared stand-in for the OpenRouter API (httpx.MockTransport) used by the LLM-mode tests."""
from __future__ import annotations

import json
from typing import Any

import httpx


FREE_MODELS = ["nvidia/nemotron-3-ultra-550b-a55b:free", "google/gemma-4-31b-it:free", "openrouter/free"]
MODELS_ENDPOINT = {"data": [
    {"id": m, "pricing": {"prompt": "0", "completion": "0"}} for m in FREE_MODELS
] + [{"id": "openai/some-paid-model", "pricing": {"prompt": "0.000002", "completion": "0.000008"}}]}


class FakeOpenRouter:
    def __init__(self, replies: list[Any]) -> None:
        self.replies = list(replies)
        self.chat_requests: list[dict[str, Any]] = []
        self.model_list_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/models"):
            self.model_list_calls += 1
            return httpx.Response(200, json=MODELS_ENDPOINT)
        assert request.url.path.endswith("/chat/completions"), request.url
        assert request.headers["authorization"] == "Bearer sk-or-test"
        self.chat_requests.append(json.loads(request.content))
        reply = self.replies.pop(0)
        if isinstance(reply, httpx.Response):
            return reply
        return httpx.Response(200, json=reply)


def turn(content: str = "", tool_calls: list[tuple[str, str, Any]] | None = None, finish: str | None = None,
         reasoning: str | None = None, model: str = FREE_MODELS[0]) -> dict[str, Any]:
    calls = [{"id": cid, "type": "function", "function": {"name": name, "arguments": args if isinstance(args, str) else json.dumps(args)}}
             for cid, name, args in (tool_calls or [])]
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = calls
    if reasoning:
        message["reasoning"] = reasoning
    return {"id": "gen-1", "model": model, "object": "chat.completion",
            "choices": [{"index": 0, "finish_reason": finish or ("tool_calls" if calls else "stop"), "message": message}]}
