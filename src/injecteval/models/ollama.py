"""Ollama backend — local open-weights models over http://localhost:11434.

Handles both native tool calling and the text fallback, because tool-call
reliability on small models is uneven and we do not want harness quirks showing
up in the results as robustness.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from injecteval.models.base import parse_text_tool_call
from injecteval.types import ModelResponse, ToolCall

DEFAULT_HOST = "http://localhost:11434"


class OllamaBackend:
    def __init__(
        self,
        model: str = "llama3.2:latest",
        host: str = DEFAULT_HOST,
        native_tools: bool = True,
        timeout: float = 300.0,
    ) -> None:
        self.model = model
        self.name = f"ollama:{model}"
        self.host = host.rstrip("/")
        self.native_tools = native_tools
        self._client = httpx.Client(timeout=timeout)

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        seed: int = 0,
        temperature: float = 0.0,
    ) -> ModelResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": _to_ollama(messages),
            "stream": False,
            "options": {"temperature": temperature, "seed": seed},
        }
        if self.native_tools and tools:
            payload["tools"] = tools

        r = self._client.post(f"{self.host}/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()
        msg = data.get("message", {}) or {}
        text = msg.get("content", "") or ""

        calls: list[ToolCall] = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {}) or {}
            args = fn.get("arguments", {}) or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            calls.append(ToolCall(name=fn.get("name", ""), arguments=args, id=f"c{i}"))

        if not calls and text:
            calls = parse_text_tool_call(text)

        return ModelResponse(
            text=text,
            tool_calls=calls,
            usage={
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
            },
            raw=data,
        )

    def close(self) -> None:
        self._client.close()


def _to_ollama(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ollama wants tool results as role='tool' with plain string content."""
    out = []
    for m in messages:
        mm = {"role": m["role"], "content": m.get("content", "") or ""}
        if m["role"] == "assistant" and m.get("tool_calls"):
            mm["tool_calls"] = [
                {"function": {"name": c["name"], "arguments": c["arguments"]}}
                for c in m["tool_calls"]
            ]
        if m["role"] == "tool":
            mm["role"] = "tool"
        out.append(mm)
    return out
