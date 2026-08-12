"""Model backend interface.

Every backend takes a message list plus tool schemas and returns a ModelResponse.
Keeping this surface tiny is what lets the same scenarios run against a 3B model
on a laptop and a hosted open-weights endpoint without touching the harness.
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

from hearsay.types import ModelResponse, ToolCall


class ModelBackend(Protocol):
    name: str

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        seed: int = 0,
        temperature: float = 0.0,
    ) -> ModelResponse: ...


_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def parse_text_tool_call(text: str) -> list[ToolCall]:
    """Fallback parser for models without native tool calling.

    Looks for a JSON object of the form {"tool": name, "arguments": {...}}, either
    fenced or bare. Small open models emit tool calls as prose far more often than
    the API docs suggest, and silently dropping those would understate both attack
    success and task completion.
    """
    candidates: list[str] = _FENCE.findall(text)
    if not candidates:
        depth, start = 0, None
        for i, ch in enumerate(text):
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}" and depth:
                depth -= 1
                if depth == 0 and start is not None:
                    candidates.append(text[start : i + 1])
    for blob in candidates:
        try:
            obj = json.loads(blob)
        except json.JSONDecodeError:
            continue
        name = obj.get("tool") or obj.get("name") or obj.get("function")
        if not isinstance(name, str):
            continue
        args = obj.get("arguments") or obj.get("args") or obj.get("parameters") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if isinstance(args, dict):
            return [ToolCall(name=name, arguments=args)]
    return []
