"""Defense interface.

A defense is middleware with three hooks, which is enough to express every
mitigation family in the literature without special-casing any of them:

    system_prompt_suffix()   -> instruction-level hardening
    transform_tool_result()  -> what the model is allowed to see
    check_tool_call()        -> what the model is allowed to do

Defenses also declare `overhead`, because a mitigation that halves ASR at 3x the
latency and 2x the tokens is a different product decision than one that is free,
and the comparison table is useless without that column.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from injecteval.types import ToolCall, ToolResult, Verdict


@dataclass
class DefenseContext:
    """Everything a defense may inspect when ruling on a call."""

    user_task: str
    step: int
    # Text the agent has seen that came from untrusted sources, in arrival order.
    untrusted_seen: list[ToolResult] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


class Defense:
    name: str = "none"
    description: str = "No mitigation. Baseline."

    # Set by defenses that make their own model calls. A defense that needs a
    # model and silently degrades without one would report as working, so
    # construction fails loudly instead.
    needs_model: bool = False

    def __init__(self, backend: Any = None) -> None:
        self.backend = backend
        self.model_calls = 0
        self.model_tokens = 0
        if self.needs_model and backend is None:
            raise ValueError(
                f"Defense {self.name!r} makes its own model calls and needs a backend. "
                f"Pass one to get_defense(), or run this defense only with --model set."
            )

    def _ask(self, prompt: str, seed: int = 0) -> str:
        """One quarantined model call, metered so its cost lands in the results."""
        resp = self.backend.chat([{"role": "user", "content": prompt}], [], seed=seed)
        self.model_calls += 1
        self.model_tokens += sum((resp.usage or {}).values())
        return resp.text or ""

    def system_prompt_suffix(self) -> str:
        return ""

    def transform_tool_result(
        self, call: ToolCall, result: ToolResult, ctx: DefenseContext
    ) -> ToolResult:
        return result

    def check_tool_call(self, call: ToolCall, ctx: DefenseContext) -> Verdict:
        return Verdict(allow=True)

    @property
    def extra_model_calls(self) -> int:
        return self.model_calls
