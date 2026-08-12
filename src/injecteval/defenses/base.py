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

    def system_prompt_suffix(self) -> str:
        return ""

    def transform_tool_result(
        self, call: ToolCall, result: ToolResult, ctx: DefenseContext
    ) -> ToolResult:
        return result

    def check_tool_call(self, call: ToolCall, ctx: DefenseContext) -> Verdict:
        return Verdict(allow=True)

    # Extra model calls this defense makes per agent step (for cost accounting).
    @property
    def extra_model_calls(self) -> int:
        return 0
