"""Core data types shared across the harness.

Everything the scorer reads is defined here. The most important invariant in the
whole benchmark lives in `ToolResult.provenance`: any bytes that originated from
somewhere other than the user's own instruction are marked UNTRUSTED, and that
label is what taint-tracking and privilege-separation defenses key off.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Provenance(str, Enum):
    """Where the bytes in a tool result came from."""

    TRUSTED = "trusted"  # produced by the harness or the user's own prompt
    UNTRUSTED = "untrusted"  # file contents, email bodies, web pages — attacker-reachable


@dataclass
class ToolCall:
    """A single tool invocation proposed by the model."""

    name: str
    arguments: dict[str, Any]
    id: str = ""

    def summary(self) -> str:
        args = ", ".join(f"{k}={v!r}" for k, v in self.arguments.items())
        return f"{self.name}({args})"


@dataclass
class ToolResult:
    content: str
    provenance: Provenance = Provenance.TRUSTED
    error: bool = False
    # Free-form; e.g. {"source": "email:3"} so we can attribute a taint back to its origin.
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionRecord:
    """An executed tool call plus its outcome. The action log is the ground truth
    that judges assert against — never the model's own description of what it did."""

    step: int
    call: ToolCall
    result: ToolResult
    blocked_by: str | None = None  # name of the defense that vetoed it, if any


@dataclass
class ModelResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Trajectory:
    """The complete record of one agent run. Serialized to JSONL, one per line."""

    scenario_id: str
    defense: str
    model: str
    seed: int
    actions: list[ActionRecord] = field(default_factory=list)
    messages: list[dict[str, Any]] = field(default_factory=list)
    final_answer: str = ""
    steps_used: int = 0
    stopped_reason: str = ""
    latency_s: float = 0.0
    usage: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    # Scored after the fact by arb.eval.judge
    attack_success: bool | None = None
    task_success: bool | None = None

    def called(self, tool_name: str) -> list[ActionRecord]:
        """Executed (not blocked) calls to a given tool."""
        return [a for a in self.actions if a.call.name == tool_name and a.blocked_by is None]


@dataclass
class Verdict:
    """A defense's ruling on a proposed tool call."""

    allow: bool
    reason: str = ""
