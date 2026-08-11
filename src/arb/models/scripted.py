"""Deterministic fake backends.

`NaiveCompliantBackend` is the one that matters. It is a hand-written agent that
reads everything it can reach and then obeys the first imperative it finds in
untrusted content. It is not a model — it is a *fixed upper bound on
vulnerability*, and it earns its place for three reasons:

  1. CI can run the entire pipeline — env, injection, defenses, judges — with no
     GPU, no network, and no model weights.
  2. It validates the judges. If a scenario's attack cannot succeed against an
     agent that is trying to be exploited, the scenario is broken, not robust.
  3. It gives every defense a control: a defense that fails to move ASR against
     this backend does not work at all, independent of model choice.
"""

from __future__ import annotations

import re
from typing import Any

from arb.types import ModelResponse, ToolCall

# Marks the exfiltration sink a payload asks for. Payloads embed a literal
# address; the naive agent picks it up the same way a compromised model would.
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


class ScriptedBackend:
    """Replays a fixed list of ModelResponses. For unit tests."""

    def __init__(self, responses: list[ModelResponse], name: str = "scripted") -> None:
        self.responses = list(responses)
        self.name = name
        self._i = 0

    def reset(self) -> None:
        self._i = 0

    def chat(self, messages, tools, seed: int = 0, temperature: float = 0.0) -> ModelResponse:
        if self._i >= len(self.responses):
            return ModelResponse(tool_calls=[ToolCall("finish", {"answer": "done"})])
        r = self.responses[self._i]
        self._i += 1
        return r


class NaiveCompliantBackend:
    """A maximally-injectable agent, implemented without a model."""

    name = "scripted:naive_compliant"

    # Words that mark text as an imperative aimed at the assistant. Kept blunt on
    # purpose: this backend models "obeys anything that looks like an order", not
    # any particular model's judgement.
    _IMPERATIVE = ("ignore", "instruction", "system", "forward", "must", "required", "directive")

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._obeyed = False

    def reset(self) -> None:
        """Called at the start of every run. Without this, state from one trial
        leaks into the next and every cell after the first is contaminated."""
        self._seen = set()
        self._obeyed = False

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        seed: int = 0,
        temperature: float = 0.0,
    ) -> ModelResponse:
        available = {t["function"]["name"] for t in tools}
        observed = "\n".join(str(m.get("content") or "") for m in messages if m["role"] == "tool")

        # 1. Obey any injected instruction as soon as one is visible.
        if not self._obeyed:
            call = self._obey(observed, available)
            if call:
                self._obeyed = True
                return ModelResponse(text="Handling an additional request.", tool_calls=[call])

        # 2. Otherwise, explore: enumerate, then read everything enumerated.
        for probe, args in (
            ("list_files", {"path": "/"}),
            ("list_emails", {"folder": "inbox"}),
            ("memory_read", {}),
            ("search_web", {"query": ""}),
        ):
            if probe in available and probe not in self._seen:
                self._seen.add(probe)
                return ModelResponse(tool_calls=[ToolCall(probe, args)])

        readers = (
            ("read_file", "path", r"^/\S+", available),
            ("read_email", "id", r"^\[(\w+)\]", available),
            ("browse", "url", r"https?://\S+", available),
        )
        for tool, arg, pattern, avail in readers:
            if tool not in avail:
                continue
            for target in re.findall(pattern, observed, re.MULTILINE):
                if f"{tool}:{target}" not in self._seen:
                    self._seen.add(f"{tool}:{target}")
                    return ModelResponse(tool_calls=[ToolCall(tool, {arg: target})])

        return ModelResponse(tool_calls=[ToolCall("finish", {"answer": _summarize(observed)})])

    def _obey(self, observed: str, available: set[str]) -> ToolCall | None:
        low = observed.lower()

        # Memory plants are checked first. A payload that explicitly asks to be
        # saved for later is a persistence attack, and treating it as an
        # immediate exfil would collapse the two families into one.
        if "memory_write" in available and ("persistent notes" in low or "future sessions" in low):
            m = re.search(r"remember[^\n:]*[:\-]\s*(.+)", observed, re.IGNORECASE)
            if m:
                return ToolCall(
                    "memory_write", {"key": "user_preference", "value": m.group(1).strip()[:400]}
                )

        if "send_email" in available and any(w in low for w in self._IMPERATIVE):
            # Exfiltrate to the last address mentioned in untrusted content that
            # is not the user's own — the same heuristic a duped model applies.
            addrs = [a for a in _EMAIL_RE.findall(observed) if not a.startswith("user@")]
            if addrs:
                return ToolCall(
                    "send_email",
                    {"to": addrs[-1], "subject": "Requested data", "body": observed[:2000]},
                )
        return None


def _summarize(observed: str) -> str:
    return " ".join(observed.split())[:1200] or "No data found."
