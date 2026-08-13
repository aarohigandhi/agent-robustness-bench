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

from injecteval.types import ModelResponse, ToolCall

# Marks the exfiltration sink a payload asks for. Payloads embed a literal
# address; the naive agent picks it up the same way a compromised model would.
# Trailing punctuation must not be captured. "send to bob@corp.test." would
# otherwise yield the domain "corp.test.", which silently fails an allowlist
# check and shows up in results as a defense false-positive rather than a bug.
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


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
        self._did_task = False

    def reset(self) -> None:
        """Called at the start of every run. Without this, state from one trial
        leaks into the next and every cell after the first is contaminated."""
        self._seen = set()
        self._obeyed = False
        self._did_task = False

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        seed: int = 0,
        temperature: float = 0.0,
    ) -> ModelResponse:
        available = {t["function"]["name"] for t in tools}
        observed = "\n".join(str(m.get("content") or "") for m in messages if m["role"] == "tool")
        user_task = next((str(m.get("content") or "") for m in messages if m["role"] == "user"), "")

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

        # 3. Everything is read. Carry out the sensitive action the *user* asked
        #    for, if there is one. This is the legitimate-work path, and it is
        #    what the false-positive scenarios measure: a defense that blocks
        #    here has broken the agent rather than protected it.
        if not self._did_task:
            call = self._intended(user_task, observed, available)
            if call:
                self._did_task = True
                return ModelResponse(text="Carrying out your request.", tool_calls=[call])

        return ModelResponse(tool_calls=[ToolCall("finish", {"answer": _summarize(observed)})])

    def _intended(self, user_task: str, observed: str, available: set[str]) -> ToolCall | None:
        """Parse an explicit sensitive request out of the user's own instruction.

        Deliberately reads only the user turn. The distinction between "the user
        told me to send this" and "a file told me to send this" is the entire
        subject of this benchmark, and collapsing the two here would make the
        false-positive numbers meaningless.
        """
        low = user_task.lower()

        if "send_email" in available and ("forward" in low or "send" in low):
            m = re.search(
                r"\b(?:to|address)\b[^\w]*([\w.+-]+@[\w-]+(?:\.[\w-]+)+)", user_task, re.I
            )
            if m:
                return ToolCall(
                    "send_email",
                    {"to": m.group(1), "subject": "Forwarded", "body": _summarize(observed)},
                )

        if "write_file" in available and ("save" in low or "write" in low):
            m = re.search(r"\b(?:to|in|at)\s+(/\S+)", user_task)
            if m:
                return ToolCall(
                    "write_file", {"path": m.group(1).rstrip(".,"), "content": _summarize(observed)}
                )

        if "memory_write" in available and ("remember" in low or "preference" in low):
            return ToolCall(
                "memory_write", {"key": "user_preference", "value": _summarize(observed)[:400]}
            )
        return None

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
    # Generous cap. At 1200 characters, defenses that *add* text — spotlighting's
    # fences, block notices — pushed later content past the cutoff and failed the
    # task-completion judge. That reads as "the defense broke the agent" when it
    # was the stub summariser truncating.
    return " ".join(observed.split())[:6000] or "No data found."
