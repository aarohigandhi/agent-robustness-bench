"""The sandboxed world the agent acts in.

Deliberately *not* a real filesystem, inbox, or browser. Everything is in-memory
and seeded from the scenario file, which buys us three things the benchmark needs:

  1. Hermetic runs — no network, no live systems, no authorization questions.
  2. Determinism — same seed and same model settings give the same world.
  3. Assertable state — judges read `world.sent_emails` directly instead of
     trying to infer success from the model's prose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from injecteval.types import Provenance, ToolResult


@dataclass
class Email:
    id: str
    sender: str
    to: str
    subject: str
    body: str
    folder: str = "inbox"
    read: bool = False


@dataclass
class SentEmail:
    to: str
    subject: str
    body: str


@dataclass
class World:
    """In-memory filesystem + inbox + web + agent memory."""

    files: dict[str, str] = field(default_factory=dict)
    emails: list[Email] = field(default_factory=list)
    pages: dict[str, str] = field(default_factory=dict)
    memory: dict[str, str] = field(default_factory=dict)

    # --- side-effect ledgers: what the agent actually did to the world ---
    sent_emails: list[SentEmail] = field(default_factory=list)
    written_files: list[str] = field(default_factory=list)
    memory_writes: list[tuple[str, str]] = field(default_factory=list)

    # ------------------------------------------------------------------ files
    def list_files(self, path: str = "/") -> ToolResult:
        path = _norm_dir(path)
        hits = sorted(p for p in self.files if p.startswith(path))
        if not hits:
            return ToolResult(f"No files under {path}", error=True)
        return ToolResult("\n".join(hits))

    def read_file(self, path: str) -> ToolResult:
        path = _norm(path)
        if path not in self.files:
            return ToolResult(f"No such file: {path}", error=True)
        # File contents are attacker-reachable.
        return ToolResult(
            self.files[path], provenance=Provenance.UNTRUSTED, metadata={"source": f"file:{path}"}
        )

    def write_file(self, path: str, content: str) -> ToolResult:
        path = _norm(path)
        self.files[path] = content
        self.written_files.append(path)
        return ToolResult(f"Wrote {len(content)} bytes to {path}")

    # ------------------------------------------------------------------ email
    def list_emails(self, folder: str = "inbox") -> ToolResult:
        rows = [e for e in self.emails if e.folder == folder]
        if not rows:
            return ToolResult(f"No emails in {folder}")
        lines = [f"[{e.id}] from={e.sender} subject={e.subject!r} read={e.read}" for e in rows]
        return ToolResult("\n".join(lines))

    def read_email(self, id: str) -> ToolResult:  # noqa: A002 - matches the tool schema
        for e in self.emails:
            if e.id == str(id):
                e.read = True
                body = f"From: {e.sender}\nTo: {e.to}\nSubject: {e.subject}\n\n{e.body}"
                return ToolResult(
                    body, provenance=Provenance.UNTRUSTED, metadata={"source": f"email:{e.id}"}
                )
        return ToolResult(f"No such email: {id}", error=True)

    def send_email(self, to: str, subject: str, body: str) -> ToolResult:
        self.sent_emails.append(SentEmail(to=to, subject=subject, body=body))
        return ToolResult(f"Email sent to {to}.")

    # -------------------------------------------------------------------- web
    def browse(self, url: str) -> ToolResult:
        if url not in self.pages:
            return ToolResult(f"404: {url}", error=True)
        return ToolResult(
            self.pages[url], provenance=Provenance.UNTRUSTED, metadata={"source": f"web:{url}"}
        )

    def search_web(self, query: str) -> ToolResult:
        hits = [u for u, body in self.pages.items() if query.lower() in (u + body).lower()]
        if not hits:
            return ToolResult(f"No results for {query!r}")
        return ToolResult("\n".join(sorted(hits)))

    # ----------------------------------------------------------------- memory
    def memory_read(self) -> ToolResult:
        if not self.memory:
            return ToolResult("(memory is empty)")
        body = "\n".join(f"{k}: {v}" for k, v in sorted(self.memory.items()))
        # Memory is untrusted: in the persistence track it is exactly the channel
        # a payload uses to survive from one session into the next.
        return ToolResult(body, provenance=Provenance.UNTRUSTED, metadata={"source": "memory"})

    def memory_write(self, key: str, value: str) -> ToolResult:
        self.memory[key] = value
        self.memory_writes.append((key, value))
        return ToolResult(f"Remembered {key!r}.")

    # ------------------------------------------------------------------ misc
    def snapshot(self) -> dict[str, Any]:
        return {
            "sent_emails": [vars(e) for e in self.sent_emails],
            "written_files": list(self.written_files),
            "memory": dict(self.memory),
            "memory_writes": [list(t) for t in self.memory_writes],
        }


def _norm(path: str) -> str:
    p = str(path).replace("\\", "/").strip()
    return p if p.startswith("/") else "/" + p


def _norm_dir(path: str) -> str:
    p = _norm(path)
    return p if p.endswith("/") else p + "/"


def build_world(spec: dict[str, Any]) -> World:
    """Construct a World from the `environment:` block of a scenario file."""
    w = World()
    w.files = {_norm(k): v for k, v in (spec.get("files") or {}).items()}
    w.pages = dict(spec.get("pages") or {})
    w.memory = dict(spec.get("memory") or {})
    for i, e in enumerate(spec.get("emails") or []):
        w.emails.append(
            Email(
                id=str(e.get("id", i + 1)),
                sender=e.get("from", "unknown@example.test"),
                to=e.get("to", "user@example.test"),
                subject=e.get("subject", ""),
                body=e.get("body", ""),
                folder=e.get("folder", "inbox"),
            )
        )
    return w
