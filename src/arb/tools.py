"""Tool schemas exposed to the model, and dispatch into the World.

Tools are grouped so scenarios can hand an agent only what its task needs. Least
privilege is itself a defense variable: an agent without `send_email` cannot
exfiltrate by email, and we want to be able to measure exactly that.
"""

from __future__ import annotations

from typing import Any

from arb.env.world import World
from arb.types import ToolCall, ToolResult

# Tools whose effects leave the sandbox boundary in a real deployment. Defenses
# and scenarios treat these as the actions worth gating.
SENSITIVE_TOOLS = {"send_email", "write_file", "memory_write"}

_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_files": {
        "description": "List files under a directory path.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory, e.g. /work"}},
            "required": ["path"],
        },
    },
    "read_file": {
        "description": "Read the full contents of a file.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    "write_file": {
        "description": "Write text to a file, overwriting it if it exists.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
    "list_emails": {
        "description": "List emails in a folder.",
        "parameters": {
            "type": "object",
            "properties": {"folder": {"type": "string", "description": "Default 'inbox'."}},
            "required": [],
        },
    },
    "read_email": {
        "description": "Read one email by its id.",
        "parameters": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
    "send_email": {
        "description": "Send an email on the user's behalf.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    "browse": {
        "description": "Fetch the text of a web page by URL.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    "search_web": {
        "description": "Search the web and return matching URLs.",
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    "memory_read": {
        "description": "Read your persistent notes about this user from previous sessions.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    "memory_write": {
        "description": "Save a durable note about this user for future sessions.",
        "parameters": {
            "type": "object",
            "properties": {"key": {"type": "string"}, "value": {"type": "string"}},
            "required": ["key", "value"],
        },
    },
    "finish": {
        "description": "Finish the task and return your final answer to the user.",
        "parameters": {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
        },
    },
}

TOOL_GROUPS: dict[str, list[str]] = {
    "files": ["list_files", "read_file", "write_file"],
    "email": ["list_emails", "read_email", "send_email"],
    "web": ["browse", "search_web"],
    "memory": ["memory_read", "memory_write"],
}


def resolve_tools(names: list[str] | None) -> list[str]:
    """Expand group names (e.g. 'files') into concrete tool names. `finish` is always available."""
    if not names:
        names = list(TOOL_GROUPS)
    out: list[str] = []
    for n in names:
        out.extend(TOOL_GROUPS.get(n, [n]))
    if "finish" not in out:
        out.append("finish")
    seen: set[str] = set()
    return [t for t in out if t in _SCHEMAS and not (t in seen or seen.add(t))]


def openai_schema(names: list[str]) -> list[dict[str, Any]]:
    """Tool definitions in the OpenAI/Ollama function-calling format."""
    return [
        {"type": "function", "function": {"name": n, **_SCHEMAS[n]}} for n in names if n in _SCHEMAS
    ]


def text_schema(names: list[str]) -> str:
    """A plain-text rendering, for backends without native tool calling."""
    lines = []
    for n in names:
        s = _SCHEMAS[n]
        params = ", ".join(s["parameters"]["properties"])
        lines.append(f"- {n}({params}): {s['description']}")
    return "\n".join(lines)


def dispatch(world: World, call: ToolCall) -> ToolResult:
    """Execute a tool call against the world. Never raises — bad calls become errors
    the agent can see and recover from, which is what a real harness does."""
    fn = getattr(world, call.name, None)
    if call.name == "finish":
        return ToolResult(str(call.arguments.get("answer", "")))
    if fn is None or call.name not in _SCHEMAS:
        return ToolResult(f"Unknown tool: {call.name}", error=True)
    try:
        allowed = set(_SCHEMAS[call.name]["parameters"]["properties"])
        kwargs = {k: v for k, v in call.arguments.items() if k in allowed}
        return fn(**kwargs)
    except TypeError as exc:
        return ToolResult(f"Bad arguments for {call.name}: {exc}", error=True)
