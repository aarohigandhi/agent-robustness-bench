"""Payload library and the injector that plants payloads into a World."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

from arb.env.world import World

_PAYLOAD_FILE = Path(__file__).parent / "payloads.yaml"


@functools.lru_cache(maxsize=1)
def payloads() -> dict[str, dict[str, Any]]:
    return yaml.safe_load(_PAYLOAD_FILE.read_text(encoding="utf-8"))


def families() -> list[str]:
    return sorted({p["family"] for p in payloads().values()})


def render(payload_id: str, variables: dict[str, str]) -> str:
    lib = payloads()
    if payload_id not in lib:
        raise ValueError(f"Unknown payload {payload_id!r}. Available: {', '.join(sorted(lib))}")
    template = lib[payload_id]["template"]
    try:
        return template.format(**variables)
    except KeyError as exc:
        raise ValueError(f"Payload {payload_id!r} needs injection var {exc}") from exc


def inject(world: World, spec: dict[str, Any]) -> str:
    """Plant a rendered payload into the world per the scenario's `injection:` block.

    Returns the rendered payload text so the trajectory can record exactly what
    was planted — reproducibility requires the payload, not just its id.
    """
    text = render(spec["payload"], spec.get("vars") or {})
    placement = spec.get("placement") or {}
    kind = placement.get("type", "file")
    mode = placement.get("mode", "append")

    if kind == "file":
        path = placement["path"]
        path = path if path.startswith("/") else "/" + path
        if path not in world.files and mode != "create":
            raise ValueError(f"Injection target file {path!r} not in environment")
        base = world.files.get(path, "")
        world.files[path] = _combine(base, text, mode)
    elif kind == "email":
        eid = str(placement["id"])
        for e in world.emails:
            if e.id == eid:
                e.body = _combine(e.body, text, mode)
                break
        else:
            raise ValueError(f"Injection target email {eid!r} not in environment")
    elif kind == "page":
        url = placement["url"]
        if url not in world.pages and mode != "create":
            raise ValueError(f"Injection target page {url!r} not in environment")
        world.pages[url] = _combine(world.pages.get(url, ""), text, mode)
    elif kind == "memory":
        world.memory[placement.get("key", "note")] = text
    else:
        raise ValueError(f"Unknown injection placement type {kind!r}")
    return text


def _combine(base: str, payload: str, mode: str) -> str:
    if mode == "prepend":
        return f"{payload}\n{base}"
    if mode in ("replace", "create"):
        return payload
    if mode == "middle":
        lines = base.splitlines()
        mid = len(lines) // 2
        return "\n".join(lines[:mid] + [payload] + lines[mid:])
    return f"{base}\n{payload}"  # append
