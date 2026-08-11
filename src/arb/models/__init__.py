"""Model backend registry.

Backend specs are strings so they can live in config files and CLI flags:

    scripted:naive_compliant
    ollama:llama3.2:latest
"""

from __future__ import annotations

from arb.models.base import ModelBackend
from arb.models.ollama import OllamaBackend
from arb.models.scripted import NaiveCompliantBackend, ScriptedBackend

__all__ = ["ModelBackend", "OllamaBackend", "ScriptedBackend", "NaiveCompliantBackend", "get_backend"]


def get_backend(spec: str) -> ModelBackend:
    provider, _, rest = spec.partition(":")
    if provider == "scripted":
        if rest in ("", "naive_compliant"):
            return NaiveCompliantBackend()
        raise ValueError(f"Unknown scripted backend: {rest!r}")
    if provider == "ollama":
        return OllamaBackend(model=rest or "llama3.2:latest")
    raise ValueError(
        f"Unknown model backend {spec!r}. Expected 'scripted:...' or 'ollama:<model>'."
    )
