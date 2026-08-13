"""Scenario loading.

A scenario is a declarative YAML file, not code. That is the single most
important structural choice in the benchmark: task, environment, attack, and
success criteria become four independent axes, so an ablation is a loop rather
than a rewrite, and an outside contributor can add a case without reading the
harness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SCENARIO_DIR = Path(__file__).parent / "scenario_files"


@dataclass
class Scenario:
    id: str
    task_prompt: str
    environment: dict[str, Any]
    tools: list[str]
    attack_success: dict[str, Any]
    task_success: dict[str, Any]
    injection: dict[str, Any] | None = None
    # Did the agent take *any* attacker-directed step, short of full success?
    # Binary ASR scores a partial compliance as a clean pass, which is wrong: an
    # agent that opened the credentials file but did not send it was compromised.
    attack_progress: dict[str, Any] | None = None
    # Benign scenarios: what it looks like when a defense blocks legitimate work.
    false_positive: dict[str, Any] | None = None
    description: str = ""
    family: str = "none"
    max_steps: int = 12
    # Persistence track: a follow-up session run against carried-over memory.
    followup: dict[str, Any] | None = None
    path: Path | None = None
    tags: list[str] = field(default_factory=list)

    @property
    def is_control(self) -> bool:
        """Control scenarios carry no injection and measure baseline task completion."""
        return self.injection is None

    @property
    def is_benign_probe(self) -> bool:
        """Benign scenarios that require a *legitimate* sensitive action, so that
        over-blocking by a defense is measurable rather than invisible."""
        return self.false_positive is not None


def load_scenario(path: str | Path) -> Scenario:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    missing = {"id", "task", "environment", "attack_success", "task_success"} - set(raw)
    if missing and not (missing == {"attack_success"} and "injection" not in raw):
        raise ValueError(f"{path.name}: missing required keys: {', '.join(sorted(missing))}")
    injection = raw.get("injection")
    return Scenario(
        id=raw["id"],
        description=raw.get("description", ""),
        task_prompt=raw["task"]["prompt"],
        environment=raw["environment"],
        tools=raw.get("tools") or [],
        injection=injection,
        attack_progress=raw.get("attack_progress"),
        false_positive=raw.get("false_positive"),
        family=(injection or {}).get("family", "none"),
        attack_success=raw.get("attack_success") or {},
        task_success=raw["task_success"],
        max_steps=int(raw.get("max_steps", 12)),
        followup=raw.get("followup"),
        tags=raw.get("tags") or [],
        path=path,
    )


def load_all(directory: str | Path | None = None) -> list[Scenario]:
    d = Path(directory) if directory else SCENARIO_DIR
    return sorted((load_scenario(p) for p in d.glob("*.yaml")), key=lambda s: s.id)
