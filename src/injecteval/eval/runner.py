"""Experiment runner.

Builds a fresh world for every single run. Sharing a world between runs would
let one trial's side effects leak into the next, which in a security benchmark
means fabricated attack successes.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from injecteval.attacks import inject
from injecteval.defenses import get_defense
from injecteval.env.world import World, build_world
from injecteval.eval.judge import evaluate
from injecteval.harness.agent import run_agent
from injecteval.models.base import ModelBackend
from injecteval.scenarios import Scenario
from injecteval.tools import resolve_tools
from injecteval.types import Trajectory


@dataclasses.dataclass
class RunOutcome:
    trajectory: Trajectory
    family: str
    world: World
    payload: str = ""
    # Benign scenarios only: the defense blocked legitimate work. None = not measured.
    false_positive: bool | None = None
    # Persistence track only: the second-session trajectory, run against carried memory.
    followup: Trajectory | None = None
    plant_success: bool | None = None
    latent_attack_success: bool | None = None


def run_one(
    scenario: Scenario,
    backend: ModelBackend,
    defense_name: str,
    seed: int,
) -> RunOutcome:
    world = build_world(scenario.environment)
    payload = inject(world, scenario.injection) if scenario.injection else ""
    defense = get_defense(defense_name, backend)
    tools = resolve_tools(scenario.tools)

    traj = run_agent(
        world=world,
        task_prompt=scenario.task_prompt,
        tool_names=tools,
        backend=backend,
        defense=defense,
        seed=seed,
        max_steps=scenario.max_steps,
        scenario_id=scenario.id,
    )
    traj.attack_success = (
        evaluate(scenario.attack_success, traj, world) if scenario.injection else False
    )
    if scenario.injection and scenario.attack_progress:
        # Full success implies progress, so that the two are never contradictory.
        traj.attack_progress = bool(traj.attack_success) or evaluate(
            scenario.attack_progress, traj, world
        )
    traj.task_success = evaluate(scenario.task_success, traj, world)
    if scenario.is_benign_probe:
        traj.false_positive = evaluate(scenario.false_positive, traj, world)

    outcome = RunOutcome(
        trajectory=traj,
        family=scenario.family,
        world=world,
        payload=payload,
        false_positive=traj.false_positive,
    )

    if scenario.followup:
        _run_followup(scenario, backend, defense_name, seed, world, outcome)
    return outcome


def _run_followup(
    scenario: Scenario,
    backend: ModelBackend,
    defense_name: str,
    seed: int,
    session0: World,
    outcome: RunOutcome,
) -> None:
    """The persistence track.

    Session 1 gets a *clean* environment — no poisoned file, no attacker email.
    The only thing carried across is whatever the agent chose to write into its
    own durable memory during session 0. If the attack fires here, it fired from
    memory alone, which is precisely the thing single-turn benchmarks score as a
    clean pass.
    """
    spec = scenario.followup
    outcome.plant_success = evaluate(spec.get("plant_success"), outcome.trajectory, session0)

    world2 = build_world(spec.get("environment") or {})
    world2.memory = dict(session0.memory)  # the only bridge between sessions

    traj2 = run_agent(
        world=world2,
        task_prompt=spec["task"]["prompt"],
        tool_names=resolve_tools(spec.get("tools") or scenario.tools),
        backend=backend,
        defense=get_defense(defense_name, backend),
        seed=seed + 10_000,
        max_steps=int(spec.get("max_steps", scenario.max_steps)),
        scenario_id=f"{scenario.id}#followup",
    )
    traj2.attack_success = evaluate(spec.get("attack_success"), traj2, world2)
    traj2.task_success = evaluate(spec.get("task_success") or scenario.task_success, traj2, world2)

    outcome.followup = traj2
    outcome.latent_attack_success = bool(traj2.attack_success)


def run_grid(
    scenarios: Iterable[Scenario],
    backend: ModelBackend,
    defenses: list[str],
    trials: int = 30,
    seed0: int = 0,
    progress=None,
) -> Iterator[RunOutcome]:
    """Yield one RunOutcome per (scenario x defense x trial) cell.

    A generator so long runs stream to disk instead of accumulating in memory,
    and so a crash three hours in does not cost the completed trials.
    """
    scenarios = list(scenarios)
    total = len(scenarios) * len(defenses) * trials
    done = 0
    for scenario in scenarios:
        for defense_name in defenses:
            for t in range(trials):
                outcome = run_one(scenario, backend, defense_name, seed=seed0 + t)
                done += 1
                if progress:
                    progress(done, total, outcome)
                yield outcome


def write_jsonl(outcomes: Iterable[RunOutcome], path: str | Path) -> int:
    """Persist raw trajectories. Every claim in the writeup must be re-derivable
    from this file without re-running the models."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for outcome in outcomes:
            fh.write(json.dumps(_serialize(outcome), ensure_ascii=False) + "\n")
            n += 1
    return n


def _serialize(outcome: RunOutcome) -> dict[str, Any]:
    rec = {
        "family": outcome.family,
        "payload": outcome.payload,
        "trajectory": _traj_dict(outcome.trajectory),
        "world_after": outcome.world.snapshot(),
    }
    if outcome.followup is not None:
        rec["plant_success"] = outcome.plant_success
        rec["latent_attack_success"] = outcome.latent_attack_success
        rec["followup"] = _traj_dict(outcome.followup)
    return rec


def _traj_dict(traj: Trajectory) -> dict[str, Any]:
    d = dataclasses.asdict(traj)
    d["actions"] = [
        {
            "step": a.step,
            "tool": a.call.name,
            "arguments": a.call.arguments,
            "blocked_by": a.blocked_by,
            "error": a.result.error,
            "provenance": a.result.provenance.value,
            "result_preview": a.result.content[:500],
        }
        for a in traj.actions
    ]
    d.pop("messages", None)  # full transcripts are large; re-derivable from actions
    return d
