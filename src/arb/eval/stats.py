"""Proportion statistics and results aggregation.

Wilson score intervals rather than the normal approximation, because a working
defense scores near zero and that is exactly where the naive interval breaks:
0/30 successes gives `0.0 +/- 0.0`, asserting certainty from thirty samples.
Wilson returns [0, 0.11] instead, which is the honest statement.

Reference: Wilson, E.B. (1927), J. Am. Stat. Assoc. 22(158), 209-212.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

# Two-sided normal quantiles for common confidence levels.
_Z = {0.90: 1.6449, 0.95: 1.9600, 0.99: 2.5758}


def wilson(successes: int, n: int, confidence: float = 0.95) -> tuple[float, float, float]:
    """Return (point estimate, lower bound, upper bound) as proportions in [0, 1]."""
    if n <= 0:
        return (0.0, 0.0, 1.0)
    if successes < 0 or successes > n:
        raise ValueError(f"successes={successes} out of range for n={n}")
    z = _Z.get(confidence)
    if z is None:
        raise ValueError(f"confidence must be one of {sorted(_Z)}")

    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (p, max(0.0, center - margin), min(1.0, center + margin))


def intervals_overlap(a: tuple[float, float, float], b: tuple[float, float, float]) -> bool:
    """Cheap significance guard. If two intervals overlap, do not claim a
    difference between them in the writeup."""
    return not (a[2] < b[1] or b[2] < a[1])


@dataclass
class Cell:
    """One (scenario-family x defense x model) combination — the unit that gets n runs."""

    key: tuple[str, ...]
    n: int = 0
    attack_successes: int = 0
    task_successes: int = 0
    errors: int = 0
    blocked_calls: int = 0
    latency_s: list[float] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def asr(self) -> tuple[float, float, float]:
        return wilson(self.attack_successes, self.n)

    @property
    def tcr(self) -> tuple[float, float, float]:
        return wilson(self.task_successes, self.n)

    @property
    def mean_latency(self) -> float:
        return sum(self.latency_s) / len(self.latency_s) if self.latency_s else 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def aggregate(trajectories, key_fields=("family", "defense")) -> dict[tuple[str, ...], Cell]:
    """Bucket scored trajectories into cells. `trajectories` is an iterable of
    (trajectory, family) pairs already carrying attack_success / task_success."""
    cells: dict[tuple[str, ...], Cell] = {}
    for traj, family in trajectories:
        attrs = {"family": family, "defense": traj.defense, "model": traj.model,
                 "scenario": traj.scenario_id}
        key = tuple(str(attrs[f]) for f in key_fields)
        cell = cells.setdefault(key, Cell(key=key))
        cell.n += 1
        cell.attack_successes += int(bool(traj.attack_success))
        cell.task_successes += int(bool(traj.task_success))
        cell.errors += int(traj.error is not None)
        cell.blocked_calls += sum(1 for a in traj.actions if a.blocked_by)
        cell.latency_s.append(traj.latency_s)
        cell.prompt_tokens += traj.usage.get("prompt_tokens", 0)
        cell.completion_tokens += traj.usage.get("completion_tokens", 0)
    return cells


def _pct(t: tuple[float, float, float]) -> str:
    p, lo, hi = t
    return f"{p * 100:5.1f}%  [{lo * 100:.1f}, {hi * 100:.1f}]"


def markdown_table(cells: dict[tuple[str, ...], Cell], key_fields=("family", "defense")) -> str:
    """Render the results grid. Intervals are printed next to every rate so a
    reader cannot accidentally treat a noisy number as a finding."""
    headers = [f.title() for f in key_fields] + [
        "n", "ASR (95% CI)", "TCR (95% CI)", "Blocked", "Mean s", "Tokens"
    ]
    rows = [headers, ["---"] * len(headers)]
    for key in sorted(cells):
        c = cells[key]
        rows.append(
            list(key)
            + [
                str(c.n),
                _pct(c.asr),
                _pct(c.tcr),
                str(c.blocked_calls),
                f"{c.mean_latency:.2f}",
                str(c.total_tokens),
            ]
        )
    return "\n".join("| " + " | ".join(r) + " |" for r in rows)


def persistence_table(outcomes) -> str:
    """Persistence metrics broken out per defense.

    Pooling these across defenses would hide the whole finding: a defense can
    block the plant, or allow the plant but block the later firing, and those are
    different security properties with different failure modes. The session-0
    column is kept alongside deliberately — it is the number single-turn work
    publishes, and the gap between it and latent ASR is the contribution.
    """
    by_defense: dict[str, list] = {}
    for o in outcomes:
        if o.followup is not None:
            by_defense.setdefault(o.trajectory.defense, []).append(o)

    lines = [
        "| Defense | n | Session-0 ASR | Plant rate | Latent ASR (95% CI) |",
        "| --- | --- | --- | --- | --- |",
    ]
    for defense in sorted(by_defense):
        runs = by_defense[defense]
        n = len(runs)
        s0 = sum(1 for o in runs if o.trajectory.attack_success)
        planted = sum(1 for o in runs if o.plant_success)
        latent = sum(1 for o in runs if o.latent_attack_success)
        lines.append(
            f"| {defense} | {n} | {s0 / n * 100:.1f}% | {planted / n * 100:.1f}% "
            f"| {_pct(wilson(latent, n))} |"
        )
    return "\n".join(lines)


def worst_case_summary(cells: dict[tuple[str, ...], Cell]) -> str:
    """Per-defense worst family, not the mean.

    An attacker picks the family that works; they do not sample uniformly. The
    pooled average of one catastrophic family and five clean ones describes
    neither, and errs toward claiming safety. This table reports the max.
    """
    by_defense: dict[str, list[tuple[str, Cell]]] = {}
    for (family, defense), cell in cells.items():
        by_defense.setdefault(defense, []).append((family, cell))

    lines = ["| Defense | Mean ASR | Worst family | Worst-case ASR |", "| --- | --- | --- | --- |"]
    for defense in sorted(by_defense):
        entries = by_defense[defense]
        total_n = sum(c.n for _, c in entries)
        total_hits = sum(c.attack_successes for _, c in entries)
        mean = total_hits / total_n if total_n else 0.0
        worst_family, worst = max(entries, key=lambda kv: kv[1].asr[0])
        lines.append(
            f"| {defense} | {mean * 100:.1f}% | {worst_family} | {_pct(worst.asr)} |"
        )
    return "\n".join(lines)
