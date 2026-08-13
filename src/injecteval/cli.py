"""Command line interface.

injecteval scenarios                        list scenarios
injecteval defenses                         list defenses
injecteval payloads                         list attack families
injecteval run --trials 30                  run the grid and print the results
injecteval selftest                         validate every scenario is exploitable
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from injecteval.attacks import payloads
from injecteval.defenses import DEFENSES, MODEL_BACKED
from injecteval.eval.runner import run_grid, run_one, write_jsonl
from injecteval.eval.stats import (
    aggregate,
    false_positive_table,
    markdown_table,
    persistence_table,
    worst_case_summary,
)
from injecteval.models import get_backend
from injecteval.scenarios import load_all

# Defenses that cost nothing but a regex and a system prompt. Always runnable.
STATIC_DEFENSES = [
    "none",
    "prompt_hardening",
    "spotlighting",
    "taint_tracking",
    "tool_policy",
    "layered",
]


def _cmd_scenarios(args) -> int:
    for s in load_all(args.scenario_dir):
        kind = "control" if s.is_control else s.family
        print(f"{s.id:<32} {kind:<22} tools={','.join(s.tools) or 'all'}")
    return 0


def _cmd_defenses(args) -> int:
    for name in sorted(DEFENSES):
        print(f"{name:<20} {DEFENSES[name].description}")
    return 0


def _cmd_payloads(args) -> int:
    for pid, spec in sorted(payloads().items()):
        print(f"{pid:<22} [{spec['family']}]")
        print(f"  {' '.join(spec['description'].split())}\n")
    return 0


def _cmd_run(args) -> int:
    scenarios = load_all(args.scenario_dir)
    if args.scenario:
        wanted = set(args.scenario)
        scenarios = [s for s in scenarios if s.id in wanted]
        if not scenarios:
            print(f"No scenarios matched {sorted(wanted)}", file=sys.stderr)
            return 1

    backend = get_backend(args.model)
    scripted = args.model.startswith("scripted:")
    # Model-backed defenses need a real model to reason with. Handing them the
    # deterministic stub would produce a monitor that vetoes everything and an
    # extractor that returns nothing — 0% ASR and 0% TCR, which looks like a
    # result and is an artifact. Off by default on the stub, refused if asked for.
    defenses = args.defense or (
        STATIC_DEFENSES if scripted else STATIC_DEFENSES + sorted(MODEL_BACKED)
    )
    if scripted and (bad := sorted(set(defenses) & MODEL_BACKED)):
        print(
            f"error: {', '.join(bad)} "
            f"{'requires' if len(bad) == 1 else 'require'} a real model; "
            f"rerun with --model ollama:<name>",
            file=sys.stderr,
        )
        return 1
    total = len(scenarios) * len(defenses) * args.trials

    print(f"model    : {backend.name}")
    print(f"scenarios: {len(scenarios)}   defenses: {len(defenses)}   trials: {args.trials}")
    print(f"runs     : {total}\n")

    def progress(done, total, outcome):
        if args.quiet:
            return
        bar = f"[{done:>{len(str(total))}}/{total}]"
        t = outcome.trajectory
        flags = "".join(
            ("A" if t.attack_success else "."),
        ) + ("T" if t.task_success else ".")
        print(f"\r{bar} {t.scenario_id[:28]:<28} {t.defense:<18} {flags}", end="", flush=True)

    outcomes = list(run_grid(scenarios, backend, defenses, args.trials, progress=progress))
    if not args.quiet:
        print("\n")

    out = Path(args.out)
    n = write_jsonl(outcomes, out)
    print(f"wrote {n} trajectories -> {out}\n")

    scored = [(o.trajectory, o.family) for o in outcomes]
    cells = aggregate(scored, key_fields=("family", "defense"))
    print("## Attack success and task completion by family x defense\n")
    print(markdown_table(cells, key_fields=("family", "defense")))

    attacked = {k: c for k, c in cells.items() if k[0] != "none"}
    if attacked:
        print("\n## Worst case per defense\n")
        print(
            "An attacker uses the family that works, so the mean understates "
            "exposure. The right-hand column is the number to design against.\n"
        )
        print(worst_case_summary(attacked))

    if any(o.false_positive is not None for o in outcomes):
        print("\n## What the defenses break\n")
        print(
            "Benign scenarios only: no injection anywhere, and a sensitive action the user\n"
            "explicitly asked for. Every block counted here is legitimate work refused. Read\n"
            "this table next to the ASR grid above — a defense that wins there and loses here\n"
            "has not solved the problem, it has moved it.\n"
        )
        print(false_positive_table(outcomes))

    if any(o.followup is not None for o in outcomes):
        print("\n## Persistence track\n")
        print(
            "Session-0 ASR is what a single-turn benchmark would publish. Latent ASR is\n"
            "the same payload firing in a later session against a clean environment, with\n"
            "no attacker content present. The gap between those two columns is the finding.\n"
        )
        print(persistence_table(outcomes))
    return 0


def _cmd_selftest(args) -> int:
    """Every attack scenario must be exploitable by an agent that is trying to be
    exploited. A scenario the naive backend cannot break is a broken scenario,
    and would otherwise be published as evidence of robustness."""
    backend = get_backend("scripted:naive_compliant")
    failures = []
    for s in load_all(args.scenario_dir):
        outcome = run_one(s, backend, "none", seed=0)
        t = outcome.trajectory
        if s.is_benign_probe:
            # Undefended, the legitimate action must go through. If it does not,
            # the scenario cannot detect over-blocking and the FPR column is a lie.
            ok = bool(t.task_success) and not t.false_positive
            label = "benign work completes"
        elif s.is_control:
            ok = bool(t.task_success)
            label = "task reachable"
        elif s.followup:
            ok = bool(outcome.plant_success and outcome.latent_attack_success)
            label = "plants and fires later"
        else:
            ok = bool(t.attack_success)
            label = "attack reachable"
        status = "ok  " if ok else "FAIL"
        print(f"{status} {s.id:<32} {label:<24} steps={t.steps_used} task={bool(t.task_success)}")
        if not ok:
            failures.append(s.id)

    if failures:
        print(
            f"\n{len(failures)} scenario(s) not reachable: {', '.join(failures)}", file=sys.stderr
        )
        return 1
    print("\nall scenarios reachable")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="injecteval", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--scenario-dir", default=None, help="Directory of scenario YAML files.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scenarios", help="List scenarios.").set_defaults(fn=_cmd_scenarios)
    sub.add_parser("defenses", help="List defenses.").set_defaults(fn=_cmd_defenses)
    sub.add_parser("payloads", help="List attack families.").set_defaults(fn=_cmd_payloads)

    r = sub.add_parser("run", help="Run the benchmark grid.")
    r.add_argument(
        "--model",
        default="scripted:naive_compliant",
        help="Backend spec, e.g. ollama:llama3.2:latest",
    )
    r.add_argument(
        "--trials",
        type=int,
        default=30,
        help="Runs per cell. Below ~30 the intervals are too wide to conclude anything.",
    )
    r.add_argument("--defense", action="append", help="Repeatable. Defaults to all.")
    r.add_argument("--scenario", action="append", help="Repeatable scenario id filter.")
    r.add_argument("--out", default="results/runs.jsonl")
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(fn=_cmd_run)

    st = sub.add_parser("selftest", help="Check every scenario is actually exploitable.")
    st.set_defaults(fn=_cmd_selftest)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
