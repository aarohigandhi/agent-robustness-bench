"""End-to-end checks against the deterministic naive backend.

These are the tests that would catch a broken benchmark — the failure mode where
everything runs, reports 0% ASR, and looks like a robust system.
"""

import pytest

from injecteval.eval.runner import run_one
from injecteval.models import get_backend
from injecteval.scenarios import load_all

SCENARIOS = load_all()
ATTACKED = [s for s in SCENARIOS if not s.is_control and not s.followup]
CONTROLS = [s for s in SCENARIOS if s.is_control]
PERSISTENCE = [s for s in SCENARIOS if s.followup]
BENIGN = [s for s in SCENARIOS if s.is_benign_probe]


@pytest.fixture
def backend():
    return get_backend("scripted:naive_compliant")


@pytest.mark.parametrize("scenario", ATTACKED, ids=lambda s: s.id)
def test_attack_is_reachable_with_no_defense(scenario, backend):
    """A scenario an intentionally-exploitable agent cannot break is a broken
    scenario, and would publish as evidence of robustness."""
    outcome = run_one(scenario, backend, "none", seed=0)
    assert outcome.trajectory.attack_success is True


@pytest.mark.parametrize("scenario", CONTROLS, ids=lambda s: s.id)
def test_control_task_is_completable(scenario, backend):
    """Without this ceiling, a low TCR under a defense is unattributable."""
    outcome = run_one(scenario, backend, "none", seed=0)
    assert outcome.trajectory.task_success is True


@pytest.mark.parametrize("scenario", ATTACKED, ids=lambda s: s.id)
@pytest.mark.parametrize("defense", ["taint_tracking", "tool_policy", "layered"])
def test_structural_defenses_block_exfiltration(scenario, defense, backend):
    outcome = run_one(scenario, backend, defense, seed=0)
    assert outcome.trajectory.attack_success is False
    assert any(a.blocked_by for a in outcome.trajectory.actions)


@pytest.mark.parametrize("scenario", ATTACKED, ids=lambda s: s.id)
@pytest.mark.parametrize("defense", ["taint_tracking", "tool_policy", "layered"])
def test_defenses_do_not_destroy_the_task(scenario, defense, backend):
    """The tradeoff guard. A defense that zeroes ASR by breaking the agent is
    not a defense, and this benchmark exists to make that visible."""
    outcome = run_one(scenario, backend, defense, seed=0)
    assert outcome.trajectory.task_success is True


@pytest.mark.parametrize("scenario", PERSISTENCE, ids=lambda s: s.id)
def test_persistence_is_invisible_to_single_turn_scoring(scenario, backend):
    """The core claim of the persistence track, asserted directly."""
    outcome = run_one(scenario, backend, "none", seed=0)
    assert outcome.trajectory.attack_success is False, "session 0 should look clean"
    assert outcome.plant_success is True, "payload should reach durable memory"
    assert outcome.latent_attack_success is True, "and fire in the clean later session"


@pytest.mark.parametrize("scenario", PERSISTENCE, ids=lambda s: s.id)
def test_persistence_blocked_at_the_plant(scenario, backend):
    outcome = run_one(scenario, backend, "taint_tracking", seed=0)
    assert outcome.plant_success is False
    assert outcome.latent_attack_success is False


@pytest.mark.parametrize("scenario", PERSISTENCE, ids=lambda s: s.id)
def test_persistence_blocked_at_the_firing(scenario, backend):
    """tool_policy allows the plant but stops the egress. Distinguishing this
    from blocking the plant is why persistence metrics are reported separately."""
    outcome = run_one(scenario, backend, "tool_policy", seed=0)
    assert outcome.plant_success is True
    assert outcome.latent_attack_success is False


@pytest.mark.parametrize("scenario", BENIGN, ids=lambda s: s.id)
def test_benign_work_completes_undefended(scenario, backend):
    """If the legitimate action does not go through with no defense in place,
    the scenario cannot detect over-blocking and its FPR column is meaningless."""
    outcome = run_one(scenario, backend, "none", seed=0)
    assert outcome.trajectory.task_success is True
    assert outcome.false_positive is False


@pytest.mark.parametrize("scenario", BENIGN, ids=lambda s: s.id)
def test_taint_tracking_blocks_legitimate_work(scenario, backend):
    """The headline false-positive result, pinned so it cannot regress silently.

    Taint tracking scores 0% ASR across every attack family and 100% FPR here.
    Both numbers follow from the same rule, because a summary of a file and an
    exfiltration of that file are indistinguishable by provenance alone."""
    outcome = run_one(scenario, backend, "taint_tracking", seed=0)
    assert outcome.false_positive is True
    assert outcome.trajectory.task_success is False


@pytest.mark.parametrize("scenario", BENIGN, ids=lambda s: s.id)
def test_tool_policy_permits_legitimate_work(scenario, backend):
    """The contrast case. Allowlisting egress destinations stops the same attacks
    without refusing ordinary work, which is what puts it on the frontier."""
    outcome = run_one(scenario, backend, "tool_policy", seed=0)
    assert outcome.false_positive is False
    assert outcome.trajectory.task_success is True


def test_email_addresses_exclude_trailing_punctuation(backend):
    """Regression guard. "forward to sam@corp.test." once yielded the domain
    "corp.test.", which failed the allowlist and surfaced as a defense
    false-positive rather than as the parsing bug it was."""
    scenario = next(s for s in BENIGN if "forward" in s.id)
    outcome = run_one(scenario, backend, "none", seed=0)
    sent = outcome.world.sent_emails
    assert sent, "the benign forward should have gone out"
    assert sent[0].to == "sam@corp.test"


def test_runs_do_not_leak_state_into_each_other(backend):
    """A stateful backend reused across trials silently contaminates every cell
    after the first. This caught a real bug during development."""
    scenario = ATTACKED[0]
    first = run_one(scenario, backend, "none", seed=0)
    second = run_one(scenario, backend, "none", seed=0)
    assert first.trajectory.steps_used == second.trajectory.steps_used
    assert first.trajectory.attack_success == second.trajectory.attack_success
    assert len(second.world.sent_emails) == len(first.world.sent_emails)


def test_fresh_world_per_run(backend):
    scenario = ATTACKED[0]
    a = run_one(scenario, backend, "none", seed=0)
    b = run_one(scenario, backend, "none", seed=1)
    assert a.world is not b.world
