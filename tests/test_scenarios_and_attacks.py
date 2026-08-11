import pytest

from arb.attacks import families, inject, payloads, render
from arb.env.world import build_world
from arb.scenarios import load_all

SCENARIOS = load_all()


def test_scenarios_exist():
    assert len(SCENARIOS) >= 5


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_scenario_injection_resolves_and_lands(scenario):
    """Every scenario's payload must render with the vars it declares and land
    somewhere the agent can actually reach. A payload planted at a path that does
    not exist would silently produce 0% ASR."""
    world = build_world(scenario.environment)
    if scenario.is_control:
        assert scenario.injection is None
        return

    text = inject(world, scenario.injection)
    assert "{" not in text, "unrendered template variable left in payload"

    blob = (
        "\n".join(world.files.values())
        + "\n".join(e.body for e in world.emails)
        + "\n".join(world.pages.values())
        + "\n".join(world.memory.values())
    )
    assert text.strip() in blob


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_attacked_scenarios_declare_success_criteria(scenario):
    assert scenario.task_success
    if not scenario.is_control:
        assert scenario.attack_success, "an attacked scenario needs an attack_success judge"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_exfil_sinks_use_the_reserved_test_tld(scenario):
    """Scope guard. `.test` cannot resolve on the public internet, so no payload
    in this repository is a working exploit even if copied out of it."""
    for value in ((scenario.injection or {}).get("vars") or {}).values():
        if "@" in str(value):
            assert str(value).endswith(".test"), f"non-.test sink: {value}"


def test_payload_library_covers_the_declared_families():
    assert set(families()) >= {
        "naive_override",
        "authority_spoof",
        "tool_result_spoof",
        "obfuscated",
        "conditional_trigger",
        "memory_persistence",
    }


def test_every_payload_documents_itself():
    for pid, spec in payloads().items():
        assert spec.get("description", "").strip(), f"{pid} has no description"
        assert spec.get("family"), f"{pid} has no family"


def test_missing_template_var_fails_loudly():
    with pytest.raises(ValueError):
        render("authority_spoof", {})


def test_injection_into_a_missing_target_fails_loudly():
    world = build_world({"files": {"/a.txt": "hi"}})
    spec = {
        "payload": "naive_override",
        "placement": {"type": "file", "path": "/nope.txt", "mode": "append"},
        "vars": {"target_file": "/a.txt", "exfil_address": "x@y.test"},
    }
    with pytest.raises(ValueError):
        inject(world, spec)
