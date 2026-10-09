from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.ui.planner_selection import (
    default_description_policy,
    description_probe_required,
    make_planner_selection,
)


def test_known_recommended_uses_profile_without_implicit_describe() -> None:
    policy = default_description_policy("recommended", exact_profile_known=True)
    assert policy.local == "profile"
    assert policy.remote == "profile"
    assert policy.local_override is False
    assert description_probe_required(policy, opcode=0x02) is False
    assert description_probe_required(policy, opcode=0x06) is False


def test_full_research_and_unknown_profile_use_live_writable_descriptions() -> None:
    for preset in ("full", "research"):
        policy = default_description_policy(preset, exact_profile_known=True)
        assert (policy.local, policy.remote) == ("live", "live")
    unknown = default_description_policy("recommended", exact_profile_known=False)
    assert (unknown.local, unknown.remote) == ("live", "live")


def test_custom_follows_profile_and_carries_explicit_per_class_override() -> None:
    policy = default_description_policy("custom", exact_profile_known=True).with_override(
        "remote", "live"
    )
    plan = {
        make_plan_key(2, 2): GroupScanPlan(
            group=2, opcode=2, rr_max=1, instances=(0,), registers=(1,)
        )
    }
    request = object()
    selection = make_planner_selection(
        plan,
        selected_preset="custom",
        operation_requests=(request,),
        operation_selection=(True,),
        description_policy=policy,
    )
    assert selection == plan
    assert selection.selected_preset == "custom"
    assert selection.operation_requests == (request,)
    assert selection.description_policy.for_opcode(2) == "profile"
    assert selection.description_policy.for_opcode(6) == "live"
    assert selection.description_policy.remote_override is True
