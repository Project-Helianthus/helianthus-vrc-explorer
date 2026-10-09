import pytest

from helianthus_vrc_explorer.scanner.b524_operation_reads import parse_operation_read_plan
from helianthus_vrc_explorer.ui.operation_planner import (
    append_exact_operation_request,
    operation_planner_rows,
    operation_request_preview,
    parse_operation_request_spec,
    replace_event_day_codes,
)


def test_event_program_groups_days_and_paired_setpoints_without_losing_requests() -> None:
    requests = parse_operation_read_plan(
        {
            "schema_version": 1,
            "requests": [
                {
                    "operation": operation,
                    "profile": "zone",
                    "instance": 1,
                    "address": address,
                    "weekday_code": code,
                }
                for address in (1, 2)
                for code in (0, 1, 2)
                for operation in ("GetEvent", "GetEventSetPoint")
            ],
        }
    )
    rows = operation_planner_rows(requests)
    assert len(rows) == 2
    assert rows[0].indices == tuple(range(6))
    assert rows[1].indices == tuple(range(6, 12))
    assert "Zone" in rows[0].name
    assert "0x01" in rows[0].name
    assert "00..02" in rows[0].scope
    assert "OP09" in rows[0].scope and "OP0B" in rows[0].scope
    assert rows[0].selected([True] * 12) is True
    selection = [True] * 12
    rows[0].toggle(selection)
    assert selection == [False] * 6 + [True] * 6
    rows[0].toggle(selection)
    assert selection == [True] * 12


def test_unpaired_setpoint_and_other_operations_keep_their_exact_selectors() -> None:
    requests = parse_operation_read_plan(
        {
            "schema_version": 1,
            "requests": [
                {"operation": "ReadVR91"},
                {
                    "operation": "GetEventSetPoint",
                    "profile": "dhw",
                    "instance": 0,
                    "address": 2,
                    "weekday_code": 255,
                },
            ],
        }
    )
    rows = operation_planner_rows(requests)
    assert len(rows) == 2
    assert rows[0].indices == (0,)
    assert rows[1].indices == (1,)
    assert "FF" in rows[1].scope
    assert "OP0B" in rows[1].scope and "OP09" not in rows[1].scope


def test_classic_program_editor_updates_raw_codes_and_preserves_other_programs(monkeypatch) -> None:
    from rich.console import Console

    from helianthus_vrc_explorer.scanner.b524_default_events import event_program_requests
    from helianthus_vrc_explorer.ui.planner import prompt_scan_plan

    requests = list(
        event_program_requests("zone", instance=1, address=1, weekday_codes=(0, 1))
        + event_program_requests("zone", instance=1, address=2, weekday_codes=(0, 1))
    )
    unchanged = requests[4:]
    selection = [True] * len(requests)
    answers = iter(["codes 1 0x100", "codes 1 0x08,0xFF", "1"])
    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner.Prompt.ask", lambda *_args, **_kwargs: next(answers)
    )
    console = Console(record=True)
    prompt_scan_plan(
        console,
        [],
        request_rate_rps=None,
        operation_requests=requests,
        operation_selection=selection,
    )
    assert [request.selector["weekday_code"] for request in requests[:4]] == [8, 8, 255, 255]
    assert requests[4:] == unchanged
    assert selection == [True] * 4 + [False] * 4
    assert "Invalid Event codes" in console.export_text()


def test_code_edit_preserves_disabled_program_and_exact_other_selectors() -> None:
    from helianthus_vrc_explorer.scanner.b524_default_events import event_program_requests

    requests = list(
        event_program_requests("system", instance=0, address=1, weekday_codes=(0, 1))
        + event_program_requests("zone", instance=2, address=2, weekday_codes=(0, 1))
    )
    other = requests[4:]
    selection = [False] * 4 + [True] * 4
    replace_event_day_codes(requests, selection, operation_planner_rows(requests)[0], (0xFF,))
    assert len(requests) == 6
    assert requests[2:] == other
    assert selection == [False, False, True, True, True, True]


def test_planner_adds_exact_read_rows_without_argv_and_preserves_vrc700_guards() -> None:
    timer = parse_operation_request_spec(
        "ReadTimer channel=zone-heating instance=0x01 weekday=0x02"
    )
    assert timer.requires_vrc700 is True
    assert timer.selector == {"channel": "zone-heating", "instance": 1, "weekday": 2}
    assert "OP03 ReadTimer" in operation_request_preview(timer)
    assert f"payload={timer.payload.hex()}" in operation_request_preview(timer)

    requests: list[object] = []
    selection: list[bool] = []
    request = append_exact_operation_request(requests, selection, "ReadVR91")
    assert request.requires_vrc700 is True
    assert requests == [request]
    assert selection == [True]
    with pytest.raises(ValueError, match="duplicates"):
        append_exact_operation_request(requests, selection, "ReadVR91")
