"""Compact program selections shared by the visual and classic planners."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from ..scanner.plan import parse_int_token


def raw_code_range(codes: Sequence[int]) -> str:
    values = sorted(set(codes))
    if len(values) > 1 and values == list(range(values[0], values[-1] + 1)):
        return f"{values[0]:02X}..{values[-1]:02X}"
    return ",".join(f"{value:02X}" for value in values)


@dataclass(frozen=True)
class OperationPlannerRow:
    indices: tuple[int, ...]
    name: str
    scope: str
    profile: str | None = None
    instance: int = 0
    address: int = 0
    codes: tuple[int, ...] = ()
    automatic: bool = False

    def selected(self, selection: Sequence[bool]) -> bool:
        return all(selection[index] for index in self.indices)

    def mark(self, selection: Sequence[bool]) -> str:
        if self.selected(selection):
            return "✓"
        return "◐" if any(selection[index] for index in self.indices) else " "

    def toggle(self, selection: list[bool]) -> None:
        enabled = not self.selected(selection)
        for index in self.indices:
            selection[index] = enabled


def operation_planner_rows(requests: Sequence[object]) -> list[OperationPlannerRow]:
    grouped: dict[tuple[object, ...], list[int]] = {}
    key: tuple[object, ...]
    for index, request in enumerate(requests):
        selector = getattr(request, "selector", {})
        operation = getattr(request, "operation", "operation")
        if (
            operation in {"GetEvent", "GetEventSetPoint"}
            and isinstance(selector, Mapping)
            and selector.get("profile") in {"system", "dhw", "zone"}
            and all(
                type(selector.get(key)) is int for key in ("instance", "address", "weekday_code")
            )
        ):
            key = ("event", selector["profile"], selector["instance"], selector["address"])
        else:
            key = ("request", index)
        grouped.setdefault(key, []).append(index)

    result: list[OperationPlannerRow] = []
    for key, indices in grouped.items():
        first = requests[indices[0]]
        if key[0] == "event":
            profile, instance, address = str(key[1]), cast(int, key[2]), cast(int, key[3])
            codes = tuple(
                sorted(
                    {getattr(requests[index], "selector", {})["weekday_code"] for index in indices}
                )
            )
            opcodes = sorted(
                {
                    0x09 if getattr(requests[index], "operation", "") == "GetEvent" else 0x0B
                    for index in indices
                }
            )
            family = {"system": "System", "dhw": "Native DHW", "zone": "Zone"}[profile]
            identity = f" {instance:#04x}" if profile == "zone" else ""
            result.append(
                OperationPlannerRow(
                    indices=tuple(indices),
                    name=f"{family}{identity} · Program {address:#04x}",
                    scope=f"Codes {raw_code_range(codes)} · "
                    + "/".join(f"OP{opcode:02X}" for opcode in opcodes),
                    profile=profile,
                    instance=instance,
                    address=address,
                    codes=codes,
                    automatic=all(
                        getattr(requests[index], "automatic_event", False) for index in indices
                    ),
                )
            )
        else:
            selector = getattr(first, "selector", {})
            scope = (
                ", ".join(f"{name}={value}" for name, value in selector.items())
                if isinstance(selector, Mapping)
                else ""
            )
            result.append(
                OperationPlannerRow(
                    indices=tuple(indices),
                    name=str(getattr(first, "operation", "operation")),
                    scope=scope,
                )
            )
    return result


def replace_event_day_codes(
    requests: list[object], selection: list[bool], row: OperationPlannerRow, codes: Sequence[int]
) -> None:
    from ..protocol.b524_schedules import EventProfileName
    from ..scanner.b524_default_events import event_program_requests

    if not row.automatic or row.profile is None:
        raise ValueError("Only automatic Event programs have an editable raw-code window")
    replacements = event_program_requests(
        cast(EventProfileName, row.profile),
        instance=row.instance,
        address=row.address,
        weekday_codes=codes,
    )
    enabled = row.selected(selection)
    first = row.indices[0]
    removed = set(row.indices)
    retained_requests = [request for index, request in enumerate(requests) if index not in removed]
    retained_selection = [value for index, value in enumerate(selection) if index not in removed]
    requests[:] = [*retained_requests[:first], *replacements, *retained_requests[first:]]
    selection[:] = [
        *retained_selection[:first],
        *([enabled] * len(replacements)),
        *retained_selection[first:],
    ]


def parse_operation_request_spec(spec: str) -> object:
    """Build one exact typed read request from planner text, without argv state."""

    from ..scanner.b524_operation_reads import parse_operation_read_plan

    tokens = spec.strip().split()
    if not tokens:
        raise ValueError("Operation request is empty")
    request: dict[str, object] = {"operation": tokens[0]}
    for token in tokens[1:]:
        if "=" not in token:
            raise ValueError("Operation selectors must use key=value")
        key, value = token.split("=", 1)
        if not key or key in request:
            raise ValueError(f"Duplicate or empty selector: {key or token}")
        request[key] = value if key in {"channel", "profile"} else parse_int_token(value)
    return parse_operation_read_plan({"schema_version": 1, "requests": [request]})[0]


def operation_request_preview(request: object) -> str:
    """Return exact operation, native selector and payload for planner review."""

    operation = str(getattr(request, "operation", "operation"))
    opcode = getattr(request, "opcode", None)
    selector = getattr(request, "selector", {})
    payload = getattr(request, "payload", b"")
    opcode_text = f"OP{opcode:02X}" if isinstance(opcode, int) else "OP?"
    selector_text = (
        " ".join(f"{key}={value}" for key, value in selector.items())
        if isinstance(selector, Mapping)
        else ""
    )
    payload_text = payload.hex() if isinstance(payload, bytes) else "?"
    return " ".join(
        part for part in (opcode_text, operation, selector_text, f"payload={payload_text}") if part
    )


def append_exact_operation_request(
    requests: list[object], selection: list[bool], spec: str
) -> object:
    """Append one finite exact request, retaining parser and VRC700 guards."""

    if len(requests) != len(selection):
        raise ValueError("operation_selection must match operation_requests")
    request = parse_operation_request_spec(spec)
    payload = getattr(request, "payload", None)
    if any(getattr(existing, "payload", None) == payload for existing in requests):
        raise ValueError("Operation request duplicates an existing native payload")
    requests.append(request)
    selection.append(True)
    return request
