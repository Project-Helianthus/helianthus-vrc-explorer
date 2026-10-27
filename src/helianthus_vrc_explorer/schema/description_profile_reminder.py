"""Operator-facing wording for the description-profile reminder.

``description_catalog_status`` reports one status per target. ``exact`` means the
target's native identity was observed and is in the bundled catalog.
``unqualified`` means the controller profile is in the catalog but the target's own
class/firmware identity was not observed; a Full scan reads that identity.
``unknown`` covers the rest: the controller profile is not in the catalog, or the
target's identity was observed and the catalog has no matching row.
``absent`` marks a remote slot whose own presence probe found no connected device:
there is no identity to observe, so the slot is stored but never counted, never named
in the reminder and never given the Full advice.

The functions here only turn those statuses into text and counts. They read nothing
beyond their arguments and never modify the artifact or the stored status rows.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

_EXACT = "exact"
_NOT_OBSERVED = "unqualified"
_NOT_IN_CATALOG = "unknown"
ABSENT = "absent"
_NOT_CONNECTED = "not_connected"


def controller_profile_known(controller_status: Mapping[str, Any] | None) -> bool:
    """Return whether the controller profile is in the bundled catalog."""

    if not isinstance(controller_status, Mapping):
        return False
    return controller_status.get("status") == _EXACT or bool(controller_status.get("profile_id"))


def present_remote_rows(rows: Iterable[object]) -> list[Mapping[str, Any]]:
    """Return the well-formed remote status rows that are not ``absent`` slots."""

    return [row for row in rows if isinstance(row, Mapping) and row.get("status") != ABSENT]


def remote_exact_counts(rows: Iterable[object]) -> tuple[int, int]:
    """Return ``(exact, total)`` over the well-formed remote rows of present devices.

    ``absent`` slots hold no device, so they are in neither number.
    """

    present = present_remote_rows(rows)
    return sum(row.get("status") == _EXACT for row in present), len(present)


def remote_absent_count(rows: Iterable[object]) -> int:
    """Return how many well-formed remote rows are ``absent`` slots."""

    return sum(isinstance(row, Mapping) and row.get("status") == ABSENT for row in rows)


def remote_rows_need_reminder(rows: Iterable[object]) -> bool:
    """Return whether a present remote device is not exact (``absent`` slots never are)."""

    return any(row.get("status") != _EXACT for row in present_remote_rows(rows))


def _lookup(mapping: object, key: str) -> object:
    if not isinstance(mapping, Mapping):
        return None
    if key in mapping:
        return mapping[key]
    lowered = key.lower()
    for candidate, value in mapping.items():
        if isinstance(candidate, str) and candidate.lower() == lowered:
            return value
    return None


def _clean_text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _group_name(group_obj: object) -> str | None:
    """Return the recorded group name, ignoring the scanner's `Unknown` placeholder."""

    name = _clean_text(_lookup(group_obj, "name"))
    return None if name is None or name.lower() == "unknown" else name


def remote_slot_not_connected(artifact: Mapping[str, Any], group: str, instance: str) -> bool:
    """Return whether this scan's own presence probe found no device in the remote slot.

    The probe is the ``device_connected`` read stored under ``availability_probes``; only
    a clean "not connected" answer counts. A probe that was not run, or whose reply was
    unreadable, leaves the slot undecided and the function returns ``False``.
    """

    groups = _lookup(_lookup(artifact.get("operations"), "0x06"), "groups")
    probe = _lookup(_lookup(_lookup(groups, group), "availability_probes"), instance)
    return (
        isinstance(probe, Mapping)
        and probe.get("connection_state") == _NOT_CONNECTED
        and probe.get("present") is not True
    )


def remote_rows_with_presence(
    artifact: Mapping[str, Any], rows: Iterable[object]
) -> list[dict[str, Any]]:
    """Return copies of the status rows, with ``absent`` for slots that hold no device.

    Artifacts written before the ``absent`` status stored an empty slot as ``unqualified``.
    Their presence probes are still in the artifact, so a row that is not exact and whose
    slot was probed as not connected is relabelled here. The stored rows are not modified.
    """

    result: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        item = dict(row)
        if item.get("status") not in {_EXACT, ABSENT} and remote_slot_not_connected(
            artifact, str(item.get("group", "")), str(item.get("instance", ""))
        ):
            item["status"] = ABSENT
        result.append(item)
    return result


def remote_rows_with_designation(
    artifact: Mapping[str, Any], rows: Iterable[object]
) -> list[dict[str, Any]]:
    """Return copies of the status rows, with a ``designation`` when the artifact has one.

    The designation is the instance ``designation`` if recorded, else the OP06 group
    name. The stored rows are not modified.
    """

    groups = _lookup(_lookup(artifact.get("operations"), "0x06"), "groups")
    result: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        item = dict(row)
        if _clean_text(item.get("designation")) is None:
            item.pop("designation", None)
            group_obj = _lookup(groups, str(row.get("group", "")))
            instance_obj = _lookup(
                _lookup(group_obj, "instances"),
                str(row.get("instance", "")),
            )
            designation = _clean_text(_lookup(instance_obj, "designation")) or _group_name(
                group_obj
            )
            if designation is not None:
                item["designation"] = designation
        result.append(item)
    return result


def _row_label(row: Mapping[str, Any]) -> str:
    label = f"GG {row.get('group', '?')} II {row.get('instance', '?')}"
    designation = _clean_text(row.get("designation"))
    return f"{label} ({designation})" if designation else label


def _row_reason(status: object, *, controller_known: bool) -> str:
    if status == _NOT_OBSERVED:
        return "remote identity not observed"
    if not controller_known:
        return "controller profile not in the catalog"
    if status == _NOT_IN_CATALOG:
        return "remote identity observed but not in the catalog"
    return "not exact"


def describe_non_exact_remote_rows(
    controller_status: Mapping[str, Any] | None, remote_rows: Iterable[object]
) -> list[str]:
    """Describe every non-exact remote row: group, instance, designation, status, reason.

    ``absent`` slots hold no device and are not described.
    """

    known = controller_profile_known(controller_status)
    descriptions: list[str] = []
    for row in present_remote_rows(remote_rows):
        if row.get("status") == _EXACT:
            continue
        status = row.get("status")
        descriptions.append(
            f"{_row_label(row)} status {status if status is not None else 'missing'}, "
            f"{_row_reason(status, controller_known=known)}"
        )
    return descriptions


def compose_description_profile_reminder(
    controller_status: Mapping[str, Any] | None, remote_rows: Sequence[object]
) -> str | None:
    """Compose the reminder text, or ``None`` when nothing needs a reminder.

    The text states whether the controller profile is in the catalog and names each
    present remote device that is not exact. Rows of ``absent`` slots (no device
    connected) are ignored: they are not counted, named or given advice. The Full advice
    is given only when a Full scan can observe what is missing: a remote identity that
    was not observed, or an unknown controller profile (the controller-level advice). A
    row whose identity was observed but is not in the catalog keeps only the save/share
    advice.
    """

    known = controller_profile_known(controller_status)
    controller_exact = isinstance(controller_status, Mapping) and (
        controller_status.get("status", _EXACT) == _EXACT
    )
    rows = present_remote_rows(remote_rows)
    non_exact = [row for row in rows if row.get("status") != _EXACT]
    if known and controller_exact and not non_exact:
        return None

    head = f"Controller description profile is {'in' if known else 'not in'} the catalog"
    if known and not controller_exact:
        head += " but not exact"
    if rows:
        exact, total = remote_exact_counts(rows)
        head += f"; {exact} of {total} remote descriptions are exact"
    parts = [head + "."]
    if non_exact:
        details = describe_non_exact_remote_rows(controller_status, non_exact)
        parts.append("Not exact: " + "; ".join(details) + ".")
    if not known:
        parts.append(
            "Use Full for live writable descriptions within known bounds, "
            "then save/share JSON manually if useful."
        )
    elif any(row.get("status") == _NOT_OBSERVED for row in non_exact):
        parts.append(
            "Use Full to observe the missing remote identity and read live writable "
            "descriptions within known bounds, then save/share JSON manually if useful."
        )
    else:
        parts.append("Save/share JSON manually if useful.")
    return " ".join(parts)
