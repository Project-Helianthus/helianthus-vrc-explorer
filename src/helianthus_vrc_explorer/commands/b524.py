from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

import typer

from ..protocol.b524_schedules import (
    EVENT_PROFILES,
    TIMER_CHANNELS,
    EventProfileName,
    TimerChannelName,
    build_event_read_payload,
    build_event_setpoint_read_payload,
    build_event_setpoint_write_payload,
    build_event_write_payload,
    build_timer_read_payload,
    build_timer_write_payload,
    build_vr91_read_payload,
    parse_event_response,
    parse_event_setpoint_response,
    parse_timer_response,
    parse_vr91_response,
)
from ..protocol.basv import parse_scan_identification
from ..transport.base import TransportCommandNotEnabled, TransportError
from ..transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from ..transport.enhanced_tcp import EnhancedTcpConfig, EnhancedTcpTransport

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Read B524 operation tables, edit offline, or apply a qualified timer change.",
)

_VRC700_DEVICE_IDS = frozenset({"70000", "B7S00"})
_DAY_CODES = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}


def _parse_u8(raw: str, name: str) -> int:
    try:
        value = int(raw, 0)
    except ValueError as exc:
        raise typer.BadParameter(f"{name} must be an integer or 0x-prefixed hex byte") from exc
    if not 0 <= value <= 0xFF:
        raise typer.BadParameter(f"{name} must be in range 0..255")
    return value


def _parse_weekday(raw: str) -> int:
    normalized = raw.strip().lower()
    if normalized in _DAY_CODES:
        return _DAY_CODES[normalized]
    value = _parse_u8(raw, "weekday")
    if value > 6:
        raise typer.BadParameter("weekday must be Monday..Sunday or 0..6")
    return value


def _event_profile(raw: str) -> EventProfileName:
    if raw not in EVENT_PROFILES:
        raise typer.BadParameter(f"profile must be one of {', '.join(EVENT_PROFILES)}")
    return cast(EventProfileName, raw)


def _timer_channel(raw: str) -> TimerChannelName:
    if raw not in TIMER_CHANNELS:
        raise typer.BadParameter(f"channel must be one of {', '.join(TIMER_CHANNELS)}")
    return cast(TimerChannelName, raw)


def _make_transport(
    *,
    transport_protocol: str,
    host: str,
    port: int,
    source_address: int,
    trace_file: Path | None,
) -> EbusdTcpTransport | EnhancedTcpTransport:
    normalized = transport_protocol.strip().lower()
    if normalized == "tcp":
        return EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, trace_path=trace_file))
    if normalized in {"ens", "enh", "enhanced"}:
        return EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                src=source_address,
                trace_path=trace_file,
            )
        )
    raise typer.BadParameter("transport must be tcp, ens, enh, or enhanced")


def _request(
    payload: bytes,
    *,
    transport_protocol: str,
    host: str,
    port: int,
    source_address: str,
    dst: str,
    trace_file: Path | None,
    require_vrc700: bool,
) -> tuple[bytes, int, dict[str, str] | None, int]:
    dst_value = _parse_u8(dst, "dst")
    source_value = _parse_u8(source_address, "source-address")
    transport = _make_transport(
        transport_protocol=transport_protocol,
        host=host,
        port=port,
        source_address=source_value,
        trace_file=trace_file,
    )
    attempts = 0

    def _attempt() -> None:
        nonlocal attempts
        attempts += 1

    try:
        with transport.session():
            target_qualification: dict[str, str] | None = None
            if require_vrc700:
                identity_payload = transport.send_proto(dst_value, 0x07, 0x04, b"")
                try:
                    identity = parse_scan_identification(identity_payload)
                except ValueError as exc:
                    raise typer.BadParameter(
                        "target identity could not be qualified for this VRC700 operation"
                    ) from exc
                device_id = identity.device_id.upper()
                if identity.manufacturer != 0xB5 or device_id not in _VRC700_DEVICE_IDS:
                    raise typer.BadParameter(
                        "this operation requires device identity 70000 or B7S00; "
                        f"target reported {identity.device_id or 'unknown'}"
                    )
                target_qualification = {
                    "service": "07/04",
                    "destination_address": f"0x{dst_value:02X}",
                    "manufacturer": f"0x{identity.manufacturer:02X}",
                    "device_id": device_id,
                    "eid": device_id,
                    "software_raw_hex": identity.sw,
                    "hardware_raw_hex": identity.hw,
                    "raw_identity_payload_hex": identity_payload.hex(),
                }
            reply = transport.send_with_attempt_hook(dst_value, payload, _attempt)
    except typer.BadParameter:
        raise
    except TransportCommandNotEnabled as exc:
        typer.echo(
            "ebusd rejected raw hex commands; enable the hex command and retry.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except TransportError as exc:
        typer.echo(f"B524 request failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    return reply, dst_value, target_qualification, attempts


def _read_output(
    *,
    operation: str,
    opcode: int,
    selector: dict[str, object],
    payload: bytes,
    reply: bytes,
    decoded: Any,
    dst: int,
    target_qualification: dict[str, str] | None,
    attempts: int,
) -> None:
    output: dict[str, Any] = {
        "operation": operation,
        "opcode": f"0x{opcode:02X}",
        "destination": f"0x{dst:02X}",
        "decode_qualification": (
            "profile_vrc700" if target_qualification is not None else "schema_unqualified"
        ),
        "selector_correlation": "request_context",
        "request": {
            "selector": selector,
            "payload_hex": payload.hex(),
            "attempts": attempts,
        },
        "reply": {
            "raw_hex": reply.hex(),
            "length": len(reply),
            "decoded": asdict(decoded),
        },
    }
    if target_qualification is not None:
        output["device_id"] = target_qualification["device_id"]
        output["target_qualification"] = target_qualification
    typer.echo(json.dumps(output, indent=2, sort_keys=True))


@app.command("apply-operation")
def apply_operation(
    plan_path: Path = typer.Option(..., "--plan", exists=True, dir_okay=False),  # noqa: B008
    execute: bool = typer.Option(False, "--execute", help="Apply one qualified native write."),  # noqa: B008
    qualification_path: Path | None = typer.Option(  # noqa: B008
        None, "--qualification", exists=True, dir_okay=False
    ),  # noqa: B008
    confirm: str | None = typer.Option(
        None, "--confirm", help="Exact confirmation from the offline preview."
    ),  # noqa: B008
    dst: str | None = typer.Option(None, "--dst"),  # noqa: B008
    transport_protocol: str = typer.Option("tcp", "--transport"),  # noqa: B008
    source_address: str = typer.Option("0xF7", "--source-address"),  # noqa: B008
    host: str = typer.Option("127.0.0.1", "--host"),  # noqa: B008
    port: int = typer.Option(8888, "--port", min=1, max=65535),  # noqa: B008
    trace_file: Path | None = typer.Option(None, "--trace-file"),  # noqa: B008
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", help="Save the preview or execution evidence."
    ),  # noqa: B008
) -> None:
    """Preview an operation edit; --execute requires native qualification and confirmation."""
    from ..scanner.b524_operation_edit import build_operation_edit_preview, parse_operation_edit
    from ..scanner.b524_operation_writes import (
        execute_controlled_write,
        parse_native_write_qualification,
        validate_operation_write_qualification,
    )

    source_value = _parse_u8(source_address, "source-address")
    try:
        document = json.loads(plan_path.read_text(encoding="utf-8"))
        request = parse_operation_edit(document)
        dst_value = cast(int, request.destination_address)
        if dst is not None:
            explicit_dst = _parse_u8(dst, "dst")
            if explicit_dst != dst_value:
                raise ValueError("--dst does not match plan destination_address")
        result = build_operation_edit_preview(document, dst=dst_value)
        if execute:
            if result["availability"]["state"] == "schema_unqualified":
                raise ValueError(
                    "schema_unqualified: Events/EventSetPoint native writes unavailable"
                )
            if qualification_path is None:
                raise ValueError("--execute requires --qualification and exact --confirm")
            qualification = parse_native_write_qualification(
                json.loads(qualification_path.read_text(encoding="utf-8"))
            )
            validate_operation_write_qualification(request, qualification)
            if confirm != result["required_confirmation"]:
                raise ValueError("--confirm must match the exact confirmation from the preview")
    except (OSError, TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    if execute:
        transport = _make_transport(
            transport_protocol=transport_protocol,
            host=host,
            port=port,
            source_address=source_value,
            trace_file=trace_file,
        )
        try:
            with transport.session():
                result = execute_controlled_write(
                    transport,
                    dst=dst_value,
                    request=request,
                    qualification=qualification,
                    concrete_confirmation=cast(str, confirm),
                )
        except (ValueError, TransportError) as exc:
            typer.echo(f"B524 write was not verified: {exc}", err=True)
            raise typer.Exit(1) from exc
    encoded = json.dumps(result, indent=2, sort_keys=True)
    typer.echo(encoded)
    if output is not None:
        try:
            output.write_text(encoded + "\n", encoding="utf-8")
        except OSError as exc:
            typer.echo(f"Could not save B524 evidence: {exc}", err=True)
            raise typer.Exit(1) from exc
    if execute and result.get("outcome") != "verified":
        raise typer.Exit(1)


def _preview_output(operation: str, opcode: int, payload: bytes) -> None:
    typer.echo(
        json.dumps(
            {
                "operation": operation,
                "opcode": f"0x{opcode:02X}",
                "payload_hex": payload.hex(),
                "mutative": True,
                "live_send": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


def _read_options_request(
    payload: bytes,
    *,
    transport_protocol: str,
    host: str,
    port: int,
    source_address: str,
    dst: str,
    trace_file: Path | None,
    require_vrc700: bool,
) -> tuple[bytes, int, dict[str, str] | None, int]:
    return _request(
        payload,
        transport_protocol=transport_protocol,
        host=host,
        port=port,
        source_address=source_address,
        dst=dst,
        trace_file=trace_file,
        require_vrc700=require_vrc700,
    )


@app.command("read-timer")
def read_timer(
    channel: str = typer.Option(..., "--channel", help="Documented VRC700 timer channel."),  # noqa: B008
    instance: int = typer.Option(0, "--instance", min=0, max=255),  # noqa: B008
    weekday: str = typer.Option("monday", "--weekday", help="Monday..Sunday or 0..6."),  # noqa: B008
    transport_protocol: str = typer.Option("tcp", "--transport"),  # noqa: B008
    dst: str = typer.Option("0x15", "--dst"),  # noqa: B008
    source_address: str = typer.Option("0xF7", "--source-address"),  # noqa: B008
    host: str = typer.Option("127.0.0.1", "--host"),  # noqa: B008
    port: int = typer.Option(8888, "--port", min=1, max=65535),  # noqa: B008
    trace_file: Path | None = typer.Option(None, "--trace-file"),  # noqa: B008
) -> None:
    """Read one VRC700 timer day with OP03 ReadTimer."""

    selected_channel = _timer_channel(channel)
    selected_weekday = _parse_weekday(weekday)
    try:
        payload = build_timer_read_payload(
            selected_channel,
            instance=instance,
            weekday=selected_weekday,
        )
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    reply, dst_value, target_qualification, attempts = _read_options_request(
        payload,
        transport_protocol=transport_protocol,
        host=host,
        port=port,
        source_address=source_address,
        dst=dst,
        trace_file=trace_file,
        require_vrc700=True,
    )
    try:
        decoded = parse_timer_response(reply)
    except ValueError as exc:
        typer.echo(f"ReadTimer reply could not be decoded: {exc}; raw={reply.hex()}", err=True)
        raise typer.Exit(1) from exc
    _read_output(
        operation="ReadTimer",
        opcode=0x03,
        selector={"channel": selected_channel, "instance": instance, "weekday": selected_weekday},
        payload=payload,
        reply=reply,
        decoded=decoded,
        dst=dst_value,
        target_qualification=target_qualification,
        attempts=attempts,
    )


def _event_read(
    *,
    setpoint: bool,
    profile: str,
    instance: int,
    address: str,
    weekday_code: str,
    transport_protocol: str,
    dst: str,
    source_address: str,
    host: str,
    port: int,
    trace_file: Path | None,
) -> None:
    selected_profile = _event_profile(profile)
    address_value = _parse_u8(address, "address")
    weekday_value = _parse_u8(weekday_code, "weekday-code")
    try:
        if setpoint:
            payload = build_event_setpoint_read_payload(
                selected_profile,
                instance=instance,
                address=address_value,
                weekday_code=weekday_value,
            )
        else:
            payload = build_event_read_payload(
                selected_profile,
                instance=instance,
                address=address_value,
                weekday_code=weekday_value,
            )
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    reply, dst_value, _target_qualification, attempts = _read_options_request(
        payload,
        transport_protocol=transport_protocol,
        host=host,
        port=port,
        source_address=source_address,
        dst=dst,
        trace_file=trace_file,
        require_vrc700=False,
    )
    try:
        decoded = (
            parse_event_setpoint_response(reply, selected_profile)
            if setpoint
            else parse_event_response(reply)
        )
    except ValueError as exc:
        operation = "GetEventSetPoint" if setpoint else "GetEvent"
        typer.echo(f"{operation} reply could not be decoded: {exc}; raw={reply.hex()}", err=True)
        raise typer.Exit(1) from exc
    _read_output(
        operation="GetEventSetPoint" if setpoint else "GetEvent",
        opcode=0x0B if setpoint else 0x09,
        selector={
            "profile": selected_profile,
            "instance": instance,
            "address": address_value,
            "weekday_code": weekday_value,
        },
        payload=payload,
        reply=reply,
        decoded=decoded,
        dst=dst_value,
        target_qualification=None,
        attempts=attempts,
    )


@app.command("read-event")
def read_event(
    profile: str = typer.Option(..., "--profile", help="Profile: system, dhw, or zone."),  # noqa: B008
    instance: int = typer.Option(0, "--instance", min=0, max=255),  # noqa: B008
    address: str = typer.Option(..., "--address"),  # noqa: B008
    weekday_code: str = typer.Option(
        ..., "--weekday-code", help="Explicit raw weekday selector; no default interpretation."
    ),  # noqa: B008
    transport_protocol: str = typer.Option("tcp", "--transport"),  # noqa: B008
    dst: str = typer.Option("0x15", "--dst"),  # noqa: B008
    source_address: str = typer.Option("0xF7", "--source-address"),  # noqa: B008
    host: str = typer.Option("127.0.0.1", "--host"),  # noqa: B008
    port: int = typer.Option(8888, "--port", min=1, max=65535),  # noqa: B008
    trace_file: Path | None = typer.Option(None, "--trace-file"),  # noqa: B008
) -> None:
    """Read one profile-qualified OP09 GetEvent table."""

    _event_read(
        setpoint=False,
        profile=profile,
        instance=instance,
        address=address,
        weekday_code=weekday_code,
        transport_protocol=transport_protocol,
        dst=dst,
        source_address=source_address,
        host=host,
        port=port,
        trace_file=trace_file,
    )


@app.command("read-event-setpoint")
def read_event_setpoint(
    profile: str = typer.Option(..., "--profile", help="Profile: system, dhw, or zone."),  # noqa: B008
    instance: int = typer.Option(0, "--instance", min=0, max=255),  # noqa: B008
    address: str = typer.Option(..., "--address"),  # noqa: B008
    weekday_code: str = typer.Option(
        ..., "--weekday-code", help="Explicit raw weekday selector; no default interpretation."
    ),  # noqa: B008
    transport_protocol: str = typer.Option("tcp", "--transport"),  # noqa: B008
    dst: str = typer.Option("0x15", "--dst"),  # noqa: B008
    source_address: str = typer.Option("0xF7", "--source-address"),  # noqa: B008
    host: str = typer.Option("127.0.0.1", "--host"),  # noqa: B008
    port: int = typer.Option(8888, "--port", min=1, max=65535),  # noqa: B008
    trace_file: Path | None = typer.Option(None, "--trace-file"),  # noqa: B008
) -> None:
    """Read one profile-qualified OP0B GetEventSetPoint table."""

    _event_read(
        setpoint=True,
        profile=profile,
        instance=instance,
        address=address,
        weekday_code=weekday_code,
        transport_protocol=transport_protocol,
        dst=dst,
        source_address=source_address,
        host=host,
        port=port,
        trace_file=trace_file,
    )


@app.command("read-vr91")
def read_vr91(
    transport_protocol: str = typer.Option("tcp", "--transport"),  # noqa: B008
    dst: str = typer.Option("0x15", "--dst"),  # noqa: B008
    source_address: str = typer.Option("0xF7", "--source-address"),  # noqa: B008
    host: str = typer.Option("127.0.0.1", "--host"),  # noqa: B008
    port: int = typer.Option(8888, "--port", min=1, max=65535),  # noqa: B008
    trace_file: Path | None = typer.Option(None, "--trace-file"),  # noqa: B008
) -> None:
    """Read the VRC700 remote-controller status block with OP08 ReadVR91."""

    payload = build_vr91_read_payload()
    reply, dst_value, target_qualification, attempts = _read_options_request(
        payload,
        transport_protocol=transport_protocol,
        host=host,
        port=port,
        source_address=source_address,
        dst=dst,
        trace_file=trace_file,
        require_vrc700=True,
    )
    try:
        decoded = parse_vr91_response(reply)
    except ValueError as exc:
        typer.echo(f"ReadVR91 reply could not be decoded: {exc}; raw={reply.hex()}", err=True)
        raise typer.Exit(1) from exc
    _read_output(
        operation="ReadVR91",
        opcode=0x08,
        selector={},
        payload=payload,
        reply=reply,
        decoded=decoded,
        dst=dst_value,
        target_qualification=target_qualification,
        attempts=attempts,
    )


def _parse_values(values: list[str] | None) -> tuple[int, int, int, int, int, int, int]:
    raw_values = values or []
    if len(raw_values) != 7:
        raise typer.BadParameter(f"repeat --value exactly 7 times, got {len(raw_values)}")
    parsed = tuple(_parse_u8(raw, f"value {index}") for index, raw in enumerate(raw_values, 1))
    return (parsed[0], parsed[1], parsed[2], parsed[3], parsed[4], parsed[5], parsed[6])


def _event_preview(
    *,
    setpoint: bool,
    profile: str,
    instance: int,
    address: str,
    weekday_code: str,
    values: list[str] | None,
) -> None:
    selected_profile = _event_profile(profile)
    address_value = _parse_u8(address, "address")
    weekday_value = _parse_u8(weekday_code, "weekday-code")
    selected_values = _parse_values(values)
    try:
        payload = (
            build_event_setpoint_write_payload(
                selected_profile,
                instance=instance,
                address=address_value,
                weekday_code=weekday_value,
                values=selected_values,
            )
            if setpoint
            else build_event_write_payload(
                selected_profile,
                instance=instance,
                address=address_value,
                weekday_code=weekday_value,
                values=selected_values,
            )
        )
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    _preview_output(
        "SetEventSetPoint" if setpoint else "SetEvent",
        0x0C if setpoint else 0x0A,
        payload,
    )


@app.command("preview-set-event")
def preview_set_event(
    profile: str = typer.Option(..., "--profile"),  # noqa: B008
    instance: int = typer.Option(0, "--instance", min=0, max=255),  # noqa: B008
    address: str = typer.Option(..., "--address"),  # noqa: B008
    weekday_code: str = typer.Option(
        ..., "--weekday-code", help="Explicit raw weekday selector; no default interpretation."
    ),  # noqa: B008
    values: list[str] | None = typer.Option(None, "--value"),  # noqa: B008
) -> None:
    """Build an OP0A SetEvent payload without sending it."""

    _event_preview(
        setpoint=False,
        profile=profile,
        instance=instance,
        address=address,
        weekday_code=weekday_code,
        values=values,
    )


@app.command("preview-set-event-setpoint")
def preview_set_event_setpoint(
    profile: str = typer.Option(..., "--profile"),  # noqa: B008
    instance: int = typer.Option(0, "--instance", min=0, max=255),  # noqa: B008
    address: str = typer.Option(..., "--address"),  # noqa: B008
    weekday_code: str = typer.Option(
        ..., "--weekday-code", help="Explicit raw weekday selector; no default interpretation."
    ),  # noqa: B008
    values: list[str] | None = typer.Option(None, "--value"),  # noqa: B008
) -> None:
    """Build an OP0C SetEventSetPoint payload without sending it."""

    _event_preview(
        setpoint=True,
        profile=profile,
        instance=instance,
        address=address,
        weekday_code=weekday_code,
        values=values,
    )


def _parse_time_code(raw: str, *, stop: bool) -> int:
    try:
        hour_raw, minute_raw = raw.split(":", 1)
        hour = int(hour_raw, 10)
        minute = int(minute_raw, 10)
    except (ValueError, TypeError) as exc:
        raise typer.BadParameter(f"invalid time {raw!r}; expected HH:MM") from exc
    if minute not in range(0, 60, 10):
        raise typer.BadParameter(f"time {raw!r} must use a 10-minute boundary")
    if hour == 24 and minute == 0 and stop:
        return 0x90
    if not 0 <= hour <= 23:
        raise typer.BadParameter(f"time {raw!r} is outside 00:00..23:50")
    return hour * 6 + minute // 10


def _parse_slots(
    raw_slots: list[str] | None,
) -> tuple[tuple[int, int] | None, tuple[int, int] | None, tuple[int, int] | None]:
    items = raw_slots or []
    if len(items) > 3:
        raise typer.BadParameter(f"at most 3 --slot values are allowed, got {len(items)}")
    parsed: list[tuple[int, int] | None] = []
    for raw in items:
        try:
            start_raw, stop_raw = raw.split("-", 1)
        except ValueError as exc:
            raise typer.BadParameter(f"invalid slot {raw!r}; expected HH:MM-HH:MM") from exc
        parsed.append(
            (
                _parse_time_code(start_raw, stop=False),
                _parse_time_code(stop_raw, stop=True),
            )
        )
    parsed.extend([None] * (3 - len(parsed)))
    return (parsed[0], parsed[1], parsed[2])


@app.command("preview-write-timer")
def preview_write_timer(
    channel: str = typer.Option(..., "--channel"),  # noqa: B008
    instance: int = typer.Option(0, "--instance", min=0, max=255),  # noqa: B008
    weekday: str = typer.Option("monday", "--weekday"),  # noqa: B008
    slots: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--slot",
        help="HH:MM-HH:MM; repeat up to 3 times.",
    ),
) -> None:
    """Build an OP04 WriteTimer payload without sending it."""

    selected_channel = _timer_channel(channel)
    selected_weekday = _parse_weekday(weekday)
    selected_slots = _parse_slots(slots)
    try:
        payload = build_timer_write_payload(
            selected_channel,
            instance=instance,
            weekday=selected_weekday,
            slots=selected_slots,
        )
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    _preview_output("WriteTimer", 0x04, payload)
