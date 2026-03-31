from __future__ import annotations

import contextlib
import csv
import json
import math
import struct
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import cast

import typer
from rich.console import Console
from rich.text import Text

from . import __version__
from .ebusd import parse_ebusd_info_target_addresses
from .protocol.b524 import build_directory_probe_payload
from .protocol.basv import (
    ScanIdentification,
    parse_scan_identification,
    parse_vaillant_scan_id_chunks,
)
from .scanner.b509 import parse_b509_range
from .scanner.director import GROUP_CONFIG, classify_groups, discover_groups
from .scanner.register import is_instance_present
from .scanner.scan import PlannerUiMode, default_output_filename, scan_vrc
from .schema.ebusd_csv import EbusdCsvSchema
from .schema.myvaillant_map import MyvaillantRegisterMap
from .transport.base import TransportCommandNotEnabled, TransportError, TransportTimeout
from .transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from .transport.enhanced_tcp import EnhancedTcpConfig, EnhancedTcpTransport
from .ui.browse_textual import run_browse_from_artifact
from .ui.emphasis import rich_star_bold_text
from .ui.html_report import render_html_report
from .ui.live import ScanSessionPreface, make_scan_observer
from .ui.planner import PlannerPreset
from .ui.summary import render_summary

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

_DEFAULT_TRANSPORT_PROTOCOL = "tcp"
_DEFAULT_EBUSD_HOST = "127.0.0.1"
_DEFAULT_EBUSD_PORT = 8888
_SCAN_IDENT_RETRIES = 1


@dataclass(frozen=True, slots=True)
class _TransportSettings:
    protocol: str
    host: str
    port: int
    src: int | None = None


@dataclass(frozen=True, slots=True)
class _ModelCatalogEntry:
    model_number: str
    marketing_name: str
    ebus_model: str
    notes: str


def _normalize_planner_preset(raw: str) -> str:
    normalized = raw.strip().lower()
    if normalized == "aggressive":
        return "full"
    return normalized


def _load_default_myvaillant_map() -> tuple[MyvaillantRegisterMap | None, str | None]:
    """Load bundled default myVaillant mapping for installed/package use."""

    try:
        resource = resources.files("helianthus_vrc_explorer.data").joinpath(
            "myvaillant_register_map.csv"
        )
        with resources.as_file(resource) as map_path:
            return (
                MyvaillantRegisterMap.from_path(map_path),
                f"myvaillant_map:{map_path.name}",
            )
    except Exception:
        # Dev fallback (editable checkout) when package resources are unavailable.
        fallback = Path(__file__).resolve().parents[2] / "data" / "myvaillant_register_map.csv"
        if fallback.exists():
            try:
                return (
                    MyvaillantRegisterMap.from_path(fallback),
                    f"myvaillant_map:{fallback.name}",
                )
            except Exception:
                return (None, None)
        return (None, None)


def _emit_scan_status(console: Console, message: str) -> None:
    console.print(f"[scan] {message}", highlight=False, markup=False, style="cyan")


def _load_default_model_catalog() -> dict[str, _ModelCatalogEntry]:
    paths: list[Path] = []
    with contextlib.suppress(Exception):
        resource = resources.files("helianthus_vrc_explorer.data").joinpath("models.csv")
        with resources.as_file(resource) as path:
            paths.append(path)
    paths.append(Path(__file__).resolve().parents[2] / "data" / "models.csv")

    for candidate in paths:
        if not candidate.exists():
            continue
        rows: dict[str, _ModelCatalogEntry] = {}
        with candidate.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                model_number = str((row or {}).get("model_number") or "").strip()
                if not model_number:
                    continue
                rows[model_number] = _ModelCatalogEntry(
                    model_number=model_number,
                    marketing_name=str((row or {}).get("marketing_name") or "").strip(),
                    ebus_model=str((row or {}).get("ebus_model") or "").strip(),
                    notes=str((row or {}).get("notes") or "").strip(),
                )
        if rows:
            return rows
    return {}


def _load_ebus_model_name_map() -> dict[str, str]:
    paths: list[Path] = []
    with contextlib.suppress(Exception):
        resource = resources.files("helianthus_vrc_explorer.data").joinpath("ebus_model_names.csv")
        with resources.as_file(resource) as path:
            paths.append(path)
    paths.append(Path(__file__).resolve().parents[2] / "data" / "ebus_model_names.csv")

    for candidate in paths:
        if not candidate.exists():
            continue
        rows: dict[str, str] = {}
        with candidate.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                code = str((row or {}).get("ebus_model") or "").strip().upper()
                friendly_name = str((row or {}).get("friendly_name") or "").strip()
                if not code or not friendly_name:
                    continue
                rows[code] = friendly_name
        if rows:
            return rows
    return {}


def _format_device_identity(
    *,
    device_id: str,
    model_name_map: dict[str, str],
) -> str:
    code = device_id.strip()
    if not code:
        return "n/a"
    friendly_name = model_name_map.get(code.upper())
    if not friendly_name:
        return code
    if friendly_name.lower() == code.lower():
        return friendly_name
    return f"{friendly_name} ({code})"


def _resolve_brand_name(
    manufacturer_id: int,
    *,
    entry: _ModelCatalogEntry | None,
) -> str:
    if entry is not None:
        text = " ".join((entry.marketing_name, entry.notes, entry.ebus_model)).lower()
        if "saunier" in text or "duval" in text:
            return "Saunier Duval"
    if manufacturer_id == 0xB5:
        return "Vaillant"
    return f"MF 0x{manufacturer_id:02X}"


def _format_model_identity(
    *,
    manufacturer_id: int,
    model_number: str,
    catalog: dict[str, _ModelCatalogEntry],
) -> str:
    number = model_number.strip()
    if not number:
        return "n/a"

    entry = catalog.get(number)
    if entry is None:
        return number

    family = entry.notes.strip()
    model = entry.marketing_name.strip()
    ebus_model = entry.ebus_model.strip()

    descriptor = ""
    if family and model:
        descriptor = family if family.lower() == model.lower() else f"{family} ({model})"
    elif family:
        descriptor = family
    elif model:
        descriptor = model
    elif ebus_model:
        descriptor = ebus_model

    brand = _resolve_brand_name(manufacturer_id, entry=entry)
    if descriptor:
        return f"{brand} {descriptor} {number}"
    return f"{brand} {number}"


def _load_default_dry_run_fixture_text() -> tuple[str | None, str | None]:
    """Load bundled default dry-run fixture JSON text."""

    try:
        resource = resources.files("helianthus_vrc_explorer.fixtures").joinpath(
            "vrc720_full_scan.json"
        )
        return (resource.read_text(encoding="utf-8"), "packaged:vrc720_full_scan.json")
    except Exception:
        fallback = Path(__file__).resolve().parents[2] / "fixtures" / "vrc720_full_scan.json"
        if fallback.exists():
            try:
                return (fallback.read_text(encoding="utf-8"), str(fallback))
            except Exception:
                return (None, None)
        return (None, None)


def _na(value: str | None) -> str:
    text = (value or "").strip()
    return text if text else "n/a"


def _format_fw(sw: str | None, hw: str | None) -> str:
    sw_hex = (sw or "").strip().upper()
    hw_hex = (hw or "").strip().upper()
    if not sw_hex and not hw_hex:
        return "n/a"
    return f"SW {sw_hex or 'n/a'} / HW {hw_hex or 'n/a'}"


def _probe_scan_identity(
    transport: EbusdTcpTransport | EnhancedTcpTransport,
    *,
    dst: int,
    model_catalog: dict[str, _ModelCatalogEntry] | None = None,
    model_name_map: dict[str, str] | None = None,
) -> dict[str, str]:
    identity = {
        "device": "n/a",
        "model": "n/a",
        "serial": "n/a",
        "firmware": "n/a",
    }
    try:
        payload = transport.send_proto(dst, 0x07, 0x04, b"")
        ident = parse_scan_identification(payload)
    except TransportCommandNotEnabled:
        raise
    except Exception:
        return identity

    device_name_map = model_name_map if model_name_map is not None else _load_ebus_model_name_map()
    identity["device"] = _na(
        _format_device_identity(device_id=ident.device_id, model_name_map=device_name_map)
    )
    identity["firmware"] = _format_fw(ident.sw, ident.hw)
    if ident.manufacturer != 0xB5:
        return identity

    try:
        chunks = [
            transport.send_proto(dst, 0xB5, 0x09, bytes((qq,))) for qq in (0x24, 0x25, 0x26, 0x27)
        ]
        scan_id = parse_vaillant_scan_id_chunks(chunks)
    except TransportCommandNotEnabled:
        raise
    except Exception:
        return identity

    catalog = model_catalog if model_catalog is not None else _load_default_model_catalog()
    identity["model"] = _na(
        _format_model_identity(
            manufacturer_id=ident.manufacturer,
            model_number=scan_id.model_number,
            catalog=catalog,
        )
    )
    identity["serial"] = _na(scan_id.serial_number)
    return identity


def _build_scan_session_preface(
    *,
    dst: int,
    endpoint: str,
    identity: dict[str, str] | None = None,
) -> ScanSessionPreface:
    data = identity or {}
    return ScanSessionPreface(
        app_line=f"helianthus-vrc-explorer v{__version__}",
        scan_line=f"Scanning VRC Regulator (B524) at address 0x{dst:02X}",
        rows=(
            ("Device", _na(data.get("device"))),
            ("Model", _na(data.get("model"))),
            ("Serial", _na(data.get("serial"))),
            ("Firmware", _na(data.get("firmware"))),
            ("ebusd", endpoint),
            ("Started", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")),
        ),
    )


def _emit_non_tty_session_preface(preface: ScanSessionPreface) -> None:
    console = Console(stderr=True)
    console.print(rich_star_bold_text(preface.app_line))
    console.print(rich_star_bold_text(preface.scan_line))
    for label, value in preface.rows:
        console.print(Text.assemble(f"{label}: ", rich_star_bold_text(value)))


def _can_launch_interactive_browse(console: Console) -> bool:
    return (
        console.is_terminal
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and sys.platform != "win32"
    )


def _is_missing_textual_module(exc: ModuleNotFoundError) -> bool:
    name = getattr(exc, "name", None)
    if isinstance(name, str) and (name == "textual" or name.startswith("textual.")):
        return True
    return "textual" in str(exc)


def _can_prompt_transport_retry(console: Console) -> bool:
    return (
        console.is_terminal
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and sys.platform != "win32"
    )


def _is_default_transport_settings(settings: _TransportSettings) -> bool:
    return (
        settings.protocol == _DEFAULT_TRANSPORT_PROTOCOL
        and settings.host == _DEFAULT_EBUSD_HOST
        and settings.port == _DEFAULT_EBUSD_PORT
    )


def _build_transport(
    settings: _TransportSettings,
    *,
    trace_file: Path | None,
) -> EbusdTcpTransport | EnhancedTcpTransport:
    if settings.protocol == "tcp":
        return EbusdTcpTransport(
            EbusdTcpConfig(host=settings.host, port=settings.port, trace_path=trace_file)
        )
    if settings.protocol == "enhanced":
        return EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=settings.host,
                port=settings.port,
                src=settings.src if settings.src is not None else 0x31,
                trace_path=trace_file,
            )
        )
    raise typer.BadParameter(f"Unsupported transport protocol: {settings.protocol!r}")


def _prompt_transport_retry_settings(
    console: Console,
    *,
    settings: _TransportSettings,
    error_message: str,
) -> _TransportSettings | None:
    typer.echo(f"Transport setup failed: {error_message}", err=True)
    try:
        from .ui.transport_retry_textual import TransportRetrySettings, run_transport_retry_modal

        result = run_transport_retry_modal(
            initial=TransportRetrySettings(
                protocol=settings.protocol,
                host=settings.host,
                port=settings.port,
            ),
            error_message=error_message,
        )
        if result is None:
            return None
        proto = result.protocol.lower()
        if proto in ("ens", "enh", "enhanced"):
            proto = "enhanced"
        # Default src to 0xF7 for enhanced if not already set (e.g. retry
        # switching from tcp where src is None).
        src = settings.src if settings.src is not None else (0xF7 if proto == "enhanced" else None)
        return _TransportSettings(
            protocol=proto,
            host=result.host,
            port=result.port,
            src=src,
        )
    except Exception as exc:
        typer.echo(
            f"Transport retry modal unavailable ({exc}). Falling back to prompts.",
            err=True,
        )

    protocol = typer.prompt(
        "Protocol",
        default=settings.protocol,
    ).strip()
    host = typer.prompt(
        "ebusd host",
        default=settings.host,
    ).strip()
    port = typer.prompt(
        "ebusd port",
        default=str(settings.port),
    ).strip()
    try:
        parsed_port = int(port, 10)
    except ValueError:
        typer.echo(f"Invalid port value: {port!r}", err=True)
        return settings
    if not (1 <= parsed_port <= 65535):
        typer.echo(f"Port out of range 1..65535: {parsed_port}", err=True)
        return settings
    retry = typer.confirm("Retry with these settings?", default=True)
    if not retry:
        return None
    # Normalize ens/enh aliases to "enhanced" (same wire protocol).
    normalized = protocol.lower()
    if normalized in ("ens", "enh", "enhanced"):
        normalized = "enhanced"
    src = settings.src if settings.src is not None else (0xF7 if normalized == "enhanced" else None)
    return _TransportSettings(
        protocol=normalized,
        host=host or settings.host,
        port=parsed_port,
        src=src,
    )


def _probe_group_descriptor(
    transport: EbusdTcpTransport | EnhancedTcpTransport,
    *,
    dst: int,
    group: int,
) -> float | None:
    payload = build_directory_probe_payload(group)
    for _ in range(2):
        try:
            response = transport.send(dst, payload)
        except TransportCommandNotEnabled:
            raise
        except (TransportError, TransportTimeout):
            continue
        if len(response) < 4:
            continue
        descriptor = struct.unpack("<f", response[:4])[0]
        if math.isnan(descriptor):
            continue
        # Any valid 4-byte directory reply is transport-level evidence that B524 is supported.
        return descriptor
    return None


def _probe_scan_identification(
    transport: EbusdTcpTransport | EnhancedTcpTransport,
    *,
    dst: int,
    retries: int = _SCAN_IDENT_RETRIES,
) -> ScanIdentification | None:
    attempts = max(1, retries + 1)
    for _ in range(attempts):
        try:
            payload = transport.send_proto(dst, 0x07, 0x04, b"")
        except TransportCommandNotEnabled:
            raise
        except (TransportError, TransportTimeout):
            continue
        try:
            return parse_scan_identification(payload)
        except Exception:
            continue
    return None


def _resolve_scan_destination(transport: EbusdTcpTransport, *, dst: str) -> int:
    requested = dst.strip().lower()
    if requested != "auto":
        return _parse_u8_address(dst)

    # Best-effort bus wake-up. Some ebusd setups ignore this and that's fine.
    try:
        transport.send_proto(0xFE, 0x07, 0xFE, b"", expect_response=False)
    except TransportCommandNotEnabled:
        raise
    except (TransportError, TransportTimeout):
        pass

    addresses = parse_ebusd_info_target_addresses(transport.command_lines("info", read_all=True))
    if not addresses:
        typer.echo(
            "Auto destination failed: no target addresses found in ebusd info output.",
            err=True,
        )
        raise typer.Exit(2)

    compatible_addrs: list[int] = []
    for addr in addresses:
        ident = _probe_scan_identification(transport, dst=addr)
        if ident is None:
            continue
        if ident.manufacturer != 0xB5:
            continue
        descriptor = _probe_group_descriptor(transport, dst=addr, group=0x00)
        if descriptor is None:
            continue
        compatible_addrs.append(addr)

    if not compatible_addrs:
        typer.echo(
            "Auto destination failed: no compatible VRC/B524 device found. Retry with --dst 0x..",
            err=True,
        )
        raise typer.Exit(2)

    selected = 0x15 if 0x15 in compatible_addrs else min(compatible_addrs)
    if len(compatible_addrs) > 1:
        candidates = ", ".join(f"0x{addr:02X}" for addr in compatible_addrs)
        typer.echo(
            f"Auto-selected dst=0x{selected:02X} (compatible candidates: {candidates})",
            err=True,
        )
    else:
        typer.echo(f"Auto-selected dst=0x{selected:02X} (compatible B524 target).", err=True)
    return selected


def _parse_u8_address(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise typer.BadParameter(f"Invalid address: {value!r}") from exc

    if not (0x00 <= parsed <= 0xFF):
        raise typer.BadParameter(f"Address out of range 0x00..0xFF: {value!r}")
    return parsed


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Print version and exit.",
        is_eager=True,
    ),
) -> None:
    if version:
        typer.echo(f"helianthus-vrc-explorer {__version__}")
        raise typer.Exit(0)


@app.command()
def scan(
    transport_protocol: str = typer.Option(  # noqa: B008
        _DEFAULT_TRANSPORT_PROTOCOL,
        "--transport",
        help="Transport: tcp (ebusd hex) or ens/enh (enhanced eBUS adapter).",
    ),
    dst: str = typer.Option(  # noqa: B008
        "auto",
        "--dst",
        help="Destination eBUS address (e.g. 0x15) or auto (default).",
    ),
    source_address: str = typer.Option(  # noqa: B008
        "0xF7",
        "--source-address",
        help="Source initiator address for enhanced transport. Ignored for tcp.",
    ),
    host: str = typer.Option(  # noqa: B008
        _DEFAULT_EBUSD_HOST,
        "--host",
        help="ebusd host (TCP).",
    ),
    port: int = typer.Option(  # noqa: B008
        _DEFAULT_EBUSD_PORT,
        "--port",
        help="ebusd port (TCP).",
    ),
    dry_run: bool = typer.Option(  # noqa: B008
        False,
        "--dry-run",
        help="Replay a scan fixture using DummyTransport (no device I/O).",
    ),
    output_dir: Path = typer.Option(  # noqa: B008
        Path("."),
        "--output-dir",
        help="Directory to write the scan JSON artifact to.",
    ),
    ebusd_csv_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--ebusd-csv-path",
        envvar="HELIA_EBUSD_CSV_PATH",
        help="Optional ebusd configuration CSV (e.g. 15.720.csv) used to annotate register names.",
    ),
    myvaillant_map_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--myvaillant-map-path",
        envvar="HELIA_MYVAILLANT_MAP_PATH",
        help="Optional myVaillant-equivalence mapping CSV used to annotate register leaf names.",
    ),
    trace_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--trace-file",
        envvar="HELIA_EBUSD_TRACE_PATH",
        help="Write an ebusd request/response trace log to this file.",
    ),
    b509_range: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--b509-range",
        help=(
            "B509 register range to dump (repeatable), format: 0x0000..0x00FF. "
            "If omitted, defaults to 0x0000..0x00FF."
        ),
    ),
    b555_dump: bool = typer.Option(  # noqa: B008
        False,
        "--b555-dump/--no-b555-dump",
        help=(
            "Opt-in read-only B555 timer dump (A3/A4/A5). Disabled by default to keep "
            "the standard B524/B509 scan path unchanged."
        ),
    ),
    b516_dump: bool = typer.Option(  # noqa: B008
        False,
        "--b516-dump/--no-b516-dump",
        help=(
            "Opt-in read-only B516 energy dump (active request/response only). Disabled "
            "by default to keep the standard B524/B555/B509 scan path unchanged."
        ),
    ),
    planner_ui: str = typer.Option(  # noqa: B008
        "disabled",
        "--planner-ui",
        help="Interactive planner mode: disabled, auto, textual, or classic.",
    ),
    preset: str = typer.Option(  # noqa: B008
        "recommended",
        "--preset",
        help=(
            "Planner preset: conservative, recommended, full, exhaustive, or custom. "
            "`full` scans every instance slot and full RR ranges; "
            "`exhaustive` also injects all GG 0x00-0x11 groups. Expect very long runs."
        ),
    ),
    no_tips: bool = typer.Option(  # noqa: B008
        False,
        "--no-tips",
        help="Hide scan header tips in interactive terminal mode.",
    ),
    redact: bool = typer.Option(  # noqa: B008
        False,
        "--redact",
        help="Redact device identity fields (e.g. serial number) in console output.",
    ),
    probe_constraints: bool = typer.Option(  # noqa: B008
        False,
        "--probe-constraints/--no-probe-constraints",
        help=(
            "Research-only live B524 opcode 0x01 constraint probe (GG/RR). "
            "Disabled by default: it can add hundreds of extra bus requests and some BASV2 "
            "setups return noisy/unreliable replies. Normal scans already use the bundled "
            "static BASV2 constraint catalog."
        ),
    ),
) -> None:
    """Scan a VRC regulator using B524 (GetExtendedRegisters)."""
    transport_proto = transport_protocol.strip().lower()
    # ens and enh are aliases — both use the enhanced eBUS adapter protocol.
    if transport_proto in ("ens", "enh", "enhanced"):
        transport_proto = "enhanced"
    if transport_proto not in {"tcp", "enhanced"}:
        typer.echo(
            "Invalid --transport value. Expected: tcp, ens, or enh.",
            err=True,
        )
        raise typer.Exit(2)
    requested_dst = dst.strip().lower()
    explicit_dst_u8: int | None = None
    if requested_dst != "auto":
        # Validate explicit destination before any network activity.
        explicit_dst_u8 = _parse_u8_address(dst)
    if transport_proto != "tcp" and requested_dst == "auto" and not dry_run:
        typer.echo(
            "Auto destination only supported on ebusd TCP. Use --dst 0x.. for enhanced transport.",
            err=True,
        )
        raise typer.Exit(2)

    dst_u8: int
    console = Console(stderr=True)
    planner_ui_value = planner_ui.strip().lower()
    if planner_ui_value not in {"disabled", "auto", "textual", "classic"}:
        typer.echo(
            "Invalid --planner-ui value. Expected one of: disabled, auto, textual, classic.",
            err=True,
        )
        raise typer.Exit(2)
    preset_value = _normalize_planner_preset(preset)
    valid_presets = {"conservative", "recommended", "full", "exhaustive", "custom"}
    if preset_value not in valid_presets:
        typer.echo(
            "Invalid --preset value. Expected one of: "
            "conservative, recommended, aggressive, exhaustive, custom.",
            err=True,
        )
        raise typer.Exit(2)

    ebusd_schema: EbusdCsvSchema | None = None
    ebusd_schema_source: str | None = None
    if ebusd_csv_path is not None:
        try:
            ebusd_schema = EbusdCsvSchema.from_path(ebusd_csv_path)
            ebusd_schema_source = f"ebusd_csv:{ebusd_csv_path.name}"
        except Exception as exc:
            typer.echo(f"Warning: failed to load ebusd CSV schema: {exc}", err=True)

    myvaillant_map: MyvaillantRegisterMap | None = None
    myvaillant_map_source: str | None = None
    identity_for_artifact: dict[str, str] | None = None
    if myvaillant_map_path is not None:
        try:
            myvaillant_map = MyvaillantRegisterMap.from_path(myvaillant_map_path)
            myvaillant_map_source = f"myvaillant_map:{myvaillant_map_path.name}"
        except Exception as exc:
            typer.echo(f"Warning: failed to load myVaillant mapping: {exc}", err=True)
    else:
        myvaillant_map, myvaillant_map_source = _load_default_myvaillant_map()

    if dry_run:
        dst_u8 = 0x15 if requested_dst == "auto" else cast(int, explicit_dst_u8)
        fixture_text, fixture_source = _load_default_dry_run_fixture_text()
        if fixture_text is None:
            typer.echo("Fixture not found: vrc720_full_scan.json", err=True)
            raise typer.Exit(2)
        try:
            artifact = json.loads(fixture_text)
        except json.JSONDecodeError as exc:
            origin = fixture_source or "vrc720_full_scan.json"
            typer.echo(f"Invalid JSON fixture: {origin} ({exc})", err=True)
            raise typer.Exit(2) from exc
        preface = _build_scan_session_preface(
            dst=dst_u8,
            endpoint="n/a (dry-run fixture)",
            identity=None,
        )
        _emit_non_tty_session_preface(preface)
    else:
        source_addr_u8 = (
            _parse_u8_address(source_address) if transport_proto == "enhanced" else None
        )
        transport_settings = _TransportSettings(
            protocol=transport_proto,
            host=host,
            port=port,
            src=source_addr_u8,
        )
        allow_transport_retry = _is_default_transport_settings(transport_settings)
        b509_ranges: list[tuple[int, int]] = []
        if b509_range:
            for spec in b509_range:
                try:
                    b509_ranges.append(parse_b509_range(spec))
                except ValueError as exc:
                    typer.echo(f"Invalid --b509-range {spec!r}: {exc}", err=True)
                    raise typer.Exit(2) from exc
        else:
            b509_ranges = [(0x0000, 0x00FF)]
        while True:
            _emit_scan_status(
                console,
                (
                    f"Opening {transport_settings.protocol.upper()} transport to "
                    f"{transport_settings.host}:{transport_settings.port}"
                ),
            )
            transport = _build_transport(transport_settings, trace_file=trace_file)
            opened_session = False
            try:
                with transport.session():
                    opened_session = True
                    if requested_dst == "auto":
                        _emit_scan_status(console, "Resolving destination address from ebusd")
                        dst_u8 = _resolve_scan_destination(
                            cast(EbusdTcpTransport, transport), dst=dst
                        )
                        _emit_scan_status(console, f"Resolved destination to 0x{dst_u8:02X}")
                    else:
                        dst_u8 = cast(int, explicit_dst_u8)
                        _emit_scan_status(console, f"Using explicit destination 0x{dst_u8:02X}")
                    title = f"helianthus-vrc-explorer scan (B524) dst=0x{dst_u8:02X}"
                    subtitle_lines = [f"Planner: {planner_ui_value} (preset={preset_value})"]

                    _emit_scan_status(console, f"Probing regulator identity at 0x{dst_u8:02X}")
                    identity = _probe_scan_identity(transport, dst=dst_u8)
                    if redact:
                        identity["serial"] = "<SERIAL_NUMBER_REDACTED>"
                    identity_for_artifact = dict(identity)
                    preface = _build_scan_session_preface(
                        dst=dst_u8,
                        endpoint=f"{transport_settings.host}:{transport_settings.port}",
                        identity=identity,
                    )
                    if not console.is_terminal:
                        _emit_non_tty_session_preface(preface)
                    with make_scan_observer(
                        console=console,
                        title=title,
                        subtitle_lines=subtitle_lines,
                        show_tips=not no_tips,
                        session_preface=preface,
                    ) as observer:
                        artifact = scan_vrc(
                            transport,
                            dst=dst_u8,
                            b509_ranges=b509_ranges,
                            b555_dump=b555_dump,
                            b516_dump=b516_dump,
                            ebusd_host=transport_settings.host,
                            ebusd_port=transport_settings.port,
                            ebusd_schema=ebusd_schema,
                            myvaillant_map=myvaillant_map,
                            observer=observer,
                            console=console,
                            planner_ui=cast(PlannerUiMode, planner_ui_value),
                            planner_preset=cast(PlannerPreset, preset_value),
                            probe_constraints=probe_constraints,
                        )
                break
            except TransportCommandNotEnabled as exc:
                typer.echo(
                    "ebusd returned `ERR: command not enabled`. "
                    "Restart ebusd with `--enablehex` and retry.",
                    err=True,
                )
                raise typer.Exit(2) from exc
            except (TransportError, TransportTimeout) as exc:
                if (
                    not opened_session
                    and allow_transport_retry
                    and _can_prompt_transport_retry(console)
                ):
                    maybe_settings = _prompt_transport_retry_settings(
                        console,
                        settings=transport_settings,
                        error_message=str(exc),
                    )
                    if maybe_settings is None:
                        typer.echo("Transport setup aborted by user.", err=True)
                        raise typer.Exit(1) from exc
                    transport_settings = maybe_settings
                    allow_transport_retry = True
                    continue
                raise

    meta_obj = artifact.get("meta")
    if isinstance(meta_obj, dict):
        sources_obj = meta_obj.get("schema_sources")
        if isinstance(sources_obj, list):
            if ebusd_schema_source:
                sources_obj.append(ebusd_schema_source)
            if myvaillant_map_source:
                sources_obj.append(myvaillant_map_source)
        if identity_for_artifact is not None:
            meta_obj["identity"] = dict(identity_for_artifact)
            meta_obj["resolved_identity"] = dict(identity_for_artifact)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / default_output_filename(
        dst=dst_u8,
        scan_timestamp=artifact.get("meta", {}).get("scan_timestamp"),
    )
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if _can_launch_interactive_browse(console):
        # Post-scan default UX: enter the new fullscreen browse UI directly.
        try:
            run_browse_from_artifact(artifact, allow_write=False)
        except ModuleNotFoundError as exc:
            if not _is_missing_textual_module(exc):
                raise
            typer.echo(
                "Interactive browse UI unavailable in this environment (missing "
                "'textual'); continuing without browse.",
                err=True,
            )

    html_path = output_path.with_suffix(".html")
    html_path.write_text(
        render_html_report(
            artifact,
            title=f"helianthus-vrc-explorer scan report ({output_path.name})",
        ),
        encoding="utf-8",
    )

    # Summary to stderr; keep stdout stable for scripting (artifact path only).
    render_summary(console, artifact, output_path=output_path)
    typer.echo(str(output_path))


@app.command()
def discover(
    host: str = typer.Option(  # noqa: B008
        "127.0.0.1",
        "--host",
        help="ebusd host (TCP).",
    ),
    port: int = typer.Option(  # noqa: B008
        8888,
        "--port",
        help="ebusd port (TCP).",
    ),
    trace_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--trace-file",
        envvar="HELIA_EBUSD_TRACE_PATH",
        help="Write an ebusd request/response trace log to this file.",
    ),
) -> None:
    """Discover eBUS devices via QueryExistence broadcast and per-address scan (0704)."""

    transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, trace_path=trace_file))
    try:
        with transport.session():
            # 1) QueryExistence (broadcast). This is best-effort: some ebusd setups will simply
            # respond with a textual status (e.g. "done broadcast").
            try:
                transport.send_proto(0xFE, 0x07, 0xFE, b"", expect_response=False)
            except TransportCommandNotEnabled:
                raise
            except (TransportError, TransportTimeout):
                pass

            info_lines = transport.command_lines("info", read_all=True)
            addresses = parse_ebusd_info_target_addresses(info_lines)
            if not addresses:
                typer.echo("No target addresses found in ebusd info output.", err=True)
                raise typer.Exit(2)

            devices: dict[int, dict[str, object]] = {}
            for addr in addresses:
                ident = _probe_scan_identification(transport, dst=addr)
                if ident is None:
                    continue

                entry: dict[str, object] = {
                    "manufacturer": ident.manufacturer,
                    "device_id": ident.device_id,
                    "sw": ident.sw,
                    "hw": ident.hw,
                }

                if ident.manufacturer == 0xB5:
                    try:
                        chunks = [
                            transport.send_proto(addr, 0xB5, 0x09, bytes((qq,)))
                            for qq in (0x24, 0x25, 0x26, 0x27)
                        ]
                        scan_id = parse_vaillant_scan_id_chunks(chunks)
                        entry["model_number"] = scan_id.model_number
                        entry["serial_number"] = scan_id.serial_number
                    except TransportCommandNotEnabled:
                        raise
                    except Exception:
                        pass

                devices[addr] = entry

            if not devices:
                typer.echo("No devices responded to scan (0704).", err=True)
                raise typer.Exit(2)

            for addr in sorted(devices):
                entry = devices[addr]
                manufacturer_obj = entry.get("manufacturer")
                manufacturer = (
                    manufacturer_obj
                    if isinstance(manufacturer_obj, int) and not isinstance(manufacturer_obj, bool)
                    else 0
                )
                device_id = str(entry.get("device_id") or "").strip()
                sw = str(entry.get("sw") or "")
                hw = str(entry.get("hw") or "")
                model_number = entry.get("model_number")
                serial_number = entry.get("serial_number")

                line = (
                    f"addr=0x{addr:02X} mf=0x{manufacturer:02X} id={device_id or '?'} "
                    f"sw={sw or '????'} hw={hw or '????'}"
                )
                if isinstance(model_number, str) and isinstance(serial_number, str):
                    line += f" model={model_number} serial={serial_number}"
                typer.echo(line)

            # 4) If a Vaillant device is present at 0x15, run B524 group/instance discovery.
            vrc = devices.get(0x15)
            mf_obj = vrc.get("manufacturer") if isinstance(vrc, dict) else None
            if isinstance(mf_obj, int) and not isinstance(mf_obj, bool) and mf_obj == 0xB5:
                try:
                    groups = classify_groups(discover_groups(transport, dst=0x15))
                except TransportCommandNotEnabled:
                    raise
                except Exception as exc:
                    typer.echo(f"VRC@0x15 B524 discovery failed: {exc}", err=True)
                    raise typer.Exit(1) from exc

                typer.echo("VRC@0x15 B524 instances per group:")
                for group in groups:
                    config = GROUP_CONFIG.get(group.group)
                    if group.descriptor == 1.0 and config is not None:
                        ii_max = int(config["ii_max"])
                        present = 0
                        for ii in range(0x00, ii_max + 1):
                            try:
                                if is_instance_present(
                                    transport,
                                    dst=0x15,
                                    group=group.group,
                                    instance=ii,
                                ):
                                    present += 1
                            except TransportCommandNotEnabled:
                                raise
                            except Exception:
                                continue
                        typer.echo(
                            f"GG=0x{group.group:02X} name={group.name} desc={group.descriptor:g} "
                            f"instances={present}/{ii_max + 1}"
                        )
                    else:
                        typer.echo(
                            f"GG=0x{group.group:02X} name={group.name} desc={group.descriptor:g} "
                            "instances=1"
                        )
    except TransportCommandNotEnabled as exc:
        typer.echo(
            "ebusd returned `ERR: command not enabled`. "
            "Restart ebusd with `--enablehex` and retry.",
            err=True,
        )
        raise typer.Exit(2) from exc


@app.command()
def browse(
    file: Path | None = typer.Option(  # noqa: B008
        None,
        "--file",
        help="Path to an existing scan JSON artifact (default browse mode).",
    ),
    live: bool = typer.Option(  # noqa: B008
        False,
        "--live",
        help="Live mode (planned). In P0, only --file mode is implemented.",
    ),
    device: str | None = typer.Option(  # noqa: B008
        None,
        "--device",
        help="Device identifier for --live mode (planned).",
    ),
    allow_write: bool = typer.Option(  # noqa: B008
        False,
        "--allow-write",
        help=(
            "Enable write/edit actions in browse UI (safe mode + confirmation). "
            "Note: --file mode edits do not write to the device."
        ),
    ),
) -> None:
    """Browse scan results in fullscreen Textual UI (file mode)."""

    _ = device
    if live:
        typer.echo("Live browse mode is not implemented yet; use --file <artifact.json>.", err=True)
        raise typer.Exit(2)

    if file is None:
        typer.echo("Missing required option: --file <artifact.json>.", err=True)
        raise typer.Exit(2)
    if not file.exists():
        typer.echo(f"Artifact not found: {file}", err=True)
        raise typer.Exit(2)

    try:
        artifact = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        typer.echo(f"Invalid JSON artifact: {file} ({exc})", err=True)
        raise typer.Exit(2) from exc
    if not isinstance(artifact, dict):
        typer.echo(f"Invalid artifact root object: {file}", err=True)
        raise typer.Exit(2)

    if not Console().is_terminal:
        console = Console(stderr=True)
        render_summary(console, artifact, output_path=file)
        typer.echo("Browse UI requires a TTY terminal.", err=True)
        raise typer.Exit(0)

    run_browse_from_artifact(artifact, allow_write=allow_write)
