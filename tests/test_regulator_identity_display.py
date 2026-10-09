from copy import deepcopy
from io import StringIO

from rich.console import Console

from helianthus_vrc_explorer.cli import _build_scan_session_preface, _probe_scan_identity
from helianthus_vrc_explorer.transport.base import TransportNack
from helianthus_vrc_explorer.ui.browse_textual import _build_identity_header_renderable
from helianthus_vrc_explorer.ui.html_report import render_html_report


def artifact_with_sw(sw: str) -> dict:
    return {
        "schema_version": "2.3",
        "meta": {"identity": {"device_id": "BASV0", "sw": sw, "model": "n/a"}},
        "operations": {},
    }


def test_same_eid_displays_distinct_models_from_sw_in_all_headers() -> None:
    for sw, expected in (("0388", "VRC720"), ("0403", "VRT380")):
        artifact = artifact_with_sw(sw)
        baseline = deepcopy(artifact)
        html = render_html_report(artifact)
        assert 'class="identity-label">Profile' in html
        assert expected in html
        output = StringIO()
        console = Console(file=output, force_terminal=False, width=160)
        renderable = _build_identity_header_renderable(artifact)
        assert renderable is not None
        console.print(renderable)
        assert "Profile" in output.getvalue()
        assert expected in output.getvalue()
        preface = _build_scan_session_preface(
            dst=0x15, endpoint="offline", identity=artifact["meta"]["identity"]
        )
        assert any(label == "Profile" and expected in value for label, value in preface.rows)
        assert artifact == baseline


def test_no_family_is_inferred_from_eid_or_hardware_version() -> None:
    artifact = artifact_with_sw("0507")
    artifact["meta"]["identity"]["hw"] = "0388"
    html = render_html_report(artifact)
    assert 'class="identity-label">Profile' not in html
    assert _build_identity_header_renderable(artifact) is None


def test_conflicting_supplied_spn_and_sw_do_not_select_a_profile() -> None:
    artifact = artifact_with_sw("0388")
    artifact["meta"]["identity"]["spn"] = "0193"
    assert 'class="identity-label">Profile' not in render_html_report(artifact)


def test_native_sw_selects_exact_model_before_optional_serial_enrichment() -> None:
    class IdentityTransport:
        def send_proto(self, dst: int, primary: int, secondary: int, payload: bytes) -> bytes:
            if (primary, secondary) == (0x07, 0x04):
                return b"\xb5BASV0\x04\x03\x01\x00"
            raise TransportNack("optional enrichment unavailable")

    identity = _probe_scan_identity(IdentityTransport(), dst=0x15)  # type: ignore[arg-type]
    assert identity["sw"] == "0403"
    assert identity["spn"] == "0193"
    assert identity["assigned_model"] == "VRT380"
    assert identity["protocol_family"] == "VRC720"
    assert identity["model"] == "VRT380"
    assert identity["serial"] == "n/a"


def test_other_manufacturer_does_not_receive_the_regulator_profile() -> None:
    artifact = artifact_with_sw("0388")
    artifact["meta"]["identity"]["manufacturer"] = "0x50"
    assert 'class="identity-label">Profile' not in render_html_report(artifact)
