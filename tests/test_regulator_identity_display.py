from copy import deepcopy
from io import StringIO

from rich.console import Console

from helianthus_vrc_explorer.cli import _build_scan_session_preface, _probe_scan_identity
from helianthus_vrc_explorer.transport.base import TransportNack
from helianthus_vrc_explorer.ui.browse_textual import _build_identity_header_renderable
from helianthus_vrc_explorer.ui.html_report import render_html_report


def artifact_with_hw(hw: str) -> dict:
    return {
        "schema_version": "2.3",
        "meta": {"identity": {"device_id": "BASV0", "hw": hw, "model": "n/a"}},
        "operations": {},
    }


def test_same_eid_displays_distinct_models_from_hw_in_all_headers() -> None:
    # hw="8803" byte-swaps to decimal 388 (SPN 0184); hw="0304" to 403 (SPN 0193).
    for hw, expected in (("8803", "VRC720"), ("0304", "VRT380")):
        artifact = artifact_with_hw(hw)
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


def test_no_family_is_inferred_from_eid_or_an_unmatched_hardware_version() -> None:
    artifact = artifact_with_hw("9999")
    # Raw sw is preserved as evidence but must not drive identification, even
    # though it would have matched the catalog under the pre-0.6.1 sw rule.
    artifact["meta"]["identity"]["sw"] = "0388"
    html = render_html_report(artifact)
    assert 'class="identity-label">Profile' not in html
    assert _build_identity_header_renderable(artifact) is None


def test_conflicting_supplied_spn_and_hw_do_not_select_a_profile() -> None:
    artifact = artifact_with_hw("8803")
    artifact["meta"]["identity"]["spn"] = "0193"
    assert 'class="identity-label">Profile' not in render_html_report(artifact)


def test_native_hw_selects_exact_model_before_optional_serial_enrichment() -> None:
    class IdentityTransport:
        def send_proto(self, dst: int, primary: int, secondary: int, payload: bytes) -> bytes:
            if (primary, secondary) == (0x07, 0x04):
                # manufacturer=0xb5, device_id="BASV0", sw=0403 (raw, unused
                # for matching), hw=0304 (byte-swaps to decimal 403 -> 0193).
                return b"\xb5BASV0\x04\x03\x03\x04"
            raise TransportNack("optional enrichment unavailable")

    identity = _probe_scan_identity(IdentityTransport(), dst=0x15)  # type: ignore[arg-type]
    assert identity["sw"] == "0403"
    assert identity["hw"] == "0304"
    assert identity["spn"] == "0193"
    assert identity["spn_source"] == "hw"
    assert identity["assigned_model"] == "VRT380"
    assert identity["model_assignment_qualification"] == "project_catalog"
    assert identity["protocol_family"] == "VRC720"
    assert identity["model"] == "VRT380"
    assert identity["serial"] == "n/a"


def test_other_manufacturer_does_not_receive_the_regulator_profile() -> None:
    artifact = artifact_with_hw("8803")
    artifact["meta"]["identity"]["manufacturer"] = "0x50"
    assert 'class="identity-label">Profile' not in render_html_report(artifact)


def test_ctlx0_sw0127_hw0404_is_vr940_in_all_headers() -> None:
    from helianthus_vrc_explorer.schema.regulator_identity import (
        lookup_regulator_identity,
        spn_from_hw,
    )

    # Real recorded example: a CTLX0 reporting SW 0127 / HW 0404 resolves,
    # under the hw-based rule, to SPN 0x0194 -- not the stale 0x007F an
    # sw-based rule would have produced.
    identity = {"manufacturer": "0xB5", "device_id": "CTLX0", "sw": "0127", "hw": "0404"}
    match = lookup_regulator_identity("CTLX0", spn_from_hw("0404"))
    assert match is not None and match.model_name == "VR940"
    assert match.spn_hex == "0194"
    artifact = {"schema_version": "2.3", "meta": {"identity": identity}, "operations": {}}
    baseline = deepcopy(artifact)
    assert "VR940" in render_html_report(artifact)
    output = StringIO()
    Console(file=output, width=140).print(_build_identity_header_renderable(artifact))
    assert "VR940" in output.getvalue()
    preface = _build_scan_session_preface(dst=0x15, endpoint="offline", identity=identity)
    assert any(label == "Profile" and "VR940" in value for label, value in preface.rows)
    assert artifact == baseline
