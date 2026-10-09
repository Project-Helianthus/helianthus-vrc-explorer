# ruff: noqa: E501

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from helianthus_vrc_explorer.scanner.b524_operation_edit import build_operation_edit_preview
from helianthus_vrc_explorer.ui.html_report import render_html_report


def _record(opcode: str, selector: dict[str, object], raw: str, **overrides: object) -> dict:
    row = {
        "operation": {"0x03": "ReadTimer", "0x09": "GetEvent", "0x0b": "GetEventSetPoint"}[opcode],
        "opcode_hex": opcode,
        "selector": selector,
        "request_payload_hex": "",
        "response_raw_hex": raw,
        "response_state": "value",
        "decode_qualification": "schema_unqualified",
        "selector_correlation": "request_context",
        "request_attempts": 1,
        "decoded": {"complete": True},
    }
    row.update(overrides)
    return row


def _artifact() -> dict:
    first = {"profile": "zone", "instance": 0, "address": 1, "weekday_code": 129}
    second = {"profile": "zone", "instance": 1, "address": 1, "weekday_code": 129}
    return {
        "meta": {"destination_address": "0x15"},
        "b524_operation_reads": [
            _record("0x09", first, "03ff18242a30363c"),
            _record("0x0b", first, "03282a2c2e303234"),
            _record("0x09", second, "03ff242a30363c42"),
            _record("0x0b", second, "0330323436383a3c"),
        ],
    }


def _run_editor(artifact: dict, section_key: str, actions: str) -> dict:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated HTML editor tests")
    html = render_html_report(artifact)
    start = html.index("const B524_TIMER_CHANNELS")
    end = html.index("function renderB524OperationRows", start)
    implementation = html[start:end]
    harness = r"""
class MiniElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase(); this.children = []; this.parentElement = null;
    this.dataset = {}; this.style = {}; this.listeners = {}; this.attributes = {};
    this.className = ""; this.value = ""; this.checked = false; this.disabled = false;
    this.type = ""; this.title = ""; this.download = ""; this.href = ""; this._text = "";
  }
  appendChild(child) { this.children.push(child); child.parentElement = this; return child; }
  addEventListener(kind, callback) { (this.listeners[kind] ||= []).push(callback); }
  dispatch(kind) { for (const callback of this.listeners[kind] || []) callback({target: this}); }
  click() { if (!this.disabled) this.dispatch("click"); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  set innerHTML(value) { this._html = String(value); this.children = []; }
  get innerHTML() { return this._html || ""; }
}
const document = {createElement: (tagName) => new MiniElement(tagName)};
let capturedBlob = null;
class Blob { constructor(parts, options) { this.parts = parts; this.options = options; } }
const URL = {
  createObjectURL(blob) { capturedBlob = blob; return "blob:edit"; },
  revokeObjectURL() {},
};
function normalizeOpcodeKey(value) {
  if (typeof value === "number" && Number.isInteger(value)) return `0x${value.toString(16).padStart(2, "0")}`;
  if (typeof value !== "string") return null;
  const parsed = Number(value.trim().toLowerCase());
  return Number.isInteger(parsed) ? `0x${parsed.toString(16).padStart(2, "0")}` : null;
}
function descendants(root) {
  const found = [];
  for (const child of root.children) { found.push(child, ...descendants(child)); }
  return found;
}
function byRole(root, role) { return descendants(root).filter((node) => node.dataset.role === role); }
"""
    script = (
        harness
        + "\nconst artifact = "
        + json.dumps(artifact)
        + ";\n"
        + implementation
        + "\nconst container = document.createElement('div');\n"
        + f"const sectionKey = {json.dumps(section_key)};\n"
        + "const opcode = `0x${sectionKey.slice('operation_'.length)}`;\n"
        + "const reads = artifact.b524_operation_reads;\n"
        + "const rows = reads.filter((row) => normalizeOpcodeKey(row.opcode_hex || row.opcode) === opcode);\n"
        + "renderB524OperationEditor(sectionKey, rows, reads, container, artifact.meta);\n"
        + actions
    )
    result = subprocess.run(
        [node, "-e", script], check=True, text=True, capture_output=True, timeout=10
    )
    return json.loads(result.stdout)


def _assert_preview_matches_python(preview: dict, document: dict) -> None:
    expected = build_operation_edit_preview(document, dst=document["destination_address"])
    for key in (
        "schema_version",
        "operation",
        "opcode_hex",
        "destination",
        "selector",
        "payload_hex",
        "expected_before_raw_hex",
        "expected_after_raw_hex",
        "diff",
        "live_send",
    ):
        assert preview[key] == expected[key]


def test_second_selector_can_be_edited_previewed_and_exported() -> None:
    result = _run_editor(
        _artifact(),
        "operation_09",
        r"""
const selectors = byRole(container, "operation-edit-select");
selectors[1].click();
const values = byRole(container, "operation-value");
values[1].value = "0x25"; values[1].dispatch("input");
byRole(container, "operation-preview-button")[0].click();
const preview = JSON.parse(byRole(container, "operation-preview")[0].textContent);
byRole(container, "operation-export-button")[0].click();
const exported = JSON.parse(capturedBlob.parts.join(""));
console.log(JSON.stringify({preview, exported, selectors: selectors.length}));
""",
    )

    assert result["selectors"] == 2
    assert result["preview"]["destination"] == "0x15"
    assert result["preview"]["payload_hex"] == "0a03010181ff252a30363c42"
    assert result["preview"]["live_write"] is False
    assert result["preview"]["expected_before_raw_hex"] == [
        "03ff242a30363c42",
        "0330323436383a3c",
    ]
    assert result["preview"]["expected_after_raw_hex"] == [
        "03ff252a30363c42",
        "0330323436383a3c",
    ]
    assert result["preview"]["diff"][0]["changed"] is True
    assert result["exported"] == {
        "schema_version": 1,
        "destination_address": 0x15,
        "operation": "SetEvent",
        "selector": {"profile": "zone", "instance": 1, "address": 1, "weekday_code": 129},
        "values": [255, 37, 42, 48, 54, 60, 66],
        "expected_before_raw_hex": ["03ff242a30363c42", "0330323436383a3c"],
    }
    _assert_preview_matches_python(result["preview"], result["exported"])


def test_setpoint_editor_uses_op0b_values_and_canonical_pair_order() -> None:
    artifact = _artifact()
    artifact["b524_operations"] = {
        "register_tables": [{"payload_hex": "0b03010181", "reply_hex": "0330323436383a3c"}]
    }
    result = _run_editor(
        artifact,
        "operation_0b",
        r"""
byRole(container, "operation-edit-select")[1].click();
const initialValues = byRole(container, "operation-value").map((node) => node.value);
byRole(container, "operation-preview-button")[0].click();
const preview = JSON.parse(byRole(container, "operation-preview")[0].textContent);
byRole(container, "operation-export-button")[0].click();
const exported = JSON.parse(capturedBlob.parts.join(""));
const legacyVisible = b524SectionHasContent("register_tables", artifact.b524_operations, artifact.meta);
console.log(JSON.stringify({initialValues, preview, exported, legacyVisible}));
""",
    )

    assert result["initialValues"] == ["48", "50", "52", "54", "56", "58", "60"]
    assert result["preview"]["operation"] == "SetEventSetPoint"
    assert result["preview"]["payload_hex"] == "0c0301018130323436383a3c"
    assert result["preview"]["expected_before_raw_hex"] == [
        "03ff242a30363c42",
        "0330323436383a3c",
    ]
    assert result["legacyVisible"] is False
    _assert_preview_matches_python(result["preview"], result["exported"])


def test_ambiguous_pair_failed_and_raw_only_records_are_disabled() -> None:
    artifact = _artifact()
    artifact["b524_operation_reads"].append(dict(artifact["b524_operation_reads"][3]))
    event = _run_editor(
        artifact,
        "operation_09",
        r"""
const buttons = byRole(container, "operation-edit-select");
console.log(JSON.stringify(buttons.map((button) => ({disabled: button.disabled, title: button.title}))));
""",
    )
    assert event[1]["disabled"] is True
    assert "exactly one OP09 and one OP0B" in event[1]["title"]

    timer_selector = {"channel": "zone-heating", "instance": 1, "weekday": 2}
    timer_artifact = {
        "meta": {"destination_address": "0x15"},
        "b524_operation_reads": [
            _record("0x03", timer_selector, "00909090909090", response_state="timeout"),
            _record("0x03", timer_selector, "000c1890909090", decoded=None),
        ],
    }
    timer = _run_editor(
        timer_artifact,
        "operation_03",
        r"""
const buttons = byRole(container, "operation-edit-select");
console.log(JSON.stringify(buttons.map((button) => ({disabled: button.disabled, title: button.title}))));
""",
    )
    assert [item["disabled"] for item in timer] == [True, True]
    assert "response state" in timer[0]["title"]
    assert "decoded canonical baseline" in timer[1]["title"]


def test_timer_editor_exports_null_slots_and_codec_ordering() -> None:
    selector = {"channel": "zone-heating", "instance": 2, "weekday": 4}
    artifact = {
        "meta": {"destination_address": 21},
        "b524_operation_reads": [_record("0x03", selector, "000c1890903042")],
    }
    result = _run_editor(
        artifact,
        "operation_03",
        r"""
byRole(container, "operation-edit-select")[0].click();
const unused = byRole(container, "timer-slot-unused");
unused[2].checked = true; unused[2].dispatch("change");
byRole(container, "operation-preview-button")[0].click();
const preview = JSON.parse(byRole(container, "operation-preview")[0].textContent);
byRole(container, "operation-export-button")[0].click();
const exported = JSON.parse(capturedBlob.parts.join(""));
console.log(JSON.stringify({preview, exported}));
""",
    )

    assert result["preview"]["destination"] == "0x15"
    assert result["preview"]["payload_hex"] == "04030202040c1890909090"
    assert result["exported"]["values"] == [[12, 24], None, None]
    _assert_preview_matches_python(result["preview"], result["exported"])


@pytest.mark.parametrize("destination", [None, True, 256, -1, "invalid"])
def test_invalid_target_rejects_preview_and_cannot_export(destination) -> None:
    artifact = _artifact()
    artifact["meta"]["destination_address"] = destination
    result = _run_editor(
        artifact,
        "operation_09",
        r"""
byRole(container, "operation-edit-select")[0].click();
byRole(container, "operation-preview-button")[0].click();
byRole(container, "operation-export-button")[0].click();
console.log(JSON.stringify({message: byRole(container, "operation-validation")[0].textContent, disabled: byRole(container, "operation-export-button")[0].disabled, downloaded: capturedBlob !== null}));
""",
    )
    assert "destination" in result["message"]
    assert result["disabled"] is True
    assert result["downloaded"] is False


def test_numeric_nondefault_target_is_retained_in_preview() -> None:
    artifact = _artifact()
    artifact["meta"]["destination_address"] = 0x26
    result = _run_editor(
        artifact,
        "operation_09",
        r"""
byRole(container, "operation-edit-select")[0].click();
byRole(container, "operation-preview-button")[0].click();
byRole(container, "operation-export-button")[0].click();
console.log(JSON.stringify({preview: JSON.parse(byRole(container, "operation-preview")[0].textContent), exported: JSON.parse(capturedBlob.parts.join(""))}));
""",
    )
    assert result["preview"]["destination"] == "0x26"
    assert result["exported"]["destination_address"] == 0x26
