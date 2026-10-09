from __future__ import annotations

import json
import re
import shutil
import subprocess
from copy import deepcopy

import pytest

from helianthus_vrc_explorer.ui.browse_store import BrowseStore
from helianthus_vrc_explorer.ui.html_report import render_html_report


def _artifact(sw: str = "0507", *, exact: bool = True) -> dict:
    artifact = {
        "meta": {
            "identity": {"eid": "BASV2", "sw": sw, "hw": "1704"},
            "profile_context": {
                "profile": "controller_b524",
                "api_version": 1.0,
                "api_revision": 1.0,
            },
        },
        "operations": {"0x02": {"groups": {"0x02": {"instances": {}}}}},
    }
    if not exact:
        artifact["meta"].pop("profile_context")
    instances = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]
    for ii in (0, 1, 2, 3, 9, 10):
        instances[f"0x{ii:02x}"] = {
            "present": ii != 3,
            "registers": {
                "0x0002": {
                    "read_opcode": "0x02",
                    "type": "UCH",
                    "value": 1,
                    "raw_hex": "01",
                    "response_state": "active",
                    "flags_access": "read_only_visible",
                }
            },
        }
    return artifact


@pytest.mark.parametrize(
    "sw,exact,expected",
    [
        ("0507", True, ["0x00", "0x01", "0x02", "0x09"]),
        ("0508", True, ["0x01", "0x02", "0x09"]),
        ("0507", False, ["0x01", "0x02", "0x09"]),
    ],
)
def test_browser_native_circuit_projection_requires_exact_profile(sw, exact, expected):
    artifact = _artifact(sw, exact=exact)
    original = deepcopy(artifact)
    store = BrowseStore.from_artifact(artifact)
    instances = [node for node in store.tree_nodes if node.level == "instance"]
    assert [node.instance_key for node in instances] == expected
    assert {row.address.instance_key for row in store.rows} == {
        "0x00",
        "0x01",
        "0x02",
        "0x03",
        "0x09",
        "0x0a",
    }
    assert artifact == original


@pytest.mark.parametrize(
    "sw,exact,expected",
    [
        ("0507", True, ["0x00", "0x01", "0x02", "0x09"]),
        ("0508", True, ["0x01", "0x02", "0x09"]),
        ("0507", False, ["0x01", "0x02", "0x09"]),
    ],
)
def test_generated_html_table_keeps_qualified_native_circuits(sw, exact, expected):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated HTML table regression")
    artifact = _artifact(sw, exact=exact)
    original = deepcopy(artifact)
    html = render_html_report(artifact)
    start = html.index("function renderActiveGroup(")
    end = html.index("function renderB524Tab()", start)
    minimum = re.search(r"const B524_CIRCUIT_II_MIN = [01];", html)
    harness = r"""
class Node {
  constructor(tag) {
    this.tag = tag; this.children = []; this.className = "";
    this.classList = {add: (...names) => {this.className += " " + names.join(" ");}};
    this.textContent = ""; this.innerHTML = ""; this.title = "";
  }
  appendChild(child) {this.children.push(child); return child;}
  addEventListener() {}
}
const document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (text) => Object.assign(new Node("text"), {textContent: text}),
};
const sheetArea = new Node("div");
const state = {b524Filters: {
  hideMissingInstances: true, hideAbsent: false, hideDormant: false,
}};
function getOperationGroup() {return artifact.operations["0x02"].groups["0x02"];}
function getGroupObject(value) {return value;}
function groupLabelForSection(_group, _section, fallback) {return fallback;}
function entryStatusKind() {return "ok";}
function entryStatusLabel() {return "OK";}
function sortedHexKeys(keys) {return keys.sort((a, b) => parseInt(a, 16) - parseInt(b, 16));}
function visibleRegisterKeys() {return ["0x0002"];}
function parseHexKey(value) {return parseInt(value, 16);}
function rowIsAbsent() {return false;}
function rowIsDormant() {return false;}
function groupPresentationForSection() {return null;}
function getInstanceObject(value) {return value;}
function bytesFromHex(raw) {return raw.match(/../g).map((value) => parseInt(value, 16));}
function getRowOverride() {return null;}
function setRowOverride() {}
function candidateTypeSpecsForLength() {return ["UCH"];}
function parseTypedValue(_type, bytes) {return {value: bytes[0], error: null};}
function formatValue(value) {return String(value);}
function statusChipClass() {return "";}
function appendAccessBadges() {}
function finalPlanForRoute() {return null;}
"""
    actions = r"""
const mount = new Node("div");
renderActiveGroup("0x02", "0x02", mount);
const walk = (item) => [item, ...item.children.flatMap(walk)];
console.log(JSON.stringify(walk(mount).filter((item) =>
  item.tag === "th" && item.textContent.startsWith("0x")
).map((item) => item.textContent)));
"""
    script = (
        "const artifact = "
        + json.dumps(artifact)
        + ";\n"
        + (minimum.group(0) if minimum else "")
        + harness
        + html[start:end]
        + actions
    )
    result = subprocess.run(
        [node, "-e", script], check=True, text=True, capture_output=True, timeout=10
    )
    assert json.loads(result.stdout) == expected
    assert artifact == original
