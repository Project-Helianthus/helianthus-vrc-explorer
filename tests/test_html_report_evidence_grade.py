"""HTML report: entry-level evidence grade and codec provenance in the entry details.

The page embeds the grade and provenance the shared rules (``ui/evidence_display.py``)
resolve for each entry; the generated script only formats them and applies the interactive
row override to a cell that holds an entry.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from copy import deepcopy
from typing import Any

import pytest

from helianthus_vrc_explorer.ui.html_report import render_html_report

OVERRIDE_LINE = "Decoded value: Hypothesis (manual type override; view only)"


def _entry(**extra: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "UIN",
        "value": 1,
        "raw_hex": "0100",
        "flags": 3,
        "flags_access": "writable_visible",
        "parameter_description": {
            "qualification": "matched",
            "codec_provenance": "selector_qualified",
        },
    }
    entry.update(extra)
    return entry


def _artifact(selected: dict[tuple[str, str, str, str], dict[str, Any]]) -> dict[str, Any]:
    operations: dict[str, Any] = {}
    for (op, gg, ii, rr), entry in selected.items():
        group = operations.setdefault(op, {"groups": {}})["groups"].setdefault(
            gg, {"instances": {}}
        )
        group["instances"].setdefault(ii, {"registers": {}})["registers"][rr] = entry
    return {"schema_version": "2.3", "operations": operations}


def _embedded_rows(html: str) -> list[list[str]]:
    match = re.search(r"const B524_ENTRY_EVIDENCE = new Map\((\[.*?\])\.map\(", html, re.S)
    assert match is not None
    return json.loads(match.group(1))  # type: ignore[no-any-return]


def _node() -> str:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated HTML evidence checks")
    return node


def _evidence_script(html: str) -> str:
    start = html.index("const B524_ENTRY_EVIDENCE_LABELS")
    return html[start : html.index("function b524CorrespondenceSecondaryText", start)]


def _run(script: str) -> Any:
    result = subprocess.run(
        [_node(), "-e", script], check=True, text=True, capture_output=True, timeout=10
    )
    return json.loads(result.stdout)


# One base selector plus a neighbour that differs from it in exactly one field of the key
# (operation, group, instance, register). Every neighbour carries its own grade/provenance,
# so a lookup that ignores any key field returns another entry's values.
BASE = ("0x02", "0x09", "0x01", "0x0002")
NEIGHBOURS = {
    "operation": ("0x06", "0x09", "0x01", "0x0002"),
    "group": ("0x02", "0x0a", "0x01", "0x0002"),
    "instance": ("0x02", "0x09", "0x02", "0x0002"),
    "register": ("0x02", "0x09", "0x01", "0x0003"),
}


def _keyed_artifact() -> dict[str, Any]:
    selected = {
        BASE: _entry(evidence_grade="Proven"),
        NEIGHBOURS["operation"]: _entry(
            evidence_grade="Hypothesis",
            parameter_description={"codec_provenance": "length_inferred"},
        ),
        NEIGHBOURS["group"]: _entry(
            parameter_description={"codec_provenance": "group_provenance"},
        ),
        NEIGHBOURS["instance"]: _entry(
            evidence_grade="Proven",
            parameter_description={"codec_provenance": "instance_provenance"},
        ),
        NEIGHBOURS["register"]: _entry(
            evidence_grade="Hypothesis",
            parameter_description={"codec_provenance": "register_provenance"},
        ),
    }
    return _artifact(selected)


def test_embedded_table_resolves_each_entry_by_its_full_selector() -> None:
    rows = _embedded_rows(render_html_report(_keyed_artifact()))

    assert sorted(rows) == sorted(
        [
            [*BASE, "Proven", "selector_qualified", "Hypothesis"],
            [*NEIGHBOURS["operation"], "Hypothesis", "length_inferred", "Hypothesis"],
            [*NEIGHBOURS["group"], "Unknown", "group_provenance", "Hypothesis"],
            [*NEIGHBOURS["instance"], "Proven", "instance_provenance", "Hypothesis"],
            [*NEIGHBOURS["register"], "Hypothesis", "register_provenance", "Hypothesis"],
        ]
    )


def test_entries_that_supply_nothing_to_show_are_left_out() -> None:
    entry = _entry(value=None, error="parse_error: short payload")
    del entry["parameter_description"]
    html = render_html_report(_artifact({BASE: entry}))

    assert _embedded_rows(html) == []


def test_an_entry_with_only_a_decoded_value_reads_hypothesis_for_the_decoded_value() -> None:
    entry = _entry()
    del entry["parameter_description"]
    html = render_html_report(_artifact({BASE: entry}))

    assert _embedded_rows(html) == [[*BASE, "Unknown", "Unknown", "Hypothesis"]]


def test_an_undecoded_entry_keeps_its_retained_grade_and_reads_unknown_for_the_decode() -> None:
    entry = _entry(evidence_grade="Proven", value=None, error="parse_error: short payload")
    html = render_html_report(_artifact({BASE: entry}))

    assert _embedded_rows(html) == [[*BASE, "Proven", "selector_qualified", "Unknown"]]


def test_entry_level_provenance_fallback_is_embedded_without_a_description() -> None:
    entry = _entry(codec_provenance="length_inferred")
    del entry["parameter_description"]
    html = render_html_report(_artifact({BASE: entry}))

    assert _embedded_rows(html) == [[*BASE, "Unknown", "length_inferred", "Hypothesis"]]


def test_invalid_grades_are_not_embedded_as_grades() -> None:
    selected = {
        ("0x02", "0x09", "0x01", f"0x{index:04x}"): _entry(evidence_grade=grade)
        for index, grade in enumerate(["proven", "qualified", True, 1, ["Proven"]])
    }
    html = render_html_report(_artifact(selected))

    assert {row[4] for row in _embedded_rows(html)} == {"Unknown"}


def test_lookup_returns_each_entrys_own_values_for_every_key_field() -> None:
    html = render_html_report(_keyed_artifact())
    selectors = [BASE, *NEIGHBOURS.values()]
    script = _evidence_script(html) + (
        "const selectors = "
        + json.dumps(selectors)
        + ";console.log(JSON.stringify(selectors.map(([op, gg, ii, rr]) => "
        + "b524EntryEvidence(op, gg, ii, rr, {}, null))));"
    )

    results = _run(script)

    assert [(r["grade"], r["provenance"]) for r in results] == [
        ("Proven", "selector_qualified"),
        ("Hypothesis", "length_inferred"),
        ("Unknown", "group_provenance"),
        ("Proven", "instance_provenance"),
        ("Hypothesis", "register_provenance"),
    ]
    assert all(not r["overridden"] for r in results)
    assert [r["decoded"] for r in results] == ["Hypothesis"] * 5
    assert results[0]["lines"] == [
        "Entry evidence: Proven",
        "Decoded value: Hypothesis",
        "Codec provenance: selector_qualified",
    ]


def test_selector_the_artifact_does_not_hold_reads_unknown() -> None:
    html = render_html_report(_keyed_artifact())
    script = _evidence_script(html) + (
        "console.log(JSON.stringify("
        + 'b524EntryEvidence("0x02", "0x09", "0x03", "0x0002", {}, null)));'
    )

    result = _run(script)

    assert (result["grade"], result["provenance"], result["decoded"]) == (
        "Unknown",
        "Unknown",
        "Unknown",
    )


def test_override_adds_a_hypothesis_line_without_regrading_the_entry() -> None:
    html = render_html_report(_keyed_artifact())
    script = _evidence_script(html) + (
        "console.log(JSON.stringify("
        + 'b524EntryEvidence("0x02", "0x09", "0x01", "0x0002", {}, "HEX:2")));'
    )

    result = _run(script)

    assert result["grade"] == "Proven"
    assert result["overridden"] is True
    assert result["decoded"] == "Hypothesis"
    assert result["lines"] == [
        "Entry evidence: Proven",
        OVERRIDE_LINE,
        "Codec provenance: selector_qualified",
    ]


def test_sparse_cell_is_unknown_even_when_the_row_is_overridden() -> None:
    # The selector is graded Proven in the table, but the selected cell holds no entry.
    html = render_html_report(_keyed_artifact())
    script = _evidence_script(html) + "".join(
        "console.log(JSON.stringify("
        f'b524EntryEvidence("0x02", "0x09", "0x01", "0x0002", {cell}, {override})));'
        for cell in ("null", "undefined", "false", "0")
        for override in ('"HEX:2"', "null")
    )

    results = [
        json.loads(line)
        for line in subprocess.run(
            [_node(), "-e", script], check=True, text=True, capture_output=True, timeout=10
        ).stdout.splitlines()
    ]

    assert len(results) == 8
    for result in results:
        assert (result["grade"], result["provenance"], result["overridden"]) == (
            "Unknown",
            "Unknown",
            False,
        )
        assert result["decoded"] == "Unknown"
        assert result["lines"] == [
            "Entry evidence: Unknown",
            "Decoded value: Unknown",
            "Codec provenance: Unknown",
        ]


def _cell_script(
    html: str,
    *,
    entry: str,
    override: str,
    value_bytes: str = "[1, 0]",
    decode_error: str = "null",
) -> str:
    start = html.index("const evidence = b524EntryEvidence(")
    end = html.index('if (typeof entry.flags_access === "string"', start)
    return (
        _evidence_script(html)
        + """
const opKey = "0x02", groupKey = "0x09", iiKey = "0x01", rrKey = "0x0002";
const document = {createElement: () => ({})};
const appended = [];
const td = {appendChild: (el) => appended.push({className: el.className, text: el.textContent})};
const entry = """
        + entry
        + """;
const override = """
        + override
        + """;
const valueBytes = """
        + value_bytes
        + """;
const decoded = {error: """
        + decode_error
        + """};
"""
        + html[start:end]
        + "console.log(JSON.stringify({appended, tooltip: evidence.lines}));"
    )


def test_cell_shows_an_explicit_grade_and_keeps_unknown_in_the_hover_details() -> None:
    html = render_html_report(_keyed_artifact())

    graded = _run(_cell_script(html, entry="{}", override="null"))
    assert graded["appended"] == [
        {
            "className": "cell-raw",
            "text": "Entry evidence: Proven · Decoded value: Hypothesis · "
            "Codec provenance: selector_qualified",
        }
    ]

    overridden = _run(_cell_script(html, entry="{}", override='"HEX:2"'))
    assert overridden["appended"] == [
        {
            "className": "cell-raw",
            "text": f"Entry evidence: Proven · {OVERRIDE_LINE} · "
            "Codec provenance: selector_qualified",
        }
    ]

    ungraded = render_html_report(_artifact({BASE: _entry()}))
    quiet = _run(_cell_script(ungraded, entry="{}", override="null"))
    assert quiet["appended"] == []
    assert quiet["tooltip"] == [
        "Entry evidence: Unknown",
        "Decoded value: Hypothesis",
        "Codec provenance: selector_qualified",
    ]
    ungraded_override = _run(_cell_script(ungraded, entry="{}", override='"HEX:2"'))
    assert len(ungraded_override["appended"]) == 1
    assert OVERRIDE_LINE in ungraded_override["appended"][0]["text"]
    assert "Entry evidence: Unknown" in ungraded_override["appended"][0]["text"]


def test_hover_details_always_carry_the_grade_lines() -> None:
    html = render_html_report({})

    pushed = html.index("tipParts.push(...evidence.lines);")
    assert pushed < html.index('td.title = tipParts.join("\\n")', pushed)
    # Cells that hold no entry render the em dash and never reach the evidence lines.
    sparse = html.index("cell-missing")
    assert sparse < html.index("const evidence = b524EntryEvidence(")


def test_report_leaves_the_stored_artifact_unchanged() -> None:
    artifact = _keyed_artifact()
    before = deepcopy(artifact)

    html = render_html_report(artifact)

    assert artifact == before
    match = re.search(
        r'<script id="artifact-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert match is not None
    stored = json.loads(match.group(1))
    group = stored["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x01"]["registers"]
    assert group["0x0002"]["evidence_grade"] == "Proven"
    original = before["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x01"]["registers"]
    added = set(group["0x0002"]) - set(original["0x0002"])
    assert not {key for key in added if "evidence" in key or "provenance" in key}
    assert "Entry evidence" not in match.group(1)
    assert "Decoded value" not in match.group(1)


def test_embedded_provenance_is_the_retained_value_not_the_display_normalisation() -> None:
    entry = _entry(parameter_description={"codec_provenance": "not_a_known_provenance"})
    html = render_html_report(_artifact({BASE: entry}))

    assert _embedded_rows(html) == [[*BASE, "Unknown", "not_a_known_provenance", "Hypothesis"]]
    match = re.search(
        r'<script id="artifact-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert match is not None
    stored = json.loads(match.group(1))
    retained = stored["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x01"]["registers"]
    # The report's own description pass relabels the value for its description line; the
    # grade and provenance lines keep what the artifact retained.
    assert retained["0x0002"]["parameter_description"]["codec_provenance"] == "legacy_unknown"


_DOM_HARNESS = r"""
class Node {
  constructor(tag) {
    this.tag = tag; this.children = []; this.className = "";
    this.classList = {add: (...names) => {
      this.className = [this.className, ...names].filter(Boolean).join(" ");
    }};
    this.textContent = ""; this.innerHTML = ""; this.title = "";
  }
  appendChild(child) { this.children.push(child); return child; }
  addEventListener() {}
}
const document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (text) => {
    const node = new Node("text");
    node.textContent = text;
    return node;
  },
};
const sheetArea = new Node("div");
const state = {b524Filters: {hideMissingInstances: false, hideAbsent: false, hideDormant: false}};
let groupData = null;
let overrides = {};
function getOperationGroup() { return groupData; }
function getGroupObject(value) { return value; }
function groupLabelForSection(_group, _section, fallback) { return fallback; }
function entryStatusKind() { return "ok"; }
function entryStatusLabel() { return "OK"; }
function sortedHexKeys(keys) { return keys.sort((a, b) => parseInt(a, 16) - parseInt(b, 16)); }
function visibleRegisterKeys(instances) {
  const keys = new Set();
  for (const instance of Object.values(instances)) {
    for (const key of Object.keys(instance.registers || {})) keys.add(key);
  }
  return sortedHexKeys(Array.from(keys));
}
function parseHexKey(value) { return parseInt(value, 16); }
function rowIsAbsent() { return false; }
function rowIsDormant() { return false; }
function groupPresentationForSection() { return null; }
function getInstanceObject(value) { return value; }
function bytesFromHex(raw) { return raw.match(/../g).map((value) => parseInt(value, 16)); }
function getRowOverride(_group, rrKey) { return rrKey in overrides ? overrides[rrKey] : null; }
function setRowOverride() {}
function candidateTypeSpecsForLength() { return ["UIN", "HEX:2"]; }
function parseTypedValue(_typeSpec, bytes) { return {value: bytes[0], error: null}; }
function formatValue(value) { return String(value); }
function statusChipClass() { return ""; }
function appendAccessBadges() {}
function finalPlanForRoute() { return null; }
function b524CorrespondenceSecondaryText() { return ""; }
"""


def _rendered_cells(html: str, group: dict[str, Any], overrides: dict[str, str]) -> dict[str, Any]:
    """Render the report's real group table and return {register: {instance: cell}}."""
    start = html.index("function renderActiveGroup(")
    end = html.index("function renderB524Tab()", start)
    docs_start = html.index("const B524_DOCS_CATALOG_NAMES")
    docs_end = html.index("function b524CorrespondenceSecondaryText", docs_start)
    script = (
        _DOM_HARNESS
        + html[docs_start:docs_end]
        + html[start:end]
        + "groupData = "
        + json.dumps(group)
        + ";overrides = "
        + json.dumps(overrides)
        + """;
const mount = new Node("div");
renderActiveGroup("0x09", "0x02", mount);
const walk = (item) => [item, ...item.children.flatMap(walk)];
const table = walk(mount).find((item) => item.tag === "table");
const instanceKeys = walk(table.children[0]).filter((n) => n.tag === "th").slice(1)
  .map((th) => th.textContent);
const result = {};
for (const tr of table.children[1].children) {
  const cells = tr.children.slice(1);
  const register = tr.children[0].children[0].textContent;
  result[register] = {};
  cells.forEach((td, index) => {
    result[register][instanceKeys[index]] = {
      lines: td.children.filter((n) => n.className === "cell-raw").map((n) => n.textContent),
      title: td.title,
      html: td.innerHTML,
    };
  });
}
console.log(JSON.stringify(result));
"""
    )
    return _run(script)  # type: ignore[no-any-return]


def test_rendered_cells_show_the_explicit_grade_and_override_and_keep_sparse_cells_empty() -> None:
    graded = _entry(evidence_grade="Proven")
    ungraded = _entry()
    selected = {
        ("0x02", "0x09", "0x00", "0x0002"): graded,
        ("0x02", "0x09", "0x00", "0x0003"): ungraded,
        ("0x02", "0x09", "0x01", "0x0003"): ungraded,
    }
    artifact = _artifact(selected)
    html = render_html_report(artifact)
    group = artifact["operations"]["0x02"]["groups"]["0x09"]

    plain = _rendered_cells(html, group, {})
    overridden = _rendered_cells(html, group, {"0x0002": "HEX:2", "0x0003": "HEX:2"})

    graded_line = (
        "Entry evidence: Proven · Decoded value: Hypothesis · Codec provenance: selector_qualified"
    )
    assert plain["0x0002"]["0x00"]["lines"][-1] == graded_line
    assert "Entry evidence: Proven" in plain["0x0002"]["0x00"]["title"].split("\n")
    assert "Decoded value: Hypothesis" in plain["0x0002"]["0x00"]["title"].split("\n")
    assert "Codec provenance: selector_qualified" in plain["0x0002"]["0x00"]["title"].split("\n")
    # An ungraded entry keeps Unknown out of the cell but in its hover details.
    assert all("Entry evidence" not in line for line in plain["0x0003"]["0x00"]["lines"])
    assert plain["0x0003"]["0x00"]["title"].split("\n")[-3:] == [
        "Entry evidence: Unknown",
        "Decoded value: Hypothesis",
        "Codec provenance: selector_qualified",
    ]
    # The sparse cell (no entry at instance 0x01) renders the dash only.
    sparse = plain["0x0002"]["0x01"]
    assert sparse["lines"] == [] and sparse["title"] == "" and "cell-missing" in sparse["html"]
    # A row override adds the separate Hypothesis line to cells that hold an entry ...
    assert overridden["0x0002"]["0x00"]["lines"][-1] == (
        f"Entry evidence: Proven · {OVERRIDE_LINE} · Codec provenance: selector_qualified"
    )
    assert overridden["0x0003"]["0x00"]["lines"][-1] == (
        f"Entry evidence: Unknown · {OVERRIDE_LINE} · Codec provenance: selector_qualified"
    )
    assert OVERRIDE_LINE in overridden["0x0003"]["0x01"]["title"]
    # ... but never to a cell that holds none.
    sparse = overridden["0x0002"]["0x01"]
    assert sparse["lines"] == [] and sparse["title"] == "" and "cell-missing" in sparse["html"]


def test_cell_does_not_claim_an_override_that_produced_no_value() -> None:
    html = render_html_report(_keyed_artifact())

    for value_bytes, decode_error in (("null", "null"), ("[1, 0]", '"parse_error: short"')):
        result = _run(
            _cell_script(
                html,
                entry="{}",
                override='"HEX:2"',
                value_bytes=value_bytes,
                decode_error=decode_error,
            )
        )
        assert result["appended"] == [
            {
                "className": "cell-raw",
                "text": "Entry evidence: Proven · Decoded value: Hypothesis · "
                "Codec provenance: selector_qualified",
            }
        ]
