"""The AdapterMux certification record names every owned cell and stays fail-closed."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PROCEDURE = _ROOT / "docs" / "adaptermux-certification-run.md"
_OFFLINE = _ROOT / "docs" / "offline-acceptance.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_TABLE_START = "<!-- certification-cells: start -->"
_TABLE_END = "<!-- certification-cells: end -->"
_SESSION_START = "<!-- certification-session: start -->"
_SESSION_END = "<!-- certification-session: end -->"
_SESSION_HEADER = "| Field | `ENS` | `ENH` |"
_SESSION_FIELDS = ("protocol-family", "transport-refusal")
_SESSION_ROW = re.compile(
    r"^\| `(?P<field>protocol-family|transport-refusal)` \| "
    r"`(?P<ens>[A-Za-z0-9-]+)` \| `(?P<enh>[A-Za-z0-9-]+)` \|$"
)
_CELL_ROW = re.compile(
    r"^\| `(?P<cell>[A-Z0-9-]+)` \| `(?P<southbound>[A-Z0-9]+)` \| "
    r"`(?P<invariant>[A-Z0-9]+)` \| `(?P<disposition>[a-z-]+)` \| "
    r"`(?P<command>[a-z-]+)` \| `(?P<grade>[A-Za-z]+)` \| "
    r"`(?P<qualification>[a-z-]+)` \| `(?P<outcome>[a-z-]+)` \|$"
)
_HEADER = (
    "| Cell | Southbound | Invariant | Disposition | Command | Grade | Qualification | Outcome |"
)
_RECORD_FOR = {
    "execute": ("pending", "pending", "pending"),
    "recorded-from-coexistence-scan": ("pending", "pending", "pending"),
    "not-run": ("Unknown", "none", "not-run"),
}
_COMMAND_FOR = {
    "execute": "scan",
    "recorded-from-coexistence-scan": "same-scan",
    "not-run": "not-run",
}
_EXECUTED = {
    ("ENS", "CX01"): ("execute", "scan"),
    ("ENH", "CX01"): ("execute", "scan"),
    ("ENS", "AD06"): ("recorded-from-coexistence-scan", "same-scan"),
    ("ENH", "AD06"): ("recorded-from-coexistence-scan", "same-scan"),
    ("ENS", "AD08"): ("recorded-from-coexistence-scan", "same-scan"),
    ("ENH", "AD08"): ("recorded-from-coexistence-scan", "same-scan"),
}
_SOUTHBOUNDS = ("ENS", "ENH", "UDP", "TCP", "UARTENS", "UARTENH", "UARTRAW")
_INVARIANTS = ("AD05", "AD06", "AD08", "AD12", "CX01")
_FIELDS = (
    "southbound",
    "invariant",
    "disposition",
    "command",
    "grade",
    "qualification",
    "outcome",
)
_Row = tuple[str, str, str, str, str, str, str]
_SENTENCES = (
    "The candidate build is the Explorer build the session is qualifying.",
    "The gateway AdapterMux listener is already running for the southbound under test.",
    "Explorer connects to that listener as an ENH client and uses no other endpoint.",
    "Record the Explorer version line and do not raise a version.",
    "The coexistence rows name northbound client `vrc-explorer`.",
    "The scan is read-only.",
    "This procedure has no device write.",
    "The direct adapter path is outside this procedure.",
    "Grade Proven is the retained scan exit status.",
    (
        "For every row, record the cell, southbound, invariant, disposition, "
        "command, evidence grade, qualification, and outcome."
    ),
    "The Grade, Qualification, and Outcome columns are the record fields of each row.",
    "Before the run they hold `pending` on every row the run fills.",
    "Replace each `pending` with the recorded value in the published record.",
    "A row that still holds `pending` is not a pass.",
    "A `not-run` row keeps grade `Unknown`, qualification `none`, and outcome `not-run`.",
    "The Grade column holds `Proven`, `Hypothesis`, or `Unknown`.",
    "The Qualification column holds the selector qualification in family wording, or `none`.",
    "The Outcome column holds `pass`, `fail`, `blocked`, or `not-run`.",
    (
        "A `recorded-from-coexistence-scan` row takes the outcome of the `execute` "
        "row of the same southbound."
    ),
    "Its grade is at most Hypothesis.",
    (
        "Use it only when that exit status is retained, and only for the fact "
        "that the scan completed."
    ),
    "Grade Hypothesis is an interpretation of that completed scan.",
    "Grade Unknown is missing context, including any wire symbol the scan did not retain.",
    "A completed enhanced scan through the listener supports Hypothesis for START/SEND.",
    (
        "It supports Hypothesis for the echo of each raw symbol Explorer sent "
        "in a completed transaction."
    ),
    "Broadcast reception and raw escape pairs stay Unknown on every row.",
    "The JSON artifact and the HTML report contain the scan timestamp and the destination address.",
    "The JSON artifact and the HTML report contain the listener host and port.",
    (
        "The JSON artifact and the HTML report contain the probed model and serial "
        "in `identity` and `resolved_identity`."
    ),
    "The file names contain the destination address and the scan timestamp.",
    "The HTML report also embeds that JSON.",
    "Do not retain the JSON artifact.",
    "Do not retain the HTML report.",
    "Do not retain a redacted copy of either file.",
    "Delete both files after the scan exit status is recorded.",
    "Save the scan exit status in `ADAPTERMUX_SCAN_STATUS` immediately after the scan.",
    "That assignment runs before any artifact inspection or deletion.",
    "The retained scan exit status is `ADAPTERMUX_SCAN_STATUS`.",
    "The published row omits the artifact body.",
    "No scan artifact is retained.",
    "Retaining the JSON artifact or the HTML report is not a pass.",
    "A retained scan artifact returns to this repository.",
    "Confirm the JSON artifact and the HTML report are gone.",
    "Qualification is a separate record and does not set the grade.",
    "The grade does not set qualification.",
    "Record the controller protocol family only.",
    "Read the protocol family from `identity` before deleting the artifact.",
    "The protocol family field holds the catalog protocol family, or `Unknown`.",
    "The protocol family field is `Unknown` when the exact EID/SPN pair is unmatched.",
    "Do not record the EID or the SPN.",
    "The protocol family is not an evidence grade.",
    "The published record is the cell table and the session fields.",
    "For the session, record the protocol family and the transport refusal.",
    "A missing session field is not a pass.",
    "A session field that still holds `pending` is not a pass.",
    "When the executable rows are blocked, the protocol family field is `Unknown`.",
    ("When the executable rows are blocked, the transport-refusal indicator is `blocked`."),
    "A redirected scan still exits 0 after a caught transport error.",
    "With no terminal attached, discovery failures are not written to the raw log.",
    "The summary does not count those discovery failures.",
    "A transport error is a register `error` value that begins with `transport_error`.",
    "A transport diagnostic is a `transport_diagnostic` object in the artifact.",
    (
        "A transport recovery is `transport_recovery` or the incomplete reason "
        "`transport_recovery_exhausted`."
    ),
    "Before deleting either artifact, check the JSON artifact for a transport refusal.",
    (
        "Do not copy an error string, a raw value, an address, an endpoint, a model, "
        "a serial, or a time into that indicator."
    ),
    "The indicator is `refused` when the artifact holds a transport error.",
    "The indicator is `refused` when the artifact holds a transport diagnostic.",
    "The indicator is `refused` when the artifact holds a transport recovery.",
    "The indicator is `none` only when that check finds none of those.",
    "Record the sanitized transport-refusal indicator before deletion.",
    "A scan exit status of 0 does not show that the listener refused nothing.",
    "The summary error count is not the transport-refusal check.",
    "An `execute` row passes only when that indicator is `none`.",
    "Do not record a model name, serial, address, or time.",
    (
        "If the listener endpoint or the initiator is not supplied, "
        "record the executable rows as blocked."
    ),
    "Set `$ADAPTERMUX_INITIATOR` to the initiator the session assigns to Explorer.",
    "That initiator differs from the initiator of every other client of the listener.",
    ("The scan passes it with `--source-address`, and its enhanced transport arbitrates with it."),
    "If the controller does not answer at that destination, record the executable rows as blocked.",
    "Set `$ADAPTERMUX_RAW_LOG` to the raw session log path before the scan.",
    "Sanitize the raw session log before retention.",
    "Drop the non-interactive preface and the scan status lines from the retained log.",
    "Drop any other retained-log line that contains a model, a serial, or a controller address.",
    "Drop any other retained-log line that contains the listener endpoint or a start time.",
    "Do not retain the raw redirect.",
    "Leave the sanitized session log in place.",
    "Restore stops Explorer and sends no further bus command.",
    "An unexpected fail returns to the owning repository.",
    "An unexpected pass returns to the owning repository.",
    "Blocked cells stay visible.",
    "Not-run cells stay visible.",
    "UDP rows are not run.",
    "TCP rows are not run.",
    "UART-direct rows are not run.",
)
_FLAGS = (
    "--transport enh",
    '--host "$ADAPTERMUX_LISTENER_HOST"',
    '--port "$ADAPTERMUX_LISTENER_PORT"',
    '--source-address "$ADAPTERMUX_INITIATOR"',
    "--preset recommended",
)
_SCAN_COMMAND = re.compile(
    r"```bash\n(python -m helianthus_vrc_explorer scan\b.*?)\n```",
    re.DOTALL,
)
_REDIRECT = '  </dev/null >"$ADAPTERMUX_RAW_LOG" 2>&1'
_STATUS_CAPTURE = "ADAPTERMUX_SCAN_STATUS=$?"
_FORBIDDEN = (
    ("Leave the session output in place.", "raw session output retained"),
    ("Keep that artifact for local inspection.", "unsanitized artifact retained"),
    ("Grade Proven is a fact inside the retained artifact.", "unsanitized artifact retained"),
    (
        "Grade Hypothesis is an interpretation supported by that artifact.",
        "unsanitized artifact retained",
    ),
    (
        "A scan exit status of 0 shows that the listener refused nothing.",
        "exit status treated as a refusal check",
    ),
)
_OFFLINE_LINK = "](adaptermux-certification-run.md)"
_CHANGELOG_LINK = "docs/adaptermux-certification-run.md"


def _expected_rows() -> dict[str, _Row]:
    rows: dict[str, _Row] = {}
    for southbound in _SOUTHBOUNDS:
        for invariant in _INVARIANTS:
            cell = f"{southbound}-{invariant}"
            disposition, command = _EXECUTED.get((southbound, invariant), ("not-run", "not-run"))
            grade, qualification, outcome = _RECORD_FOR[disposition]
            rows[cell] = (
                southbound,
                invariant,
                disposition,
                command,
                grade,
                qualification,
                outcome,
            )
    return rows


def _sentence_errors(text: str) -> list[str]:
    errors: list[str] = []
    for sentence in _SENTENCES:
        count = text.count(sentence)
        if count != 1:
            kind = "missing" if count == 0 else "duplicate"
            errors.append(f"{kind} sentence: {sentence}")
    return errors


def _flag_errors(text: str) -> list[str]:
    errors: list[str] = []
    for flag in _FLAGS:
        if text.count(flag) != 1:
            errors.append(f"missing flag: {flag}")
    return errors


def _scan_command_errors(text: str) -> list[str]:
    found = _SCAN_COMMAND.findall(text)
    if len(found) != 1:
        return ["missing scan command"]
    body = found[0]
    if "--transport enh" not in body or "--transport tcp" in body:
        return ["scan does not use the enhanced transport"]
    if '--host "$ADAPTERMUX_LISTENER_HOST"' not in body:
        return ["scan does not target the AdapterMux listener"]
    if '--port "$ADAPTERMUX_LISTENER_PORT"' not in body:
        return ["scan does not target the AdapterMux listener"]
    if '--source-address "$ADAPTERMUX_INITIATOR"' not in body:
        return ["scan does not pass the supplied initiator"]
    return _status_capture_errors(body)


def _status_capture_errors(body: str) -> list[str]:
    lines = body.splitlines()
    if _REDIRECT not in lines:
        return ["scan output not redirected"]
    redirect_at = lines.index(_REDIRECT)
    if redirect_at + 1 >= len(lines) or lines[redirect_at + 1] != _STATUS_CAPTURE:
        return ["scan exit status not captured before post-processing"]
    return []


def _initiator_errors(text: str) -> list[str]:
    if text.count("$ADAPTERMUX_INITIATOR") != 2:
        return ["missing initiator binding"]
    return []


def _forbidden_errors(text: str) -> list[str]:
    return [label for phrase, label in _FORBIDDEN if phrase in text]


def _relay_errors(text: str) -> list[str]:
    if "relay" in text.lower():
        return ["scan routed through a relay instead of the listener"]
    return []


def _session_body(text: str) -> tuple[str, list[str]]:
    if text.count(_SESSION_START) != 1 or text.count(_SESSION_END) != 1:
        return "", ["missing certification session fields"]
    body = text.split(_SESSION_START, 1)[1].split(_SESSION_END, 1)[0]
    return body, []


def _parse_session_line(line: str) -> tuple[tuple[str, tuple[str, str]] | None, list[str]]:
    if not line.startswith("| `"):
        return None, []
    match = _SESSION_ROW.fullmatch(line)
    if match is None:
        return None, [f"unreadable session field: {line}"]
    values = (match.group("ens"), match.group("enh"))
    return (match.group("field"), values), []


def _session_rows(body: str) -> tuple[dict[str, tuple[str, str]], list[str]]:
    errors: list[str] = []
    found: dict[str, tuple[str, str]] = {}
    if _SESSION_HEADER not in body.splitlines():
        errors.append("session fields lack the ENS and ENH columns")
    for line in body.splitlines():
        parsed, row_errors = _parse_session_line(line)
        errors.extend(row_errors)
        if parsed is None:
            continue
        field, values = parsed
        if field in found:
            errors.append(f"{field} duplicate")
        found[field] = values
    return found, errors


def _session_value_errors(found: dict[str, tuple[str, str]]) -> list[str]:
    errors: list[str] = []
    for field in _SESSION_FIELDS:
        if field not in found:
            errors.append(f"{field} missing")
            continue
        if found[field] != ("pending", "pending"):
            errors.append(f"{field} value")
    return errors


def _session_errors(text: str) -> list[str]:
    body, errors = _session_body(text)
    if errors:
        return errors
    found, row_errors = _session_rows(body)
    return [*row_errors, *_session_value_errors(found)]


def _parse_cells(text: str) -> tuple[dict[str, _Row], list[str]]:
    errors: list[str] = []
    if text.count(_TABLE_START) != 1 or text.count(_TABLE_END) != 1:
        return {}, ["missing certification cell table"]
    body = text.split(_TABLE_START, 1)[1].split(_TABLE_END, 1)[0]
    if _HEADER not in body.splitlines():
        errors.append("cell table lacks the grade, qualification and outcome columns")
    rows: dict[str, _Row] = {}
    for line in body.splitlines():
        if not line.startswith("| `"):
            continue
        match = _CELL_ROW.fullmatch(line)
        if match is None:
            errors.append(f"unreadable cell row: {line}")
            continue
        cell = match.group("cell")
        if cell in rows:
            errors.append(f"{cell} duplicate")
        rows[cell] = (
            match.group("southbound"),
            match.group("invariant"),
            match.group("disposition"),
            match.group("command"),
            match.group("grade"),
            match.group("qualification"),
            match.group("outcome"),
        )
    return rows, errors


def _inventory_errors(rows: dict[str, _Row]) -> list[str]:
    errors: list[str] = []
    expected = _expected_rows()
    for cell in sorted(set(rows) - set(expected)):
        errors.append(f"{cell} unexpected")
    for cell in sorted(set(expected) - set(rows)):
        errors.append(f"{cell} missing")
    for cell in sorted(set(rows) & set(expected)):
        errors.extend(_cell_errors(cell, rows[cell], expected[cell]))
    return errors


def _cell_errors(
    cell: str,
    got: _Row,
    want: _Row,
) -> list[str]:
    errors: list[str] = []
    southbound, invariant, disposition, command = got[:4]
    if cell != f"{southbound}-{invariant}":
        errors.append(f"{cell} cell")
    if _COMMAND_FOR.get(disposition) != command:
        errors.append(f"{cell} command")
    for name, actual, required in zip(_FIELDS, got, want, strict=True):
        if actual != required:
            errors.append(f"{cell} {name}")
    return errors


def certification_errors(text: str) -> list[str]:
    errors = _sentence_errors(text)
    errors.extend(_flag_errors(text))
    errors.extend(_scan_command_errors(text))
    errors.extend(_initiator_errors(text))
    errors.extend(_forbidden_errors(text))
    errors.extend(_relay_errors(text))
    errors.extend(_session_errors(text))
    rows, parse_errors = _parse_cells(text)
    errors.extend(parse_errors)
    if parse_errors:
        return errors
    errors.extend(_inventory_errors(rows))
    return errors


def _link_errors(text: str, link: str) -> list[str]:
    if text.count(link) != 1:
        return [f"missing link: {link}"]
    return []


def _mutate_column(text: str, cell: str, column: int, value: str) -> str:
    prefix = f"| `{cell}` |"
    lines: list[str] = []
    found = False
    for line in text.splitlines():
        if line.startswith(prefix):
            parts = line[2:-2].split(" | ")
            parts[column] = f"`{value}`"
            line = "| " + " | ".join(parts) + " |"
            found = True
        lines.append(line)
    if not found:
        raise AssertionError(cell)
    suffix = "\n" if text.endswith("\n") else ""
    return "\n".join(lines) + suffix


class AdapterMuxCertificationRunTests(unittest.TestCase):
    def test_procedure_is_accepted(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        self.assertEqual(certification_errors(text), [])

    def test_removed_sentence_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        for sentence in _SENTENCES:
            with self.subTest(sentence=sentence):
                mutated = text.replace(sentence, "", 1)
                errors = certification_errors(mutated)
                self.assertIn(f"missing sentence: {sentence}", errors)

    def test_duplicated_sentence_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        sentence = _SENTENCES[0]
        mutated = text.replace(sentence, f"{sentence} {sentence}", 1)
        errors = certification_errors(mutated)
        self.assertIn(f"duplicate sentence: {sentence}", errors)

    def test_removed_flag_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        for flag in _FLAGS:
            with self.subTest(flag=flag):
                mutated = text.replace(flag, "", 1)
                errors = certification_errors(mutated)
                self.assertIn(f"missing flag: {flag}", errors)

    def test_tcp_scan_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        needle = "  --transport enh \\\n"
        self.assertIn(needle, text)
        for replacement in ("  --transport tcp \\\n", "  --transport enh --transport tcp \\\n"):
            with self.subTest(replacement=replacement):
                errors = certification_errors(text.replace(needle, replacement, 1))
                self.assertIn("scan does not use the enhanced transport", errors)

    def test_scan_off_the_listener_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        for name in ("HOST", "PORT"):
            needle = f'"$ADAPTERMUX_LISTENER_{name}" \\\n'
            self.assertIn(needle, text)
            with self.subTest(name=name):
                mutated = text.replace(needle, f'"$ADAPTERMUX_RELAY_{name}" \\\n', 1)
                errors = certification_errors(mutated)
                self.assertIn("scan does not target the AdapterMux listener", errors)
                self.assertIn("scan routed through a relay instead of the listener", errors)

    def test_relay_endpoint_in_prose_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        needle = "Explorer connects to that listener as an ENH client and uses no other endpoint."
        self.assertIn(needle, text)
        mutated = text.replace(needle, "Explorer's only endpoint is the guarded command relay.", 1)
        errors = certification_errors(mutated)
        self.assertIn("scan routed through a relay instead of the listener", errors)

    def test_scan_without_initiator_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        needle = '  --source-address "$ADAPTERMUX_INITIATOR" \\\n'
        self.assertIn(needle, text)
        errors = certification_errors(text.replace(needle, "", 1))
        self.assertIn("scan does not pass the supplied initiator", errors)
        self.assertIn("missing initiator binding", errors)

    def test_late_exit_status_capture_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        needle = _REDIRECT + "\n" + _STATUS_CAPTURE + "\n"
        self.assertIn(needle, text)
        cases = (
            _REDIRECT + "\n",
            _REDIRECT + "\nrm -- results/scan.json\n" + _STATUS_CAPTURE + "\n",
            _STATUS_CAPTURE + "\n" + _REDIRECT + "\n",
        )
        for replacement in cases:
            with self.subTest(replacement=replacement):
                errors = certification_errors(text.replace(needle, replacement, 1))
                self.assertIn("scan exit status not captured before post-processing", errors)

    def test_scan_without_redirection_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        needle = "  --preset recommended \\\n" + _REDIRECT + "\n"
        self.assertIn(needle, text)
        cases = (
            "  --preset recommended\n",
            "  --preset recommended \\\n" + '  </dev/null >"$ADAPTERMUX_RAW_LOG"\n',
            "  --preset recommended \\\n" + '  >"$ADAPTERMUX_RAW_LOG" 2>&1\n',
        )
        for replacement in cases:
            with self.subTest(replacement=replacement):
                errors = certification_errors(text.replace(needle, replacement, 1))
                self.assertIn("scan output not redirected", errors)

    def test_retained_raw_session_output_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        mutated = text.replace(
            "Leave the sanitized session log in place.",
            "Leave the session output in place.",
            1,
        )
        errors = certification_errors(mutated)
        self.assertIn("raw session output retained", errors)

    def test_retained_scan_artifact_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        needle = "Do not retain the JSON artifact."
        self.assertIn(needle, text)
        mutated = text.replace(needle, "Keep that artifact for local inspection.", 1)
        errors = certification_errors(mutated)
        self.assertIn("missing sentence: Do not retain the JSON artifact.", errors)
        self.assertIn("unsanitized artifact retained", errors)

    def test_grade_tied_to_unsanitized_artifact_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        needle = "Grade Proven is the retained scan exit status."
        self.assertIn(needle, text)
        mutated = text.replace(
            needle,
            "Grade Proven is a fact inside the retained artifact.",
            1,
        )
        errors = certification_errors(mutated)
        self.assertIn("missing sentence: Grade Proven is the retained scan exit status.", errors)
        self.assertIn("unsanitized artifact retained", errors)

    def test_cell_field_mutation_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        cases = (
            ("ENS-CX01", 0, "ENS-CX99", "ENS-CX01 missing"),
            ("ENS-CX01", 1, "UDP", "ENS-CX01 southbound"),
            ("ENS-CX01", 2, "AD05", "ENS-CX01 invariant"),
            ("ENS-CX01", 3, "not-run", "ENS-CX01 disposition"),
            ("ENS-CX01", 4, "not-run", "ENS-CX01 command"),
            ("UDP-CX01", 3, "execute", "UDP-CX01 disposition"),
            ("ENS-AD08", 3, "not-run", "ENS-AD08 disposition"),
            ("ENH-AD08", 3, "not-run", "ENH-AD08 disposition"),
            ("ENH-AD05", 3, "execute", "ENH-AD05 disposition"),
        )
        for cell, column, value, expected in cases:
            with self.subTest(cell=cell, column=column):
                mutated = _mutate_column(text, cell, column, value)
                errors = certification_errors(mutated)
                self.assertIn(expected, errors)

    def test_record_field_mutation_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        cases = (
            ("ENS-CX01", 5, "Proven", "ENS-CX01 grade"),
            ("ENS-CX01", 6, "none", "ENS-CX01 qualification"),
            ("ENS-CX01", 7, "pass", "ENS-CX01 outcome"),
            ("ENH-AD06", 5, "Proven", "ENH-AD06 grade"),
            ("UDP-CX01", 5, "Proven", "UDP-CX01 grade"),
            ("UDP-CX01", 6, "pending", "UDP-CX01 qualification"),
            ("ENS-AD05", 7, "pass", "ENS-AD05 outcome"),
        )
        for cell, column, value, expected in cases:
            with self.subTest(cell=cell, column=column):
                mutated = _mutate_column(text, cell, column, value)
                errors = certification_errors(mutated)
                self.assertIn(expected, errors)

    def test_table_without_record_fields_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        self.assertIn(_HEADER + "\n", text)
        lines: list[str] = []
        for line in text.splitlines():
            if line.startswith("| "):
                line = "| " + " | ".join(line[2:-2].split(" | ")[:5]) + " |"
            lines.append(line)
        errors = certification_errors("\n".join(lines) + "\n")
        self.assertIn("cell table lacks the grade, qualification and outcome columns", errors)
        self.assertIn(
            "unreadable cell row: | `ENS-CX01` | `ENS` | `CX01` | `execute` | `scan` |",
            errors,
        )

    def test_dropped_session_field_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        row = "| `protocol-family` | `pending` | `pending` |\n"
        self.assertIn(row, text)
        errors = certification_errors(text.replace(row, "", 1))
        self.assertIn("protocol-family missing", errors)

    def test_filled_session_field_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        row = "| `transport-refusal` | `pending` | `pending` |"
        self.assertIn(row, text)
        filled = "| `transport-refusal` | `none` | `none` |"
        errors = certification_errors(text.replace(row, filled, 1))
        self.assertIn("transport-refusal value", errors)

    def test_exit_status_alone_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        needle = "A scan exit status of 0 does not show that the listener refused nothing."
        self.assertIn(needle, text)
        mutated = text.replace(
            needle,
            "A scan exit status of 0 shows that the listener refused nothing.",
            1,
        )
        errors = certification_errors(mutated)
        self.assertIn(f"missing sentence: {needle}", errors)
        self.assertIn("exit status treated as a refusal check", errors)

    def test_dropped_not_run_row_is_rejected(self) -> None:
        text = _PROCEDURE.read_text(encoding="utf-8")
        row = (
            "| `UARTENS-AD12` | `UARTENS` | `AD12` | `not-run` | `not-run` "
            "| `Unknown` | `none` | `not-run` |\n"
        )
        self.assertIn(row, text)
        errors = certification_errors(text.replace(row, "", 1))
        self.assertIn("UARTENS-AD12 missing", errors)

    def test_offline_card_links_the_procedure(self) -> None:
        text = _OFFLINE.read_text(encoding="utf-8")
        self.assertEqual(_link_errors(text, _OFFLINE_LINK), [])
        mutated = text.replace(_OFFLINE_LINK, "", 1)
        self.assertEqual(_link_errors(mutated, _OFFLINE_LINK), [f"missing link: {_OFFLINE_LINK}"])

    def test_changelog_links_the_procedure(self) -> None:
        text = _CHANGELOG.read_text(encoding="utf-8")
        unreleased = text.split("## Unreleased\n", 1)[1].split("\n## ", 1)[0]
        self.assertEqual(_link_errors(unreleased, _CHANGELOG_LINK), [])
        mutated = unreleased.replace(_CHANGELOG_LINK, "", 1)
        self.assertEqual(
            _link_errors(mutated, _CHANGELOG_LINK),
            [f"missing link: {_CHANGELOG_LINK}"],
        )
