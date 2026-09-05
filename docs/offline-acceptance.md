# Offline acceptance card

This card verifies the public, read-first CLI from a clean checkout. It uses only repository-owned
sanitized fixtures and does not contact an eBUS adapter, a controller, or another device endpoint.
“Offline” here means no device or protocol I/O. Creating the environment may use the configured
package index unless its dependencies have been staged in a local wheelhouse.

Use Python 3.12 or newer. Run the command blocks below in Bash. `PYTHON_BIN` defaults to
`python3`, so a supported later interpreter can be selected with `PYTHON_BIN=/path/to/python3.14`.
From the repository root, prepare the development environment and run the same checks as CI. Leave
`WHEELHOUSE` unset to use pip's configured public package index. To use a prepared local
wheelhouse, export `WHEELHOUSE` before running every block; both development and external wheel
installs then use the same `--no-index --find-links` dependency source. The wheelhouse must contain
the runtime, development, and build dependencies needed by the selected block.

```bash
set -euo pipefail
PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" - <<'PY'
import sys

if sys.version_info < (3, 12):
    raise SystemExit(f"Python 3.12+ is required, got {sys.version.split()[0]}")
PY
PIP_DEPENDENCY_ARGS=()
if [[ -n "${WHEELHOUSE:-}" ]]; then
  PIP_DEPENDENCY_ARGS=(--no-index --find-links "$WHEELHOUSE")
fi
"$PYTHON_BIN" -m venv .venv
.venv/bin/python -m pip install "${PIP_DEPENDENCY_ARGS[@]}" --upgrade pip
.venv/bin/python -m pip install "${PIP_DEPENDENCY_ARGS[@]}" -e ".[dev]" build "setuptools>=68" wheel
.venv/bin/ruff check .
.venv/bin/python scripts/check_protocol_terminology.py
.venv/bin/python scripts/check_b524_namespace_guardrails.py
.venv/bin/python scripts/check_docs_sync.py
.venv/bin/python scripts/check_offline_acceptance_evidence.py
.venv/bin/ruff format --check .
.venv/bin/mypy src
.venv/bin/pytest
```

All commands must exit zero. `pytest` must collect and pass the full suite. The B524 guardrail and
schema tests cover operation-aware identity, legacy migration, response states, raw payload retention,
and interrupted scans retaining `meta.incomplete` with their accumulated observations.

## Build and installed-model check

`data/models.csv` is the editable source, and the packaged copy must be generated from it without a
diff. Build both distribution formats, then install the wheel into a separate directory so imports
cannot resolve from this checkout:

```bash
set -euo pipefail
PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" - <<'PY'
import sys

if sys.version_info < (3, 12):
    raise SystemExit(f"Python 3.12+ is required, got {sys.version.split()[0]}")
PY
PIP_DEPENDENCY_ARGS=()
if [[ -n "${WHEELHOUSE:-}" ]]; then
  PIP_DEPENDENCY_ARGS=(--no-index --find-links "$WHEELHOUSE")
fi
.venv/bin/python scripts/generate_models_csv.py
git diff --exit-code -- data/models.csv src/helianthus_vrc_explorer/data/models.csv
.venv/bin/python -m build --no-isolation

VRC_ACCEPTANCE_DIR="$(mktemp -d)"
"$PYTHON_BIN" -m venv "$VRC_ACCEPTANCE_DIR/venv"
"$VRC_ACCEPTANCE_DIR/venv/bin/python" -m pip install "${PIP_DEPENDENCY_ARGS[@]}" --upgrade pip
"$VRC_ACCEPTANCE_DIR/venv/bin/python" -m pip install "${PIP_DEPENDENCY_ARGS[@]}" dist/*.whl
PACKAGE_MODELS="$("$VRC_ACCEPTANCE_DIR/venv/bin/python" -c 'from importlib import resources; print(resources.files("helianthus_vrc_explorer.data").joinpath("models.csv"))')"
cmp -s data/models.csv "$PACKAGE_MODELS"
unzip -l dist/*.whl | rg 'helianthus_vrc_explorer/data/models\.csv'
unzip -l dist/*.whl | rg 'helianthus_vrc_explorer/fixtures/vrc720_full_scan\.json'
tar -tzf dist/*.tar.gz | rg 'src/helianthus_vrc_explorer/data/models\.csv'
tar -tzf dist/*.tar.gz | rg 'src/helianthus_vrc_explorer/fixtures/vrc720_full_scan\.json'
```

Pass when every command exits zero. The final comparison proves the installed wheel loads the
canonical model data. The wheel and source distribution must both contain
`helianthus_vrc_explorer/data/models.csv` and
`helianthus_vrc_explorer/fixtures/vrc720_full_scan.json`.

## Scriptable CLI and fixture replay

Continue with the separately installed interpreter. The dry run uses the packaged
`vrc720_full_scan.json` fixture and makes no device or network request.

```bash
set -euo pipefail
RUNNER="$VRC_ACCEPTANCE_DIR/venv/bin/python"
OUTPUT_DIR="$VRC_ACCEPTANCE_DIR/output"
mkdir -p "$OUTPUT_DIR"

(
  cd "$VRC_ACCEPTANCE_DIR"
  "$RUNNER" -m helianthus_vrc_explorer --version \
    > "$OUTPUT_DIR/version.stdout" 2> "$OUTPUT_DIR/version.stderr"
  "$RUNNER" -m helianthus_vrc_explorer scan --dry-run --dst 0x15 --output-dir "$OUTPUT_DIR" \
    > "$OUTPUT_DIR/scan.stdout" 2> "$OUTPUT_DIR/scan.stderr"
)

test "$(wc -l < "$OUTPUT_DIR/version.stdout")" -eq 1
test ! -s "$OUTPUT_DIR/version.stderr"
EXPECTED_VERSION="$("$RUNNER" -c 'from helianthus_vrc_explorer import __version__; print(f"helianthus-vrc-explorer {__version__}")')"
test "$(< "$OUTPUT_DIR/version.stdout")" = "$EXPECTED_VERSION"
test "$(wc -l < "$OUTPUT_DIR/scan.stdout")" -eq 1
ARTIFACT="$(< "$OUTPUT_DIR/scan.stdout")"
test -s "$ARTIFACT"
test -s "${ARTIFACT%.json}.html"
"$RUNNER" - "$ARTIFACT" <<'PY'
import json
import sys

artifact = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert artifact["schema_version"] == "2.3"
assert isinstance(artifact.get("operations", {}).get("0x02"), dict)
PY
```

Pass when `--version` emits one `helianthus-vrc-explorer <version>` line and exits zero, `scan` exits
zero, and `scan.stdout` contains exactly one line: the absolute JSON artifact path. Progress and the
scan summary belong on stderr. The JSON and matching HTML report must exist, and the artifact must
retain its schema version and opcode-keyed operation.

The deterministic evidence checker first verifies the original synthetic JSON fixture. It requires its
root schema version, separate operation/group/instance/register paths, retained known-good raw
payloads, explicitly present `empty_reply` and `nack` response/error fields, incomplete reason,
and the synthetic unknown-group `0x06/0x69/0x00/0x0000` identity with
`meta.issue_suggestion.unknown_groups` provenance. Only after those checks does it migrate a deep
copy to confirm compatibility without a register-count change. It rejects field removal or a
`0x02`/`0x06` collapse. The fixture is explicitly synthetic and offline; it is not a capture or
hardware proof.

Replay that checked-in fixture through the same installed CLI as additional scriptability evidence.
In a non-TTY environment, `browse` prints its summary to stderr and exits zero after reporting that
the fullscreen UI needs a TTY.

```bash
set -euo pipefail
"$RUNNER" -m helianthus_vrc_explorer browse --file fixtures/offline_acceptance_evidence.json \
  > "$OUTPUT_DIR/evidence.stdout" 2> "$OUTPUT_DIR/evidence.stderr"
"$RUNNER" -m helianthus_vrc_explorer browse --file fixtures/demo_browse.json \
  > "$OUTPUT_DIR/demo.stdout" 2> "$OUTPUT_DIR/demo.stderr"

test ! -s "$OUTPUT_DIR/evidence.stdout"
test ! -s "$OUTPUT_DIR/demo.stdout"
rg -F 'Local Devices (0x02)' "$OUTPUT_DIR/evidence.stderr"
rg -F 'Remote Devices (0x06)' "$OUTPUT_DIR/evidence.stderr"
rg -F 'Unknown 0x69' "$OUTPUT_DIR/evidence.stderr"
rg -F 'groups: 0x69' "$OUTPUT_DIR/evidence.stderr"
rg -F 'Browse UI requires a TTY terminal.' "$OUTPUT_DIR/evidence.stderr"
rg -F 'Local Devices (0x02)' "$OUTPUT_DIR/demo.stderr"
```

Pass when both commands exit zero. The JSON-level checker is the required evidence for the separate
`0x02` and `0x06` paths, raw payloads, response states, errors, incomplete metadata, and unknown
group provenance; the browse summary is additional evidence that the installed non-TTY CLI retains
the unknown-group label and remains scriptable. `demo_browse.json` must remain readable as a
local-operation artifact.

## Failure and hardware boundary

Any nonzero exit, missing JSON or HTML output, more than one stdout line from the dry run, changed
generated model CSV, absent packaged resource, failed JSON-level evidence check, or missing
local/remote operation labels is a failure. Investigate it with a focused regression test before
changing behavior.

This acceptance card does not validate live discovery, transport timing, controller behavior, or
device writes. Those require an explicit operator-approved hardware procedure; do not use these
commands as authorization to contact a live system.
