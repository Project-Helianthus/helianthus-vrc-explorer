# Offline acceptance card

This card verifies the public, read-first CLI from a clean checkout. It uses only repository-owned
sanitized fixtures and does not contact an eBUS adapter, a controller, or any network endpoint.

Use Python 3.12 or newer. From the repository root, prepare the development environment and run the
same checks as CI:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]" build
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
.venv/bin/python scripts/generate_models_csv.py
git diff --exit-code -- data/models.csv src/helianthus_vrc_explorer/data/models.csv
.venv/bin/python -m build

VRC_ACCEPTANCE_DIR="$(mktemp -d)"
python3.12 -m venv "$VRC_ACCEPTANCE_DIR/venv"
"$VRC_ACCEPTANCE_DIR/venv/bin/python" -m pip install dist/*.whl
PACKAGE_MODELS="$("$VRC_ACCEPTANCE_DIR/venv/bin/python" -c 'from importlib import resources; print(resources.files("helianthus_vrc_explorer.data").joinpath("models.csv"))')"
cmp -s data/models.csv "$PACKAGE_MODELS"
unzip -l dist/*.whl | rg 'helianthus_vrc_explorer/(data/models\.csv|fixtures/vrc720_full_scan\.json)'
tar -tzf dist/*.tar.gz | rg 'src/helianthus_vrc_explorer/(data/models\.csv|fixtures/vrc720_full_scan\.json)'
```

Pass when every command exits zero. The final comparison proves the installed wheel loads the
canonical model data. The wheel and source distribution must both contain
`helianthus_vrc_explorer/data/models.csv` and
`helianthus_vrc_explorer/fixtures/vrc720_full_scan.json`.

## Scriptable CLI and fixture replay

Continue with the separately installed interpreter. The dry run uses the packaged
`vrc720_full_scan.json` fixture and makes no device or network request.

```bash
RUNNER="$VRC_ACCEPTANCE_DIR/venv/bin/python"
OUTPUT_DIR="$VRC_ACCEPTANCE_DIR/output"
mkdir -p "$OUTPUT_DIR"

(
  cd "$VRC_ACCEPTANCE_DIR"
  "$RUNNER" -m helianthus_vrc_explorer --version
  "$RUNNER" -m helianthus_vrc_explorer scan --dry-run --dst 0x15 --output-dir "$OUTPUT_DIR" \
    > "$OUTPUT_DIR/scan.stdout" 2> "$OUTPUT_DIR/scan.stderr"
)

test "$(wc -l < "$OUTPUT_DIR/scan.stdout")" -eq 1
ARTIFACT="$(< "$OUTPUT_DIR/scan.stdout")"
test -s "$ARTIFACT"
test -s "${ARTIFACT%.json}.html"
rg -F 'schema_version' "$ARTIFACT"
rg -F '"0x02"' "$ARTIFACT"
```

Pass when `--version` emits one `helianthus-vrc-explorer <version>` line and exits zero, `scan` exits
zero, and `scan.stdout` contains exactly one line: the absolute JSON artifact path. Progress and the
scan summary belong on stderr. The JSON and matching HTML report must exist, and the artifact must
retain its schema version and opcode-keyed operation.

The deterministic evidence checker verifies the synthetic fixture at the JSON level after schema
migration. It requires separate operation/group/instance/register paths, retained known-good raw
payloads, explicit `empty_reply` and `nack` response/error fields, and the `meta.incomplete` reason.
It rejects field removal or a `0x02`/`0x06` collapse. The fixture is explicitly synthetic and offline;
it is not a capture or hardware proof.

Replay that checked-in fixture through the same installed CLI as additional scriptability evidence.
In a non-TTY environment, `browse` prints its summary to stderr and exits zero after reporting that
the fullscreen UI needs a TTY.

```bash
"$RUNNER" -m helianthus_vrc_explorer browse --file fixtures/offline_acceptance_evidence.json \
  > "$OUTPUT_DIR/evidence.stdout" 2> "$OUTPUT_DIR/evidence.stderr"
"$RUNNER" -m helianthus_vrc_explorer browse --file fixtures/demo_browse.json \
  > "$OUTPUT_DIR/demo.stdout" 2> "$OUTPUT_DIR/demo.stderr"

test ! -s "$OUTPUT_DIR/evidence.stdout"
test ! -s "$OUTPUT_DIR/demo.stdout"
rg -F 'Local Devices (0x02)' "$OUTPUT_DIR/evidence.stderr"
rg -F 'Remote Devices (0x06)' "$OUTPUT_DIR/evidence.stderr"
rg -F 'Browse UI requires a TTY terminal.' "$OUTPUT_DIR/evidence.stderr"
rg -F 'Local Devices (0x02)' "$OUTPUT_DIR/demo.stderr"
```

Pass when both commands exit zero. The JSON-level checker is the required evidence for the separate
`0x02` and `0x06` paths, raw payloads, response states, errors, and incomplete metadata; the browse
summary is additional evidence that the installed non-TTY CLI remains scriptable. `demo_browse.json`
must remain readable as a local-operation artifact.

## Failure and hardware boundary

Any nonzero exit, missing JSON or HTML output, more than one stdout line from the dry run, changed
generated model CSV, absent packaged resource, failed JSON-level evidence check, or missing
local/remote operation labels is a failure. Investigate it with a focused regression test before
changing behavior.

This acceptance card does not validate live discovery, transport timing, controller behavior, or
device writes. Those require an explicit operator-approved hardware procedure; do not use these
commands as authorization to contact a live system.
