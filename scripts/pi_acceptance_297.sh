#!/usr/bin/env bash
# Offline acceptance for #297. No scan, network transport, device or Git writes.
# Usage: TRACE=/path/to/stored.trace DOCS_EBUS_ROOT=/path/to/docs-ebus \
#          bash scripts/pi_acceptance_297.sh [trace] [new-output-directory]
# Python >=3.12 with this project's dev dependencies must already be installed.
# Expected: replay artifact schema 2.4; imported application baseline integer 2.
# An incomplete replay identity can legitimately export zero baseline rows.
# Expected source-pair native hashes (refreshing committed fixtures is #299):
# description 23f8f3a95315920b4746b7d7e70b648e73c1da8bb2734450e9ac34e77b6ae1cb
# observations 70a9194788779a7d1e47ef05a83e1d583b83b72cc8643b744b44ee5f5570db86
# overlay a4d6157363a75b2f3a64ef75a14be426e518dbd7453e171880d63aee17e24687
# With the pinned docs-ebus checkout, validator and all six cmp calls exit 0.
# Without DOCS_EBUS_ROOT the external gate is explicitly skipped, not claimed.
# Output is retained for inspection; nothing is deleted.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
trace=${1:-${TRACE:-}}
if [[ -z "$trace" || ! -f "$trace" ]]; then
    printf 'Set TRACE or pass an existing stored ENH/ENS trace.\n' >&2
    exit 2
fi
trace=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$trace")
python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python >=3.12 required"'
if [[ -n "${DOCS_EBUS_ROOT:-}" ]]; then
    DOCS_EBUS_ROOT=$(cd "$DOCS_EBUS_ROOT" && pwd)
    export DOCS_EBUS_ROOT
fi
if [[ -n "${2:-}" ]]; then
    mkdir "$2"
    out=$(cd "$2" && pwd)
else
    out=$(mktemp -d "${TMPDIR:-/tmp}/vrc-297.XXXXXX")
fi
cd "$repo_root"
export PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}"
python3 -m helianthus_vrc_explorer replay-trace "$trace" --output "$out/replay.json"
python3 scripts/validate_artifact.py "$out/replay.json"
python3 scripts/import_b524_descriptions.py "$out/replay.json" "$out/baseline.json" --allow-legacy-interpretation
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["schema_version"] == "2.4"; assert json.load(open(sys.argv[2]))["schema_version"] == 2' "$out/replay.json" "$out/baseline.json"
for target in native native-again; do
    python3 scripts/export_b524_evidence.py --allow-legacy-interpretation --output-dir "$out/$target"
done
for name in b524-basv0-description-profile-v1.json b524-basv0-register-observations-v1.json b524-basv0-validation-scope-v1.json; do
    cmp "$out/native/$name" "$out/native-again/$name"
done
if [[ -n "${DOCS_EBUS_ROOT:-}" ]]; then
    python3 "$DOCS_EBUS_ROOT/scripts/validate_b524_basv0_description_profile.py" \
        "$out/native/b524-basv0-description-profile-v1.json" \
        --observations "$out/native/b524-basv0-register-observations-v1.json" \
        --scopes "$out/native/b524-basv0-validation-scope-v1.json"
    for name in b524-basv0-description-profile-v1.json b524-basv0-register-observations-v1.json; do
        cmp "$out/native/$name" "$DOCS_EBUS_ROOT/protocols/vaillant/fixtures/$name"
    done
    cmp "$out/native/b524-basv0-validation-scope-v1.json" \
        "$DOCS_EBUS_ROOT/development/fixtures/b524-basv0-validation-scope-v1.json"
else
    printf 'SKIP: docs validator and docs byte comparisons require DOCS_EBUS_ROOT.\n'
fi
python3 -m pytest -q -p no:cacheprovider \
    --basetemp="$out/pytest" tests/test_issue_297_evidence_contract.py \
    tests/test_b524_evidence_export.py tests/test_replay_trace.py
printf 'Offline acceptance passed; inspect retained output: %s\n' "$out"
