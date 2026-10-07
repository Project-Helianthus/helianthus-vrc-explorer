# helianthus-vrc-explorer

[![CI](https://github.com/Project-Helianthus/helianthus-vrc-explorer/actions/workflows/ci.yml/badge.svg)](https://github.com/Project-Helianthus/helianthus-vrc-explorer/actions/workflows/ci.yml)

Helianthus VRC Explorer is a professional CLI tool for scanning **Vaillant VRC-series heating regulators/controllers** (e.g. VRC 700/720) via eBUS (B5 24 / B524 GetExtendedRegisters). It focuses on safe, read-oriented discovery and produces a high-quality JSON artifact.

This repository has **no relation to VRChat**.

## Goals
- Scan VRC regulators using the B524 protocol family (groups, instances, registers).
- Provide a polished terminal experience (rich formatting, progress, summaries).
- Produce complete JSON artifacts with metadata.
- Keep non-code assets (CSV/JSON fixtures, schemas) as editable data files, not hardcoded into Python.
- CI-gated development: lint + format + tests for every PR.

## Non-goals (for now)
- Shipping a full Home Assistant integration from this repository.
- Writing to devices by default. Any write/control functionality must be explicit and reviewed.

## Prerequisites
You need a working eBUS stack before this tool can talk to a regulator:

`Vaillant VRC regulator on eBUS` -> `eBUS adapter` -> `ebusd daemon` -> `helianthus-vrc-explorer`

Minimum setup:
- A supported eBUS-to-host adapter (hardware), wired to your eBUS.
- `ebusd` installed, running, and reachable over TCP (defaults to `127.0.0.1:8888`).
- `ebusd` must have the `hex` command enabled (`--enablehex`), since this tool uses raw telegram exchange.
- Network reachability from the machine running this tool to the `ebusd` TCP endpoint.

## Who Is This For?
- Home automation users and integrators who already have `ebusd` working and want a **safe, read-first** register explorer.
- Contributors reverse-engineering Vaillant VRC-series behavior and building mappings/decoders from real scans.

## Quick start
```bash
python -m helianthus_vrc_explorer scan \
  --planner-ui auto \
  --preset recommended
```

`scan` auto-discovers the destination (`--dst auto`) by default. Use `--dst 0x..` to force an address.

Contributors can verify the installed CLI, packaged data, and sanitized B524 replay inputs without
hardware by following the [offline acceptance card](docs/offline-acceptance.md).

Namespace contract for implementers:
- Stable B524 namespace invariants (identity, discovery authority, constraint scope, artifact keys, fixture compatibility): [public B524 namespace invariants](https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/architecture/b524-namespace-invariants.md)
- This README remains user-facing; invariant-level semantics are documented in the public eBUS documentation once implementation behavior is stable.

Key scan UX flags:
- `--planner-ui auto|textual|classic`
- `--preset recommended|full|research|custom`
- `--probe-constraints/--no-probe-constraints` (targeted OP01/OP07 descriptions for observed writable parameters; enabled by default)
- `--description-budget` (optional limit; all eligible parameters in the selected scope by default)
- `--request-budget` (optional B524 send limit including transport retries; no implicit send cap)
- `--scan-plan` (version 1 JSON file for exact custom read selectors)
- `--b509-dump` (B509 is opt-in; `--b509-range` requires this flag)
- `--no-tips`
- `--redact` (redact identity fields like serial number from console output)
- `--trace-file /path/to/trace.log`
- `--ebusd-csv-path /path/to/15.720.csv` (optional enrichment: adds eBUSd register names)
- `--myvaillant-map-path /path/to/myvaillant_register_map.csv` (optional enrichment: adds myVaillant-style leaf names)

If startup fails on default transport (`tcp://127.0.0.1:8888`) in an interactive TTY, scan opens a retry dialog so you can adjust protocol/host/port and retry or cancel.

Transport note:
- Default discovery reads the bounded OP00 `ReadSystemInformation` identifiers `0x0000..0x0011`. These are system-information identifiers, not group numbers. The artifact preserves `identifier`, snake-case `name`, finite `value` or `null`, and `raw_hex` for each response.
- OP00 `0x0000` (`circuit_count`) guides OP02/GG02 instance coverage; OP00 `0x0001` (`zone_count`) guides OP02/GG03. A valid expected count permits sparse II probing until that many successful instances are found. Missing, invalid, or inconsistent counts retain the bounded profile fallback rather than claiming completeness.
- On `ebusd-tcp`, `ERR: timeout`, `ERR: arbitration lost`, `ERR: SYN received`, and `ERR: wrong symbol received` now trigger a fixed 5-second quiet backoff before retry so the bus can settle.
- On `ebusd-tcp`, `ERR: no signal` now triggers a fixed 15-second quiet backoff before retry so the eBUS side can recover instead of being polled aggressively.
- On Enhanced TCP, recoverable socket/session failures reconnect and retry the same recognized read. Automatic retransmission is restricted to recognized reads; ambiguous writes and adapter host errors are not retried. Per-transaction retry/reconnect limits remain bounded and independent of optional scan budgets.
- Exhausted Enhanced recovery saves an incomplete artifact with `incomplete_reason="transport_recovery_exhausted"`, the pending selector, sanitized cause/phase/retry/reconnect counts, and recent request evidence. Completed observations remain available; remaining selectors are not converted into generic errors. A failure tag in HTML is concise; detailed diagnostics remain in JSON and the trace.
- Legacy group-directory artifacts and old TT constraint interpretations remain viewable but are explicitly unqualified. They do not define group semantics, value codecs, or a complete parameter-description contract.
- Instance availability is namespace-specific. Dual-namespace radio groups (`0x09`, `0x0A`) are discovered independently per opcode namespace instead of sharing remote results across local and remote.
- Artifacts retain the availability contract plus raw per-slot probe evidence under `availability_contract` and `availability_probes`, including the opcode `0x06` generic header block (`RR=0x0001..0x0004`) used for remote namespace occupancy.
- Empty ACK / 0-byte B524 register replies are preserved as `response_state="empty_reply"` (rendered as “empty reply / dormant”), not as transport errors.
- B524 register replies expose profile-scoped attribute hints: bit 0 hints visibility, bit 1 hints writability. They do not establish User/Installer roles or persistence. Older artifacts retain their historical labels, displayed as unqualified interpretations.
- OP `0x06` register-map fallbacks include a generic device header for `RR=0x0001..0x0004`, but BASV2 heat-source inventory is 1-indexed on `GG=0x01` (primary / type 1) and `GG=0x02` (secondary / type 2). `GG=0x00` is local-only on BASV2.
- GG `0x09` is intentionally dual-use: local/control semantics on `0x02`, remote radio-device semantics on `0x06`.
- Scanner annotations include the integer sentinel `0x7FFFFFFF` as `value_display="sentinel_invalid_i32 (0x7FFFFFFF)"` when decoded in integer contexts.
- Unknown groups are namespace-classified from live opcode responsiveness evidence. There is no implicit unknown-group `[0x02, 0x06]` fallback.
- Contextual enum annotations are local-namespace scoped: group `0x02` local (`0x02`) register context never relabels remote (`0x06`) entries.
- Canonical namespace identity is always an opcode hex key (`0x02`, `0x06`, ...). Labels like `local`/`remote` are presentation metadata only.
- Browse UI, CLI summary, and HTML report derive namespace labels from opcode identity and render them as qualified displays (for example `Local (0x02)`, `Remote (0x06)`).
- Legacy artifacts that still carry mixed opcodes inside a single non-dual group are rendered per-namespace in browse/report surfaces to prevent local/remote intermixing and override bleed.
- Persisted per-operation namespace topology is authoritative for consumers. Do not infer or rewrite namespace shape from descriptors.
- B524 browse/report row identity is namespace-aware even for single-namespace groups: dedupe key `<group>:<namespace>:<instance>:<register>` and path format `B524/<section>/<operation>/<group-name>/<namespace-display>/<instance>/<register-name>` are round-trip stable.
- Artifact schema contract is versioned (`schema_version: "2.3"` current, operations-first layout). Readers keep backward compatibility by migrating unversioned, `2.0`, `2.1`, and `2.2` artifacts in-memory.
- CI enforces these rules with `python scripts/check_b524_namespace_guardrails.py`.

Coverage and parameter-description note:

- Send accounting includes each ebusd command attempt and Enhanced request attempt, including internal retransmissions. Connection/arbitration failure may consume an attempt; these counters do not prove physical bus delivery. Description coverage counts candidates separately from `request_attempts` and `retries`.
- `recommended` uses qualified OP00 counts for sparse circuit/zone instance discovery, with a bounded fallback for zero, unavailable, invalid or unmet counts. It scans characterized OP02 groups `00..05,08,09` and OP06 groups `01,02,08,09,0A,0C,0E,0F` consistently through CLI and interactive planners.
- `full` audits every declared II slot in those characterized profile families independently of counts, using normal RR bounds. It reports count mismatches; configured profile coverage is not universal wire-space completeness.
- `research` expands groups and RR bounds with multiple bounded discovery selectors. A failed first `II=00/RR=0000` probe does not veto later probes. It is non-exhaustive; an explicit `--request-budget` saves an incomplete artifact at exhaustion. Legacy aliases remain `aggressive` -> `full`, `exhaustive` -> `research`, and `conservative` -> `recommended`.
- Descriptions are acquired after scalar reads for every observed writable parameter in the selected scope by default. Explicit budgets reserve half for OP01 and half for OP07, borrow unused capacity, and rotate across group/instance queues. Any observed writable format is eligible, including unknown codecs whose description replies remain raw and unqualified. Artifacts report eligible, planned, attempted, received, interpreted, unavailable, unqualified and omitted coverage. Each matched record carries its scoped identity, opcode pair, codec, width, min, max, step, and raw reply.
- System Information acquisition uses one progress row. Both planners show readable count and context labels. A configured trace file suppresses the trace-file tip; ordinary arbitration retries remain in diagnostics without warning scrollback.
- Browser parent selections show navigation without aggregating descendant registers. Select a leaf to inspect its registers. HTML uses compact descriptions and access/visibility tags, and shows transport failures without duplicate exception text.
- Bundled descriptions remain prior observations. Compatible qualified live descriptions are compared by codec, width, min, max and step; missing optional identity data is marked partial rather than mismatched. Missing required remote identity remains unqualified. Known profile contradictions and actual description differences remain distinct from unavailable evidence. Sanitized baseline updates can be merged with `scripts/import_b524_descriptions.py ARTIFACT OUTPUT --merge` without erasing other observations.
- OP00 API version/revision and other count classes remain profile context. Ventilation hints can annotate known candidates; they do not establish a same-numbered GG route or prove absence.

Exact custom scans use `--preset custom --scan-plan plan.json`. The file is validated before device I/O, permits only OP02/OP06, and preserves explicit selectors regardless of discovery, adding mandatory OP02/GG02/II0A once when local circuits are selected. Plans exceeding 100000 scalar reads are rejected before queuing.

With planning or budget options, `--dry-run` executes the selected policy against the bundled fixture through DummyTransport. The default `--dry-run` invocation displays that fixture directly. The artifact records `dry_run_mode` as `deterministic_scan` or `fixture_view`.

```json
{
  "schema_version": 1,
  "groups": [
    {"opcode": "0x02", "group": "0x02", "instances": ["0x00", "0x03"], "registers": ["0x0002", "0x0010..0x0015"]}
  ]
}
```
- The browse edit confirmation validates every supported value format against that matched description. If no matched description is available, the UI warns that confirmation is unvalidated. Browse edits only alter the local artifact view; they never write to a live device.
- `HTI` uses three numeric bytes in `HH MM SS` order, with ranges `0..23`, `0..59`, `0..59`. Python decoding, offline edit encoding and HTML type overrides use this same contract. The separate `BTI` datatype in the [ebusd type registry](https://github.com/john30/ebusd/blob/68f6336bad89607a4200ca9e86f9cd7860b31f86/src/lib/ebus/datatype.cpp) uses BCD. Existing artifact values are retained; replay a raw trace or apply an explicit type override to recompute an older decoded time.

Output:
- JSON artifact: `b524_scan_0x??_<timestamp>.json`
- HTML report: `b524_scan_0x??_<timestamp>.html`
- Interactive terminals: after scan, the new fullscreen browse UI opens automatically (`q` to exit back to summary).

Replay an ENH/ENS trace (no live bus I/O) into a fresh schema-2.3 JSON artifact plus matching HTML:
```bash
python -m helianthus_vrc_explorer replay-trace /path/to/captured.trace --output-dir .
```

Replay limitations (v1):
- Only current `EnhancedTcpTransport` ENH/ENS trace format is supported.
- Reconstruction is deterministic and only for fields derivable from captured request/response bytes.
- Metadata requiring live probing (for example runtime identity enrichment) is not replayed.
- A replay artifact represents the first B524 destination in the trace. Exchanges for other destinations are excluded and counted in its limitations.

Browse a saved artifact in fullscreen Textual UI:
```bash
python -m helianthus_vrc_explorer browse --file b524_scan_0x15_<timestamp>.json
```

Enable safe write mode in browse UI:
```bash
python -m helianthus_vrc_explorer browse \
  --file b524_scan_0x15_<timestamp>.json \
  --allow-write
```

### Write Safety
By default the tool is **read-only**.

`scan` is always read-only.

`browse --allow-write` enables edit actions in the fullscreen UI, and requires per-write confirmation
(old value -> new value -> confirm).

In `browse --file` mode, edits do **not** write to the device (they only update the UI view). Live
device writes are planned.

## Features
- Session preface with regulator identity and transport endpoint.
- Phased scanner progress: Group Discovery, Instance Discovery, Register Scan.
- Bounded OP00 system-information discovery with raw response evidence and count-guided instance coverage.
- Targeted OP01/OP07 parameter descriptions for observed writable values, including offline range and step validation.
- Interactive planner (`textual` or classic) with presets and per-group overrides.
- Register decoding with raw payload retention and TT/metadata annotations in JSON.
- Auto-generated HTML report alongside JSON scan output.
- Fullscreen register browser with B524 operation-first sections:
  - OP00 ReadSystemInformation
  - OP02 GetParameter
  - OP03 ReadTimer
  - OP06 GetDeviceParameter
  - OP0B GetEventSetPoint
  - Legacy unqualified group-directory and constraint views, when present
- Tabbed register views: `Config`, `Config-Limits`, `State`.
- Watch/pin/rate controls and safe write workflow (`--allow-write` + confirmation).

## Data Enrichment Sources (Optional)
This tool can enrich raw scan output with human-readable names:
- **myVaillant map** (`--myvaillant-map-path`): a small curated CSV mapping `(GG,II,RR)` to myVaillant-style leaf names.
  - Default: packaged at `src/helianthus_vrc_explorer/data/myvaillant_register_map.csv`.
  - Opcode-aware namespace policy: `0x06` mappings must be explicit; generic opcode-less fallback rows are local `0x02` defaults only.
- **eBUSd CSV schema** (`--ebusd-csv-path`): adds register names from an eBUSd configuration CSV (e.g. `15.720.csv`).
  - Source: typically taken from an `ebusd-configuration` checkout (not bundled here).

## Scan UI Preview
<picture>
  <source srcset="artifacts/readme/preview.gif" type="image/gif">
  <img src="artifacts/readme/preview.png" alt="helianthus-vrc-explorer scan UI preview">
</picture>

Capture first 5 minutes of autorun, sped up 10x (300s -> 30s):

```bash
./scripts/capture_tui_preview.sh --capture-seconds 300 --speedup 10
```

## Planner UI Preview
<picture>
  <source srcset="artifacts/readme/planner.gif" type="image/gif">
  <img src="artifacts/readme/planner.png" alt="helianthus-vrc-explorer planner UI preview">
</picture>

```bash
./scripts/capture_planner_preview.sh
```

## Browse UI Preview
<picture>
  <source srcset="artifacts/readme/browse.gif" type="image/gif">
  <img src="artifacts/readme/browse.png" alt="helianthus-vrc-explorer browse UI preview">
</picture>

```bash
./scripts/capture_browse_preview.sh
```

Preview script options (all three capture scripts):
- `--output-seconds 45` override final animation duration.
- `--cols 132 --rows 40` tune terminal geometry.
- `--font-size 18` control render font size (pixels).
- `--poster-percent 40` choose which moment becomes `<name>.png`.
- `--command "python -m helianthus_vrc_explorer ..."` capture a different run.
- `--font-path "/path/to/Anonymous Pro.ttf"` force font selection.

Dependencies for preview generation:
- `asciinema`
- `agg`
- `expect`
- `Pillow` (available in project dev environment)

## Development
Requirements: Python 3.12+

```bash
python -m venv venv
source venv/bin/activate

pip install -e ".[dev]"
ruff check .
ruff format .
pytest
```

## Data files
If you need to add or update non-code data (schemas, fixtures, CSV/JSON dumps), keep it as data under `data/` so non-programmers can review and edit it via PRs.

## License
GPL-3.0-or-later. See `LICENSE`.

### Profile-scoped discovery and offline descriptions

- Characterized OP06 device headers use numeric-byte firmware triplets (`FWU`): raw `02 11 00` displays `02.17.00`; `FF FF FF` remains unavailable. Raw components qualify the firmware profile and do not establish SemVer. Generic legacy `FW` decoding remains available for older/unrelated artifacts.

- Local circuit scans always include `GG02/II0A` (`virtual_dhw` designation), independently of `circuit_count`. Acquisition does not confirm an active physical circuit; protocol role remains unknown.
- OP06 connected-device discovery begins at II01 in the characterized profile and is independent of OP00. Recommended stops at the first qualified not-connected Boolean; full/research audit the configured bound. Transport/decode unknowns and retained inventory remain separate.
- Bundled parameter descriptions are displayed offline in HTML and browse, with exact model/firmware, namespace and instance qualification. Rechecks report `matches`, `differs`, `unavailable`, or `profile_mismatch`. Bundled metadata never substitutes for current-target validation.
- Numeric descriptions retain decoded min/max/step. Date/time limits can be interpreted while STEP remains unknown; edits outside known ranges are rejected, and unknown stepping leaves edits incompletely validated. Unsupported formats retain raw description evidence.
- FLAGS provide profile-scoped visibility/writability hints. They establish no user/installer role, volatility, persistence or physical connected-device state. Old artifact labels remain historical, unqualified interpretations.

See the [public discovery and description contract](https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/b524-profile-discovery-and-descriptions.md).
