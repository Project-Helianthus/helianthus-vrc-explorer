# Fixtures

This directory contains **scan artifact fixtures** used for deterministic, offline tests and for
`scan --dry-run` output.

## Format (Minimal, Stable)

A fixture is a JSON object with:

- `schema_version`: Artifact schema version. Current writer: `2.4`.
- `meta`: arbitrary metadata about the scan (timestamps, device info, etc.).
- `operations`: mapping of opcode -> operation data (operations-first structure).

## Schema Compatibility Strategy

- Writers emit `schema_version: "2.4"` (operations-first contract, neutral codecs and independent raw API identity).
- Readers support legacy artifacts by in-memory migration:
  - unversioned fixtures (no `schema_version`)
  - `schema_version: "2.0"`
  - `schema_version: "2.1"`
  - `schema_version: "2.2"` (groups-first, with optional `dual_namespace`/`namespaces`)
  - `schema_version: "2.3"` (operations-first, legacy codec vocabulary)
- Migration preserves register counts and register payload entries; no registers are dropped or
  synthesized during migration.
- Checked-in fixtures remain historical input; #299 owns the native fixture refresh.
  Readers migrate copies to `2.4` without rewriting source files.

### `operations`

`operations` is an object keyed by **opcode hex strings** (`0x02`, `0x06`, `0x01`, etc.).

Each operation entry contains:

- `groups` (object): Mapping of group key (`0xGG`) -> group data.

Each group entry contains:

- `descriptor_observed` (number): Value returned by the B524 directory probe
  (`opcode=0x00`), encoded as float32 little-endian on the wire.
- `instances` (object, optional): Mapping of instance key (`0xII`) -> instance data.

Each instance entry contains:

- `registers` (object, optional): Mapping of register key (`0xRRRR`) -> register data.

Each register entry contains:

- `raw_hex` (string): Hex-encoded **value bytes only** for a register read response (no 4-byte echo
  header).
- `read_opcode` (string, optional): Explicit opcode carried on the entry for provenance tracking.

### Example

```json
{
  "schema_version": "2.4",
  "meta": {},
  "operations": {
    "0x02": {
      "groups": {
        "0x02": {
          "descriptor_observed": 1.0,
          "instances": {
            "0x00": {
              "registers": {
                "0x000f": { "raw_hex": "3412" }
              }
            }
          }
        }
      }
    }
  }
}
```

## DummyTransport Behavior

- Directory probe (`00 <GG> 00`): returns `float32le(descriptor_observed)` for known groups,
  otherwise `0.0`.
- Register read (`02/06 00 <GG> <II> <RR_LO> <RR_HI>`): returns `echo(4 bytes) + value_bytes`
  where `value_bytes = bytes.fromhex(raw_hex)`. If missing, `TransportTimeout` is raised.
- Operations-first fixtures are read directly by opcode key. Legacy fixtures are auto-migrated
  to operations-first during load.

## Synthetic offline acceptance evidence

`offline_acceptance_evidence.json` is deliberately synthetic. It combines only sanitized values and
entry shapes already present in this repository's fixtures and tests; it is not a device capture and
does not establish a protocol or hardware fact.

It contains separate `0x02` and `0x06` operation paths, retained active raw payloads, explicit
`empty_reply` and `nack` response states, and incomplete metadata with the existing
`user_interrupt` reason. It also carries the sanitized unknown group `0x69` under operation
`0x06`, with an explicit `issue_suggestion.unknown_groups` provenance entry. Run
`python scripts/check_offline_acceptance_evidence.py` to verify those paths and fields in the
original fixture before it migrates a deep copy for compatibility and register-count preservation.
The checker rejects field removal, operation collapse, response-state changes, loss of incomplete
metadata, and loss of unknown-group identity or provenance.

## Sanitized BASV0 metadata evidence

`b524-basv0-description-profile-v1.json` retains all 2,093 observed Describe
candidates for the exact BASV0/SW0217/HW8803/API1 context. Raw descriptions and
missing limits remain explicit. Only codecs backed by a public exact-selector
schema or local constraint codec are qualified; length-based interpretations
remain raw evidence.

`b524-basv0-register-observations-v1.json` retains all 6,585 scalar selector
observations as names, access FLAGS, response class, payload width, presence
state, and an optional reference to the description catalog. Current values and
raw value payloads are intentionally omitted. In particular, an echoed payload
with FLAGS `00` stays distinct from a status-only `00` response.

## 2.4 interpretations and native export boundary

Version `2.4` keeps the operations-first structure and changes the output codec
vocabulary and API identity representation. For established Explorer provenance
only, scans through `2.3` and known application-baseline `1` inputs use this
migration-on-read mapping:

| Legacy label | Effective plain-byte interpretation |
| --- | --- |
| `HDA:3` | `DATE_DMY_U8X3` (`DD MM YY`, 2000–2099) |
| `HTI` | `TIME_HMS_U8X3` (`HH MM SS`) |

External packed-BCD labels remain distinct. Adapters copy input, retain original
labels/source versions as application provenance, and leave raw bytes and stored
values intact. Opening a file never rewrites it; exporting migrated meanings
requires `--allow-legacy-interpretation`. API version and revision are observed
independently as `api_version_raw` and `api_revision_raw`; an `API1` display label
cannot reconstruct missing identity.

The three version domains are scan string `2.4`, application-baseline integer `2`
(readers accept `1`/`2`), and native evidence `/v1`. Export with
`scripts/export_b524_evidence.py` from the retained sanitized source pair and
independent identity manifest. Its output matches the docs native schemas:
CC0 descriptions have neutral codecs and no `validation_scope`; register
observations explicitly mark `current_values`, `native_headers` and
`response_payloads` as `omitted`. A separate application overlay has exactly one
row per description selector `(operation, group, instance, register)`, with no
orphans or duplicates. It is application policy, not CC0 evidence or reusable
presence authority. Consumers recompute current applicability.

Calendar/clock candidates remain display-only, with unknown STEP; candidate
bounds do not reject syntactically valid edits. Evidence grades remain separate:
retained byte structure is **Proven**, codec/range and derived width/presence
interpretations are **Hypothesis**, and missing context/STEP is **Unknown**.
Publish family-level observations; BASV0/BASV2 identity strings do not establish
support for every model in a family.

The #297 exporter pins byte parity with docs-ebus. The optional
`DOCS_EBUS_ROOT` test gate invokes that checkout's validator and schemas without
vendoring them. The checked-in public and packaged native JSON files remain
unchanged here; regenerate both pairs and distribute the application overlay in
#299, including its licensing and package location.
