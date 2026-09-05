# Fixtures

This directory contains **scan artifact fixtures** used for deterministic, offline tests and for
`scan --dry-run` output.

## Format (Minimal, Stable)

A fixture is a JSON object with:

- `schema_version`: Artifact schema version. Current: `2.3`.
- `meta`: arbitrary metadata about the scan (timestamps, device info, etc.).
- `operations`: mapping of opcode -> operation data (operations-first structure).

## Schema Compatibility Strategy

- Writers emit `schema_version: "2.3"` (operations-first contract).
- Readers support legacy artifacts by in-memory migration:
  - unversioned fixtures (no `schema_version`)
  - `schema_version: "2.0"`
  - `schema_version: "2.1"`
  - `schema_version: "2.2"` (groups-first, with optional `dual_namespace`/`namespaces`)
- Migration preserves register counts and register payload entries; no registers are dropped or
  synthesized during migration.
- Checked-in fixtures in this repository are migrated to `2.3` in lockstep.

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
  "schema_version": "2.3",
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
`user_interrupt` reason. Run `python scripts/check_offline_acceptance_evidence.py` to verify those
paths and fields. The checker rejects field removal, operation collapse, response-state changes, and
loss of incomplete metadata.
