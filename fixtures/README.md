# Fixtures

This directory contains **scan artifact fixtures** used for deterministic, offline tests and for
`scan --dry-run` output.

## Format (Minimal, Stable)

A fixture is a JSON object with:

- `schema_version`: Artifact schema version. Current: `2.1`.
- `meta`: arbitrary metadata about the scan (timestamps, device info, etc.).
- `groups`: mapping of group id -> group data.

## Schema Compatibility Strategy

- Writers emit `schema_version: "2.1"` (namespace-aware contract).
- Readers support legacy artifacts by in-memory migration:
  - unversioned fixtures (no `schema_version`)
  - `schema_version: "2.0"`
- Migration preserves register counts and register payload entries; no registers are dropped or
  synthesized during migration.
- Checked-in fixtures in this repository are migrated to `2.1` in lockstep.

### `groups`

`groups` is an object keyed by **hex strings**:

- group key: `0xGG` (u8)
- instance key: `0xII` (u8)
- register key: `0xRRRR` (u16)

Each group entry contains:

- `descriptor_type` or `descriptor_observed` (number): Value returned by the B524 directory probe
  (`opcode=0x00`), encoded as float32 little-endian on the wire.
- `instances` (object, optional): Mapping of instance id -> instance data.
- `namespaces` (object, optional): Artifact v2 namespace mapping keyed by read opcode (`0x02`,
  `0x06`, etc.). When present, this is the source of register data even if `dual_namespace` is
  omitted.

Each instance entry contains:

- `registers` (object, optional): Mapping of register id -> register data.

Each register entry contains:

- `raw_hex` (string): Hex-encoded **value bytes only** for a register read response (no 4-byte echo
  header).
- `read_opcode` (string, optional): Explicit opcode for flat fixtures that should only answer one
  namespace/opcode. If omitted, DummyTransport falls back to the configured opcode set for that
  group.

### Example

```json
{
  "schema_version": "2.1",
  "meta": {},
  "groups": {
    "0x02": {
      "descriptor_type": 1.0,
      "dual_namespace": false,
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
```

## DummyTransport Behavior

- Directory probe (`00 <GG> 00`): returns `float32le(descriptor_type)` for known groups, otherwise
  `0.0`.
- Register read (`02/06 00 <GG> <II> <RR_LO> <RR_HI>`): returns `echo(4 bytes) + value_bytes`
  where `value_bytes = bytes.fromhex(raw_hex)`. If missing, `TransportTimeout` is raised.
- Flat legacy fixtures without `read_opcode` follow the configured group opcode(s). Single-opcode
  groups answer only that opcode; legacy dual-opcode groups answer both until the fixture is
  upgraded to `namespaces`.
