# B524 Namespace Invariants

This document is the implementation-facing contract for B524 namespace behavior.
User-facing guidance in `README.md` should reference this document and only describe
behavior that is already stable in code/tests.

## Scope

- Applies to scanner planning/discovery, artifact schema, browse/report identity, and fixture migration.
- Covers register families (`0x02`, `0x06`) and the `0x01` constraint probe scope decision.
- Uses `opcode` as canonical namespace identity; labels like `local`/`remote` are display metadata.

## Invariants

1. Opcode-first identity is mandatory.
   - Namespace key: `<opcode>` (for example `0x02`, `0x06`).
   - Canonical register identity tuple: `(opcode, group, instance, register)`.
   - Any GG-first fallback that can merge/opacify namespaces is invalid.

2. Discovery is advisory, not semantic authority.
   - GG directory probe (`opcode 0x00`) results are evidence for discovery flow only.
   - Semantic identity, namespace topology, and row identity are not derived from descriptor values.
   - **Ban:** GG discovery MUST NOT be used as semantic authority.

3. Constraint scope is explicitly `opcode_0x02_default`.
   - Decision: `opcode_0x02_default`.
   - Rationale: the bundled static catalog is seeded from `0x01` probe evidence, but it is only trusted for opcode `0x02` by default.
   - Outcome: remote opcode `0x06` does not inherit seeded static constraints unless a constraint entry explicitly scopes into that namespace or a live probe confirms it.

4. Artifact identity keys are namespace-aware.
   - Persisted topology authority: `groups[*].dual_namespace` plus `groups[*].namespaces` (when present).
   - UI/report dedupe key contract: `<group>:<namespace>:<instance>:<register>`.
   - Path contract: `B524/<group-name>/<namespace-display>/<instance>/<register-name>`.

5. Fixture compatibility is migration-based, not semantic rewrite.
   - Current artifact schema: `2.1`.
   - Legacy unversioned/`2.0` fixtures are migrated in-memory with register-count preservation.
   - Migration may normalize container shape, but must not drop register entries or collapse namespace identity.
   - Legacy mixed-opcode single-group artifacts are rendered split-by-namespace in browse/report consumers.

## Historical Context

Issues #120 and #125 remain useful exploratory context (how we reached the namespace split), but they are not active semantic authority. The active authority is:

- current code behavior in this repository,
- tests/fixtures that validate it,
- and this invariants contract.

When historical notes conflict with current contract, follow current contract and open a corrective docs issue/PR.

## Protocol Notes Implemented In Explorer

These notes are scanner/register-map behaviors implemented in this repository only.
They are observational and do not replace the opcode-first identity contract above.

1. OP `0x06` generic device-header registers (`RR=0x0001..0x0004`) are mapped experimentally.
   - Generic rows are provided for `device_connected`, `device_class_address`, `device_error_code`, and `device_firmware_version`.
   - Group-specific rows (for example GG `0x09`/`0x0A` radio fields) remain authoritative when present; wildcard header rows are fallback only.

2. GG `0x09` is dual-use by opcode namespace.
   - OP `0x02`: local control/write-path style registers (for example quick-mode related control path).
   - OP `0x06`: remote radio-device inventory/status registers.
   - GG identity must never be merged across opcodes.

3. Empty ACK/0-byte replies are treated as `dormant` in scanner artifacts.
   - Meaning: register exists but feature is currently inactive (not an absent-register NACK/timeout class).
   - This status is rendered distinctly from `absent` in explorer UI/report consumers.

4. Sentinel `0x7FFFFFFF` is annotated when decoded as integer payload.
   - Artifact entries expose `value_display="sentinel_invalid_i32 (0x7FFFFFFF)"` for this case.
   - This is scanner-layer annotation only; semantic/runtime policy outside explorer belongs to gateway/poller repos.
