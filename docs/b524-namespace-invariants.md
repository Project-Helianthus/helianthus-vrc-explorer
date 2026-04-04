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

3. Constraint scope is explicitly `gg_rr_invariant`.
   - Decision: `gg_rr_invariant`.
   - Rationale: `0x01` probe frame shape is `01 GG RR` and does not encode register-read opcode or instance.
   - Outcome: static constraints are GG/RR-scoped across register-read namespaces.

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
