# Changelog

## 0.6.0

- Correct B524 OP00 `ReadSystemInformation` discovery and use qualified circuit and zone counts in the recommended scan profile.
- Acquire scoped OP01 and OP07 descriptions for observed writable parameters and validate supported formats during offline browse edits.
- Preserve raw descriptions, incomplete scans and namespace-aware identities; keep semantic register names in `snake_case`.
- Provide deterministic `recommended`, `full`, `research` and exact `custom` scan policies with bounded request accounting and fair description budgets.
- Release Enhanced transport ownership after a rejected response and preserve first description attempts before spending capacity on retries.
- Correct `HTI` parsing, offline encoding and HTML type overrides to use numeric `HH MM SS` bytes.

Artifacts remain schema 2.3. Older artifacts are readable, and their stored values are retained. Replay raw traces or apply explicit type overrides to recompute times decoded by earlier versions. Offline edits do not write to devices. Profile coverage is bounded and does not establish exhaustive wire-space discovery or live-write qualification.
