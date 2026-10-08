# Changelog

## 0.6.0

- Correct B524 OP00 `ReadSystemInformation` discovery: circuit and zone fields are supported capacities, while configured instances require independent presence evidence.
- Acquire scoped OP01 and OP07 descriptions for observed writable parameters and validate supported formats during offline browse edits.
- Preserve raw descriptions, incomplete scans and namespace-aware identities; keep semantic register names in `snake_case`.
- Provide deterministic `recommended`, `full`, `research` and exact `custom` scan policies with bounded request accounting and fair description budgets.
- Release Enhanced transport ownership after a rejected response and preserve first description attempts before spending capacity on retries.
- Include local virtual-DHW selector II09 independently of circuit capacity, and discover additional OP06 device classes from II01.
- Bundle profile/firmware/instance-scoped description baselines for offline HTML and browse, with matching/differing/unavailable rechecks.
- Plan all eligible OP01/OP07 descriptions in full/research profiles, retaining explicit budget and qualification coverage.
- Keep date/time STEP opaque when its encoding is unknown; correct legacy FLAGS role/persistence interpretations.
- Correct `HTI` parsing, offline encoding and HTML type overrides to use numeric `HH MM SS` bytes.
- Decode characterized OP06 remote-header firmware as numeric byte components (`FWU`), preserving the generic legacy `FW` codec.

Artifacts remain schema 2.3. Older artifacts are readable, and their stored values are retained. Replay raw traces or apply explicit type overrides to recompute times decoded by earlier versions. Offline edits do not write to devices. Profile coverage is bounded and does not establish exhaustive wire-space discovery or live-write qualification.
