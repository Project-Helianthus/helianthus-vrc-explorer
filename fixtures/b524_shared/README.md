# Isolated shared B524 public evidence

This test-only subset supports #312 (Refs #299). It never participates in
Explorer's packaged catalogs, live acquisition, MCP or GraphQL projections.

Run `python3 scripts/check_shared_b524_fixtures.py` from the repository root.
Ordinary tests require only this checkout and the declared development
`jsonschema` dependency. Refresh explicitly with
`python3 scripts/check_shared_b524_fixtures.py --source-root /path/to/docs-ebus`.
The source is read-only; refresh stages and validates all required inputs before
copying them into this directory. Missing or inconsistent inputs fail closed.
A refresh validates evidence and does not admit any device operation.

Provenance is the public
[docs-ebus native contract](https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md).
Paths below are relative to that repository and mirrored here:

- [Description fixture](protocols/vaillant/fixtures/b524-basv0-description-profile-v1.json)
  and [schema](protocols/vaillant/fixtures/b524-basv0-description-profile-schema-v1.json):
  copied verbatim, CC0.
- [Observation fixture](protocols/vaillant/fixtures/b524-basv0-register-observations-v1.json)
  and [schema](protocols/vaillant/fixtures/b524-basv0-register-observations-schema-v1.json):
  copied verbatim, CC0.
- [Wire-column projection](protocols/vaillant/ebus-vaillant-B524-register-map.md):
  only selector headings and Wire columns from that public register map, CC0.
- [Calendar/clock projection](protocols/vaillant/fixtures/b524-op02-calendar-clock-selectors.csv):
  only opcode, group, instance, register, payload_bytes and name columns, CC0.
- [Semantic validator source](scripts/validate_b524_basv0_description_profile.py.txt):
  verbatim `scripts/validate_b524_basv0_description_profile.py`, AGPL-3.0.
  Its `.txt` suffix preserves upstream formatting as a test resource. The checker
  loads it explicitly and redirects its two data paths to the local projections.
  No application validation-scope overlay is imported or implicitly loaded.

[CC0 license](LICENSE-CC0) and [upstream AGPL license and notice](LICENSE-AGPL)
are retained separately with trailing whitespace normalized. This subset is
outside the Python package.

`manifest.json` carries the public profile page's two SHA-256 pins, encoded in
Base64. Digest input is each complete published fixture file, including UTF-8
formatting and final newline. Refresh verifies those page-cited pins against the
copied bytes; it never synthesizes missing description bytes. A checker cannot
authenticate a coordinated malicious rewrite of both fixtures and manifest.

Proven applies to retained description bytes; codec interpretation and presence
remain Hypothesis; omitted context remains Unknown. These grades are separate
from each record's codec qualification, codec basis and raw profile identity.
The identity strings describe the BASV0 observation, not model support. Omitted
native headers, response payloads and current values stay explicit `omitted`
markers. Missing descriptions stay JSON null; explicitly empty bytes are never
substituted for them. The semantic validator independently checks span decoding,
full selector joins, local profile identity and qualified codec consistency.
