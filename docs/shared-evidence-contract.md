# Shared evidence contract for 0.7

This contract defines ownership and release requirements for the explorer
and [docs-ebus]. It is a 0.7 target, not a claim that the current fixtures
already satisfy parity. Identically named `/v1` files currently differ.

## Artifact kinds and sources of truth

- Scan artifacts belong to the explorer. Their `schema_version` is `2.x`
  (currently `2.3`); readers continue migration on read as described in the
  [fixture guide](../fixtures/README.md). This version space is independent
  of the native evidence schemas.
- The application baseline belongs to the explorer. Its integer version
  (currently `1`) is defined in
  `src/helianthus_vrc_explorer/schema/parameter_descriptions.py`.
  Application policy, including validation scope, lives here rather than
  in shared native evidence.
- Native evidence fixtures use the shared CC0 shape defined by docs-ebus
  under `protocols/vaillant/fixtures/`:
  `b524-basv0-description-profile-schema-v1.json` and
  `b524-basv0-register-observations-schema-v1.json`. The explorer exports
  to these schemas; docs-ebus publishes the evidence. The explorer's
  packaged copy must be byte-identical to the published docs copy, and
  both repositories must cite the same SHA-256 for each shared fixture.
- The AGPL validation-scope overlay belongs in the docs-ebus development
  tree at `development/fixtures/b524-basv0-validation-scope-v1.json`,
  keyed by native selector. The explorer baseline is its application-side
  source. This overlay is separate from the CC0 evidence; its presence
  interpretation is not reusable authority for another installation.

The docs-ebus reuse page
`development/ebus-vaillant-b524-basv0-profile-reuse.md` explains that
separation. Consumers must derive presence from their own current evidence
and recompute validation policy; a fixture or overlay does not admit edits.

## Versioning and parity

A backward-incompatible native-evidence shape change requires a schema
suffix bump, such as `/v1` to `/v2`, in both repositories together, with
matching versioned schema and fixture filenames. Additive fields that are
backward compatible stay `/v1`; update the docs-ebus schema first. Adding
a required field is not automatically backward compatible.

The explorer must never ship a `/v1` file that fails the docs-ebus validator
`scripts/validate_b524_basv0_description_profile.py`. Refresh digests in the
same coordinated change on both sides, and verify byte equality before
release. A matching filename or suffix alone does not establish parity.

The parity work must account for separate `api_version_raw` and
`api_revision_raw`, neutral `DATE_DMY_U8X3` and `TIME_HMS_U8X3` codec names,
the separate validation-scope overlay, and the observation fixture's
`native_headers` and `response_payloads` omission markers. This contract
does not itself change those fixtures or their exporters.

## Naming ownership

Explorer canonical names are intentional and remain the display names in
scan, replay, Browser and HTML. See
`b524_register_name_correspondence.py` in
`src/helianthus_vrc_explorer/schema/` for the existing correspondence.

Docs-ebus owns the D2 catalog names in
`protocols/vaillant/fixtures/b524-op02-register-names.csv` and their
`previous_name` migration annotations, under `architecture/naming.md`.
Carry those names and `previous_name` as labelled correspondence keyed by
the full native selector `(OP, GG, II, RR)`; they never replace explorer
names or merge identities across operations or instances.

Today `myvaillant_name` holds the explorer display name unless an observed
app name is recorded. Its label must state that provenance honestly; the
field name alone does not prove an observed application name.

## Evidence grades and publication

Use only the tri-state vocabulary:

- Proven: facts within retained bytes.
- Hypothesis: decoded values, derived widths, presence interpretations and
  candidate layouts.
- Unknown: unretained context.

Selector qualification (`selector_qualified`, `qualified`) is validator
vocabulary, not an evidence grade. Successful validation does not promote
a decoded value or candidate layout to Proven.

Publish families, not models. Do not publish raw captures, serial numbers,
network details, capture time or contributor identity. BASV0/BASV2 and
their SW/HW/API strings are allowed as controller identity strings, not as
evidence of broader support. Keep omitted context explicit; shared evidence
does not establish current values, installation topology or write safety.

## Release coupling

Explorer 0.7 ships with add-on 0.7 and gateway 0.7 in the same bill of
materials (BOM). Explorer parity issues #297 and #299–#303 and docs-ebus
#581 implement this contract; #298 defines it. This page does not close
those implementation or release gates.

[docs-ebus]: https://github.com/Project-Helianthus/helianthus-docs-ebus
