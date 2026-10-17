# Reading evidence grades in Explorer

A decoded description is an interpretation of evidence, not proof of a current
value or permission to write. This guide applies the published
[native field crosswalk][crosswalk] to Explorer's existing descriptions, limits,
widths and missing context. It follows the [shared evidence contract](shared-evidence-contract.md).
Current Browser and HTML displays may not yet expose all grade labels; this page
adds no UI behavior, stored fields or artifact changes. The remaining grade UI
work in [#302](https://github.com/Project-Helianthus/helianthus-vrc-explorer/issues/302)
stays open.

## Entry-level contract (required follow-up behavior)

`evidence_grade` belongs to an individual evidence entry and grades the claim
that entry makes. Its only allowed explicit values are the case-sensitive strings
`Proven`, `Hypothesis` and `Unknown`. A file, controller, scan or mixed record
must not acquire a blanket `Proven` label. If an entry contains retained bytes
and a decoded interpretation, identify the graded claim: proof of the retained
structure does not grade its codec, decoded value or presence interpretation.
Keep those claims distinguishable as the [native crosswalk][crosswalk] requires.

This section specifies a contract, not a new stored field in existing artifacts.
The [shared evidence contract][shared] governs coordinated native schema changes;
this page neither changes a schema nor makes a field required in legacy files.

| Field or context | Required interpretation | Independence and absence |
| --- | --- | --- |
| Entry `evidence_grade` | `Proven`: facts within retained bytes; `Hypothesis`: supported interpretation; `Unknown`: missing supporting context. | An absent grade is unspecified, not implicit `Proven` or `Hypothesis`. A consumer may explain it as Unknown to the reader, but must preserve the distinction between absence and explicit `Unknown` on export. Invalid values must not be silently promoted or normalized into evidence. |
| `acquisition_state` | What happened while acquiring the entry's evidence. | Success, failure or no attempt does not assign a grade. Missing state does not establish that a read was attempted. |
| `response_state` | The retained reply outcome, including payload, status-only or error distinctions. | A reply-shaped value is not codec proof; an error does not erase prior bytes. Missing response context stays missing. |
| `selector_qualified`, `qualified` | Selector/codec validation acceptance. | Qualification neither sets nor upgrades `evidence_grade`; a grade never supplies missing qualification. |
| Profile identity and match | Applicability of separately retained native profile evidence to a target. | Observing a profile identity is not a profile match, codec qualification or native admission. No match or missing identity may be repaired by a grade. |
| Application `validation_scope` and admission | Application policy, separate from native evidence. | Neither grade nor export interpretation grants presence, edit permission or write safety. Existing fail-closed admission remains in force. |

### Synthetic examples and transitions

These examples describe claims for a synthetic BASV0-family entry; they are not
captures, new selector mappings or runtime acceptance results. “Same” means the
other stated dimensions are held fixed, not that the claims are interchangeable.

| Comparison | Claim A | Claim B | Required conclusion |
| --- | --- | --- | --- |
| Same qualification, different grade | Retained equal-width description spans: `Proven`. | Decoded limit using those spans: `Hypothesis`. Both use the same selector-qualified candidate context. | Codec qualification cannot promote the decoded claim to Proven. |
| Same grade, different acquisition | Prior decoded-limit claim: `Hypothesis`; its acquisition completed. | The same retained prior claim: `Hypothesis`; a later recheck failed with `transport_error`. | Preserve the prior claim and record the failed attempt separately; failure supplies no fresh current value. |
| Absent versus explicit grade | Legacy entry with no `evidence_grade`. | Entry explicitly graded `Unknown` because supporting context is missing. | Both lack proof, but the exported provenance must retain which grade was actually supplied. |

| Event | Grade handling | Other evidence handling |
| --- | --- | --- |
| Codec becomes qualified or a profile matches | No automatic grade transition. | Update qualification or match only from its own evidence. |
| Recheck is unattempted, unavailable or fails | Do not overwrite the prior claim's grade with a guessed result. | Preserve partial last-known-good evidence and distinguish the new attempt. |
| New observation differs from the baseline | Grade each claim on its own retained support. | Retain both observations; do not silently replace the baseline. |
| Previously omitted context becomes available | Reassess only claims supported by the added evidence. | Retain provenance; no blanket promotion of the containing record. |

## Export interpretation contract (pending implementation)

Exporters must distinguish the following interpretation vocabulary without
replacing native acquisition or response states. These are required meanings for
the follow-up exporter, not a claim that today's exporter emits these labels or
that they are new wire response codes. They are independent of `evidence_grade`
and need not be mutually exclusive: a legacy-incomplete entry can also retain a
transport error. Do not guess a single successful state to hide either fact.

| Interpretation | Required supporting evidence | Must not imply |
| --- | --- | --- |
| `transport_error` | A retained attempted operation failed at transport level; keep the original error and available partial evidence. | A register value, device absence, unsupported selector or loss of prior evidence. Missing response bytes alone do not establish a transport error. |
| `unattempted` | Explicit evidence that the operation was not attempted. | A failed read, successful empty reply or absence. Missing legacy attempt information alone is insufficient. |
| `profile_observed` | Controller/profile identity was observed, with its retained provenance and omissions. | A qualified native description profile, matched baseline, supported codec or admitted target. Observations must not manufacture a native profile. |
| `legacy_incomplete` | Legacy material lacks context required to interpret the entry, such as request, attempt or response evidence. Keep omissions explicit. | Reconstructed native bytes, an inferred successful acquisition or an implicit Proven grade. Retain any independently supported facts. |

### Sanitized observation export and remaining work

The pending `export_controller_observations.py` work is tracked by #316/K29.
It must export sanitized observations with entry-level claim provenance, explicit
omissions and the distinctions above. Preserve namespace-aware native selector
identity, including operation, group, instance and register; never merge entries
across those fields. Keep retained native evidence separate from application
policy and observation-derived interpretation. A sanitized observation export
cannot reconstruct omitted native requests, headers, payloads or current values,
and cannot become a native description profile merely by renaming its fields.

Publish controller families, never models, private captures, serial numbers,
network details, capture times or contributor identities. Preserve useful partial
and prior observations when an acquisition fails. Sanitization must not fill
missing context with guessed bytes, defaults or a successful state.

The existing `scripts/export_b524_evidence.py` handles retained sanitized source
evidence and a separate application overlay; its existence does not establish
the pending controller-observation behavior. This page is only the docs portion
of FU23. Exporter alignment remains #316/K29 and viewer work remains #315/K28;
#302 and #303 retain their remaining acceptance. No runtime, transport, MCP envelope, GraphQL
parity, hardware or release success follows from this documentation. No Pi hold
is needed for this documentation slice. Nothing here declares a stable contract
before Helianthus 1.0 or introduces an authorization gate before 0.9.

## Read four separate things

| Question | How to read the result |
| --- | --- |
| What does the evidence support? | **Proven** covers facts within retained bytes; **Hypothesis** covers supported interpretations; **Unknown** covers missing context. The crosswalk leaves some field classes, such as identity metadata and raw access flags, without a specified grade: do not invent one. |
| Is the codec accepted? | `selector_qualified` and `qualified` describe validation acceptance, not an evidence grade. A qualified decoded limit can still rely on a Hypothesis codec basis. Width alone does not qualify a codec. |
| Does the profile match? | Explorer matches the profile identifier, EID, raw software and hardware fields, and decoded numeric `api_version` and `api_revision` for local reuse. It does not compare raw API bytes. Remote slots need their own identity qualification. A match cannot supply missing evidence, prove a codec or grant native admission or write authority. |
| What happened during acquisition? | Retained `acquisition_state`, `response_state` and observed read widths describe derived session outcomes (**Hypothesis**). A retained unqualified description is raw evidence, not necessarily a failed read. It grants no codec or range. |

These distinctions come from the [crosswalk][crosswalk] and
[profile reuse contract][reuse]. Native CC0 evidence and AGPL application
validation policy remain separate. An overlay's `validation_scope` is policy,
not a native grade or reusable installation-presence authority.

## Examples: structure, interpretation and missing context

- **Proven retained structure:** a description echoes GG/RR and contains
  equal-width MIN/MAX/STEP spans. For the BASV0 local DHW bivalence description,
  the maximum span is the byte sequence `00 00 A0 41`. These bytes prove structure, not a codec,
  instance, installed equipment or write permission.
- **Hypothesis decoded interpretation:** reading that maximum span with its
  selector-qualified EXP codec yields 20. Qualification does not promote the
  decoded limit to Proven, and the limit cannot be substituted across profiles.
  Public local-constraint and exact-selector-schema codec bases are Hypothesis;
  a payload-length-inferred basis is Unknown and remains unqualified.
- **Unknown missing context:** omitted request bytes, native headers, response
  payloads and current values cannot be reconstructed from the sanitized
  fixtures. GG/RR are supported by retained description bytes, but the request
  opcode/instance association is Hypothesis: II is not echoed. Missing limits
  remain null, not zero or a guessed default.

See the native profile's [description format][format], [codec bases][basis]
and [observed local bound][bound]. Calendar/clock `DATE_DMY_U8X3` and
`TIME_HMS_U8X3` layouts and decoded limits are Hypothesis; STEP is Unknown.
They are plain-byte candidates, not packed-BCD codecs, and qualification does
not grant range-and-step validation from this fixture.

## Width, presence and response state

For BASV0 ventilation `OP02/GG09/II00..II0A/RR0001`, two-byte description spans
are **Proven** within the retained bytes. The two-byte read width and UIN codec
basis are **Hypothesis**, since native response payloads were not retained.
A one-byte UCH interpretation is rejected for this profile. Ventilation presence
remains **Unknown**: a decoded zero establishes neither absence nor positive
presence. Empty-looking zero system metadata likewise establishes neither a
numeric parameter nor a text codec. See [retained uncertainty][uncertainty]
and the [existing Explorer metadata guide](basv0-metadata.md).

FLAGS `00` accompanying an echoed payload must not be confused with a
status-only `00`. Preserve echoed payload, status-only reply and transport error
as separate outcomes. A short/status-only reply is not a register value, and a
value-shaped reply still needs a qualified codec. Raw access flags have no
specified grade in the crosswalk; their writable-capability interpretation is
family-specific inference, not proof of write acceptance. Retained response
state is Hypothesis. See the native [response header][flags] and
[response states][responses].

## Using prior evidence safely

Use current evidence to determine presence and recompute application validation
policy. Unknown or inactive qualified records are display-only; even
`format_range_and_step` never admits an edit by itself. A profile match is not a
current read or successful recheck. On an unavailable recheck, keep the baseline
as prior evidence; on a differing recheck, keep both observations. A mismatched
baseline cannot verify the current target. See [reuse scope][scope] and
[baseline rechecking][baseline]. None of these grades authorizes a write.

[crosswalk]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/development/b524-evidence-grade-crosswalk.md
[shared]: https://github.com/Project-Helianthus/helianthus-vrc-explorer/blob/main/docs/shared-evidence-contract.md
[reuse]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/development/ebus-vaillant-b524-basv0-profile-reuse.md
[format]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md#native-description-format
[basis]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md#basis-of-the-codec-labels
[bound]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md#observed-local-bound
[uncertainty]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md#explicitly-retained-uncertainty
[flags]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-B524.md#22-common-read-response-header-0x02--0x06
[responses]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-B524.md#23-register-response-states
[scope]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/development/ebus-vaillant-b524-basv0-profile-reuse.md#validation_scope-and-presence
[baseline]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/development/ebus-vaillant-b524-explorer-discovery.md#bundled-metadata-and-rechecking
