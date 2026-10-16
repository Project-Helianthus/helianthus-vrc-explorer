# Reading evidence grades in Explorer

A decoded description is an interpretation of evidence, not proof of a current
value or permission to write. This guide applies the published
[native field crosswalk][crosswalk] to Explorer's existing descriptions, limits,
widths and missing context. It follows the [shared evidence contract](shared-evidence-contract.md).
Current Browser and HTML displays may not yet expose all grade labels; this page
adds no UI behavior, stored fields or artifact changes. The remaining grade UI
work in [#302](https://github.com/Project-Helianthus/helianthus-vrc-explorer/issues/302)
stays open.

## Read four separate things

| Question | How to read the result |
| --- | --- |
| What does the evidence support? | **Proven** covers facts within retained bytes; **Hypothesis** covers supported interpretations; **Unknown** covers missing context. The crosswalk leaves some field classes, such as identity metadata and raw access flags, without a specified grade: do not invent one. |
| Is the codec accepted? | `selector_qualified` and `qualified` describe validation acceptance, not an evidence grade. A qualified decoded limit can still rely on a Hypothesis codec basis. Width alone does not qualify a codec. |
| Does the profile match? | EID, software raw, hardware raw, API version raw and API revision raw must all match for local reuse. Remote slots need their own identity qualification. A match cannot supply missing evidence, prove a codec or grant native admission or write authority. |
| What happened during acquisition? | Retained `acquisition_state`, `response_state` and observed read widths describe derived session outcomes (**Hypothesis**). A retained unqualified description is raw evidence, not necessarily a failed read. It grants no codec or range. |

These distinctions come from the [crosswalk][crosswalk] and
[profile reuse contract][reuse]. Native CC0 evidence and AGPL application
validation policy remain separate. An overlay's `validation_scope` is policy,
not a native grade or reusable installation-presence authority.

## Examples: structure, interpretation and missing context

- **Proven retained structure:** a description echoes GG/RR and contains
  equal-width MIN/MAX/STEP spans. For the BASV0 local DHW bivalence description,
  the maximum span is `0000A041`. These bytes prove structure, not a codec,
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
[reuse]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/development/ebus-vaillant-b524-basv0-profile-reuse.md
[format]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md#native-description-format
[basis]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md#basis-of-the-codec-labels
[bound]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md#observed-local-bound
[uncertainty]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md#explicitly-retained-uncertainty
[flags]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-B524.md#22-common-read-response-header-0x02--0x06
[responses]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-B524.md#23-register-response-states
[scope]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/development/ebus-vaillant-b524-basv0-profile-reuse.md#validation_scope-and-presence
[baseline]: https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/development/ebus-vaillant-b524-explorer-discovery.md#bundled-metadata-and-rechecking
