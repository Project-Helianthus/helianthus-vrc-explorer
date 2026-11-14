# BASV2 observations in VRC Explorer

[Shared evidence contract for 0.7](shared-evidence-contract.md)

`fixtures/b524-basv2-observation-inventory-v1.json` publishes the selector
inventory and decoded description observations that VRC Explorer already holds
for the BASV2 controller in the VRC720 family. It is implementation evidence
toward [docs-ebus#574], not a description profile.

## Identity

The bundled description baseline records these controller identity strings for
the observations: EID `BASV2`, software field `0507`, hardware field `1704`,
API version 1 and API revision 1. They are evidence identifiers only. The
inventory itself carries the family (`VRC720`) and nothing narrower: no model,
no serial, no bus address, no capture time and no contributor.

## What the inventory is

It is the output of `scripts/export_controller_observations.py` over an
operations-first artifact assembled from committed data only; no scan was run.
The artifact combines two sources by exact selector `(opcode, group, instance,
register)`:

- the BASV2 rows of the bundled description baseline
  (`src/helianthus_vrc_explorer/data/b524_parameter_descriptions.json`), which
  supply codec, bounds, step and width;
- the sanitized BASV2 Full-scan selector inventory in `tests/fixtures/`, which
  adds OP06 presence, class and firmware selectors of the remote groups and the
  OP02 circuit and zone presence probes, with their response states.

Selectors present in both keep the baseline's decoded fields. The result holds
1,570 observations: 1,227 OP02 and 343 OP06 selectors. Response states come only
from the selector inventory; the baseline retains no read reply, so its other
selectors stay `unknown`. `tests/test_basv2_observation_inventory.py` rebuilds
the artifact and requires the published file to equal the exporter's output
byte for byte.

## Evidence grades

- Every observation and every decoded description is **Hypothesis**: codecs,
  bounds and widths are decoded values, not retained bytes.
- Every raw description is **Unknown** (`raw_description: "unknown"`). The
  repository retains no BASV2 description reply, so nothing can be graded
  Proven.
- Date and time bounds are format text in the baseline and are exported as
  `unknown`. Current values, reply bytes and status flags are omitted.

The decoded DHW bivalence observation at `OP02/GG00/II00/RR0001` (EXP, -20..50,
step 1) stays an unqualified Hypothesis. It supplies no bound for any other
identity and is unrelated to the BASV0 bound in [BASV0 metadata](basv0-metadata.md).

## What the inventory is not

- Not a native description profile. Unlike BASV0, no BASV2 raw description
  with request provenance is retained. A native profile still needs sanitized
  raw descriptions with their request provenance; a match with an explorer
  profile cannot stand in for missing bytes.
- Not native profile input (`native_profile_input: false`) and not write-bound
  evidence (`write_bound_evidence: false`); decoded limits cannot authorize
  edits.
- Not qualification (`qualification: "unknown"`). Source qualifiers are copied
  as claims, never promoted.
- Not a statement about other VRC720 controllers, other firmware, installation
  topology or which instances exist elsewhere.

Registry and gateway admission of BASV2 is separate work.

[docs-ebus#574]: https://github.com/Project-Helianthus/helianthus-docs-ebus/issues/574
