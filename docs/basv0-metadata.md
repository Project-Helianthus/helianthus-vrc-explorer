# BASV0 metadata in VRC Explorer 0.6.2

VRC Explorer recognises the exact local description profile identified by EID
`BASV0`, software field `0217`, hardware field `8803`, API version 1 and API
revision 1. The identity selects prior read-only metadata. It does not identify
an installation, assign zone or circuit indexes, or prove an attached remote
device.

The packaged baseline contains 34 reusable local descriptions for this profile:
21 numeric rows with complete min/max/step validation and 13 date/time rows whose
raw STEP meaning remains unknown. A codec is reusable only when it is supported
by a public exact native selector schema or by the public local constraint codec.
A matching datatype from the BASV2 catalog is not sufficient. The BASV0 DHW
bivalence description therefore keeps its observed maximum of 20 independently
of the BASV2 maximum of 50.

Scalar reads record `codec_provenance` as either `selector_qualified` or
`length_inferred`. A length-inferred codec may decode a value for display, but
its Describe response remains unqualified raw evidence. It cannot supply edit
limits or enter a reusable profile. Imported artifacts without provenance need
same-profile selector support before their descriptions become effective.

For local ventilation group `09`, the exact BASV0 profile reads RR `0001` as the
observed two-byte `UIN` shape. A decoded zero retains unknown availability. It
does not become `present=false` installation evidence, and it does not become a
positive presence signal. Status-only absence and transport/decode errors remain
separate states.

Two paired fixtures preserve the source evidence without publishing current
register values:

- `fixtures/b524-basv0-description-profile-v1.json` contains all 2,093 Describe
  candidates, raw replies, access FLAGS, nullable limits, codec basis and
  qualification.
- `fixtures/b524-basv0-register-observations-v1.json` contains all 6,585 native
  scalar selectors, names or explicit `null`, access FLAGS, response class,
  payload width, presence state and an optional reference to the description
  record.

The scalar fixture distinguishes 5,335 echoed payloads, including FLAGS `00`,
from 1,155 status-only replies and 95 transport failures. It contains no current
scalar values, raw value payloads, endpoint, serial, contributor identity,
acquisition timestamp, or installation topology claim.

HTML reports reserve “Description mismatch” for differing descriptions compared
within a compatible profile. Cached descriptions belonging to a different or
unqualified profile are omitted from the compact value display; their qualification
remains in the artifact and they cannot supply validated editing limits.
