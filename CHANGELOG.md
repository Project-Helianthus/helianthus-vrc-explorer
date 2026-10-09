# Changelog

## 0.6.0

- Add live scalar Config editing in Browser, including the Browser opened after scan: refresh native identity, profile, access and baseline; validate qualified limits; confirm the concrete target and old/new value; send once and report success only on matching readback. Uncertain outcomes offer read-only recheck instead of automatic write retransmission.
- Keep offline JSON edits separate from device writes. Decode ENUM values and offer labelled dropdowns with qualified disabled-choice reasons.
- Move scan and browse configuration into the visual UI. Select an optional preset in the startup modal, keep adapter arguments scriptable, and remove public plan and global budget arguments.
- Reuse exact native-profile descriptions without implicit Describe on known recommended profiles. Qualify remote class/firmware separately; request descriptions only for writable parameters under explicit planner override, acquisition presets or unknown profiles. Keep missing descriptions explicit.
- Add automatic Event/EventSetPoint exploration for discovered topology, conditional paired SetPoint reads, planner navigation and shared progress. Preserve raw evidence and experimental schema status. Technical OP03/08/09/0B reads remain scriptable.
- Add timer and paired Event offline edit plans, payload diffs and export. Qualified OP04 execution checks identity and baseline, sends once and reads back; native OP0A/0C execution remains unavailable pending qualification.
- Classify 39 exact regulator EID/software-PIN pairs, including CTLX0/raw SW0127/HW0404 as VRC720. Preserve raw identity and unknown pairs; model identification does not transfer another profile's limits.
- Separate OP02 controller registers from OP06 device slots throughout discovery, planner, Browser, HTML and summaries. Update group/register names in snake_case, universal remote headers, ventilation ENUMs and characterized register windows.
- Treat OP00 circuit and zone fields as supported capacities, with independent presence evidence. Keep native BASV2 circuit indexing and virtual-DHW II09 distinct; recommended selection uses mapped counts, presence gates and mandatory System/native-DHW scope.
- Hide deselected groups and absent instances in Browser/HTML. Parent nodes provide navigation without aggregating descendant registers; Config/State tabs apply only to OP02/OP06. Compact description/access displays and current access-category defaults reduce output noise.
- Correct Enhanced transport escaping, including reserved command CRC bytes, and use shared read recovery for identity and register operations. Preserve incomplete artifacts and detailed transport evidence without duplicate retry warnings.
- Restore automatic postscan Browser reconnection and distinct numeric edit confirmation. Resolve and check output directories before transport so an invalid destination fails before scanning.
- Correct HTI numeric HH/MM/SS encoding and characterized OP06 FWU numeric-byte firmware decoding. Keep opaque date/time STEP and unsupported description codecs explicitly unvalidated.

Artifacts remain schema 2.3. Older artifacts retain raw observations and historical values; replay raw traces or apply explicit type overrides when recomputation is needed. Profile windows are scheduling ceilings, not proof of exhaustive wire-space coverage. Generic IIFF descriptions cannot validate concrete devices. VRC700 paths and Event schemas retain their stated qualification limits; this release does not claim hardware validation across all models or native Event-write support.
