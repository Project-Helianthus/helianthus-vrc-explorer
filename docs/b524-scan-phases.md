# B524 scan phases

`run_b524_scan` in `scanner/b524_orchestration.py` runs a B524 scan as five
phases in a fixed order: plan, discovery, availability, scan and completion. This
page lists each phase with the local state it reads and writes.

Every phase is a function in `scanner/b524_phases.py`. The phases read and write
one typed scan context, `B524ScanContext`. `run_b524_scan` only calls the phases
in order and supplies their collaborators: group discovery, the planner-mode
resolver, the instance availability probe, and a `B524ScanCollaborators` bundle
with the planners, the hotkey reader, the register annotation sources, the
description-candidate selector and the value annotator.

## Failure handling

- Plan validation runs before any request. An invalid request raises
  `ValueError`, and no artifact is returned.
- Every later phase runs inside one guard. If the operator interrupts
  (`user_interrupt`), the request budget runs out (`request_budget_exhausted`)
  or transport recovery is exhausted (`transport_recovery_exhausted`), the scan
  stops at that point. Completion then marks the artifact incomplete and keeps
  everything written so far. Because the context is updated step by step, a
  failure part-way through any phase keeps the fields that were already
  resolved.
- If the operator explicitly asked for the full-screen planner and it is
  unavailable or fails to start, the scan raises `RuntimeError`. The guard does
  not catch it.

## 1. Plan

Function: `plan_b524_scan`, followed by `announce_b524_scan` inside the guard.

| Reads | Writes |
|---|---|
| Requested preset (normalized) and optional explicit plan | `context.planner_preset`, `context.research_mode`, `context.explicit_plan` |
| Description budget and request budget | Validation errors; `context.request_budget`, `context.description_budget` |
| Operation-read requests and operation identity | `context.operation_requests`, `context.operation_selection`, `context.operation_planner_options`, `context.device_id`, `context.manufacturer`, `context.explicit_operation_override` |
| Explicit plan, research preset, profile group table | `context.configured_groups` |
| Transport | `context.transport` (wrapped in the counting transport, with the request budget) |
| Clock, bundled constraint catalog | `context.start_perf`, `context.static_constraints` |
| Destination, ebusd endpoint, identity | `artifact.schema_version`, `meta.scan_timestamp`, `meta.destination_address`, `meta.artifact_contract`, `meta.identity`, `meta.scan_coverage` (preset, budget, scope, configured groups), `meta.b524_operation_read_plan`, `meta.ebusd_host`, `meta.ebusd_port`, `meta.constraint_catalog_source`, `meta.constraint_catalog_entries`, `meta.constraint_scope`, `meta.scan_plan` for an explicit plan |

`announce_b524_scan` logs the scan start, the warning for the full or research
preset and the description-policy line, then sends the first trace label.

## 2. Discovery

Function: `discover_b524_scope`. It uses three collaborators: group discovery,
the planner-mode resolver, and the fallback register and instance bounds for
groups that have no profile.

| Reads | Writes |
|---|---|
| System information read by group discovery (`group_discovery` progress phase) | `meta.system_information`; for unanswered identifiers, `meta.scan_coverage.qualification_incomplete`, `system_information_complete` and `unknown_system_information`; `context.information_values`, `context.ventilation_hint` |
| API identity and count identifiers | `meta.profile_context` |
| Description profile catalog | `meta.description_profile_status`, `meta.description_profile_reminder` when the profile is not exact; `context.profile_status`, `context.profile_id`, `context.description_reminder_logged` |
| Planner preset, exact profile | `context.description_policy`, policy fields in `context.operation_planner_options` |
| Configured groups | `context.classified` (profile register candidates), `context.unknown_descriptor_types` |
| Profile group table, fallback bounds | `context.metadata_map`, `meta.parameter_description_policy` |
| Console, terminal, planners, planner UI choice (through the resolver) | `context.planner_mode` |
| Explicit plan or profile operations; responsiveness probes for unknown groups | `context.resolved_group_opcodes`, `context.availability_group_opcodes`, `context.unknown_opcode_probe_map`, `meta.scan_coverage.unknown_groups` |
| Responsive unknown groups and unknown descriptor classes | `meta.issue_suggestion` |
| Resolved operations per group | `operations[op].groups[gg]` with name, instance bounds and `discovery_advisory` |
| Request counter, clock | `context.group_discovery_requests`, `context.group_discovery_duration_s` |

The planner mode is resolved after the group bounds are set and before the
unknown groups are probed. This keeps the operator's log lines in their original
order.

## 3. Availability

Function: `probe_b524_availability` (`instance_discovery` progress phase). It
uses the instance availability probe as its collaborator.

| Reads | Writes |
|---|---|
| `context.classified`, `context.metadata_map`, `context.availability_group_opcodes` | Instance discovery targets |
| `context.information_values`, `context.profile_id`, preset | Namespace topology, `availability_contract` and `availability_probes` per group; present instances; `context.native_dhw_admitted` |
| Count identifiers | `meta.instance_counts`, `meta.device_discovery`, `meta.device_count`, `meta.module_capacity_crosscheck`; coverage completeness flags and `unknown_instance_probes` |
| Request counter, clock | `context.instance_discovery_requests`, `context.instance_discovery_duration_s`; `meta.scan_coverage.discovery_completed = true` |
| Operation identity, present scalar instances | `meta.b524_event_acquisition`; automatic event requests appended to `context.operation_requests` and `context.operation_selection` |

## 4. Scan

Function: `scan_b524_registers` (`register_scan` and `describe` progress
phases). It uses the `B524ScanCollaborators` bundle.

| Reads | Writes |
|---|---|
| Present instances, `context.resolved_group_opcodes`, explicit plan, preset, discovery and availability request rates | Register plan and planner groups |
| `context.planner_mode`, planners, hotkey reader | Operator selection (plan, preset, description policy), including replanning during the scan |
| Selection | `meta.parameter_description_policy` overrides, `meta.scan_coverage.preset`, `meta.b524_operation_read_plan`, `meta.scan_plan`, `meta.group_metadata_bounds`, `meta.constraint_dictionary`, `meta.constraint_probe_enabled` |
| ebusd schema, register map, constraint catalog, `context.profile_id`, `context.ventilation_hint` | Register entries under `operations[op].groups[gg].instances[ii].registers`; `meta.constraint_mismatches`, `meta.constraint_rescan_recommended` |
| Writable observed registers, `context.description_policy`, description budget | `context.observed_description_candidates`, `context.description_candidates`, `context.description_candidates_prepared`, `meta.description_remote_profile_statuses`, description reminder, `context.description_coverage` |
| Selected operation-read requests | `b524_operation_reads` |

## 5. Completion

Functions: `record_operator_interrupt`, `record_request_budget_exhausted` or
`record_transport_recovery_exhausted` in the guard's exception handlers, each
returning the interruption reason; then `complete_b524_scan`, which always runs.

| Reads | Writes |
|---|---|
| Interruption cause | `meta.incomplete`, `meta.incomplete_reason`; `meta.budget_boundary_evidence` or `meta.transport_recovery` and `meta.transport_boundary_evidence`; system information carried by the exception; the pending register entry |
| Description candidates and policy | Description candidates selected late, when the scan stopped before they were selected; `meta.parameter_description_coverage`, `meta.parameter_description_requests` |
| Operation-read requests | `meta.b524_operation_read_plan`; `unattempted` records for selected reads that never ran; `meta.b524_operation_read_attempts` |
| Request counter, clock | `meta.scan_coverage.actual_requests`, `meta.scan_coverage.completed`, `meta.scan_duration_seconds` |
