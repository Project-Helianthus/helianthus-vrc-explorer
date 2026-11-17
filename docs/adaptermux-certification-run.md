# AdapterMux certification run

This is the bench procedure for Explorer as the external client of the gateway AdapterMux coexistence cells.
The candidate build is the Explorer build the session is qualifying.
Run it from this repository.
The gateway AdapterMux listener is already running for the southbound under test.
Explorer connects to that listener as an ENH client and uses no other endpoint.
Record the Explorer version line and do not raise a version.

```bash
python -m helianthus_vrc_explorer --version
```

Keep that single line in the record.
The coexistence rows name northbound client `vrc-explorer`.
The scan is read-only.
This procedure has no device write.
A write needs its own operator authorization at action time.
The direct adapter path is outside this procedure.

Supply the listener endpoint in the command environment at action time.
Set `$ADAPTERMUX_INITIATOR` to the initiator the session assigns to Explorer.
That initiator differs from the initiator of every other client of the listener.
The scan passes it with `--source-address`, and its enhanced transport arbitrates with it.
If the listener endpoint or the initiator is not supplied, record the executable rows as blocked.
The non-interactive enhanced scan uses the scan setup's default controller destination.
If the controller does not answer at that destination, record the executable rows as blocked.
Do not record a model name, serial, address, or time.
Record the controller protocol family only.
Read the protocol family from `identity` before deleting the artifact.
The protocol family field holds the catalog protocol family, or `Unknown`.
The protocol family field is `Unknown` when the exact EID/SPN pair is unmatched.
Do not record the EID or the SPN.
The protocol family is not an evidence grade.
Session, candidate, and hardware-setup labels stay opaque: no endpoint and no serial.

## Command

Run the scan while the gateway smoke for that coexistence cell is inside its
measurement window, and only after the smoke has taken its first reading.
Set `$ADAPTERMUX_RAW_LOG` to the raw session log path before the scan.
The command itself redirects standard input from `/dev/null` and standard output
and standard error to that log, so no terminal is attached: the visual setup and
the post-scan browser do not start, and the preset stays the one in the command.
One scan serves the coexistence cell on that southbound. The START/SEND row and
the per-symbol echo row of the same southbound use that scan. Do not start a
second Explorer.

```bash
python -m helianthus_vrc_explorer scan \
  --transport enh \
  --host "$ADAPTERMUX_LISTENER_HOST" \
  --port "$ADAPTERMUX_LISTENER_PORT" \
  --source-address "$ADAPTERMUX_INITIATOR" \
  --preset recommended \
  </dev/null >"$ADAPTERMUX_RAW_LOG" 2>&1
```

Transport `enh` is Explorer's enhanced transport: it sends START and SEND to the
listener and checks the echo of every raw symbol it sends. Explorer speaks ENH to
the listener on both the `ENS` and the `ENH` southbound. A non-interactive
scan writes a JSON artifact and an HTML report under `results`.
The JSON artifact and the HTML report contain the scan timestamp and the destination address.
The JSON artifact and the HTML report contain the listener host and port.
The JSON artifact and the HTML report contain the probed model and serial in `identity` and `resolved_identity`.
The file names contain the destination address and the scan timestamp.
The HTML report also embeds that JSON.
Do not retain the JSON artifact.
Do not retain the HTML report.
Do not retain a redacted copy of either file.
A redirected scan still exits 0 after a caught transport error.
With no terminal attached, discovery failures are not written to the raw log.
The summary does not count those discovery failures.
A transport error is a register `error` value that begins with `transport_error`.
A transport diagnostic is a `transport_diagnostic` object in the artifact.
A transport recovery is `transport_recovery` or the incomplete reason `transport_recovery_exhausted`.
Before deleting either artifact, check the JSON artifact for a transport refusal.
The indicator is `refused` when the artifact holds a transport error.
The indicator is `refused` when the artifact holds a transport diagnostic.
The indicator is `refused` when the artifact holds a transport recovery.
The indicator is `none` only when that check finds none of those.
Record the sanitized transport-refusal indicator before deletion.
Do not copy an error string, a raw value, an address, an endpoint, a model, a serial, or a time into that indicator.
Delete both files after the scan exit status is recorded.
The published row omits the artifact body.
No scan artifact is retained.
Sanitize the raw session log before retention.
Drop the non-interactive preface and the scan status lines from the retained log.
Drop any other retained-log line that contains a model, a serial, or a controller address.
Drop any other retained-log line that contains the listener endpoint or a start time.
Retain the scan exit status.
The retained session log is the sanitized log only.

## Cells

The published record is the cell table and the session fields.
For the session, record the protocol family and the transport refusal.
A missing row is not a pass.
A missing session field is not a pass.
A session field that still holds `pending` is not a pass.
`execute` runs the command above, once per southbound.
`recorded-from-coexistence-scan` with command `same-scan` copies the START/SEND
or per-symbol echo claim from the coexistence scan of the same southbound and
starts no process. `not-run` starts nothing.
The Grade, Qualification, and Outcome columns are the record fields of each row.
Before the run they hold `pending` on every row the run fills.
Replace each `pending` with the recorded value in the published record.
A row that still holds `pending` is not a pass.
A `not-run` row keeps grade `Unknown`, qualification `none`, and outcome `not-run`.

<!-- certification-cells: start -->
| Cell | Southbound | Invariant | Disposition | Command | Grade | Qualification | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ENS-AD05` | `ENS` | `AD05` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `ENS-AD06` | `ENS` | `AD06` | `recorded-from-coexistence-scan` | `same-scan` | `pending` | `pending` | `pending` |
| `ENS-AD08` | `ENS` | `AD08` | `recorded-from-coexistence-scan` | `same-scan` | `pending` | `pending` | `pending` |
| `ENS-AD12` | `ENS` | `AD12` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `ENS-CX01` | `ENS` | `CX01` | `execute` | `scan` | `pending` | `pending` | `pending` |
| `ENH-AD05` | `ENH` | `AD05` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `ENH-AD06` | `ENH` | `AD06` | `recorded-from-coexistence-scan` | `same-scan` | `pending` | `pending` | `pending` |
| `ENH-AD08` | `ENH` | `AD08` | `recorded-from-coexistence-scan` | `same-scan` | `pending` | `pending` | `pending` |
| `ENH-AD12` | `ENH` | `AD12` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `ENH-CX01` | `ENH` | `CX01` | `execute` | `scan` | `pending` | `pending` | `pending` |
| `UDP-AD05` | `UDP` | `AD05` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UDP-AD06` | `UDP` | `AD06` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UDP-AD08` | `UDP` | `AD08` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UDP-AD12` | `UDP` | `AD12` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UDP-CX01` | `UDP` | `CX01` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `TCP-AD05` | `TCP` | `AD05` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `TCP-AD06` | `TCP` | `AD06` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `TCP-AD08` | `TCP` | `AD08` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `TCP-AD12` | `TCP` | `AD12` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `TCP-CX01` | `TCP` | `CX01` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENS-AD05` | `UARTENS` | `AD05` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENS-AD06` | `UARTENS` | `AD06` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENS-AD08` | `UARTENS` | `AD08` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENS-AD12` | `UARTENS` | `AD12` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENS-CX01` | `UARTENS` | `CX01` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENH-AD05` | `UARTENH` | `AD05` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENH-AD06` | `UARTENH` | `AD06` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENH-AD08` | `UARTENH` | `AD08` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENH-AD12` | `UARTENH` | `AD12` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTENH-CX01` | `UARTENH` | `CX01` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTRAW-AD05` | `UARTRAW` | `AD05` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTRAW-AD06` | `UARTRAW` | `AD06` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTRAW-AD08` | `UARTRAW` | `AD08` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTRAW-AD12` | `UARTRAW` | `AD12` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
| `UARTRAW-CX01` | `UARTRAW` | `CX01` | `not-run` | `not-run` | `Unknown` | `none` | `not-run` |
<!-- certification-cells: end -->

<!-- certification-session: start -->
| Field | `ENS` | `ENH` |
| --- | --- | --- |
| `protocol-family` | `pending` | `pending` |
| `transport-refusal` | `pending` | `pending` |
<!-- certification-session: end -->

When the executable rows are blocked, the protocol family field is `Unknown`.
When the executable rows are blocked, the transport-refusal indicator is `blocked`.
UDP rows are not run. TCP rows are not run. UART-direct rows are not run.
The UART-direct row tokens are `UARTENS`, `UARTENH`, and `UARTRAW`. Plain UDP
and TCP stay planned on the gateway inventory, and UART-direct stays reserved.
This procedure does not execute those rows and does not mark them pass.

`AD05` names broadcast reception. `AD08` names an echo per raw symbol. `AD12`
names raw escape pairs, including a reserved byte in a CRC position. `AD06`
names START/SEND. The `AD06` and `AD08` rows take their claim from the
coexistence scan: Explorer's enhanced transport stops a transaction on a
mismatched echo of any raw symbol it sends. The `AD05` and `AD12` rows on ENS
and ENH stay `not-run`: the scan command retains no wire symbol, so it cannot
show a received broadcast or a reserved byte in a CRC position. Retaining wire
symbols is Explorer feature work and returns to this repository. These rows do
not change the gateway cell's client. They record Explorer evidence only.

## What is recorded

For every row, record the cell, southbound, invariant, disposition, command, evidence grade, qualification, and outcome.
The Grade column holds `Proven`, `Hypothesis`, or `Unknown`.
The Qualification column holds the selector qualification in family wording, or `none`.
The Outcome column holds `pass`, `fail`, `blocked`, or `not-run`.
Grade Proven is the retained scan exit status.
Use it only when that exit status is retained, and only for the fact that the scan completed.
Grade Hypothesis is an interpretation of that completed scan.
A completed enhanced scan through the listener supports Hypothesis for START/SEND.
It supports Hypothesis for the echo of each raw symbol Explorer sent in a completed transaction.
Grade Unknown is missing context, including any wire symbol the scan did not retain.
Broadcast reception and raw escape pairs stay Unknown on every row.

Qualification is a separate record and does not set the grade.
The grade does not set qualification.
A selector-qualified decoded row stays in its own qualification field.

An `execute` row passes only when the scan exits 0, both artifact files were
written, the transport-refusal indicator is `none`, both files were then
deleted, and the command passed the supplied initiator.
An `execute` row passes only when that indicator is `none`.
A scan exit status of 0 does not show that the listener refused nothing.
The summary error count is not the transport-refusal check.
Anything else is fail, or blocked when the endpoint or the initiator was not
supplied or the controller did not answer at the default destination.
A `recorded-from-coexistence-scan` row takes the outcome of the `execute` row of the same southbound.
Its grade is at most Hypothesis.
Retaining the JSON artifact or the HTML report is not a pass.

## Restore

Restore stops Explorer and sends no further bus command. Confirm no Explorer
process is still attached to the listener. Leave the sanitized session log in place.
Confirm the JSON artifact and the HTML report are gone.
Do not retain the raw redirect.
The gateway process is restored by the session owner. The next cell starts
only after Explorer has stopped.

## Unexpected results

An unexpected fail returns to the owning repository.
An unexpected pass returns to the owning repository.
An unexpected pass includes a pass on a `not-run` row and includes `xpass`.
Do not rewrite the row to match the expectation.

A scan that does not finish or a scan that writes no artifact returns to this
repository.
A listener refusal of this read-only scan returns to the gateway repository.
A retained scan artifact returns to this repository.
A gateway smoke failure, a mux framing failure, or a reserved-row outcome
returns to the gateway repository.
Blocked cells stay visible. Not-run cells stay visible.

## Out of scope

Explorer feature work and gateway gate changes are outside this procedure.
The offline acceptance card does not run these steps and does not authorize
them.
