# AdapterMux certification run

This is the bench procedure for Explorer as the external client of the gateway AdapterMux coexistence cells.
The candidate build is the Explorer build the session is qualifying.
Run it from this repository.
The gateway AdapterMux listener is already running for the southbound under test.
Explorer's only endpoint is the guarded command relay that session supplies.
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

Supply the relay endpoint in the command environment at action time.
Set `$ADAPTERMUX_INITIATOR` as the initiator these hex lines use before the scan.
This scan does not pass `--source-address`.
The scan applies that option only for enhanced transport.
These hex lines carry no source override.
If these hex lines would not use the supplied initiator, record the executable rows as blocked.
If the relay endpoint is not supplied, record the executable rows as blocked.
Do not record a model name, serial, address, or time.
Record the controller protocol family only.
Session, candidate, and hardware-setup labels stay opaque: no endpoint and no serial.

## Command

Run the scan while the gateway smoke for that coexistence cell is inside its
measurement window, and only after the smoke has taken its first reading.
Redirect standard output and standard error to a raw session log so no terminal
is attached; the preset then stays the one in the command. One scan serves
the coexistence cell on that southbound. The START/SEND row of the same
southbound uses that scan. Do not start a second Explorer.

```bash
python -m helianthus_vrc_explorer scan \
  --transport tcp \
  --host "$ADAPTERMUX_RELAY_HOST" \
  --port "$ADAPTERMUX_RELAY_PORT" \
  --preset recommended
```

Transport `tcp` is the guarded relay's command dialogue. A non-interactive
scan writes a JSON artifact and an HTML report under `results`.
The JSON artifact and the HTML report contain the scan timestamp and the destination address.
The JSON artifact and the HTML report contain the relay host and port.
The JSON artifact and the HTML report contain the probed model and serial in `identity` and `resolved_identity`.
The file names contain the destination address and the scan timestamp.
The HTML report also embeds that JSON.
Do not retain the JSON artifact.
Do not retain the HTML report.
Do not retain a redacted copy of either file.
Delete both files after the scan exit status is recorded.
The published row omits the artifact body.
No scan artifact is retained.
Sanitize the raw session log before retention.
Drop the non-interactive preface and the scan status lines from the retained log.
Drop any other retained-log line that contains a model, a serial, or a controller address.
Drop any other retained-log line that contains the relay endpoint or a start time.
Retain the scan exit status.
The retained session log is the sanitized log only.

## Cells

The table is the whole Explorer record. A missing row is not a pass.
`execute` runs the command above, once per southbound. `same-scan` copies the
START/SEND claim from the coexistence scan of the same southbound and starts
no process. `not-run` starts nothing.

<!-- certification-cells: start -->
| Cell | Southbound | Invariant | Disposition | Command |
| --- | --- | --- | --- | --- |
| `ENS-AD05` | `ENS` | `AD05` | `not-run` | `not-run` |
| `ENS-AD06` | `ENS` | `AD06` | `recorded-from-coexistence-scan` | `same-scan` |
| `ENS-AD08` | `ENS` | `AD08` | `not-run` | `not-run` |
| `ENS-AD12` | `ENS` | `AD12` | `not-run` | `not-run` |
| `ENS-CX01` | `ENS` | `CX01` | `execute` | `scan` |
| `ENH-AD05` | `ENH` | `AD05` | `not-run` | `not-run` |
| `ENH-AD06` | `ENH` | `AD06` | `recorded-from-coexistence-scan` | `same-scan` |
| `ENH-AD08` | `ENH` | `AD08` | `not-run` | `not-run` |
| `ENH-AD12` | `ENH` | `AD12` | `not-run` | `not-run` |
| `ENH-CX01` | `ENH` | `CX01` | `execute` | `scan` |
| `UDP-AD05` | `UDP` | `AD05` | `not-run` | `not-run` |
| `UDP-AD06` | `UDP` | `AD06` | `not-run` | `not-run` |
| `UDP-AD08` | `UDP` | `AD08` | `not-run` | `not-run` |
| `UDP-AD12` | `UDP` | `AD12` | `not-run` | `not-run` |
| `UDP-CX01` | `UDP` | `CX01` | `not-run` | `not-run` |
| `TCP-AD05` | `TCP` | `AD05` | `not-run` | `not-run` |
| `TCP-AD06` | `TCP` | `AD06` | `not-run` | `not-run` |
| `TCP-AD08` | `TCP` | `AD08` | `not-run` | `not-run` |
| `TCP-AD12` | `TCP` | `AD12` | `not-run` | `not-run` |
| `TCP-CX01` | `TCP` | `CX01` | `not-run` | `not-run` |
| `UARTENS-AD05` | `UARTENS` | `AD05` | `not-run` | `not-run` |
| `UARTENS-AD06` | `UARTENS` | `AD06` | `not-run` | `not-run` |
| `UARTENS-AD08` | `UARTENS` | `AD08` | `not-run` | `not-run` |
| `UARTENS-AD12` | `UARTENS` | `AD12` | `not-run` | `not-run` |
| `UARTENS-CX01` | `UARTENS` | `CX01` | `not-run` | `not-run` |
| `UARTENH-AD05` | `UARTENH` | `AD05` | `not-run` | `not-run` |
| `UARTENH-AD06` | `UARTENH` | `AD06` | `not-run` | `not-run` |
| `UARTENH-AD08` | `UARTENH` | `AD08` | `not-run` | `not-run` |
| `UARTENH-AD12` | `UARTENH` | `AD12` | `not-run` | `not-run` |
| `UARTENH-CX01` | `UARTENH` | `CX01` | `not-run` | `not-run` |
| `UARTRAW-AD05` | `UARTRAW` | `AD05` | `not-run` | `not-run` |
| `UARTRAW-AD06` | `UARTRAW` | `AD06` | `not-run` | `not-run` |
| `UARTRAW-AD08` | `UARTRAW` | `AD08` | `not-run` | `not-run` |
| `UARTRAW-AD12` | `UARTRAW` | `AD12` | `not-run` | `not-run` |
| `UARTRAW-CX01` | `UARTRAW` | `CX01` | `not-run` | `not-run` |
<!-- certification-cells: end -->

UDP rows are not run. TCP rows are not run. UART-direct rows are not run.
The UART-direct row tokens are `UARTENS`, `UARTENH`, and `UARTRAW`. Plain UDP
and TCP stay planned on the gateway inventory, and UART-direct stays reserved.
This procedure does not execute those rows and does not mark them pass.

`AD05` names broadcast reception. `AD08` names an echo per raw symbol. `AD12`
names raw escape pairs, including a reserved byte in a CRC position. Those
six ENS and ENH rows stay `not-run`: the guarded relay does not retain wire
symbols, so the scan cannot show them. `AD06` names START/SEND and takes that
claim from the coexistence scan. These rows do not change the gateway cell's
client. They record Explorer evidence only.

## What is recorded

For every row, record the cell, southbound, invariant, disposition, command, evidence grade, and qualification.
Grade Proven is the retained scan exit status.
Use it only when that exit status is retained, and only for the fact that the scan completed.
Grade Hypothesis is an interpretation of that completed scan.
A completed read through the relay supports Hypothesis for START/SEND.
Grade Unknown is missing context, including any wire symbol the relay did not retain.
Broadcast reception, per-symbol echo, and raw escape pairs stay Unknown on every row.

Qualification is a separate record and does not set the grade.
The grade does not set qualification.
A selector-qualified decoded row stays in its own qualification field.

An `execute` row passes only when the scan exits 0, both artifact files were
written and then deleted, the relay refused nothing, and these hex lines use
the supplied initiator.
Anything else is fail, or blocked when the endpoint was not supplied or these
hex lines would not use the supplied initiator.
Retaining the JSON artifact or the HTML report is not a pass.

## Restore

Restore stops Explorer and sends no further bus command. Confirm no Explorer
process is still attached to the relay. Leave the sanitized session log in place.
Confirm the JSON artifact and the HTML report are gone.
Do not retain the raw redirect.
The gateway process is restored by the session owner. The next cell starts
only after Explorer has stopped.

## Unexpected results

An unexpected fail returns to the owning repository.
An unexpected pass returns to the owning repository.
An unexpected pass includes a pass on a `not-run` row and includes `xpass`.
Do not rewrite the row to match the expectation.

A scan that does not finish, a relay refusal of this read-only scan, or a
scan that writes no artifact returns to this repository.
A retained scan artifact returns to this repository.
A gateway smoke failure, a mux framing failure, or a reserved-row outcome
returns to the gateway repository.
Blocked cells stay visible. Not-run cells stay visible.

## Out of scope

Explorer feature work and gateway gate changes are outside this procedure.
The offline acceptance card does not run these steps and does not authorize
them.
