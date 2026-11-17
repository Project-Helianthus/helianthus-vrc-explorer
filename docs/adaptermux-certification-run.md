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

Supply the relay endpoint and the initiator in the command's environment at action time.
If the relay endpoint is not supplied, record the executable rows as blocked.
Do not record a model name, serial, address, or time.
Record the controller protocol family only.
Session, candidate, and hardware-setup labels stay opaque: no endpoint and no serial.

## Command

Run the scan while the gateway smoke for that coexistence cell is inside its
measurement window, and only after the smoke has taken its first reading.
Redirect standard output and standard error to the session log so no terminal
is attached; the preset then stays the one in the command. One scan serves
the coexistence cell on that southbound. The START/SEND row of the same
southbound uses that scan. Do not start a second Explorer.

```bash
python -m helianthus_vrc_explorer scan \
  --transport tcp \
  --host "$ADAPTERMUX_RELAY_HOST" \
  --port "$ADAPTERMUX_RELAY_PORT" \
  --source-address "$ADAPTERMUX_INITIATOR" \
  --preset recommended
```

The initiator flag in that command is the only address flag this scan accepts.
Transport `tcp` is the guarded relay's command dialogue. A non-interactive
scan writes its artifact under `results` in the working directory. Keep that
artifact for local inspection. The published row omits the artifact body.

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
Grade Proven is a fact inside the retained artifact.
Use it only when the scan exit status and the artifact file are both retained, and only for the fact that the scan completed.
Grade Hypothesis is an interpretation supported by that artifact.
A completed read through the relay supports Hypothesis for START/SEND.
Grade Unknown is missing context, including any wire symbol the relay did not retain.
Broadcast reception, per-symbol echo, and raw escape pairs stay Unknown on every row.

Qualification is a separate record and does not set the grade.
The grade does not set qualification.
A selector-qualified decoded row stays in its own qualification field.

An `execute` row passes only when the scan exits 0, the artifact exists, and
the relay refused nothing. Anything else is fail, or blocked when the endpoint
was not supplied.

## Restore

Restore stops Explorer and sends no further bus command. Confirm no Explorer
process is still attached to the relay. Leave the session output in place.
The gateway process is restored by the session owner. The next cell starts
only after Explorer has stopped.

## Unexpected results

An unexpected fail returns to the owning repository.
An unexpected pass returns to the owning repository.
An unexpected pass includes a pass on a `not-run` row and includes `xpass`.
Do not rewrite the row to match the expectation.

A scan that does not finish, a relay refusal of this read-only scan, or a
missing artifact returns to this repository. A gateway smoke failure, a mux
framing failure, or a reserved-row outcome returns to the gateway repository.
Blocked cells stay visible. Not-run cells stay visible.

## Out of scope

Explorer feature work and gateway gate changes are outside this procedure.
The offline acceptance card does not run these steps and does not authorize
them.
