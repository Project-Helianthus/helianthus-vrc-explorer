# CLI reference

This file is generated from the CLI's `--help` output. Refresh it with
`python3 scripts/docs_sync_help.py` and verify it with
`python3 scripts/check_docs_sync.py`.

## Root command

<!-- BEGIN CLI HELP:root -->

```text

 Usage: python -m helianthus_vrc_explorer [OPTIONS] COMMAND [ARGS]...

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --version            Print version and exit.                                                                         │
│ --help     -h        Show this message and exit.                                                                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ scan          Scan a VRC regulator using B524 (GetExtendedRegisters).                                                │
│ replay-trace  Replay an ENH/ENS trace into a fresh schema-2.3 JSON artifact + HTML report.                           │
│ discover      Discover eBUS devices via QueryExistence broadcast and per-address scan (0704).                        │
│ browse        Browse scan results in fullscreen Textual UI (file mode).                                              │
│ b524          Read B524 operation tables, edit offline, or apply a qualified timer change.                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:root -->

## `scan`

<!-- BEGIN CLI HELP:scan -->

```text

 Usage: python -m helianthus_vrc_explorer scan [OPTIONS]

 Scan a VRC regulator using B524 (GetExtendedRegisters).

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --transport                                          <str>               Transport: tcp (ebusd hex) or ens/enh       │
│                                                                          (enhanced eBUS adapter).                    │
│                                                                          [default: tcp]                              │
│ --dst                                                <str>               Destination eBUS address (e.g. 0x15) or     │
│                                                                          auto (default).                             │
│                                                                          [default: auto]                             │
│ --source-address                                     <str>               Source initiator address for enhanced       │
│                                                                          transport. Ignored for tcp.                 │
│                                                                          [default: 0xF7]                             │
│ --host                                               <str>               ebusd host (TCP). [default: 127.0.0.1]      │
│ --port                                               <int>               ebusd port (TCP). [default: 8888]           │
│ --dry-run                                                                Replay a scan fixture using DummyTransport  │
│                                                                          (no device I/O).                            │
│ --output-dir                                         <path>              Directory to write the scan JSON artifact   │
│                                                                          to.                                         │
│                                                                          [default: .]                                │
│ --ebusd-csv-path                                     <path>              Optional ebusd configuration CSV (e.g.      │
│                                                                          15.720.csv) used to annotate register       │
│                                                                          names.                                      │
│                                                                          [env var: HELIA_EBUSD_CSV_PATH]             │
│ --myvaillant-map-path                                <path>              Optional myVaillant-equivalence mapping CSV │
│                                                                          used to annotate register leaf names.       │
│                                                                          [env var: HELIA_MYVAILLANT_MAP_PATH]        │
│ --trace-file                                         <path>              Write an ebusd request/response trace log   │
│                                                                          to this file.                               │
│                                                                          [env var: HELIA_EBUSD_TRACE_PATH]           │
│ --b509-range                                         <str>               B509 register range to dump (repeatable),   │
│                                                                          format: 0x0000..0x00FF. Requires            │
│                                                                          --b509-dump. If omitted, defaults to        │
│                                                                          0x0000..0x00FF.                             │
│ --b509-dump                --no-b509-dump                                Opt-in B509 register dump (disabled by      │
│                                                                          default). Use --b509-range to narrow/expand │
│                                                                          ranges.                                     │
│                                                                          [default: no-b509-dump]                     │
│ --b555-dump                --no-b555-dump                                Opt-in read-only B555 timer dump            │
│                                                                          (A3/A4/A5). Disabled by default to keep the │
│                                                                          standard B524/B509 scan path unchanged.     │
│                                                                          [default: no-b555-dump]                     │
│ --b516-dump                --no-b516-dump                                Opt-in read-only B516 energy dump (active   │
│                                                                          request/response only). Disabled by default │
│                                                                          to keep the standard B524/B555/B509 scan    │
│                                                                          path unchanged.                             │
│                                                                          [default: no-b516-dump]                     │
│ --planner-ui                                         <str>               Interactive planner mode: disabled, auto,   │
│                                                                          textual, or classic.                        │
│                                                                          [default: disabled]                         │
│ --preset                                             <str>               Planner preset: recommended, full,          │
│                                                                          research, or custom. `full` audits declared │
│                                                                          profile slots independently of OP00 counts; │
│                                                                          `research` performs bounded, non-exhaustive │
│                                                                          exploration. Legacy aliases:                │
│                                                                          aggressive->full, exhaustive->research,     │
│                                                                          conservative->recommended.                  │
│                                                                          [default: recommended]                      │
│ --no-tips                                                                Hide scan header tips in interactive        │
│                                                                          terminal mode.                              │
│ --redact                                                                 Redact device identity fields (e.g. serial  │
│                                                                          number) in console output.                  │
│ --probe-constraints        --no-probe-constraints                        Acquire complete OP01/OP07 descriptions for │
│                                                                          observed writable parameters. Enabled by    │
│                                                                          default for all eligible parameters;        │
│                                                                          descriptions validate later offline edits.  │
│                                                                          Missing descriptions remain explicit        │
│                                                                          warnings.                                   │
│                                                                          [default: probe-constraints]                │
│ --scan-plan                                          <file>              Version 1 JSON plan file for custom         │
│                                                                          OP02/OP06, GG, II and RR16 selectors.       │
│ --b524-read-plan                                     <file>              Explicit JSON read plan for B524 Timer,     │
│                                                                          VR91, Event and EventSetPoint operations.   │
│ --preview-read-plan                                                      Validate and encode --b524-read-plan        │
│                                                                          offline, without opening a transport.       │
│ --description-budget                                 <int range> [x>=0]  Maximum description requests, shared fairly │
│                                                                          between OP01 and OP07 (unused shares        │
│                                                                          borrowed). Default: all eligible parameters │
│                                                                          in the selected scope.                      │
│ --request-budget                                     <int range> [x>=1]  Optional maximum actual B524 sends          │
│                                                                          including retries. No implicit send cap.    │
│                                                                          Exhaustion saves a partial artifact.        │
│ --help                 -h                                                Show this message and exit.                 │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:scan -->

## `browse`

<!-- BEGIN CLI HELP:browse -->

```text

 Usage: python -m helianthus_vrc_explorer browse [OPTIONS]

 Browse scan results in fullscreen Textual UI (file mode).

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --file                 <path>  Path to an existing scan JSON artifact (default browse mode).                         │
│ --live                         Live mode (planned). In P0, only --file mode is implemented.                          │
│ --device               <str>   Device identifier for --live mode (planned).                                          │
│ --allow-write                  Enable write/edit actions in browse UI (safe mode + confirmation). Note: --file mode  │
│                                edits do not write to the device.                                                     │
│ --help         -h              Show this message and exit.                                                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:browse -->

## `discover`

<!-- BEGIN CLI HELP:discover -->

```text

 Usage: python -m helianthus_vrc_explorer discover [OPTIONS]

 Discover eBUS devices via QueryExistence broadcast and per-address scan (0704).

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --host                <str>   ebusd host (TCP). [default: 127.0.0.1]                                                 │
│ --port                <int>   ebusd port (TCP). [default: 8888]                                                      │
│ --trace-file          <path>  Write an ebusd request/response trace log to this file.                                │
│                               [env var: HELIA_EBUSD_TRACE_PATH]                                                      │
│ --help        -h              Show this message and exit.                                                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:discover -->

## `b524`

<!-- BEGIN CLI HELP:b524 -->

```text

 Usage: python -m helianthus_vrc_explorer b524 [OPTIONS] COMMAND [ARGS]...

 Read B524 operation tables, edit offline, or apply a qualified timer change.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                                                        │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ apply-operation             Preview an operation edit; --execute requires native qualification and confirmation.     │
│ read-timer                  Read one VRC700 timer day with OP03 ReadTimer.                                           │
│ read-event                  Read one profile-qualified OP09 GetEvent table.                                          │
│ read-event-setpoint         Read one profile-qualified OP0B GetEventSetPoint table.                                  │
│ read-vr91                   Read the VRC700 remote-controller status block with OP08 ReadVR91.                       │
│ preview-set-event           Build an OP0A SetEvent payload without sending it.                                       │
│ preview-set-event-setpoint  Build an OP0C SetEventSetPoint payload without sending it.                               │
│ preview-write-timer         Build an OP04 WriteTimer payload without sending it.                                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524 -->

### `b524 apply-operation`

<!-- BEGIN CLI HELP:b524-apply-operation -->

```text

 Usage: python -m helianthus_vrc_explorer b524 apply-operation
            [OPTIONS]

 Preview an operation edit; --execute requires native qualification and confirmation.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --plan                    <file>                     [required]                                                   │
│    --execute                                            Apply one qualified native write.                            │
│    --qualification           <file>                                                                                  │
│    --confirm                 <str>                      Exact confirmation from the offline preview.                 │
│    --dst                     <str>                      [default: 0x15]                                              │
│    --transport               <str>                      [default: tcp]                                               │
│    --source-address          <str>                      [default: 0xF7]                                              │
│    --host                    <str>                      [default: 127.0.0.1]                                         │
│    --port                    <int range> [1<=x<=65535]  [default: 8888]                                              │
│    --trace-file              <path>                                                                                  │
│    --output                  <path>                     Save the preview or execution evidence.                      │
│    --help            -h                                 Show this message and exit.                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524-apply-operation -->

### `b524 read-timer`

<!-- BEGIN CLI HELP:b524-read-timer -->

```text

 Usage: python -m helianthus_vrc_explorer b524 read-timer [OPTIONS]

 Read one VRC700 timer day with OP03 ReadTimer.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --channel                 <str>                      Documented VRC700 timer channel. [required]                  │
│    --instance                <int range> [0<=x<=255]    [default: 0]                                                 │
│    --weekday                 <str>                      Monday..Sunday or 0..6. [default: monday]                    │
│    --transport               <str>                      [default: tcp]                                               │
│    --dst                     <str>                      [default: 0x15]                                              │
│    --source-address          <str>                      [default: 0xF7]                                              │
│    --host                    <str>                      [default: 127.0.0.1]                                         │
│    --port                    <int range> [1<=x<=65535]  [default: 8888]                                              │
│    --trace-file              <path>                                                                                  │
│    --help            -h                                 Show this message and exit.                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524-read-timer -->

### `b524 read-event`

<!-- BEGIN CLI HELP:b524-read-event -->

```text

 Usage: python -m helianthus_vrc_explorer b524 read-event [OPTIONS]

 Read one profile-qualified OP09 GetEvent table.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --profile                 <str>                      Profile: system, dhw, or zone. [required]                    │
│    --instance                <int range> [0<=x<=255]    [default: 0]                                                 │
│ *  --address                 <str>                      [required]                                                   │
│ *  --weekday-code            <str>                      Explicit raw weekday selector; no default interpretation.    │
│                                                         [required]                                                   │
│    --transport               <str>                      [default: tcp]                                               │
│    --dst                     <str>                      [default: 0x15]                                              │
│    --source-address          <str>                      [default: 0xF7]                                              │
│    --host                    <str>                      [default: 127.0.0.1]                                         │
│    --port                    <int range> [1<=x<=65535]  [default: 8888]                                              │
│    --trace-file              <path>                                                                                  │
│    --help            -h                                 Show this message and exit.                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524-read-event -->

### `b524 read-event-setpoint`

<!-- BEGIN CLI HELP:b524-read-event-setpoint -->

```text

 Usage: python -m helianthus_vrc_explorer b524 read-event-setpoint
            [OPTIONS]

 Read one profile-qualified OP0B GetEventSetPoint table.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --profile                 <str>                      Profile: system, dhw, or zone. [required]                    │
│    --instance                <int range> [0<=x<=255]    [default: 0]                                                 │
│ *  --address                 <str>                      [required]                                                   │
│ *  --weekday-code            <str>                      Explicit raw weekday selector; no default interpretation.    │
│                                                         [required]                                                   │
│    --transport               <str>                      [default: tcp]                                               │
│    --dst                     <str>                      [default: 0x15]                                              │
│    --source-address          <str>                      [default: 0xF7]                                              │
│    --host                    <str>                      [default: 127.0.0.1]                                         │
│    --port                    <int range> [1<=x<=65535]  [default: 8888]                                              │
│    --trace-file              <path>                                                                                  │
│    --help            -h                                 Show this message and exit.                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524-read-event-setpoint -->

### `b524 read-vr91`

<!-- BEGIN CLI HELP:b524-read-vr91 -->

```text

 Usage: python -m helianthus_vrc_explorer b524 read-vr91 [OPTIONS]

 Read the VRC700 remote-controller status block with OP08 ReadVR91.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --transport               <str>                      [default: tcp]                                                  │
│ --dst                     <str>                      [default: 0x15]                                                 │
│ --source-address          <str>                      [default: 0xF7]                                                 │
│ --host                    <str>                      [default: 127.0.0.1]                                            │
│ --port                    <int range> [1<=x<=65535]  [default: 8888]                                                 │
│ --trace-file              <path>                                                                                     │
│ --help            -h                                 Show this message and exit.                                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524-read-vr91 -->

### `b524 preview-write-timer`

<!-- BEGIN CLI HELP:b524-preview-write-timer -->

```text

 Usage: python -m helianthus_vrc_explorer b524 preview-write-timer
            [OPTIONS]

 Build an OP04 WriteTimer payload without sending it.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --channel           <str>                    [required]                                                           │
│    --instance          <int range> [0<=x<=255]  [default: 0]                                                         │
│    --weekday           <str>                    [default: monday]                                                    │
│    --slot              <str>                    HH:MM-HH:MM; repeat up to 3 times.                                   │
│    --help      -h                               Show this message and exit.                                          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524-preview-write-timer -->

### `b524 preview-set-event`

<!-- BEGIN CLI HELP:b524-preview-set-event -->

```text

 Usage: python -m helianthus_vrc_explorer b524 preview-set-event
            [OPTIONS]

 Build an OP0A SetEvent payload without sending it.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --profile               <str>                    [required]                                                       │
│    --instance              <int range> [0<=x<=255]  [default: 0]                                                     │
│ *  --address               <str>                    [required]                                                       │
│ *  --weekday-code          <str>                    Explicit raw weekday selector; no default interpretation.        │
│                                                     [required]                                                       │
│    --value                 <str>                                                                                     │
│    --help          -h                               Show this message and exit.                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524-preview-set-event -->

### `b524 preview-set-event-setpoint`

<!-- BEGIN CLI HELP:b524-preview-set-event-setpoint -->

```text

 Usage: python -m helianthus_vrc_explorer b524 preview-set-event-setpoint
            [OPTIONS]

 Build an OP0C SetEventSetPoint payload without sending it.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --profile               <str>                    [required]                                                       │
│    --instance              <int range> [0<=x<=255]  [default: 0]                                                     │
│ *  --address               <str>                    [required]                                                       │
│ *  --weekday-code          <str>                    Explicit raw weekday selector; no default interpretation.        │
│                                                     [required]                                                       │
│    --value                 <str>                                                                                     │
│    --help          -h                               Show this message and exit.                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:b524-preview-set-event-setpoint -->
