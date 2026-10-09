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
│ scan          Scan a regulator; configure coverage and output in the visual UI.                                      │
│ replay-trace  Replay an ENH/ENS trace into a fresh schema-2.3 JSON artifact + HTML report.                           │
│ discover      Discover eBUS devices via QueryExistence broadcast and per-address scan (0704).                        │
│ browse        Open a scan JSON visually; connection and editing are Browser actions.                                 │
│ b524          Read B524 operation tables, edit offline, or apply a qualified timer change.                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:root -->

## `scan`

<!-- BEGIN CLI HELP:scan -->

```text

 Usage: python -m helianthus_vrc_explorer scan [OPTIONS]

 Scan a regulator; configure coverage and output in the visual UI.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --transport               <str>  Transport: tcp (ebusd hex) or ens/enh (enhanced eBUS adapter). [default: tcp]       │
│ --host                    <str>  Adapter or ebusd host. [default: 127.0.0.1]                                         │
│ --port                    <int>  Adapter or ebusd TCP port. [default: 8888]                                          │
│ --source-address          <str>  Initiator address for enhanced transport. [default: 0xF7]                           │
│ --preset                  <str>  Optional preset: recommended, full, research, or custom. When omitted, choose it in │
│                                  the startup dialog.                                                                 │
│ --help            -h             Show this message and exit.                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:scan -->

## `browse`

<!-- BEGIN CLI HELP:browse -->

```text

 Usage: python -m helianthus_vrc_explorer browse [OPTIONS]

 Open a scan JSON visually; connection and editing are Browser actions.

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                                                        │
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
│    --dst                     <str>                                                                                   │
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
