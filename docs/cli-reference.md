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
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:root -->

## `scan`

<!-- BEGIN CLI HELP:scan -->

```text

 Usage: python -m helianthus_vrc_explorer scan [OPTIONS]

 Scan a VRC regulator using B524 (GetExtendedRegisters).

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --transport                                          <str>   Transport: tcp (ebusd hex) or ens/enh (enhanced eBUS    │
│                                                              adapter).                                               │
│                                                              [default: tcp]                                          │
│ --dst                                                <str>   Destination eBUS address (e.g. 0x15) or auto (default). │
│                                                              [default: auto]                                         │
│ --source-address                                     <str>   Source initiator address for enhanced transport.        │
│                                                              Ignored for tcp.                                        │
│                                                              [default: 0xF7]                                         │
│ --host                                               <str>   ebusd host (TCP). [default: 127.0.0.1]                  │
│ --port                                               <int>   ebusd port (TCP). [default: 8888]                       │
│ --dry-run                                                    Replay a scan fixture using DummyTransport (no device   │
│                                                              I/O).                                                   │
│ --output-dir                                         <path>  Directory to write the scan JSON artifact to.           │
│                                                              [default: .]                                            │
│ --ebusd-csv-path                                     <path>  Optional ebusd configuration CSV (e.g. 15.720.csv) used │
│                                                              to annotate register names.                             │
│                                                              [env var: HELIA_EBUSD_CSV_PATH]                         │
│ --myvaillant-map-path                                <path>  Optional myVaillant-equivalence mapping CSV used to     │
│                                                              annotate register leaf names.                           │
│                                                              [env var: HELIA_MYVAILLANT_MAP_PATH]                    │
│ --trace-file                                         <path>  Write an ebusd request/response trace log to this file. │
│                                                              [env var: HELIA_EBUSD_TRACE_PATH]                       │
│ --b509-range                                         <str>   B509 register range to dump (repeatable), format:       │
│                                                              0x0000..0x00FF. Requires --b509-dump. If omitted,       │
│                                                              defaults to 0x0000..0x00FF.                             │
│ --b509-dump                --no-b509-dump                    Opt-in B509 register dump (disabled by default). Use    │
│                                                              --b509-range to narrow/expand ranges.                   │
│                                                              [default: no-b509-dump]                                 │
│ --b555-dump                --no-b555-dump                    Opt-in read-only B555 timer dump (A3/A4/A5). Disabled   │
│                                                              by default to keep the standard B524/B509 scan path     │
│                                                              unchanged.                                              │
│                                                              [default: no-b555-dump]                                 │
│ --b516-dump                --no-b516-dump                    Opt-in read-only B516 energy dump (active               │
│                                                              request/response only). Disabled by default to keep the │
│                                                              standard B524/B555/B509 scan path unchanged.            │
│                                                              [default: no-b516-dump]                                 │
│ --planner-ui                                         <str>   Interactive planner mode: disabled, auto, textual, or   │
│                                                              classic.                                                │
│                                                              [default: disabled]                                     │
│ --preset                                             <str>   Planner preset: recommended, full, research, or custom. │
│                                                              `full` expands all groups to full instance slots;       │
│                                                              `research` enables all groups with expanded RR ranges.  │
│                                                              Legacy aliases: aggressive->full, exhaustive->research, │
│                                                              conservative->recommended.                              │
│                                                              [default: recommended]                                  │
│ --no-tips                                                    Hide scan header tips in interactive terminal mode.     │
│ --redact                                                     Redact device identity fields (e.g. serial number) in   │
│                                                              console output.                                         │
│ --probe-constraints        --no-probe-constraints            Research-only live B524 opcode 0x01 constraint probe    │
│                                                              (GG/RR). Disabled by default: it can add hundreds of    │
│                                                              extra bus requests and some BASV2 setups return         │
│                                                              noisy/unreliable replies. Normal scans already use the  │
│                                                              bundled static BASV2 constraint catalog.                │
│                                                              [default: no-probe-constraints]                         │
│ --help                 -h                                    Show this message and exit.                             │
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
