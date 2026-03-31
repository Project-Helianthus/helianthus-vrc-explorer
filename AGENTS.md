# AGENTS

This repository is part of the **Helianthus Multi-Protocol HVAC Gateway Platform**.

## Dual-AI Operating Model

All development follows the dual-AI orchestrator protocol defined in the workspace-root [`AGENTS.md`](../AGENTS.md):

- **Orchestrator:** Claude Code — orchestration, hard dev (complexity 7–10), angry tester, deep consultant
- **Co-Pilot:** Codex — adversarial planning, easy dev (complexity 1–6), code review, second opinions
- Phases: Adversarial Planning → Smart Routing → Dual Code Review
- Hard rules: one issue/PR per repo, squash+merge only, doc-gate, transport-gate, MCP-first

See the root AGENTS.md for the full protocol, routing tables, system prompts, and invariants.

---

## Repo-Specific Rules

## HELIANTHUS VRC EXPLORER - MASTER PROMPT

### PROJECT OVERVIEW

You are building `helianthus-vrc-explorer`, a professional CLI tool for scanning Vaillant VRC heating regulators via eBUS protocol (command B5 24 / B524 GetExtendedRegisters). The tool produces:

1. **Live terminal UI** with rich formatting (colors, progress bars, status lines)
2. **Scrollable discovery log** showing groups, instances, and register counts
3. **JSON artifact** with complete scan results and metadata
4. **High-quality codebase** ready for production use and community contributions

---

### OPERATING MODEL (ORCHESTRATOR + SUB-AGENTS)

This repository is operated by an orchestrator that delegates every issue to a sub-agent to protect context and keep work resumable.

#### Core rules

- One issue at a time. All non-bootstrap work happens on a branch via a PR.
- Every issue is executed by a sub-agent (coder). Testing is executed by a separate sub-agent (tester).
- Max 3 concurrent agents: coder, tester, consultant. Close agents as soon as an issue is complete or an agent is idle.
- Every new step is a new agent. Do not keep agents around "just in case".
- End-of-milestone checkpoint: review all open issues for relevance and update scope/wording before starting the next milestone.

#### Merge gate (mandatory)

- Wait for CI to be green and for the GitHub review bot feedback on the PR.
- If the bot requests changes, implement fixes and wait for feedback again.
- Squash-merge only when everything is green and the maintainer explicitly says OK.

#### State persistence (mandatory)

When a sub-agent starts working on an issue or PR, it must immediately add or update an **Agent State** section in the GitHub Issue or PR description (or a comment if the description is already busy).

All state must live in:
- The GitHub Issue / PR description and comments
- The current chat conversation

Do not rely on agent memory or hidden local context.

Agent State template:

```text
Status:
Branch:
Last verified (lint/tests):
How to reproduce:
Next steps:
Notes (no secrets, no private infra):
```

#### Privacy / audit constraints (mandatory)

- Do not commit or post private identifiers (IPs other than `127.0.0.1`, serial numbers, hostnames, internal repo names).
- Local-only secrets and infrastructure details live in `AGENTS-local.md` (gitignored). This file must never be committed.

#### External references

- Example data representations (myVaillant): https://github.com/signalkraft/myPyllant/tree/main/src/myPyllant/tests/data
- Naming should follow myVaillant where applicable. Do not merge logically split registers (for example date + time).

---

### PRODUCT REQUIREMENTS

#### Core Functionality

**Scan VRC regulators using B524 protocol:**
- Auto-discover register groups (GG) via directory probe
- Enumerate instances (II) for instanced groups
- Read all registers (RR) within defined ranges
- Parse values into typed JSON (float32, u16, u8, strings, dates, times)
- Map registers to semantic names using CSV-based schema
- Resolve enum values to human-readable strings
- Handle errors gracefully (timeouts, missing registers, partial scans)

#### User Experience

**Terminal output must be polished and informative:**
- Header with device info (model, serial, firmware, hardware version)
- Live status line showing current operation (dim gray text)
- Progress bars for each scan phase (discovery, instances, registers)
- Final summary with group statistics (slots/present/active counts)
- JSON file path printed at the end
- Support for non-TTY environments (CI/CD pipelines)

#### Data Management

**All configuration data is CSV-based (not embedded in code):**
- `data/field_mappings.csv` - Register names, types, enums (auto-downloaded from GitHub)
- `data/models.csv` - VRC model lookup table (generated from the canonical list in this file)
- `data/enums.csv` - Enum value mappings (auto-extracted from field_mappings.csv)

**VRC model database (source for `data/models.csv`):**

Regenerate `data/models.csv` with:

    python scripts/generate_models_csv.py

<!-- models.csv:start -->
```csv
model_number,marketing_name,ebus_model,notes
0010036819,VRC 720/2,CTLV2,sensoCOMFORT
0020028521,VRC 430f,43000,calorMATIC 430f
0020028524,VRC 430f,43000,calorMATIC 430f
0020040079,VRC 630,63000,calorMATIC 630
0020058640,VRC 430f,43000,calorMATIC 430f
0020060427,VRC 430,43000,calorMATIC 430
0020080463,VRC 620,62000,auroMATIC 620
0020080467,VRC 630,63000,calorMATIC 630
0020080468,VRC 630,63000,calorMATIC 630
0020080472,VRC 630,63000,calorMATIC 630
0020092435,VRC 630,63000,calorMATIC 630
0020092440,VRC 630,63000,calorMATIC 630
0020108135,VRC 470f,47000,calorMATIC 470f
0020108137,VRC 470f,47000,calorMATIC 470f
0020112594,VRC 470f,47000,calorMATIC 470f
0020171314,VRC 700/2,70000,multiMATIC
0020171315,VRC 700/4,70000,multiMATIC
0020218357,VRC 700/4,70000,multiMATIC
0020231561,VRC 700(f)/4,700f0,multiMATIC
0020252922,VR920,NETX2,Internet communication module
0020252923,VR920,NETX2,Internet communication module
0020252924,VR920,NETX2,Internet communication module
0020252926,VR920,NETX2,Internet communication module
0020260962,VR921,NETX2,SensoNET
0020260963,VR921,NETX2,SensoNET
0020260964,VR921,NETX2,SensoNET
0020260965,VR921,NETX2,SensoNET
0020262148,VRC 720f/2,BASV2,sensoCOMFORT RF
0020274790,VRC 710,EMM00,sensoDIRECT
0020282696,VR921,NETX2,SensoNET
0020292012,VR940f,NETX3,myVaillant Connect
0020300000,VR940,NETX3,myVaillant Connect
0020306235,VR940f,NETX3,myVaillant Connect
0020328845,VRC 720f/3,BASV3,sensoCOMFORT RF
```
<!-- models.csv:end -->

---

### TECHNICAL REQUIREMENTS

#### Architecture

**Project structure:**

    helianthus-vrc-explorer/
    ├── src/
    │   └── helianthus_vrc_explorer/
    │       ├── __init__.py
    │       ├── __main__.py              # Entry point: python -m helianthus_vrc_explorer
    │       ├── cli.py                   # Typer CLI with all commands
    │       ├── transport/
    │       │   ├── __init__.py
    │       │   ├── base.py              # TransportInterface (ABC)
    │       │   ├── ebusd_tcp.py         # EbusdTcpTransport
    │       │   └── dummy.py             # DummyTransport (for --dry-run)
    │       ├── protocol/
    │       │   ├── __init__.py
    │       │   ├── b524.py              # B524 frame builder/parser
    │       │   └── parser.py            # Value parser (bytes -> typed values)
    │       ├── schema/
    │       │   ├── __init__.py
    │       │   ├── loader.py            # CSV schema loader
    │       │   ├── mapper.py            # Register -> semantic name mapper
    │       │   └── models.py            # Dataclasses for schema
    │       ├── scanner/
    │       │   ├── __init__.py
    │       │   ├── director.py          # Group discovery orchestrator
    │       │   └── register.py          # Register scanner
    │       └── ui/
    │           ├── __init__.py
    │           ├── live.py              # Rich live display
    │           └── summary.py           # Final output formatter
    ├── data/
    │   ├── field_mappings.csv           # Auto-downloaded from GitHub
    │   ├── models.csv                   # VRC model database
    │   └── enums.csv                    # Generated from field_mappings
    ├── fixtures/
    │   └── vrc720_full_scan.json        # Test data for --dry-run
    ├── tests/
    │   ├── test_transport.py
    │   ├── test_protocol.py
    │   ├── test_schema.py
    │   └── test_scanner.py
    ├── pyproject.toml                   # Poetry/setuptools config
    ├── README.md
    ├── AGENTS.md                        # Agent orchestration guide
    ├── AGENTS-local.md                  # Local-only (gitignored)
    ├── LICENSE                          # GPLv3
    └── .github/
        └── workflows/
            └── ci.yml                   # Linting + tests

#### Transport Layer

**EbusdTcpTransport implementation:**

The ebusd daemon exposes a TCP interface (typically `127.0.0.1:8888`). Responses may be multiline: treat the first hex line as the payload and ignore trailing `ERR` lines.

**Special types (from CSV schema):**
- `HDA:3` = date (u24le encoded as DDMMYY)
- `HTI` = time (u24le encoded as HH:MM:SS)
- `EXP` = float32le (exponential/temperature)
- `STR:*` = cstring
- `UCH` = u8 with enum
- `UIN` = u16le with enum

**CSV encoding (id column):**

    b524,020002000f00  ->  0x02 0x00 0x02 0x00 0x0F 0x00
                          ^^^^^ ^^^^^ ^^^^^ ^^^^^ ^^^^^^^^^^^
                          opcode optype  GG    II      RR

Examples from VRC720 CSV:
- `b524,020003001600` -> GG=0x03, II=0x00, RR=0x0016 (zone name)
- `b524,020002000f00` -> GG=0x02, II=0x00, RR=0x000F (heating curve)

---

**Family 0x06: Remote Register Space (Read/Write)**

**Status:** CONFIRMED (VRC720 CSV patterns)

**Request payload (READ):**

    Length: 0x06
    Bytes:  0x06 0x00 <GG> <II> <RR_LO> <RR_HI>

    Semantics:
    - byte 0: opcode 0x06 (remote register space)
    - byte 1: optype 0x00 (read)
    - byte 2-5: same as Family 0x02 (GG, II, RR)

**Request payload (WRITE):**

    Length: 0x06 + value_length
    Bytes:  0x06 0x01 <GG> <II> <RR_LO> <RR_HI> <value_bytes...>

**Response format:** Same as Family 0x02 (4-byte echo + value tail)

**CSV encoding:**

    b524,06000a010f00  ->  0x06 0x00 0x0A 0x01 0x0F 0x00
                          ^^^^^ ^^^^^ ^^^^^ ^^^^^ ^^^^^^^^^^^
                          opcode optype  GG    II      RR

Examples from VRC720 CSV:
- `b524,060009010700` -> GG=0x09, II=0x01, RR=0x0007 (room humidity, Radio Sensors VRC7xx)
- `b524,06000a010f00` -> GG=0x0A, II=0x01, RR=0x000F (room temp, VR92 addr 1)

**Difference from Family 0x02:**
- Opcode 0x06 targets **remote sensor units** (VR92, external thermostats)
- Opcode 0x02 targets **local VRC regulator** registers
- Same (GG, II, RR) structure, different address space

---

**Family 0x03/0x04: Timer Schedules (Read/Write)**

**Status:** CONFIRMED (VRC700 CSV evidence, multiple timer categories)

**CRITICAL DIFFERENCE:** Unlike families 0x02/0x06, timer families use **opcode itself** to distinguish read (0x03) vs write (0x04). There is NO separate optype byte.

**Request payload (READ):**

    Length: 0x05
    Bytes:  0x03 <SEL1> <SEL2> <SEL3> <WEEKDAY>

    Semantics:
    - byte 0: opcode 0x03 (read timer)
    - byte 1-3: selector tuple (domain/entity/kind)
    - byte 4: weekday (0x00=Monday, 0x01=Tuesday, ..., 0x06=Sunday)

**Request payload (WRITE):**

    Length: 0x05 + schedule_data_length
    Bytes:  0x04 <SEL1> <SEL2> <SEL3> <WEEKDAY> <TTM_blocks...>

**Selector tuple semantics (INFERRED from CSV patterns):**

    Category                | SEL1 | SEL2 | SEL3 | CSV ID Prefix
    ------------------------|------|------|------|---------------
    VentilationTimer        | 0x00 | 0x00 | 0x01 | 0300000100
    NoiseReductionTimer     | 0x00 | 0x00 | 0x02 | 0300000200
    TariffTimer             | 0x00 | 0x00 | 0x03 | 0300000300
    HwcTimer (hot water)    | 0x01 | 0x00 | 0x01 | 0301000100
    CcTimer (circulation)   | 0x01 | 0x00 | 0x02 | 0301000200
    Z1HeatingTimer          | 0x03 | 0x00 | 0x02 | 0303000200
    Z1CoolingTimer          | 0x03 | 0x00 | 0x01 | 0303000100
    Z2HeatingTimer          | 0x03 | 0x01 | 0x02 | 0303010200
    Z2CoolingTimer          | 0x03 | 0x01 | 0x01 | 0303010100
    Z3HeatingTimer          | 0x03 | 0x02 | 0x02 | 0303020200

**Pattern analysis:**
- SEL1 appears to encode **domain** (0x00=system, 0x01=water, 0x03=zones)
- SEL2 encodes **entity instance** (zone index for zones, 0x00 for singletons)
- SEL3 encodes **timer kind** (heating=0x02, cooling=0x01, varies by domain)

**Weekday encoding (CONFIRMED):**

    0x00 = Monday
    0x01 = Tuesday
    0x02 = Wednesday
    0x03 = Thursday
    0x04 = Friday
    0x05 = Saturday
    0x06 = Sunday

**Response format (READ):**

Timer schedules are returned as **TTM (Time Tuple Matrix) blocks**. From CSV evidence:
- Each day can have multiple time slots (e.g., 3 heating periods)
- Each slot is represented as a TTM pair: `<from_time> <to_time>`
- CSV templates show patterns like: `IGN:1, TTM, TTM, IGN:2` (read)
- Write templates: `slotindex (UCH), slotcount (UCH), TTM, TTM, ...`

**TTM encoding:** Time tuples in ebusd's proprietary format (details are tool-specific, not reversed here). Each TTM represents a time range like "06:00-22:00".

**CSV encoding examples (VRC700):**

READ timer (Monday):

    b524,0300000100  ->  0x03 0x00 0x00 0x01 0x00
                        ^^^^^ ^^^^^^^^^^^ ^^^^^
                        opcode  selector  weekday

WRITE timer (Sunday):

    b524,0400000106  ->  0x04 0x00 0x00 0x01 0x06

More examples proving weekday encoding:
- VentilationTimer_Monday: `0300000100` (read), `0400000100` (write)
- VentilationTimer_Sunday: `0300000106` (read), `0400000106` (write)
- HwcTimer_Wednesday: `0301000102` (read), `0401000102` (write)
- Z2CoolingTimer_Friday: `0303010104` (read), `0403010104` (write)

**Implications:**
- Timer scans are NOT register iteration (no RR loop)
- Iteration is over: (selector_tuple, weekday=0..6)
- Each combination yields one schedule (multiple TTM blocks per day)

---

##### Protocol Family Summary Table

    Opcode | Family Name       | Payload Len | Structure                         | Status
    -------|-------------------|-------------|-----------------------------------|----------
    0x00   | Directory Probe   | 3           | 00 <GG> 00                        | CONFIRMED
    0x01   | Constraint Probe  | 3           | 01 <GG> <RR>                      | EXPERIMENTAL
    0x02   | Local Registers   | 6 (+val)    | 02 <RW> <GG> <II> <RR_LO> <RR_HI> | CONFIRMED
    0x06   | Remote Registers  | 6 (+val)    | 06 <RW> <GG> <II> <RR_LO> <RR_HI> | CONFIRMED
    0x03   | Timer Read        | 5           | 03 <SEL1> <SEL2> <SEL3> <WD>      | CONFIRMED
    0x04   | Timer Write       | 5 (+blocks) | 04 <SEL1> <SEL2> <SEL3> <WD> ...  | CONFIRMED

**Notes:**
- `<RW>` = optype (0x00=read, 0x01=write) for families 0x02/0x06
- `<WD>` = weekday (0x00..0x06)
- Timer families (0x03/0x04) do NOT use optype byte

**Opcode 0x01 (Constraint Probe):**
- Request payload: `01 <GG> <RR>` (RR is a u8 selector, not the u16 RR used by register reads).
- Observed response header: `<TT> <GG> <RR> 00 ...`
- This probe is **off by default** because some BASV2 setups return noisy/unreliable replies.

Observed TT tags (decoded today):
- `0x06` (u8 range): `06 GG RR 00 MIN MAX STEP`
- `0x09` (u16 range, LE): `09 GG RR 00 MINlo MINhi MAXlo MAXhi STEPlo STEPhi`
- `0x0F` (float32 range, LE): `0F GG RR 00 MIN(f32le) MAX(f32le) STEP(f32le)`
- `0x0C` (date range): `0C GG RR 00 MIN(d,m,y) MAX(d,m,y) STEP(u16le) 00`

---

#### Implications for Tooling

**Critical design decisions:**

1. **DO NOT use "opclass" terminology** anywhere in code or documentation
   - Use precise terms: `opcode`, `optype` (where applicable), `selector_bytes`
   - Treat payload as raw bytes, parse by opcode dispatch

2. **Schema loader must support variable-length CSV id fields:**
   - Family 0x00: 3 bytes (directory probe, not in CSV)
   - Family 0x02/0x06: 6 bytes (opcode + optype + GG + II + RR)
   - Family 0x03/0x04: 5 bytes (opcode + selector_tuple + weekday)

3. **Register scans only apply to families 0x02 and 0x06:**
   - Iterate over (GG, II, RR) for discovered instances
   - Use opcode 0x02 for local VRC registers
   - Use opcode 0x06 for remote sensor registers (GG=0x09, 0x0A typical)

4. **Timer scans are separate workflow (not in MVP scope):**
   - Would iterate over (selector_tuple, weekday=0..6)
   - Requires understanding TTM block parsing (ebusd-specific)
   - Recommended for future enhancement

5. **CSV id parsing algorithm:**

```python
def parse_b524_id(id_hex: str) -> dict:
    """Parse ebusd CSV b524 id field into structured selector."""
    payload = bytes.fromhex(id_hex)
    opcode = payload[0]

    if opcode == 0x00:
        return {"family": "directory", "group": payload[1]}

    elif opcode in {0x02, 0x06}:
        return {
            "family": "local_registers" if opcode == 0x02 else "remote_registers",
            "optype": payload[1],  # 0x00=read, 0x01=write
            "group": payload[2],
            "instance": payload[3],
            "register": struct.unpack('<H', payload[4:6])[0],
        }

    elif opcode in {0x03, 0x04}:
        return {
            "family": "timer_read" if opcode == 0x03 else "timer_write",
            "selector": (payload[1], payload[2], payload[3]),
            "weekday": payload[4],
        }

    else:
        raise ValueError(f"Unknown B524 opcode: 0x{opcode:02X}")
```

6. **Agent discovery protocol:**
   - If agent discovers NEW B524 opcode families during development, they MUST:
     - Document findings in GitHub issue (if not repo owner)
     - Submit PR with evidence (wire captures, CSV patterns)
     - Update AGENTS.md with protocol details
     - Add test fixtures demonstrating new family
   - Do NOT guess at opcode semantics without evidence

---

#### Group Configuration

**Known groups (hardcoded reference, validated against CSV):**

    GROUP_CONFIG = {
        0x00: {"desc": 3.0, "name": "Regulator Parameters", "ii_max": 0x00, "rr_max": 0x00FF, "opcodes": [0x02]},
        0x01: {"desc": 3.0, "name": "Hot Water Circuit", "ii_max": 0x00, "rr_max": 0x13, "opcodes": [0x02]},
        0x02: {"desc": 1.0, "name": "Heating Circuits", "ii_max": 0x0A, "rr_max": 0x25, "opcodes": [0x02]},
        0x03: {"desc": 1.0, "name": "Zones", "ii_max": 0x0A, "rr_max": 0x2E, "opcodes": [0x02]},
        0x04: {"desc": 6.0, "name": "Solar Circuit", "ii_max": 0x00, "rr_max": 0x0B, "opcodes": [0x02]},
        0x05: {"desc": 1.0, "name": "Hot Water Cylinder", "ii_max": 0x01, "rr_max": 0x04, "opcodes": [0x02]},
        0x08: {"name": "Buffer / Solar Cylinder 2", "ii_max": 0x0A, "rr_max": 0x07, "opcodes": [0x02, 0x06], "rr_max_by_opcode": {0x02: 0x07, 0x06: 0x04}, "ii_max_by_opcode": {0x02: 0x00, 0x06: 0x0A}},
        0x09: {"desc": 1.0, "name": "Radio Sensors VRC7xx", "ii_max": 0x0A, "rr_max": 0x35, "opcodes": [0x02, 0x06], "rr_max_by_opcode": {0x02: 0x0F, 0x06: 0x35}},
        0x0A: {"desc": 1.0, "name": "Radio Sensors VR92", "ii_max": 0x0A, "rr_max": 0x4D, "opcodes": [0x02, 0x06], "rr_max_by_opcode": {0x02: 0x4D, 0x06: 0x35}},
        0x0C: {"desc": 1.0, "name": "Remote Accessories / FM5 Slots", "ii_max": 0x0A, "rr_max": 0x2F, "opcodes": [0x06]},
    }

**Register families by group:**

    Group  | Opcode Family | Notes
    -------|---------------|-----------------------------------------------
    0x00   | 0x02 (local)  | Regulator parameters (singleton)
    0x01   | 0x02 (local)  | Singleton (no instances)
    0x02   | 0x02 (local)  | Heating circuits (instanced)
    0x03   | 0x02 (local)  | Zones (instanced)
    0x04   | 0x02 (local)  | Solar circuit (special Type 6 format)
    0x05   | 0x02 (local)  | Hot water cylinder (instanced)
    0x08   | 0x02/0x06     | Buffer / Solar Cylinder 2 (local singleton + remote instanced)
    0x09   | 0x02/0x06     | Radio Sensors VRC7xx
    0x0A   | 0x02/0x06     | Radio Sensors VR92
    0x0C   | 0x06 (remote) | Remote accessories / FM5 slots

**Instance presence detection (per-group heuristics):**

- **GG=0x02 (Heating Circuits):** Probe RR=0x0002 (CircuitType u16). Absent if response is 0x0000, 0xFFFF, or NaN.
- **GG=0x03 (Zones):** Probe RR=0x001C (zone index u8). Absent if response is 0xFF.
- **GG=0x08 (Buffer / Solar Cylinder 2):** Include it in documented group enumerations; local `0x02` stays singleton while remote `0x06` can be instanced.
- **GG=0x09 / 0x0A (Radio Sensors VRC7xx / Radio Sensors VR92):** Present if RR=0x0007 or RR=0x000F returns non-NaN.
- **GG=0x0C (Remote Accessories / FM5 Slots):** Present if any of RR in {0x0002, 0x0007, 0x000F, 0x0016} responds.

**Instance discovery probes all slots from 0x00 to ii_max** (do not stop at gaps, they are legitimate holes). The default register scan then uses the discovered present set; only the `full` preset expands back to every slot.

#### Schema Loading

**CSV source:**

Download from GitHub (cache locally for 24h):

    https://raw.githubusercontent.com/burmistrzak/ebusd-configuration/refs/heads/add-720-series/src/vaillant/15.720.csv

**CSV structure (relevant columns):**

    type,circuit,level,name,comment,qq,zz,pbsb,id,*name,part,type,divisor/values,unit,comment
    r,,,Z1Shortname,short name of zone 1,,,b524,020003001600,value,,IGN:4,,,,value,,STR:*,,,name

**Parsing logic:**

Extract from `id` column (hex string):

**For register families (6 bytes):**

    b524,020003001600  ->  parse as: 02 00 03 00 16 00

    - Bytes 0-1: opcode + optype (0x02 0x00)
    - Byte 2: GG (group) = 0x03
    - Byte 3: II (instance) = 0x00
    - Bytes 4-5: RR (register, LE) = 0x0016

**For timer families (5 bytes):**

    b555,0300000100  ->  parse as: 03 00 00 01 00

    - Byte 0: opcode 0x03 (read timer)
    - Bytes 1-3: selector tuple (0x00, 0x00, 0x01)
    - Byte 4: weekday = 0x00 (Monday)

Extract from `type` column (after second occurrence):
- `STR:*` -> cstring
- `EXP` -> float32le
- `UCH` -> u8
- `UIN` -> u16le
- `HDA:3` -> u24le date
- `HTI` -> u24le time

Extract enums from `divisor/values` column:

    0=off;1=on;2=auto  ->  {0: "off", 1: "on", 2: "auto"}

**Fallback:** If register not in CSV, use type inference from response length.

#### CLI Interface

The CLI is canonicalized via `--help` output. This prevents drift between:
- README (user docs)
- AGENTS.md (engineering spec)
- the actual Typer CLI implementation

CI enforces this via `python scripts/check_docs_sync.py`.

<!-- BEGIN CLI HELP:root -->

```text

 Usage: python -m helianthus_vrc_explorer [OPTIONS] COMMAND [ARGS]...

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --version            Print version and exit.                                                                         │
│ --help     -h        Show this message and exit.                                                                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ scan      Scan a VRC regulator using B524 (GetExtendedRegisters).                                                    │
│ discover  Discover eBUS devices via QueryExistence broadcast and per-address scan (0704).                            │
│ browse    Browse scan results in fullscreen Textual UI (file mode).                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:root -->

<!-- BEGIN CLI HELP:scan -->

```text

 Usage: python -m helianthus_vrc_explorer scan [OPTIONS]

 Scan a VRC regulator using B524 (GetExtendedRegisters).

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --transport                                          TEXT     Transport: tcp (ebusd hex) or ens/enh (enhanced eBUS   │
│                                                               adapter).                                              │
│                                                               [default: tcp]                                         │
│ --dst                                                TEXT     Destination eBUS address (e.g. 0x15) or auto           │
│                                                               (default).                                             │
│                                                               [default: auto]                                        │
│ --source-address                                     TEXT     Source initiator address for enhanced transport.       │
│                                                               Ignored for tcp.                                       │
│                                                               [default: 0xF7]                                        │
│ --host                                               TEXT     ebusd host (TCP). [default: 127.0.0.1]                 │
│ --port                                               INTEGER  ebusd port (TCP). [default: 8888]                      │
│ --dry-run                                                     Replay a scan fixture using DummyTransport (no device  │
│                                                               I/O).                                                  │
│ --output-dir                                         PATH     Directory to write the scan JSON artifact to.          │
│                                                               [default: .]                                           │
│ --ebusd-csv-path                                     PATH     Optional ebusd configuration CSV (e.g. 15.720.csv)     │
│                                                               used to annotate register names.                       │
│                                                               [env var: HELIA_EBUSD_CSV_PATH]                        │
│ --myvaillant-map-path                                PATH     Optional myVaillant-equivalence mapping CSV used to    │
│                                                               annotate register leaf names.                          │
│                                                               [env var: HELIA_MYVAILLANT_MAP_PATH]                   │
│ --trace-file                                         PATH     Write an ebusd request/response trace log to this      │
│                                                               file.                                                  │
│                                                               [env var: HELIA_EBUSD_TRACE_PATH]                      │
│ --b509-range                                         TEXT     B509 register range to dump (repeatable), format:      │
│                                                               0x0000..0x00FF. If omitted, defaults to                │
│                                                               0x0000..0x00FF.                                        │
│ --b555-dump                --no-b555-dump                     Opt-in read-only B555 timer dump (A3/A4/A5). Disabled  │
│                                                               by default to keep the standard B524/B509 scan path    │
│                                                               unchanged.                                             │
│                                                               [default: no-b555-dump]                                │
│ --b516-dump                --no-b516-dump                     Opt-in read-only B516 energy dump (active              │
│                                                               request/response only). Disabled by default to keep    │
│                                                               the standard B524/B555/B509 scan path unchanged.       │
│                                                               [default: no-b516-dump]                                │
│ --planner-ui                                         TEXT     Interactive planner mode: disabled, auto, textual, or  │
│                                                               classic.                                               │
│                                                               [default: disabled]                                    │
│ --preset                                             TEXT     Planner preset: conservative, recommended, full,       │
│                                                               exhaustive, or custom. `full` scans every instance     │
│                                                               slot and full RR ranges; `exhaustive` also injects all │
│                                                               GG 0x00-0x11 groups. Expect very long runs.            │
│                                                               [default: recommended]                                 │
│ --no-tips                                                     Hide scan header tips in interactive terminal mode.    │
│ --redact                                                      Redact device identity fields (e.g. serial number) in  │
│                                                               console output.                                        │
│ --probe-constraints        --no-probe-constraints             Research-only live B524 opcode 0x01 constraint probe   │
│                                                               (GG/RR). Disabled by default: it can add hundreds of   │
│                                                               extra bus requests and some BASV2 setups return        │
│                                                               noisy/unreliable replies. Normal scans already use the │
│                                                               bundled static BASV2 constraint catalog.               │
│                                                               [default: no-probe-constraints]                        │
│ --help                 -h                                     Show this message and exit.                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:scan -->

<!-- BEGIN CLI HELP:browse -->

```text

 Usage: python -m helianthus_vrc_explorer browse [OPTIONS]

 Browse scan results in fullscreen Textual UI (file mode).

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --file                 PATH  Path to an existing scan JSON artifact (default browse mode).                           │
│ --live                       Live mode (planned). In P0, only --file mode is implemented.                            │
│ --device               TEXT  Device identifier for --live mode (planned).                                            │
│ --allow-write                Enable write/edit actions in browse UI (safe mode + confirmation). Note: --file mode    │
│                              edits do not write to the device.                                                       │
│ --help         -h            Show this message and exit.                                                             │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:browse -->

<!-- BEGIN CLI HELP:discover -->

```text

 Usage: python -m helianthus_vrc_explorer discover [OPTIONS]

 Discover eBUS devices via QueryExistence broadcast and per-address scan (0704).

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --host                TEXT     ebusd host (TCP). [default: 127.0.0.1]                                                │
│ --port                INTEGER  ebusd port (TCP). [default: 8888]                                                     │
│ --trace-file          PATH     Write an ebusd request/response trace log to this file.                               │
│                                [env var: HELIA_EBUSD_TRACE_PATH]                                                     │
│ --help        -h               Show this message and exit.                                                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<!-- END CLI HELP:discover -->

#### Terminal UI

**Session preface (printed once at start in TTY mode):**

    helianthus-vrc-explorer v0.1.0
    Scanning VRC Regulator (B524) at address 0x15
    Device:        Wireless 720-series Regulator BAse Station Vaillant-branded Revision 2 (BASV2)
    Model:         Vaillant sensoCOMFORT RF (VRC 720f/2) 0020262148
    Serial:        <SERIAL_NUMBER_REDACTED>
    Firmware:      SW 0507 / HW 1704
    ebusd:         127.0.0.1:8888
    Started:       2026-02-17 15:24:12Z

**Live status area (using rich.live.Live):**

    Read GG=0x02 II=0x03 RR=0x001C     <- last line (updates periodically; no scrollback spam)

**Progress bars (rich.progress.Progress):**

    Group Discovery    ━━━━━━━━━━━━ 19/19     0:00:06
    Constraint Probe   ━━━━━━━━━━━━ 120/120   0:00:02   (only if --probe-constraints)
    Instance Discovery ━━━━━━━━━━━━ 66/66     0:00:39
    Register Scan      ━━━━━━━━━━━━ 431/2482  0:03:51
    B509 Dump          ━━━━━━━━━━━━ 256/256   0:00:10   (default range 0x0000..0x00FF)

**Canonical scan phases (user-visible):**
- Group Discovery
- Constraint Probe (optional; only with `--probe-constraints`)
- Instance Discovery
- Register Scan
- B509 Dump (post-scan; range configurable via `--b509-range`)

**Sub-steps (not separate progress phases):**
- Group Classification (naming + descriptor mismatch warnings)
- Planner (preset + optional interactive overrides)

**Scrollback output (stable milestones only):**

    ✓ Discovered group GG=0x00 desc=3.0
    ✓ Discovered group GG=0x01 desc=3.0
    ✓ Discovered group GG=0x02 desc=1.0
    ...
    ⚠ Descriptor mismatch for GG=0x04: expected 6.0, got 5.0
    ⚠ Found 2 unknown groups (0x06, 0x07); skipped by default (enable in planner).
    ✓ GG=0x02 Heating Circuits: 3/11 present, RR_max=0x0025 (38 registers/instance)
    ✓ GG=0x03 Zones: 2/11 present, RR_max=0x002F (48 registers/instance)

**Final output:**

    Scan completed in 127.4s
    Wrote JSON: ./out/b524_scan_0x15_2026-02-06T194424Z.json

**Non-TTY mode (CI/CD):**

Detect via `sys.stdout.isatty()`. If false:
- the rich live UI is disabled (Null observer),
- a small preface + summary are printed to stderr,
- stdout prints the JSON artifact path only (stable for scripting).

#### Browse UI (fullscreen Textual)

The project includes a fullscreen Textual browser for scan artifacts:
- Launch directly: `python -m helianthus_vrc_explorer browse --file <artifact.json>`
- Post-scan default (TTY): the browse UI opens automatically after scan; press `q` to exit back to the summary.

Core UX:
- Left tree: B524 groups + instances (instance labels prefer discovered names when available).
- Right panel: tabs `Config`, `Config-Limits`, `State`.
- Search: `/` (scoped to current focus), `n/N` next/prev match.
- Watch: `w` toggle watch on selected row; `r` set poll interval; `p` pin/unpin.
- Safe edit: `--allow-write` enables edit actions with confirmation dialogs.

Notes:
- P0 uses `--file` mode only (offline artifact). `--live` is planned.

#### JSON Output

**File path:**

    ./out/b524_scan_<DST>_<ISO8601>.json

Example: `./out/b524_scan_0x15_2026-02-06T194424Z.json`

**JSON structure:**

    {
      "meta": {
        "scan_timestamp": "2026-02-06T19:44:24Z",
        "scan_duration_seconds": 127.4,
        "destination_address": "0x15",
        "source_address": "0x31",
        "ebusd_host": "127.0.0.1",
        "ebusd_port": 8888,
        "device_info": {
          "manufacturer": "Vaillant",
          "ebus_model": "BASV2",
          "marketing_name": "VRC 720f/2",
          "model_number": "0020262148",
          "serial_number": "<SERIAL_NUMBER_REDACTED>",
          "software_version": "0507",
          "hardware_version": "1704"
        },
        "schema_sources": [
          "https://raw.githubusercontent.com/burmistrzak/ebusd-configuration/refs/heads/add-720-series/src/vaillant/15.720.csv"
        ],
        "incomplete": false
      },
      "groups": {
        "0x02": {
          "name": "Heating Circuits",
          "descriptor_type": 1.0,
          "instances": {
            "0x00": {
              "present": true,
              "registers": {
                "0x0002": {
                  "name": "heating_circuit_type",
                  "type": "u16le",
                  "value": 1,
                  "enum_resolved": "MIXER_CIRCUIT_EXTERNAL",
                  "raw_hex": "0100"
                },
                "0x000F": {
                  "name": "heating_curve",
                  "type": "float32",
                  "value": 1.7,
                  "unit": "C/C",
                  "raw_hex": "9a99d93f"
                }
              }
            }
          }
        }
      }
    }

**NaN handling:** Represent as `null` in JSON.

**Unknown enums:** If enum value not in CSV mappings, include both:

    "value": 42,
    "enum_resolved": "UNKNOWN_0x2A"

**Partial scans (Ctrl+C):**

    "meta": {
      "incomplete": true,
      "incomplete_reason": "user_interrupt",
      "scan_duration_seconds": 45.2
    }

#### Error Handling

**Transport setup (startup failures):**
- If connecting to the **default** transport (`tcp://127.0.0.1:8888`) fails in an interactive TTY,
  the scan command opens a retry dialog so the user can edit protocol/host/port and retry or cancel.
- In non-interactive environments (or when a non-default endpoint is requested), fail fast.

**ebusd command gating:**
- If ebusd returns `ERR: command not enabled`, the tool exits with an instruction to restart ebusd
  with `--enablehex` (do not continue scanning).

**Timeouts / invalid responses during scan:**
- Errors are recorded inline per-entry (`error` field) and scanning continues (best-effort).
- On `ebusd-tcp`, `ERR: timeout`, `ERR: arbitration lost`, `ERR: SYN received`, and `ERR: wrong symbol received`
  trigger a fixed 5-second quiet backoff before retry so the bus can settle.
- On `ebusd-tcp`, `ERR: no signal` triggers a fixed 15-second quiet backoff before retry so the
  eBUS side can recover instead of being polled aggressively.
- Partial scans are valid: Ctrl+C results in `meta.incomplete=true` with a reason string.

**Signal handling:**
- SIGINT (Ctrl+C) -> graceful shutdown, save partial JSON with `incomplete: true`
- SIGTERM -> immediate save + exit(0)

**Unknown enum values:**
- Keep numeric value
- Add `"enum_resolved": "UNKNOWN_0x42"`
- In final summary, suggest: "Found unknown enum values. Please report at https://github.com/user/helianthus-vrc-explorer/issues"

#### Field Mappings (Schema)

**Register-to-semantic-name mappings (from CSV):**

**GG=0x02 (Heating Circuits, per-instance II):**

    RR     | Type      | Enum                     | Semantic Name
    -------|-----------|--------------------------|--------------------------------------------------
    0x0002 | u16le     | 1=MIXER_CIRCUIT_EXTERNAL | circuits[].extra_fields.heating_circuit_type
    0x000E | u16le     | 0=false;1=true           | circuits[].set_back_mode_enabled
    0x000F | float32le | -                        | circuits[].heating_curve
    0x0010 | float32le | -                        | circuits[].heating_flow_temperature_maximum_setpoint
    0x0012 | float32le | -                        | circuits[].heating_flow_temperature_minimum_setpoint
    0x0014 | float32le | -                        | circuits[].heat_demand_limited_by_outside_temperature
    0x0015 | u16le     | 0=NON;2=THERMOSTAT_FUNCTION | circuits[].extra_fields.room_temperature_control_mode
    0x000A | float32le | -                        | circuits[].extra_fields.epsilon

**GG=0x03 (Zones, per-zone slot II):**

    RR     | Type      | Enum                     | Semantic Name
    -------|-----------|--------------------------|--------------------------------------------------
    0x0016 | cstring   | -                        | configuration.zones[].general.name
    0x0017 | cstring   | -                        | configuration.zones[].general.name_prefix
    0x0018 | cstring   | -                        | configuration.zones[].general.name_suffix
    0x0005 | float32le | -                        | configuration.zones[].general.holiday_setpoint
    0x0003 | u24 (date)| -                        | configuration.zones[].general.holiday_start_date
    0x0021 | u24 (time)| -                        | configuration.zones[].general.holiday_start_time
    0x0004 | u24 (date)| -                        | configuration.zones[].general.holiday_end_date
    0x0020 | u24 (time)| -                        | configuration.zones[].general.holiday_end_time
    0x0006 | u16le     | 2=MANUAL                 | configuration.zones[].heating.operation_mode_heating
    0x0009 | float32le | -                        | configuration.zones[].heating.set_back_temperature
    0x0014 | float32le | -                        | configuration.zones[].heating.manual_mode_setpoint
    0x0022 | float32le | -                        | configuration.zones[].heating.desired_setpoint
    0x000E | u8        | 0=NONE                   | state.zones[].current_special_function
    0x000F | float32le | -                        | state.zones[].current_room_temperature
    0x0028 | float32le | -                        | state.zones[].current_room_humidity
    0x0013 | u16le     | -                        | configuration.zones[].associated_circuit_index_raw (1-based)
    0x001C | u8        | 0xFF=ABSENT_SLOT         | configuration.zones[].index
    0x0008 | float32le | -                        | configuration.zones[].quick_veto.temperature
    0x0024 | u24 (date)| -                        | configuration.zones[].quick_veto.end_date
    0x001E | u24 (time)| -                        | configuration.zones[].quick_veto.end_time
    0x0026 | u24 (time)| -                        | configuration.zones[].quick_veto.duration

**GG=0x09 / 0x0A (Room sensors/state):**

    RR     | Type      | Semantic Name
    -------|-----------|---------------------------
    0x0007 | float32le | room_humidity
    0x000F | float32le | room_temperature

**Known enums (extracted from CSV):**

    GG=0x02, RR=0x0002 (heating_circuit_type):
      1 -> "MIXER_CIRCUIT_EXTERNAL"

    GG=0x02, RR=0x0015 (room_temperature_control_mode):
      0 -> "NON"
      2 -> "THERMOSTAT_FUNCTION"

    GG=0x02, RR=0x000E (set_back_mode_enabled):
      0 -> false
      1 -> true

    GG=0x03, RR=0x0006 (operation_mode_heating):
      2 -> "MANUAL"

    GG=0x03, RR=0x000E (current_special_function):
      0 -> "NONE"

    GG=0x03, RR=0x001C (zone index/presence):
      0xFF -> "ABSENT_SLOT"

#### Testing Requirements

**Unit tests (pytest):**
- `test_transport.py` - EbusdTcpTransport parsing, retry logic, error handling
- `test_protocol.py` - B524 frame encoding, value parsing (all types)
- `test_schema.py` - CSV loading, enum resolution, fallback logic
- `test_scanner.py` - Group discovery, instance detection, register scanning

**Integration tests:**
- DummyTransport with `fixtures/vrc720_full_scan.json` must complete without errors
- Verify JSON output structure matches schema
- Test partial scan (simulated interrupt)

**Coverage target:** >80%

**CI/CD (GitHub Actions):**

    name: CI
    on: [push, pull_request]
    jobs:
      lint:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - uses: actions/setup-python@v4
          - run: pip install ruff mypy
          - run: ruff check .
          - run: mypy src

      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - uses: actions/setup-python@v4
          - run: pip install -e ".[dev]"
          - run: pytest --cov --cov-report=xml
          - uses: codecov/codecov-action@v3

#### Development Workflow

**Issue-driven development:**
1. Each feature/bugfix gets a GitHub issue
2. Create branch from `main`: `git checkout -b issue-<N>-<description>`
3. Implement with tests
4. Run linting: `ruff check . && mypy src`
5. Run tests: `pytest`
6. Create PR, wait for CI + @codex review
7. Address feedback, push updates
8. When approved + CI green -> squash merge to `main`

**Milestones:**
- M1: Bootstrap (project structure, CI/CD, dummy transport)
- M2: Protocol layer (B524 encoder/decoder, value parser)
- M3: Transport layer (ebusd TCP client)
- M4: Schema layer (CSV loader, enum resolver)
- M5: Scanner (group discovery, instance enumeration, register dump)
- M6: UI (rich live display, summary output)
- M7: CLI (argument parsing, error handling)
- M8: Documentation (README, examples, API docs)

**Data files (non-code):**
- All CSV/JSON files in `data/` and `fixtures/` are edited via separate PRs
- No CSV parsing logic in PRs that modify CSV structure
- Model database updates can be contributed by non-programmers

#### Code Quality Standards

**Python version:** 3.12+

**Dependencies (pyproject.toml):**

    [project]
    name = "helianthus-vrc-explorer"
    version = "0.1.0"
    requires-python = ">=3.12"
    dependencies = [
        "typer>=0.9.0",
        "rich>=13.0.0",
        "textual>=0.82.0",
        "httpx>=0.24.0",
    ]

    [project.optional-dependencies]
    dev = [
        "pillow>=10.0.0",
        "pytest>=8.0.0",
        "pytest-cov>=5.0.0",
        "ruff>=0.6.0",
        "mypy>=1.5.0",
    ]

**Linting:** ruff with strict settings
**Type checking:** mypy in strict mode
**Formatting:** ruff format (black-compatible)

**Docstrings:** Google style

    def parse_b524_response(data: bytes) -> dict[str, Any]:
        """Parse B524 response payload into typed values.

        Args:
            data: Raw response bytes (after stripping 4-byte header)

        Returns:
            Dictionary with keys: type, value, raw_hex

        Raises:
            ValueError: If data length is invalid for any known type
        """

**Logging:** Use Python `logging` module, not print statements (except for final output)

#### README.md Structure

**Include:**
1. Project description (1-2 paragraphs)
2. Features (bullet list)
3. Installation (`pip install helianthus-vrc-explorer`)
4. Quick start example
5. CLI reference (generated from typer)
6. CSV schema documentation
7. Contributing guide
8. License (GPLv3)
9. Credits/acknowledgments

**Example:**

    ## Helianthus VRC Explorer

    Professional CLI tool for scanning Vaillant VRC heating regulators via eBUS protocol.

    ### Features

    - Auto-discover register groups and instances
    - Parse typed values (float32, u16, u8, strings, dates, times)
    - Resolve enums to human-readable names
    - Rich terminal UI with live progress
    - JSON output for integration
    - CSV-based schema (contribute without coding)

    ### Installation

        pip install helianthus-vrc-explorer

    ### Quick Start

        ## Scan VRC at address 0x15
        helianthus-vrc-explorer scan --dst 0x15

    ### Contributing

    See CONTRIBUTING.md

    ### License

    GPLv3 - see LICENSE

#### AGENTS.md (For Codex Orchestration)

**Include:**
1. Project goals and architecture overview
2. Issue workflow (branch -> PR -> review -> merge)
3. Testing requirements (coverage, CI)
4. Code quality standards (linting, typing)
5. Data file contribution process
6. Review checklist for @codex
7. **B524 Protocol Family Documentation** (detailed protocol reverse-engineering notes)

**Example structure:**

    ## Agent Orchestration Guide

    ### Workflow

    1. Pick next issue from milestone
    2. Create branch: `issue-<N>-<description>`
    3. Implement feature with tests
    4. Ensure linting passes: `ruff check . && mypy src`
    5. Ensure tests pass: `pytest --cov`
    6. Create PR, tag @codex for review
    7. Address feedback, push updates
    8. When approved + CI green -> squash merge

    ### Quality Gates

    - Linting: ruff + mypy (no warnings)
    - Tests: pytest coverage >80%
    - CI: All checks green
    - Review: @codex approval required

    ### Data File Updates

    CSV/JSON files in data/ and fixtures/ are edited via separate PRs.
    Do not mix code changes with data changes.

    ### B524 Protocol Family (Reverse Engineering Notes)

    [Full B524 protocol documentation from "B524 Protocol Family" section above]

    #### Protocol Discovery Process

    If you discover new B524 opcode families during development:

    1. **Document evidence:**
       - Capture wire frames (hex dumps)
       - Extract CSV patterns showing new opcode
       - Note which VRC models exhibit this behavior

    2. **Submission process:**
       - If you are NOT d3vi1 (repo owner):
         - Create GitHub issue: "New B524 opcode discovered: 0xXX"
         - Include all evidence (frames, CSV excerpts, test cases)
         - Submit PR updating AGENTS.md with findings
       - If you ARE d3vi1:
         - Update AGENTS.md directly in your PR
         - Add test fixtures demonstrating new family

    3. **Required documentation:**
       - Payload byte layout diagram
       - Selector semantics (GG/II/RR or alternative)
       - Response format expectations
       - CSV id encoding rules
       - Confidence level: CONFIRMED vs INFERRED

    4. **Do NOT:**
       - Guess at opcode semantics without evidence
       - Implement untested protocol variants
       - Mix protocol discovery with feature PRs

---

### SCAN ALGORITHM

#### Phase: Group Discovery

**Objective:** Identify all register groups (GG) supported by the device.

**Method:**

    for GG in range(0x00, 0xFF):
        ## Build directory probe: opcode=0x00, GG, padding
        payload = bytes([0x00, GG, 0x00])
        response = transport.send(B524Frame(dst=0x15, payload=payload))
        descriptor = struct.unpack('<f', response)[0]

        if descriptor == 0.0:
            ## Hole, skip
            continue

        if math.isnan(descriptor):
            print(f"Terminator at GG={hex(GG)}")
            break

        record_group(GG, descriptor)
        print(f"Found GG={hex(GG)}, Type={descriptor}")

**Output:**

    Found 7 groups:
      Group 0x00 - Singleton (Type 3) - Regulator Parameters
      Group 0x01 - Singleton (Type 3) - Hot Water Circuit
      Group 0x02 - Instanced (Type 1) - Heating Circuits
      ...
      Terminator at GG=0x0D (NaN)

#### Sub-step: Group Classification (no progress bar)

**Objective:** Map discovered groups to known names and warn about unknown types.

**Method:**

    for GG, descriptor in discovered_groups:
        if GG in GROUP_CONFIG:
            if GROUP_CONFIG[GG]["desc"] != descriptor:
                warn(f"Descriptor mismatch for GG={hex(GG)}: expected {GROUP_CONFIG[GG]['desc']}, got {descriptor}")
            print(f"Group {hex(GG)} - {GROUP_CONFIG[GG]['name']}")
        else:
            if descriptor == 6.0:
                warn(f"Found group in unknown format type 6.0: GG={hex(GG)}")
            print(f"Group {hex(GG)} - Unknown (Type {descriptor})")

#### Phase: Constraint Probe (optional)

**Objective:** Probe the B524 constraint dictionary (`01 GG RR`) to discover min/max/step domains.

**Trigger:** Only when the user explicitly passes `--probe-constraints`.

**Notes / Caveats:**
- Normal scans already use a bundled static BASV2 constraint catalog and only use runtime `0x01` when the user explicitly asks for a live rescan.
- Some BASV2 setups return noisy/unreliable replies for opcode `0x01`; this is why it is off by default.
- Live `0x01` probing can add hundreds of extra runtime requests.
- Only a subset of response type tags (TT) are currently supported (u8/u16/f32/date ranges).

#### Phase: Instance Discovery

**Objective:** For instanced groups (desc==1.0), identify which instance slots are populated.

**Method (per group GG):**

    if descriptor != 1.0:
        ## Singleton or Type 6, no instance enumeration
        return

    ii_max = GROUP_CONFIG[GG]["ii_max"]
    present_instances = []

    for II in range(0x00, ii_max + 1):
        if is_instance_present(transport, dst=0x15, group=GG, instance=II):
            present_instances.append(II)

    print(f"Group {hex(GG)}: {len(present_instances)} present / {ii_max + 1} slots")

**Presence detection logic:**

Presence is determined by group-specific heuristics in `src/helianthus_vrc_explorer/scanner/register.py`
(function `is_instance_present`). It uses `tt_kind` + decoded values to avoid false positives
(e.g. NaN or TT=00 "no data").

**Instance discovery probes ALL slots 0x00..ii_max** (do not stop at gaps, they are legitimate holes). The default register scan remains presence-aware; only the `full` preset expands back to every slot.

#### Sub-step: Planner (preset + interactive overrides)

**Objective:** Build a scan plan (enabled groups, instances, RR_max overrides) from a preset, then
optionally allow the user to tweak the plan interactively (TTY only).

**Trigger:**
- Always applies (preset builds defaults).
- `recommended` stays presence-aware and scans only discovered instance slots.
- `full` is the explicit heavy preset: all instance slots + full RR ranges + unknown groups.
- Interactive planner opens based on `--planner-ui` and TTY detection.
- During Register Scan, `p` can reopen the planner to replan remaining work.

#### Phase: Register Scan

**Objective:** Read all registers within defined ranges for each present instance.

**Method (per group GG, instance II):**

    rr_max = GROUP_CONFIG[GG]["rr_max"]

    ## Determine opcode based on group
    opcode = 0x06 if GG in {0x09, 0x0A, 0x0C} else 0x02

    for RR in range(0x00, rr_max + 1):
        try:
            ## Build payload: opcode, optype=0x00 (read), GG, II, RR (LE)
            payload = struct.pack('<BBBBH', opcode, 0x00, GG, II, RR)
            raw_response = transport.send(B524Frame(dst=0x15, payload=payload))

            ## Strip 4-byte echo header
            value_bytes = raw_response[4:]

            parsed = parse_value(value_bytes, GG, II, RR)
            store_in_json(GG, II, RR, parsed)
        except TransportTimeout:
            mark_as_timeout(GG, II, RR)
        except Exception as e:
            log_error(GG, II, RR, e)

**Live UI update (last line only):**

    Reading GG=0x03 II=0x00 RR=0x0F -> 22.5C

**Do NOT spam scrollback with every register read.** Only update live status line.

#### Phase: B509 Dump (post-scan)

**Objective:** Dump a small range of B509 registers (proto `send_proto(dst, 0xB5, 0x09, ...)`) for
supplementary identity/config coverage.

**Defaults:** If the B524 scan completes, the tool performs a B509 dump for `0x0000..0x00FF`.
Override/extend via repeatable `--b509-range 0x0000..0x00FF` flags.

#### Final Summary

**Print to scrollback:**

    Scan Summary:
    -------------
    Total groups discovered: 7
    Total instances scanned: 127
    Total registers read: 1,024
    Timeouts: 3
    Decode errors: 0

    Group 0x02 - Heating Circuits (8 slots / 2 present / 2 active)
    Group 0x03 - Zones (10 slots / 2 present / 2 active)
    ...

    Scan completed in 127.4s
    Wrote JSON: ./out/b524_scan_0x15_2026-02-06T194424Z.json

---

### EXAMPLE SESSION

**Command:**

    python -m helianthus_vrc_explorer scan \
      --planner-ui auto \
      --preset recommended

**Terminal output:**

    Auto-selected dst=0x15 (compatible B524 target).
    ╭──────────────────────────────────────────────────────────────────────────────╮
    │ helianthus-vrc-explorer v0.1.0                                               │
    │ Scanning VRC Regulator (B524) at address 0x15                                │
    │ ──────────────────────────────────────────────────────────────────────────── │
    │ Device:        BASV2                                                         │
    │ Model:         Vaillant sensoCOMFORT RF (VRC 720f/2) 0020262148              │
    │ Serial:        <SERIAL_NUMBER_REDACTED>                                      │
    │ Firmware:      SW 0507 / HW 1704                                             │
    │ ebusd:         127.0.0.1:8888                                                │
    │ Started:       2026-02-17 15:24:12Z                                          │
    ╰──────────────────────────────────────────────────────────────────────────────╯
    Planner: auto (preset=recommended)
    ✓ Starting scan dst=0x15
    ✓ Discovered group GG=0x00 desc=3.0
    ✓ Discovered group GG=0x01 desc=3.0
    ✓ Discovered group GG=0x02 desc=1.0
    ...
    ✓ GG=0x02 Heating Circuits: 3/11 present, RR_max=0x0025 (38 registers/instance)
    ✓ GG=0x03 Zones: 2/11 present, RR_max=0x002F (48 registers/instance)
    Group Discovery    ━━━━━━━━━━━━ 19/19     0:00:06
    Instance Discovery ━━━━━━━━━━━━ 66/66     0:00:39
    Register Scan      ━━━━━━━━━━━━ 431/2482  0:03:51 Read GG=0x02 II=0x03 RR=0x001C

    (In interactive terminals, the fullscreen browse UI opens automatically after scan.
    Press `q` to exit browse and return to the summary.)

**Generated JSON (excerpt):**

    {
      "meta": {
        "scan_timestamp": "2026-02-06T19:44:24Z",
        "scan_duration_seconds": 127.4,
        "destination_address": "0x15",
        "device_info": {
          "manufacturer": "Vaillant",
          "ebus_model": "BASV2",
          "marketing_name": "VRC 720f/2",
          "model_number": "0020262148",
          "software_version": "0507",
          "hardware_version": "1704"
        }
      },
      "groups": {
        "0x03": {
          "name": "Zones",
          "descriptor_type": 1.0,
          "opcode_family": "0x02",
          "instances": {
            "0x00": {
              "present": true,
              "registers": {
                "0x0016": {
                  "name": "zone_name",
                  "type": "cstring",
                  "value": "Living Room",
                  "raw_hex": "4c6976696e6720526f6f6d00"
                },
                "0x000F": {
                  "name": "current_room_temperature",
                  "type": "float32",
                  "value": 22.5,
                  "unit": "C",
                  "raw_hex": "0000b441"
                }
              }
            }
          }
        }
      }
    }

---

### DELIVERABLES CHECKLIST

**For Issue #1 Bootstrap:**

- [ ] GitHub repo created: `helianthus-vrc-explorer`
- [ ] License: GPLv3
- [ ] Project structure (src/, data/, fixtures/, tests/)
- [ ] pyproject.toml with dependencies
- [ ] CI/CD workflow (.github/workflows/ci.yml)
- [ ] README.md with quick start
- [ ] AGENTS.md with orchestration guide + B524 protocol documentation
- [ ] Empty data/models.csv with header row
- [ ] fixtures/vrc720_full_scan.json (minimal valid fixture)
- [ ] Initial commit on main branch
- [ ] CI passing (linting + tests on empty structure)
- [ ] All bootstrap issues created and tagged

**For subsequent issues:**

- [ ] Feature implemented with unit tests
- [ ] Tests pass (coverage >80%)
- [ ] Linting passes (ruff + mypy)
- [ ] PR created with clear description
- [ ] CI green
- [ ] @codex review approved
- [ ] Squash merge to main

---

### CRITICAL REMINDERS

1. **B524 is a protocol FAMILY, not a single opcode** - dispatch by first byte, parse accordingly
2. **Use opcode 0x02 for local registers** (GG 0x00-0x04) and **opcode 0x06 for remote sensors** (GG 0x09, 0x0A, 0x0C)
3. **CSV schema is NOT hardcoded** - always load from data/field_mappings.csv
4. **ebusd responses are multiline** - parse correctly (first hex line = payload, ignore ERR after)
5. **Retry timeouts once** - then skip register and continue
6. **Probe ALL instance slots 0x00..ii_max during discovery** - do not stop at gaps; the default register scan then uses only the discovered present set
7. **NaN terminator stops discovery on the first NaN** - do not keep probing
8. **Live UI updates only last line** - do not spam scrollback
9. **Non-TTY mode is script-friendly** - rich live UI is disabled; stdout prints the artifact path only
10. **Partial scans are valid** - save with incomplete: true on Ctrl+C
11. **Unknown enums are NOT errors** - keep numeric value + UNKNOWN_0xXX
12. **Data files are edited via separate PRs** - never mix code + CSV changes
13. **Document new protocol discoveries via issue/PR** - do not guess at semantics

---

### NOTES FOR AGENT

- Read this entire prompt carefully before starting
- Clarify ambiguities before implementing
- Test incrementally (unit -> integration -> E2E)
- Document decisions in commit messages
- Ask for user feedback on UX choices
- Prioritize code quality over speed
- Each issue should be mergeable independently
- **If you discover new B524 opcodes, follow the protocol discovery process in AGENTS.md**

**Good luck building helianthus-vrc-explorer!**
