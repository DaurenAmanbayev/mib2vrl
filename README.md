# mib2vrl

> SNMP MIB files and network probe rules → Vector.dev VRL transforms

Convert SNMP MIB definitions and network probe rules into
[Vector.dev](https://vector.dev) VRL transforms and ready-to-run `vector.yaml` pipeline configs.

This project closes [vectordotdev/vector#4567](https://github.com/vectordotdev/vector/issues/4567) —
the long-standing community request for native SNMP trap support in Vector.dev.

[![Tests](https://github.com/DaurenAmanbayev/mib2vrl/actions/workflows/tests.yml/badge.svg)](https://github.com/DaurenAmanbayev/mib2vrl/actions/workflows/tests.yml)
![MIBs](https://img.shields.io/badge/MIBs%20tested-2456-blue)
![Traps](https://img.shields.io/badge/traps%20parsed-24642-blue)
![Vendors](https://img.shields.io/badge/vendors-100%2B-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## The problem this solves

[Vector.dev issue #4567](https://github.com/vectordotdev/vector/issues/4567) has been open
since 2020. Vector has no native SNMP trap source — the recommended workaround is using
`snmptrapd` as a proxy, but you still need to write VRL transforms manually for every trap
type across hundreds of MIB files.

For teams migrating from probe-based monitoring systems, there are also thousands of lines
of handwritten rules files encoding years of operational logic that would otherwise be lost.

**mib2vrl generates both automatically.**

---

## What it does

```
Network Devices
      │
      ▼  SNMP traps (UDP 162)
  snmptrapd
      │
      ▼  JSON over UDP 514
┌─────────────────────────────────────────────────────────────┐
│                    Vector.dev Pipeline                      │
│                                                             │
│  snmp_udp ──► snmp_parse ──► snmp_mib_remap ──► snmp_enrich│
│               (normalize      (VRL generated    (severity   │
│                OID format)     by mib2vrl)       lookup)    │
│                                                             │
│                              stdout / Loki / Elasticsearch  │
└─────────────────────────────────────────────────────────────┘
```

### mib2vrl — MIB files → VRL

Parses any standard SNMP MIB file (SNMPv1 `TRAP-TYPE` and SNMPv2 `NOTIFICATION-TYPE`)
and generates a complete, ready-to-run Vector pipeline.

**Tested on 2,456 MIB files from 100+ vendors — 24,642 traps parsed, 0 errors.**

| Output file | Description |
|---|---|
| `vector.yaml` | Complete Vector pipeline — ready to run |
| `vrl_remap` | VRL transform with one `if`-block per trap OID |
| `enrichment_severity.csv` | Severity lookup table |
| `netcool.rules` | Probe rules format (for migration validation) |

Vendors tested from the [librenms MIB collection](https://github.com/librenms/librenms):
Cisco, Juniper, Huawei, HP, Dell, Fortinet, F5, Checkpoint, Arista, Nokia, Ericsson,
APC, Palo Alto, Citrix, Brocade, Extreme, and 100+ more.

### rules2vrl — Probe rules → VRL

Converts `.rules`, `.lookup`, and `.severity` files used by probe-based monitoring systems
into equivalent VRL transforms. Preserves years of accumulated operator business logic.

**Validated on 815 real-world Cisco probe rules files — 100% parse rate.**

> **Compatibility note:** rules2vrl is compatible with the Netcool/OMNIbus probe rules
> file format (`.rules`, `.lookup`, `.severity`). This format is an industry-standard
> DSL used by network monitoring probes. See the [Legal Notice](#legal-notice) section below.

---

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/DaurenAmanbayev/mib2vrl
cd mib2vrl

# Add your MIB files
cp /path/to/IF-MIB.txt       mib2vrl/mibs/
cp /path/to/VENDOR-MIB.txt   mib2vrl/mibs/

# Build once
docker compose --profile convert --profile run build

# Step 1: Convert MIBs → VRL configs
docker compose --profile convert up

# Step 2: Start Vector + test traps
docker compose --profile run up -d
docker compose --profile run logs vector
```

Expected output for a `linkDown` trap:

```json
{
  "agent": "192.168.1.1",
  "alert_group": "IF-MIB",
  "alert_key": "linkDown",
  "severity": 3,
  "severity_name": "Warning",
  "ifIndex": "1",
  "ifAdminStatus": "up",
  "ifOperStatus": "down",
  "snmp_trap_oid": "snmpTraps 3"
}
```

### Local Python

```bash
# mib2vrl
cd mib2vrl
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

mib2vrl convert --mibs ./mibs/ --output ./out/ --format vrl
mib2vrl validate --output ./out/
mib2vrl simulate --mib IF-MIB --trap linkDown --count 10
```

```bash
# rules2vrl
cd rules2vrl
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

rules2vrl --rules ./rules/ --output ./out/ --format both --verbose
```

### Validate VRL output

```bash
echo '{"snmp_trap_oid":"1.3.6.1.6.3.1.1.5.3","host":"192.168.1.1","varbinds":["1","up","down"]}' | \
  docker run -v $(pwd)/mib2vrl/out:/out -i --rm \
  timberio/vector:latest-alpine \
  vrl --program /out/vrl_remap
```

---

## CLI reference

### mib2vrl

```
mib2vrl convert   --mibs <dir> --output <dir> --format [vrl|netcool|both]
                  --timeout <seconds>   per-file timeout (default: 30)
mib2vrl validate  --output <dir>
mib2vrl simulate  --mib <MIB-NAME> --trap <trapName> --count <N>
```

### rules2vrl

```
rules2vrl --rules <dir>           Directory with .rules/.lookup/.severity files
          --output <dir>          Output directory  [default: out]
          --format [vrl|vector|both]
          --include-path <dir>    Additional path for include resolution
          --verbose
```

---

## Supported probe rules DSL constructs

| Construct | Generated VRL |
|---|---|
| `@AlertGroup = "value"` | `.alert_group = "value"` |
| `@Summary = @Node + ": " + $1` | `.summary = .node + ": " + .varbinds[0]` |
| `$1, $2, $N` | `.varbinds[0], .varbinds[1]` |
| `match(@F, "literal")` | `.f == "literal"` |
| `match(@F, regex(".*"))` | `match(.f, r'.*')` |
| `regmatch($N, "^prefix")` | `match(.varbinds[N], r'^prefix')` |
| `lookup($key, table)` | `get_enrichment_table_record(...)` |
| `[$a,$b] = lookup($k, t)` | destructured enrichment lookup |
| `switch($v) { case "x": }` | `if .v == "x" {` |
| `case "a"\|"b":` | `\|\|` condition |
| `else if(cond)` | `} else if cond {` |
| `int(x) / str(x) / float(x)` | `to_int!(x) / to_string!(x) / to_float!(x)` |
| `extract($v, "regex")` | `capture(.v, r'regex')[0] ?? ""` |
| `ltrim(x) / rtrim(x) / trim(x)` | `strip_whitespace(x, "left/right")` |
| `exists($var)` | `exists(._var)` |
| `log(DEBUG, "msg")` | `# log: "msg"` (skipped) |
| Bitwise `&`, `>>` | `# TODO: not supported in VRL` |

---

## Technical notes

### OID resolution

OID parent chains are resolved using `graphlib.TopologicalSorter` (Python 3.9+ stdlib):
O(N), raises `graphlib.CycleError` on circular dependencies. Seeded with well-known roots:
`iso=1`, `ccitt=0`, `enterprises=1.3.6.1.4.1`, `mib-2=1.3.6.1.2.1`.

### Performance

During large-scale testing, a regex backtracking issue caused 37.7s parse time on
90,000-line MIB files. Root cause: `pattern.sub(replacer, text, count=1)` inside a
while loop — O(N × total_strings) complexity. Fixed by removing `count=1`.
Result: **740× speedup**. All 2,456 MIB files now parse within timeout.

### SNMPv1 generic vs specific traps

Generic traps use fixed OIDs from `snmpTraps`. Specific traps use
`{enterprise_oid}.0.{trap_number}`. The generated pipeline normalizes
both forms so VRL rules work regardless of snmptrapd output format.

### VRL `??` operator caveat

`get(map, [key])` returns `Ok(null)` on missing key — VRL's `??` error-coalescing
operator never fires in this case. Generated configs use the correct pattern:

```vrl
_mapped = get!(oid_map, [.snmp_trap_oid])
if _mapped != null { .snmp_trap_oid = _mapped }
```

---

## Running tests

```bash
cd mib2vrl   && pytest tests/ -v   # 154 tests
cd rules2vrl && pytest tests/ -v   # 304 tests
# 458 passed, 0 failures
```

---

## Project structure

```
mib2vrl/
├── mib2vrl/                    MIB → VRL converter (154 tests)
│   ├── mib2vrl/
│   │   ├── parser/             ASN.1 MIB parser (9-stage pipeline)
│   │   ├── models/             Trap, Varbind dataclasses
│   │   ├── export/             Jinja2 template engine
│   │   └── cli.py
│   ├── tests/
│   └── mibs/                   ← put your MIB files here
│
├── rules2vrl/                  Probe rules → VRL converter (304 tests)
│   ├── rules2vrl/
│   │   ├── lexer/              Tokenizer (30+ token types)
│   │   ├── ast/                Recursive descent parser
│   │   ├── codegen/            VRL code generator
│   │   └── cli.py
│   ├── tests/
│   └── rules/                  ← put your .rules files here
│
├── Dockerfile
├── docker-compose.yml
└── DOCKER.md
```

---

## Prior art

- [pysmi](https://github.com/etingof/pysmi) — MIB compiler
- [net-snmp / snmptrapd](http://www.net-snmp.org/) — SNMP trap receiver
- [librenms/mibs](https://github.com/librenms/librenms) — MIB collection used for testing
- [vectordotdev/vector#4567](https://github.com/vectordotdev/vector/issues/4567) — upstream feature request this project addresses

---

## Contributing

PRs welcome. Please add tests for any new DSL construct or MIB format edge case.

```bash
cd mib2vrl   && pytest tests/ -v
cd rules2vrl && pytest tests/ -v
```

---

## Legal Notice

**rules2vrl** implements a parser for the probe rules file format (`.rules`, `.lookup`,
`.severity`) — a text-based DSL used by network monitoring probe software.

**This project:**
- Does not include, redistribute, or derive from any proprietary source code
- Does not include any vendor-provided rules files or MIB files
- Implements an independent, clean-room parser based on the observable syntax
  of the probe rules DSL format
- Is not affiliated with, endorsed by, or sponsored by IBM, Cisco Systems,
  or any other vendor

**Users are solely responsible** for ensuring they have the legal right to use,
convert, and deploy any rules files or MIB files they provide as input.
The authors make no warranties regarding intellectual property ownership
of converted output files.

MIB files used for testing were sourced exclusively from the
[librenms/librenms](https://github.com/librenms/librenms) open source project
(GPLv3), which includes MIB files redistributed under their respective vendor licenses.
No MIB file content is included in this repository.

**This software is provided "as is", without warranty of any kind.**
The authors disclaim all liability for any claims arising from the use of this software
or any files processed by it.

---

## License

MIT — see [LICENSE](LICENSE)
