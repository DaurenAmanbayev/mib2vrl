# mib2vrl — Docker Workflow

## Prerequisites

- Docker 24+ with Compose v2 (`docker compose` command available)
- MIB files placed in `./mibs/`

## Project structure

```
mib2vrl/
├── Dockerfile
├── docker-compose.yml
├── mibs/              ← place .mib / .txt MIB files here
├── out/               ← generated configs land here
├── mib2vrl/           ← source code
└── pyproject.toml
```

---

## Quick start

### Step 1 — Build the image

```bash
docker compose --profile convert --profile run build
```

### Step 2 — Convert MIB files

```bash
docker compose --profile convert up
```

Generates in `./out/`:
- `vector.yaml` — complete Vector pipeline config
- `vrl_remap` — VRL remap transform
- `enrichment_severity.csv` — severity lookup table
- `netcool.rules` — Netcool probe rules (for migration validation)

### Step 3 — Run Vector + E2E test

```bash
docker compose --profile run up -d
docker compose --profile run logs -f trap-sender
docker compose --profile run logs vector
```

Run in detached mode (`-d`) — the `mib2vrl-init` one-shot service exits first (expected), and `--abort-on-container-exit` would prematurely kill Vector.

---

## Services

| Service | Profile | Role |
|---------|---------|------|
| `mib2vrl` | `convert` | One-shot converter, exits 0 when done |
| `mib2vrl-init` | `run` | Same converter, runs before Vector starts |
| `vector` | `run` | Listens on UDP :514, emits enriched JSON |
| `trap-sender` | `run` | Sends 4 test traps then exits |

Vector starts only after `mib2vrl-init` completes successfully. `trap-sender` starts only after Vector passes its healthcheck (`nc -z 127.0.0.1 8686`).

---

## Expected E2E output

All four test traps from `trap-sender` should appear in Vector's JSON output:

**Test 1 — linkDown (numeric OID)**
```json
{"agent":"192.168.1.1","alert_group":"IF-MIB","alert_key":"linkDown","host":"192.168.1.1","ifAdminStatus":"up","ifIndex":"1","ifOperStatus":"down","severity":3,"severity_name":"Warning","snmp_trap_oid":"snmpTraps 3","summary":"linkDown","varbinds":["1","up","down"]}
```

**Test 2 — linkUp (text OID, pass-through)**
```json
{"agent":"10.0.0.1","alert_group":"IF-MIB","alert_key":"linkUp","host":"10.0.0.1","ifAdminStatus":"down","ifIndex":"2","ifOperStatus":"up","severity":3,"severity_name":"Warning","snmp_trap_oid":"snmpTraps 4","summary":"linkUp","varbinds":["2","down","up"]}
```

**Test 3 — ciscoEnvMonTemperatureNotification (SNMPv2)**
```json
{"agent":"10.0.0.254","alert_group":"CISCO-ENVMON-MIB","alert_key":"ciscoEnvMonTemperatureNotification","ciscoEnvMonTemperatureState":"overTemperature","ciscoEnvMonTemperatureStatusDescr":"Chassis","ciscoEnvMonTemperatureStatusValue":"85","ciscoEnvMonTemperatureStatusValueRev1":"86","host":"10.0.0.254","severity":3,"severity_name":"Warning","snmp_trap_oid":"ciscoEnvMonMIBNotifications 3","summary":"ciscoEnvMonTemperatureNotification","varbinds":["Chassis","85","overTemperature","86"]}
```

**Test 4 — unknown OID (passthrough, no enrichment)**
```json
{"host":"172.16.0.1","severity_name":"Warning","snmp_trap_oid":"1.2.3.4.5.6","varbinds":[]}
```

---

## Manual testing

```bash
# Start only Vector (skip trap-sender)
docker compose --profile run up -d mib2vrl-init vector

# Wait for Vector to be healthy, then send a trap
echo '{"snmp_trap_oid":"1.3.6.1.6.3.1.1.5.3","host":"192.168.1.1","varbinds":["1","up","down"]}' \
  | nc -u -w1 127.0.0.1 514

# Check output
docker compose --profile run logs vector
```

---

## Adding new MIBs

```bash
# Copy MIB into place
cp /path/to/VENDOR-MIB.mib ./mibs/

# Rebuild image and regenerate configs
docker compose --profile convert build
docker compose --profile convert up

# Restart Vector to pick up new vector.yaml
docker compose --profile run restart vector
```

---

## Troubleshooting

**Vector healthcheck always failing**

The healthcheck uses `nc -z 127.0.0.1 8686`. Using `localhost` instead of `127.0.0.1` may resolve to `::1` (IPv6) in some environments while Vector binds only to IPv4 `0.0.0.0`.

**Vector API is gRPC, not REST**

Vector 0.55+ exposes a gRPC API on port 8686. `curl http://localhost:8686/health` will not work — use `nc -z 127.0.0.1 8686` to verify the port is open.

**WSL2 note**

On Windows with WSL2, UDP forwarding to containers works correctly. Send traps from WSL2 shell using `127.0.0.1:514` as shown above.

**Enrichment CSV path**

The `enrichment_severity.csv` path in `vector.yaml` is hardcoded to `/etc/vector/enrichment_severity.csv` (matching the `./out:/etc/vector` Docker volume mount). If you deploy Vector outside Docker, update the path in the generated `vector.yaml` or regenerate with a custom template.
