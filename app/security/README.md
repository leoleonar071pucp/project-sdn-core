# Security services

This directory contains the M4 correlation service and the future sensor
integrations for the security VM.

Documentation index:

```text
app/security/docs/00-indice.md
```

Implemented offline components:

- `suricata/`: configuration, rules and EVE fixtures.
- `event_forwarder/`: incremental EVE reader with dry-run delivery.
- `flow_collector/`: sFlow v5 and NetFlow v5 decoders.
- `telemetry_manager/`: mirror lifecycle API that never executes OVSDB.
- `sql/`: security schema used by M4 and Telemetry Manager.
- `docs/`: architecture, component guides and pending configuration.

## Safe default

All network and automatic-action flags default to `false`. In this mode:

- M4 processes events and returns `SIMULATED` actions.
- M6 builds OpenFlow payloads but does not contact ONOS.
- No OVSDB command or mirror is executed.
- MySQL persistence and identity reads remain disabled unless explicitly enabled.

Copy `m4/.env.example` to `m4/.env` only when preparing a local deployment.
Do not enable network flags while the switches are standalone.

## Local M4

```bash
cd app/security/m4
pip install -r requirements.txt
pytest -q
uvicorn app.main:app --host 127.0.0.1 --port 8084
```

The tests use memory repositories and simulated clients. They do not contact
M6, M2, ONOS, OVSDB, MySQL, Suricata, sFlow or NetFlow.

All Compose services require the explicit `deployment` profile. Do not use
that profile until the VM deployment phase.

## Deferred network validation

Do not execute these tests until the network team confirms the switches and
ONOS are ready:

- Real ONOS to M6 Packet-In requests.
- Real T0 flow installation and deletion.
- sFlow/NetFlow collection.
- Suricata `eve.json` forwarding.
- GRE/ERSPAN and OVSDB mirror lifecycle.
- Port-scan, spoofing, DDoS and exfiltration scenarios.
