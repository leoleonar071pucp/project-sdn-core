# Guia breve: M5 -> M6 Rate Limit Temporal

## Objetivo

Cuando M5 detecte saturacion o exceso de trafico en un puerto, debe avisar a M6 para que M6 instale un meter temporal en T0.

M6 aplica por defecto:

```text
rate = 50 pps
ttl = 300 segundos
tabla = T0
accion = meter -> goto_table:1
```

M5 no debe enviar `ttl_seconds` ni `meter_rate`; M6 ya los define.

## Endpoint Principal

```http
POST http://192.168.201.251:8080/m6/security/rate-limit
X-Security-Token: change-me
Content-Type: application/json
```

Payload esperado:

```json
{
  "event": "port_traffic_stress",
  "status": "firing",
  "device": "of:00006a0757adfc4e",
  "port": "1",
  "severity": "warning",
  "category": "performance",
  "metrics": {
    "rx_bps": 18432000,
    "tx_bps": 5120000
  },
  "startsAt": "2026-07-08T04:21:33Z",
  "endsAt": "0001-01-01T00:00:00Z"
}
```

Campos obligatorios:

```text
event
status
device
port
```

Campos recomendados:

```text
severity
category
metrics.rx_bps
metrics.tx_bps
startsAt
endsAt
```

## Comportamiento En M6

M6 intenta resolver el castigo asi:

```text
1. Si hay sesion activa en ese device+port:
   match = in_port + MAC + IP
   scope = host_session

2. Si no hay sesion, pero ONOS conoce host:
   match = in_port + MAC
   scope = onos_host

3. Si no hay host:
   match = in_port
   scope = port_only
```

La flow instalada queda en T0:

```text
table=0
priority=38900
timeout=300
match=in_port[,dl_src,nw_src]
actions=meter:<id>,goto_table:1
```

## Respuesta Esperada

Ejemplo cuando instala:

```json
{
  "ok": true,
  "status": "EXECUTED",
  "event": "port_traffic_stress",
  "device": "of:00006a0757adfc4e",
  "port": 1,
  "scope": "host_session",
  "src_ip": "192.168.100.55",
  "src_mac": "FA:16:3E:5A:AA:4A",
  "meter_id": "1",
  "flow_id": "49539599705616206",
  "rate_pps": 50,
  "ttl_seconds": 300,
  "table": 0,
  "priority": 38900
}
```

Si M5 manda el mismo evento otra vez antes de que expire:

```json
{
  "ok": true,
  "status": "already_active",
  "remaining_seconds": 299
}
```

Esto significa que M6 no duplico meter ni flow.

## Resolver Alerta

Cuando M5 detecte que la saturacion termino, puede mandar `status=resolved` al mismo endpoint:

```bash
curl -sS -X POST http://192.168.201.251:8080/m6/security/rate-limit \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  -d '{
    "event": "port_traffic_stress",
    "status": "resolved",
    "device": "of:00006a0757adfc4e",
    "port": "1"
  }'
```

Tambien puede usar el endpoint explicito:

```http
POST http://192.168.201.251:8080/m6/security/rate-limit/remove
```

Payload:

```json
{
  "event": "port_traffic_stress",
  "device": "of:00006a0757adfc4e",
  "port": "1"
}
```

## Listar Rate Limits Activos

```bash
curl -sS http://192.168.201.251:8080/m6/security/rate-limits \
  -H 'X-Security-Token: change-me' \
  | python3 -m json.tool
```

## Comando De Prueba

Aplicar rate limit a H1 en SW4 puerto 1:

```bash
curl -sS -X POST http://192.168.201.251:8080/m6/security/rate-limit \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  -d '{
    "event": "port_traffic_stress",
    "status": "firing",
    "device": "of:00006a0757adfc4e",
    "port": "1",
    "severity": "warning",
    "category": "performance",
    "metrics": {
      "rx_bps": 18432000,
      "tx_bps": 5120000
    },
    "startsAt": "2026-07-08T04:21:33Z",
    "endsAt": "0001-01-01T00:00:00Z"
  }' | python3 -m json.tool
```

Ver en SW4:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep -E '38900|meter'
sudo ovs-ofctl -O OpenFlow13 dump-meters sw4
```

Resultado esperado:

```text
priority=38900,... actions=meter:1,goto_table:1
meter=1 pktps burst
type=drop rate=50 burst_size=100
```

Quitar castigo:

```bash
curl -sS -X POST http://192.168.201.251:8080/m6/security/rate-limit/remove \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  -d '{
    "event": "port_traffic_stress",
    "device": "of:00006a0757adfc4e",
    "port": "1"
  }' | python3 -m json.tool
```

## Recomendacion Para M5

M5 deberia tener deduplicacion local para no enviar alertas cada segundo. Aun asi, M6 ya es idempotente por:

```text
device + port + event
```

Mientras el castigo siga activo, M6 responde `already_active`.

No usar este endpoint para troncales salvo que sea intencional, porque limitar un puerto troncal puede afectar varios hosts.
