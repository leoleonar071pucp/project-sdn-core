# M4 Security Correlator

M4 es el modulo de correlacion y decision de seguridad. Su trabajo no es
capturar paquetes ni instalar flows directamente. M4 recibe eventos de seguridad,
los normaliza, calcula riesgo, crea o actualiza incidentes y, si corresponde,
solicita a M6 que aplique una mitigacion en la red SDN.

Cadena funcional:

```text
M3 / Suricata
    -> POST /m4/events/suricata
M4
    -> normaliza evento
    -> correlaciona evidencia
    -> calcula riesgo
    -> crea/actualiza incidente
    -> decide accion
M6
    -> POST /m6/security/mitigate
    -> resuelve IP a sesion/MAC/switch/puerto
    -> instala drop temporal en T0
ONOS / OVS
    -> aplica flow de mitigacion
```

## Ubicacion del codigo

El M4 real esta en:

```text
app/security/m4
```

La carpeta historica:

```text
app/m4_mitigation
```

queda como placeholder de compatibilidad. No conviene duplicar el mismo codigo en
dos carpetas porque despues seria facil corregir una version y olvidar la otra.

## Responsabilidades

| Componente | Responsabilidad |
|---|---|
| M3 / Suricata | Detecta trafico sospechoso en el mirror/GRE y genera alertas |
| M4 | Decide si una alerta debe convertirse en incidente y accion |
| M6 | Traduce una decision de seguridad a flows ONOS/OVS |
| ONOS | Instala o elimina flows en los switches |
| SW4 | Aplica mitigaciones en T0 del borde de usuarios |

M4 no debe:

- tocar netplan, IPs, DHCP, DNS, rutas o gateways;
- instalar flows directamente en ONOS;
- conocer la topologia fisica completa;
- decidir puertos OpenFlow del host por su cuenta.

M6 si debe resolver:

```text
src_ip -> sesion activa -> MAC -> switch borde -> in_port
```

Por eso M4 le envia a M6 datos de alerta, no flows OpenFlow ya construidas.

## Endpoints

Todos los endpoints protegidos usan:

```http
X-Security-Token: change-me
```

### `GET /health`

Verifica estado general de M4.

```bash
curl -sS http://127.0.0.1:8084/health | python3 -m json.tool
```

Campos importantes:

| Campo | Significado |
|---|---|
| `network_actions_enabled` | Permite acciones de red en el cliente |
| `onos_writes_enabled` | Permite acciones que terminan escribiendo en ONOS |
| `automatic_actions_enabled` | Si es `false`, M4 simula y no llama a M6 |
| `persistence` | `memory` o `mysql` |

### `POST /m4/events`

Recibe un evento ya normalizado con el modelo interno `SecurityEvent`.

### `POST /m4/events/suricata`

Entrada principal para alertas de Suricata.

Ejemplo:

```bash
curl -sS -X POST http://127.0.0.1:8084/m4/events/suricata \
  -H 'Content-Type: application/json' \
  -H 'X-Security-Token: change-me' \
  -d '{
    "event_type": "alert",
    "src_ip": "192.168.100.55",
    "dest_ip": "192.168.100.101",
    "dest_port": 8001,
    "proto": "TCP",
    "alert": {
      "signature_id": 9000002,
      "signature": "SDN DEMO possible SQL injection",
      "severity": 2
    }
  }' | python3 -m json.tool
```

### `POST /m4/events/m6`

Recibe eventos emitidos por M6, por ejemplo denegaciones de politica o bursts.

### `POST /m4/events/telemetry`

Recibe telemetria tipo sFlow/NetFlow si se activa:

```text
FLOW_TELEMETRY_INGESTION_ENABLED=true
```

### `GET /m4/incidents`

Lista incidentes conocidos por M4.

```bash
curl -sS -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8084/m4/incidents \
  | python3 -m json.tool
```

### `GET /m4/incidents/{incident_id}`

Muestra un incidente especifico.

### `POST /m4/incidents/{incident_id}/expire`

Marca un incidente como expirado. Sirve para permitir que una alerta futura
pueda reabrir el incidente y volver a mitigar.

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8084/m4/incidents/INCIDENT_ID/expire \
  | python3 -m json.tool
```

## Flujo tecnico interno

### 1. Entrada HTTP

Archivo:

```text
app/security/m4/app/main.py
```

Funciones principales:

| Funcion | Uso |
|---|---|
| `health()` | Estado de M4 |
| `receive_normalized_event()` | Evento interno ya normalizado |
| `receive_suricata_event()` | Alerta Suricata |
| `receive_m6_event()` | Evento originado en M6 |
| `receive_telemetry_event()` | Evento sFlow/NetFlow |
| `list_incidents()` | Lista incidentes |
| `get_incident()` | Consulta incidente |
| `expire_incident()` | Expira incidente manualmente |

### 2. Normalizacion

Archivos:

```text
app/security/m4/app/adapters/suricata_adapter.py
app/security/m4/app/adapters/m6_adapter.py
app/security/m4/app/adapters/sflow_adapter.py
app/security/m4/app/adapters/netflow_adapter.py
```

El normalizador convierte payloads externos al modelo comun:

```python
SecurityEvent
```

Campos importantes:

| Campo | Uso |
|---|---|
| `source` | Fuente: `suricata`, `m6`, `sflow`, `netflow` |
| `event_type` | Tipo logico de amenaza |
| `src_ip` | IP atacante o sospechosa |
| `src_mac` | MAC si esta disponible |
| `dst_ip` | Destino atacado |
| `dst_port` | Puerto atacado |
| `protocol` | TCP, UDP, ICMP |
| `severity` | Severidad normalizada 0-100 |
| `metadata` | SID Suricata, firma, categoria, HTTP/TLS/flow |

### 3. Politica SID de Suricata

Archivo:

```text
app/security/m4/app/adapters/suricata_adapter.py
```

Mapa principal:

```python
SURICATA_SID_POLICY
```

Ejemplos:

| SID | Tipo M4 | Severidad |
|---:|---|---:|
| `9000001` | `port_scan` | `50` |
| `9000008` | `port_scan` | `50` |
| `9000009` | `port_scan` | `50` |
| `9000010` | `port_scan` | `50` |
| `9000002` | `web_attack` | `70` |
| `9000014` | `web_attack` | `70` |
| `9000018` | `suricata_medium` | `45` |
| `9000027` | `suricata_medium` | `50` |
| `9000028` | `suricata_medium` | `50` |
| `9000029` | `suricata_medium` | `50` |

Si llega un SID desconocido, M4 usa la severidad nativa de Suricata para
clasificarlo.

### 4. Correlacion

Archivo:

```text
app/security/m4/app/correlator.py
```

`EventCorrelator` agrupa eventos durante una ventana temporal:

```text
EVENT_WINDOW_SECONDS=60
```

La clave de identidad se calcula desde `SecurityEvent.identity_key()`:

```text
ip|192.168.100.55
mac|fa:16:...
mac/ip/switch/port si no hay IP
```

Esto evita tratar cada alerta como un incidente completamente aislado.

### 5. Motor de riesgo

Archivo:

```text
app/security/m4/app/risk_engine.py
```

`RiskEngine.evaluate()` suma puntajes por tipo de evento y por correlacion.

Ejemplos de puntaje base:

| Tipo | Puntaje |
|---|---:|
| `policy_denial` | `2` |
| `policy_denial_burst` | `30` |
| `port_scan` | `45` |
| `invalid_ip_mac_binding` | `80` |
| `web_attack` | `60` |
| `suricata_high` | `70` |
| `suricata_critical` | `100` |

Seleccion de accion:

| Score / condicion | Accion |
|---|---|
| `suricata_critical` | `BLOCK` |
| `invalid_ip_mac_binding` | `TEMP_BLOCK` |
| `score >= 80` | `BLOCK` |
| `score >= 50` | `TEMP_BLOCK` |
| `score >= 30` | `MIRROR` |
| `score >= 15` | `WATCH` |
| menor a 15 | `LOG` |

### 6. Gestion de incidentes

Archivo:

```text
app/security/m4/app/incident_manager.py
```

Estados:

```text
NEW -> WATCHING -> MIRRORING -> MITIGATING -> CONTAINED/BLOCKED
```

Estados importantes:

| Estado | Significado |
|---|---|
| `NEW` | Incidente creado |
| `WATCHING` | Se observa, no se mitiga |
| `MIRRORING` | Se recomienda/escalo mirror |
| `MITIGATING` | M4 esta solicitando accion |
| `CONTAINED` | Mitigacion temporal ejecutada |
| `BLOCKED` | Bloqueo fuerte ejecutado |
| `EXPIRED` | Accion anterior vencio o se levanto |
| `REOPENED` | Nueva alerta reabre incidente expirado |

M4 evita repetir acciones si ya hay una accion activa del mismo tipo. Si la
accion expira, el incidente puede pasar a `EXPIRED` y luego reabrirse.

### 7. Ejecucion contra M6

Archivo:

```text
app/security/m4/app/clients/m6_client.py
```

`M6Client.execute()` arma un payload y llama:

```http
POST /m6/security/mitigate
```

Payload conceptual:

```json
{
  "incident_id": "uuid",
  "accion": "TEMP_BLOCK",
  "source": "m4",
  "src_ip": "192.168.100.55",
  "src_mac": "fa:16:3e:...",
  "tipo": "web_attack",
  "ttl_segundos": 600,
  "sid": 9000002,
  "signature": "SDN DEMO possible SQL injection",
  "dst_ip": "192.168.100.101",
  "dst_port": 8001,
  "proto": "TCP"
}
```

M6 decide el castigo concreto segun SID/tipo y resuelve internamente:

```text
src_ip -> sesion activa -> MAC -> SW4 -> puerto fisico
```

Si no existe sesion activa, M6 debe rechazar la mitigacion y no instalar flows.

## Variables de entorno

Archivo de ejemplo:

```text
app/security/m4/.env.example
```

Variables clave:

| Variable | Valor demo | Uso |
|---|---|---|
| `SECURITY_TOKEN` | `change-me` | Token compartido M4/M6 |
| `M6_BASE_URL` | `http://192.168.201.251:8080` | API de M6 |
| `NETWORK_ACTIONS_ENABLED` | `true` | Permite acciones de red |
| `ONOS_WRITES_ENABLED` | `true` | Permite acciones que escriben flows via M6 |
| `M4_AUTOMATIC_ACTIONS_ENABLED` | `true` | Si es `false`, M4 simula |
| `SURICATA_INGESTION_ENABLED` | `true` | Permite `/m4/events/suricata` |
| `EVENT_WINDOW_SECONDS` | `60` | Ventana de correlacion |
| `TEMPORARY_BLOCK_SECONDS` | `600` | TTL bloqueo temporal |
| `LONG_BLOCK_SECONDS` | `3600` | TTL bloqueo largo |

## Levantar M4

### Opcion actual: proceso directo

En la VM monitoring:

```bash
cd /home/ubuntu/m4-security

nohup env \
  SECURITY_TOKEN=change-me \
  M6_BASE_URL=http://192.168.201.251:8080 \
  NETWORK_ACTIONS_ENABLED=true \
  ONOS_WRITES_ENABLED=true \
  M4_AUTOMATIC_ACTIONS_ENABLED=true \
  SURICATA_INGESTION_ENABLED=true \
  uvicorn app.main:app --host 0.0.0.0 --port 8084 \
  > /home/ubuntu/m4.log 2>&1 < /dev/null &
```

Verificar:

```bash
ss -ltnp | grep 8084
curl -sS http://127.0.0.1:8084/health | python3 -m json.tool
```

### Opcion Docker

M4 tambien puede correr en Docker porque es una API aislada.

```bash
docker build -t m4-security:local app/security/m4

docker run -d --name m4-security \
  --restart unless-stopped \
  -p 8084:8084 \
  -e SECURITY_TOKEN=change-me \
  -e M6_BASE_URL=http://192.168.201.251:8080 \
  -e NETWORK_ACTIONS_ENABLED=true \
  -e ONOS_WRITES_ENABLED=true \
  -e M4_AUTOMATIC_ACTIONS_ENABLED=true \
  -e SURICATA_INGESTION_ENABLED=true \
  m4-security:local
```

## Prueba rapida

Con M4 vivo y un host logueado en M6:

```bash
curl -sS -X POST http://127.0.0.1:8084/m4/events/suricata \
  -H 'Content-Type: application/json' \
  -H 'X-Security-Token: change-me' \
  -d '{
    "event_type": "alert",
    "src_ip": "192.168.100.55",
    "dest_ip": "192.168.100.101",
    "dest_port": 8001,
    "proto": "TCP",
    "alert": {
      "signature_id": 9000002,
      "signature": "SDN DEMO possible SQL injection",
      "severity": 2
    }
  }' | python3 -m json.tool
```

Resultado esperado:

```text
M4 crea/actualiza incidente
M4 decide TEMP_BLOCK o BLOCK segun score
M4 llama a M6 si automatic_actions_enabled=true
M6 instala mitigacion T0 si el host tiene sesion activa
```

Ver mitigaciones en M6:

```bash
curl -sS -H 'X-Security-Token: change-me' \
  http://192.168.201.251:8080/m6/security/mitigations \
  | python3 -m json.tool
```

## Recomendacion de repositorio

No mover todo a `app/m4_mitigation` ahora. Mejor:

1. Mantener `app/security/m4` como fuente real.
2. Dejar `app/m4_mitigation/README.md` apuntando a `app/security/m4`.
3. Si el profesor exige que M4 viva en `app/m4_mitigation`, hacer una migracion
   controlada en otro commit, moviendo carpeta completa y actualizando imports,
   Dockerfile, tests, rutas de despliegue y documentacion.

La opcion segura para evitar conflictos y codigo duplicado es mantener una sola
implementacion real.
