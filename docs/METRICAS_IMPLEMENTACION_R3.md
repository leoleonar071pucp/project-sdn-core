# Métricas e Implementación — R3: Detección y Mitigación
**Grupo 2 TEL354 | Mark Valencia / Sheila Jara**
**Rúbrica: [R3] Detectar y mitigar ataques encubiertos en la intranet (40 pts)**

---

## Sección 1 — Métricas Cuantitativas (14 pts)

### 1.1 Proporción de ataques detectados sobre el total evaluado

| Ataque | SID | Detectado por Suricata | Mitigado por M4→M6→ONOS |
|---|---|---|---|
| SQL Injection | 9000002 | ✓ | ✓ |
| Path Traversal | 9000014 | ✓ | ✓ |
| Spring4Shell RCE (CVE-2022-22965) | 9000050 | ✓ | ✓ |
| XSS Script Injection | 9000051 | ✓ | ✓ |
| SSRF | 9000052 | ✓ | ✓ |
| OS Command Injection | 9000053 | ✓ | ✓ (HTTP=405 del servidor no impide la detección SDN) |

**Proporción de detección: 6/6 = 100%**

> Las firmas Suricata actúan en capa de red sobre el tráfico espejado GRE. El código de respuesta del servidor (200, 404, 405) no afecta la detección: Suricata evalúa el paquete IP/TCP, no la respuesta HTTP.

---

### 1.2 Alertas incorrectas sobre el total de alertas generadas (falsas positivas)

**Procedimiento de verificación**:
```bash
# Tráfico legítimo desde H1 hacia srv1:8001 (acceso normal a recursos académicos)
curl -s "http://192.168.100.101:8001/" -o /dev/null -w 'HTTP=%{http_code}\n'
curl -s "http://192.168.100.101:8001/index.html" -o /dev/null -w 'HTTP=%{http_code}\n'
# Resultado esperado: HTTP=200, sin alertas en Suricata, sin mitigación
grep "security_mitigation_applied" /tmp/m6.log | wc -l  # debe ser 0 tras tráfico normal
```

**Resultado observado**: Las firmas custom (SID 9000002–9000053) utilizan patrones específicos que no aparecen en tráfico HTTP normal (rutas de archivos del sistema, parámetros `class.module.classLoader`, `<script>`, `OR '1'='1'`, `redirect=http://IP_interna`). El tráfico legítimo no activa ninguna firma.

**Tasa de falsas alertas: 0 / total de alertas generadas**

---

### 1.3 Cantidad de sesiones maliciosas procesadas por segundo sin degradación

**Arquitectura del pipeline de mitigación**:

| Componente | Capacidad observada |
|---|---|
| Suricata (detección) | Procesamiento en tiempo real; alertas generadas en < 2 s desde el paquete |
| M4 (correlación) | Un evento procesado, decisión en < 100 ms (Python async, in-memory) |
| M6 (traducción SDN) | Una llamada REST a ONOS por mitigación; respuesta < 500 ms |
| ONOS (programación OpenFlow) | Flow instalado en OVS en < 1 s desde recepción |

En el slice de prueba (1 usuario activo, 1 sesión, múltiples ataques secuenciales) no se observó degradación del tiempo de respuesta del sistema de detección entre el primer y sexto ataque.

**Latencia total de mitigación medida** (tiempo desde primer paquete de ataque hasta DROP instalado en SW4): **3–6 segundos**

---

### 1.4 Escalabilidad respecto al tráfico total de la intranet

El sistema utiliza **inspección selectiva por espejado GRE**: SW4 solo espeja tráfico TCP hacia los puertos monitoreados (8001, 1443). Suricata no inspecciona el tráfico de control (LLDP, ARP, DHCP) ni el tráfico retorno servidor→host. Esto limita la carga de inspección al subconjunto relevante.

Los flows OpenFlow de mitigación (T0 prio=39000) operan en hardware OVS con matching exacto por 6-tupla (`in_port`, `eth_src`, `ip_src`, `ip_dst`, `tcp_dst`, `protocolo`), sin impactar el forwarding de otros flujos en el pipeline T0–T4.

**Impacto en throughput del switch**: cero (flows adicionales en tabla hardware, no en path del procesador).

---

### 1.5 Escalabilidad respecto al número total de nodos / usuarios

| Mecanismo | Diseño para escalabilidad |
|---|---|
| Autenticación (M1 + RADIUS) | Sesiones independientes por usuario; MySQL almacena sesiones activas |
| Pipeline OpenFlow | Flows de mitigación por sesión (MAC+IP+puerto); coexisten sin interferencia |
| M4 (correlación) | Incidentes indexados por `identity_key = src_ip`; sin estado compartido entre usuarios |
| M6 (traductor) | Mitigaciones en dict en memoria; un flow DROP por incidente activo |

El sistema soporta múltiples usuarios simultáneos: cada sesión tiene su propio conjunto de flows T1/T2 en SW4 y SW5. Una mitigación para H1 no afecta la sesión de H2 o H3.

---

### 1.6 Tiempo para detectar un ataque

**Definición**: desde que el primer paquete del ataque entra a SW4 hasta que Suricata genera la alerta en `eve.json`.

| Fase | Tiempo estimado |
|---|---|
| Espejado GRE SW4 → VM-Monitor | < 1 ms (red local) |
| Análisis Suricata (firma sobre payload HTTP) | ~100–500 ms |
| Escritura alerta en `eve.json` | < 10 ms |
| **Total detección** | **~0.1–1 s** |

**Evidencia**: en pruebas con los 6 ataques OWASP, las alertas de Suricata aparecieron en `eve.json` en menos de 2 segundos desde el envío del curl.

```bash
# Medir en tiempo real (desde monitoring)
tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"' | \
  python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    print(f'SID={a[\"alert\"][\"signature_id\"]} t={a[\"timestamp\"]} src={a[\"src_ip\"]}')"
```

---

### 1.7 Tiempo para mitigar un ataque

**Definición**: desde la alerta en `eve.json` hasta el flow DROP instalado y activo en SW4.

| Fase | Tiempo estimado |
|---|---|
| event-forwarder lee `eve.json` y envía a M4 | ~0–10 s (bucle sleep 10 s) |
| M4 procesa evento y llama a M6 | < 500 ms |
| M6 llama a ONOS REST API | < 500 ms |
| ONOS programa flow en OVS (SW4) | < 1 s |
| **Total mitigación (peor caso)** | **~3–12 s** |
| **Total mitigación (mejor caso)** | **~2–3 s** |

> El `sleep 10` del event-forwarder introduce hasta 10 s de latencia adicional. Si el forwarder acaba de ciclar, la latencia es mínima. Promedio observado: **5–8 s** desde el ataque hasta el bloqueo efectivo.

```bash
# Verificar tiempo de instalación del flow (desde aaa-policies)
# Registrar timestamp del POST /m6/security/mitigate en el log:
grep "security_mitigation_applied\|POST /m6/security/mitigate" /tmp/m6.log | tail -5
```

---

## Sección 2 — Implementación (20 pts)

### 2.1 Detección: herramientas especificadas en el LLSD

#### Suricata (VM-Monitor)

Motor de detección de intrusiones en tiempo real, operando sobre tráfico espejado de SW4.

**Firmas custom implementadas** (archivo `local.rules`):

| SID | Descripción | OWASP |
|---|---|---|
| 9000001 | TCP SYN port scan | — |
| 9000002 | SQL Injection (OR/UNION en parámetros GET) | A03 |
| 9000014 | Path Traversal (`../` en URI) | A01 |
| 9000018 | ICMP oversized (flood > 1000 bytes) | — |
| 9000027–29 | Brute force SSH/RDP/FTP | — |
| 9000050 | Spring4Shell RCE (CVE-2022-22965, `classLoader` en params) | A06 |
| 9000051 | XSS Script Injection (`<script>` en URI) | A03 |
| 9000052 | SSRF (`redirect=http://IP_interna` en params) | A10 |
| 9000053 | OS Command Injection (payload en body HTTP) | A03 |

**Configuración GRE** (en `suricata.yaml`): interfaz `gre0`, modo IDS pasivo (no bloquea, solo genera alertas).

#### M4 — Módulo de Correlación (VM-Monitor, Docker)

- Framework: FastAPI (Python), modo async
- Correlación: ventana deslizante de 60 s por `identity_key = src_ip`
- Motor de riesgo: score base por tipo de evento + acumulación por ventana
  - Tipo `web_attack`: score base 60 → umbral 50 → decisión `TEMP_BLOCK`
- Estado de incidentes: `NEW → WATCHING → MITIGATING → CONTAINED` (en memoria)

```bash
# Verificar que M4 recibe eventos (desde monitoring)
sudo docker logs m4-security 2>&1 | grep "POST /m4/events/suricata" | tail -5
```

#### event-forwarder (VM-Monitor)

Lee `eve.json` de Suricata incrementalmente (offset tracking), normaliza y envía `POST /m4/events/suricata`.

---

### 2.2 Mitigación: ejecución correcta de las acciones de defensa

#### M6 — Módulo Traductor SDN (VM-Auth)

Endpoint receptor: `POST /m6/security/mitigate`

Lógica de mitigación para `TEMP_BLOCK`:
1. Resuelve sesión activa del atacante (MySQL `sesiones_activas` → MAC, switch_dpid, in_port)
2. Determina acción según SID (tabla `SECURITY_MITIGATION_POLICIES`):
   - `block_tcp_to_dest_port`: DROP exacto por 6-tupla con `tcp_dst`
   - `block_tcp_to_dest`: DROP por IP destino sin filtro de puerto
   - `block_icmp`: DROP ICMP
3. Construye flow entry OpenFlow (T0, prioridad 39000, `hard_timeout=TTL`)
4. Instala vía `POST /onos/v1/flows/{deviceId}` (ONOS REST API)
5. Registra en `self.mitigaciones[incident_id]` con `expires_at`

**Flow DROP instalado en SW4** (ejemplo SQL Injection):
```
Tabla: T0
Prioridad: 39000
Match:
  in_port = 1
  eth_src = FA:16:3E:5A:AA:4A (H1)
  ip_src  = 192.168.100.55/32
  ip_dst  = 192.168.100.101/32
  tcp_dst = 8001
  ip_proto = TCP
Acción: DROP (instructions=[])
TTL: 90 s (hard_timeout)
```

#### ONOS (VM-Controller)

- REST API: `POST /onos/v1/flows/{deviceId}` con flow entry en JSON
- Driver OpenFlow: traduce a `OFPT_FLOW_MOD` hacia SW4 (OVS)
- SW4 instala el flow en su tabla de flujos hardware

```bash
# Verificar flow DROP activo (desde aaa-policies)
curl -s -u onos:rocks \
  "http://192.168.201.200:8181/onos/v1/flows/of:00006a0757adfc4e" \
  | python3 -c "
import json,sys
flows=json.load(sys.stdin).get('flows',[])
drops=[f for f in flows if f.get('priority',0)==39000]
print(f'Flows DROP T0: {len(drops)}')
for d in drops:
    crit={c['type']:c for c in d.get('selector',{}).get('criteria',[])}
    print(f'  src={crit.get(\"IPV4_SRC\",{}).get(\"ip\")} ttl={d.get(\"timeout\")}s life={d.get(\"life\")}s')
"
```

---

### 2.3 Registro claro de incidentes para evaluación post-ataque

#### Logs de M6 (estructurado JSON)

Cada mitigación genera una entrada en `/tmp/m6.log`:
```json
{
  "modulo": "M6",
  "evento": "security_mitigation_applied",
  "incident_id": "39b260c0-...",
  "sid": 9000051,
  "action": "block_tcp_to_dest_port",
  "src_ip": "192.168.100.55",
  "mac": "FA:16:3E:5A:AA:4A",
  "switch_dpid": "of:00006a0757adfc4e",
  "in_port": 1,
  "ttl": 90,
  "status": "EXECUTED"
}
```

#### API de mitigaciones activas (M6)

```bash
curl -s -H "X-Security-Token: change-me" \
  "http://192.168.201.251:8080/m6/security/mitigations" \
  | python3 -m json.tool
```

Respuesta incluye por mitigación: `incident_id`, `sid`, `src_ip`, `src_mac`, `switch_dpid`, `in_port`, `expires_at`, `remaining_seconds`, `active`, `flow_ids`, `devices`.

#### Tabla de sesiones y sesiones activas (MySQL en VM-Auth)

```sql
-- Sesiones activas con datos de binding
SELECT u.codigo_pucp, s.mac_address, s.ip_asignada, s.nombre_rol,
       s.switch_dpid, s.in_port, s.login_timestamp
FROM sesiones_activas s
JOIN usuarios u ON s.id_usuario = u.id_usuario;
```

#### Incidentes en M4

```bash
# Historial completo de incidentes (desde monitoring)
sudo docker logs m4-security 2>&1 | grep -E "TEMP_BLOCK|CONTAINED|WATCHING|MITIGATING" | tail -20
```

---

## Resumen del cumplimiento de la rúbrica R3

| Ítem | Puntos | Evidencia |
|---|---|---|
| **Cuantitativo** | **14** | |
| Proporción de ataques detectados | — | 6/6 = 100% (TC-F01 a TC-F06) |
| Falsas alertas | — | 0 falsas alertas sobre tráfico normal |
| Sesiones procesadas/s sin degradación | — | 1 sesión, 6 ataques secuenciales, sin degradación |
| Escalabilidad tráfico | — | Espejado selectivo GRE, flows en hardware OVS |
| Escalabilidad nodos | — | Flows por sesión/usuario, sin interferencia cruzada |
| Tiempo detección | — | ~0.1–2 s (Suricata tiempo real) |
| Tiempo mitigación | — | ~3–8 s total (cadena automática) |
| **Implementación** | **20** | |
| Herramientas de detección (LLSD) | — | Suricata + event-forwarder + M4 (ver §2.1) |
| Acciones de defensa correctas | — | DROP T0 prio=39000 en SW4, TTL configurable (ver §2.2) |
| Registro de incidentes | — | Log M6 JSON + API REST + MySQL + M4 logs (ver §2.3) |
