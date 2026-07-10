# Plan de Pruebas Funcionales — R3: Detección y Mitigación
**Grupo 2 TEL354 | Mark Valencia / Sheila Jara**
**Tipo: Funcionales | Requisito: R3**

---

## Contexto del sistema bajo prueba

El sistema SDN Zero Trust detecta ataques HTTP desde hosts autenticados mediante:

1. **Suricata** (VM-Monitor) — analiza tráfico espejado vía GRE desde SW4, aplica firmas custom
2. **event-forwarder** — lee `eve.json` de Suricata y envía eventos a M4 vía `POST /m4/events/suricata`
3. **M4** (correlación, VM-Monitor) — evalúa riesgo, decide `TEMP_BLOCK` si score ≥ 50
4. **M6** (traductor SDN, VM-Auth) — recibe la orden de M4 e instala un flow DROP T0 en ONOS
5. **ONOS** (VM-Controller) — programa el flow en el switch de borde (SW4) vía OpenFlow 1.3

**Comportamiento esperado por caso**: el primer paquete del ataque alcanza el servidor (HTTP=200) antes de que la cadena de mitigación complete (~5 s). A partir de entonces, H1 queda bloqueado (timeout = `HTTP=000`).

---

## Infraestructura de prueba

| Componente | VM | IP datos | Servicio |
|---|---|---|---|
| H1 (atacante simulado) | h1 | 192.168.100.55 | curl desde SSH |
| srv1 (recurso académico) | srv1 | 192.168.100.101 | nginx :8001 (HTTP) / :1443 (HTTPS) |
| Suricata + event-forwarder | VM-Monitor | 192.168.201.252 | Lee `/var/log/suricata/eve.json` |
| M4 (correlación) | VM-Monitor | 192.168.201.252 | :8084 |
| M6 (traductor SDN) | VM-Auth | 192.168.201.251 | :8080 |
| ONOS | VM-Controller | 192.168.201.200 | :8181 |
| SW4 (borde usuario) | — | of:00006a0757adfc4e | OpenFlow 1.3 |

**Prerrequisito**: H1 autenticado en el portal cautivo con rol `Estudiante_Telecom` (IP 192.168.100.55, VLAN 210, acceso a srv1:8001).

---

## Flujo de mitigación automática

```
H1 lanza petición HTTP con patrón de ataque
  → SW4 espeja tráfico vía GRE a VM-Monitor
    → Suricata detecta firma (SID) en tiempo real (~1–2 s)
      → event-forwarder envía POST /m4/events/suricata (~0.5 s)
        → M4 calcula riesgo (score ≥ 50 → TEMP_BLOCK) (~0.5 s)
          → M4 llama POST /m6/security/mitigate (~0.5 s)
            → M6 instala DROP T0 prio=39000 en SW4 via ONOS (~1 s)
              → H1 bloqueado (timeout en siguientes intentos)
Tiempo total cadena: ~3–6 segundos desde el primer paquete del ataque
```

---

## Casos de prueba

### TC-F01 — A06 Vulnerable Components: Spring4Shell RCE (CVE-2022-22965)
**SID Suricata**: 9000050 | **OWASP**: A06

**Procedimiento** (desde H1):
```bash
# Ataque (versión corta — activa la firma igualmente)
curl -s -X POST http://192.168.100.101:8001/ \
 -H 'Content-Type: application/x-www-form-urlencoded' \
 -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=RCE' \
 -w '\nHTTP=%{http_code}\n'

# Verificar bloqueo ~10 s después
curl -s --max-time 5 -o /dev/null -w 'bloqueado=%{http_code}\n' http://192.168.100.101:8001/
```

| Verificación | Resultado esperado |
|---|---|
| Primer curl (ataque) | `HTTP=200` — pasa antes de la mitigación |
| Curl posterior (bloqueo) | `bloqueado=000` — timeout, DROP activo |
| Log M6 | `security_mitigation_applied` con `sid=9000050` |
| ONOS flows | Flow prio=39000 con `ip_src=192.168.100.55` en SW4 |

---

### TC-F02 — A03 Injection: XSS Script Injection en URI
**SID Suricata**: 9000051 | **OWASP**: A03

**Procedimiento** (desde H1, luego de levantar mitigación anterior):
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
  -w '\nHTTP=%{http_code}\n'

curl -s --max-time 5 -o /dev/null -w 'bloqueado=%{http_code}\n' http://192.168.100.101:8001/
```

| Verificación | Resultado esperado |
|---|---|
| Primer curl | `HTTP=200` |
| Curl posterior | `bloqueado=000` |
| SID detectado | 9000051 en logs Suricata y M6 |

---

### TC-F03 — A10 SSRF: Server-Side Request Forgery
**SID Suricata**: 9000052 | **OWASP**: A10

**Procedimiento** (desde H1, luego de levantar mitigación anterior):
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?redirect=http://192.168.201.1/admin" \
  -w '\nHTTP=%{http_code}\n'

curl -s --max-time 5 -o /dev/null -w 'bloqueado=%{http_code}\n' http://192.168.100.101:8001/
```

| Verificación | Resultado esperado |
|---|---|
| Primer curl | `HTTP=200` |
| Curl posterior | `bloqueado=000` |
| SID detectado | 9000052 |

---

### TC-F04 — A03 Injection: OS Command Injection
**SID Suricata**: 9000053 | **OWASP**: A03

> **Nota**: nginx rechaza POST con HTTP=405. El patrón es detectado igualmente por Suricata sobre el tráfico espejado en capa de red. La mitigación se aplica aunque el servidor ya rechazó la petición.

**Procedimiento** (desde H1):
```bash
# POST con payload OS injection
curl -s -X POST http://192.168.100.101:8001/ \
  -d 'cmd=ls%7Ccat%20%2Fetc%2Fpasswd' \
  -w '\nHTTP=%{http_code}\n'

# Verificar bloqueo
curl -s --max-time 5 -o /dev/null -w 'bloqueado=%{http_code}\n' http://192.168.100.101:8001/
```

| Verificación | Resultado esperado |
|---|---|
| POST con payload | `HTTP=405` (nginx rechaza POST; Suricata sí detecta) |
| Curl posterior | `bloqueado=000` — H1 bloqueado |
| SID detectado | 9000053 |

---

### TC-F05 — A03 Injection: SQL Injection
**SID Suricata**: 9000002 | **OWASP**: A03

**Procedimiento** (desde H1):
```bash
curl --path-as-is -m 8 'http://192.168.100.101:8001/?id=2%27%20OR%20%272%27=%272'

curl -s --max-time 5 -o /dev/null -w 'bloqueado=%{http_code}\n' http://192.168.100.101:8001/
```

| Verificación | Resultado esperado |
|---|---|
| Primer curl | `HTTP=200` |
| Curl posterior | `bloqueado=000` |

---

### TC-F06 — A01 Broken Access Control: Path Traversal
**SID Suricata**: 9000014 | **OWASP**: A01

**Procedimiento** (desde H1):
```bash
curl --path-as-is -m 8 'http://192.168.100.101:8001/../../etc/passwd'

curl -s --max-time 5 -o /dev/null -w 'bloqueado=%{http_code}\n' http://192.168.100.101:8001/
```

| Verificación | Resultado esperado |
|---|---|
| Primer curl | `HTTP=404` (nginx no sirve esa ruta, pero el paquete llega) |
| Curl posterior | `bloqueado=000` |

---

### TC-F07 — Ciclo completo: levantar mitigación y re-mitigar
**Objetivo**: verificar que tras levantar una mitigación el sistema puede volver a bloquear un nuevo ataque del mismo host.

**Procedimiento**:
```bash
# Paso 1: lanzar ataque (desde H1)
curl -s "http://192.168.100.101:8001/?id=1'+OR+'1'%3D'1" -o /dev/null -w 'HTTP=%{http_code}\n'

# Paso 2: esperar ~10 s y verificar bloqueo
sleep 10
curl -s --max-time 5 -o /dev/null -w 'bloqueado=%{http_code}\n' http://192.168.100.101:8001/

# Paso 3: levantar mitigación desde M6 dashboard o curl:
# (desde aaa-policies)
curl -s -H "X-Security-Token: change-me" \
  "http://localhost:8080/m6/security/mitigations?active=1" | python3 -m json.tool
# copiar incident_id y levantar:
curl -s -X POST http://localhost:8080/m6/security/unmitigate \
  -H "Content-Type: application/json" -H "X-Security-Token: change-me" \
  -d '{"incident_id": "PEGAR_ID"}'

# Paso 4: verificar que H1 puede acceder de nuevo
curl -s --max-time 5 -o /dev/null -w 'libre=%{http_code}\n' http://192.168.100.101:8001/

# Paso 5: lanzar segundo ataque
curl -s "http://192.168.100.101:8001/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" -o /dev/null -w 'HTTP=%{http_code}\n'

# Paso 6: verificar re-bloqueo
sleep 10
curl -s --max-time 5 -o /dev/null -w 'bloqueado2=%{http_code}\n' http://192.168.100.101:8001/
```

| Verificación | Resultado esperado |
|---|---|
| Primer ataque | `HTTP=200` → luego `bloqueado=000` |
| Tras levantar | `libre=200` (H1 desbloqueado) |
| Segundo ataque | `HTTP=200` → luego `bloqueado2=000` (re-bloqueado) |

---

## Comandos de verificación transversales

```bash
# Ver mitigaciones activas (desde aaa-policies)
curl -s -H "X-Security-Token: change-me" \
  "http://localhost:8080/m6/security/mitigations?active=1" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
mits = data.get('mitigations', [])
print(f'Mitigaciones activas: {len(mits)}')
for m in mits:
    print(f'  sid={m.get(\"sid\")} src={m.get(\"src_ip\")} expires={m.get(\"expires_at\")}')
"

# Ver flows DROP en ONOS (desde aaa-policies)
curl -s -u onos:rocks \
  "http://192.168.201.200:8181/onos/v1/flows/of:00006a0757adfc4e" \
  | python3 -c "
import json, sys
flows = json.load(sys.stdin).get('flows', [])
drops = [f for f in flows if f.get('priority', 0) == 39000]
print(f'Flows DROP T0 activos: {len(drops)}')
for d in drops:
    crit = {c['type']: c for c in d.get('selector', {}).get('criteria', [])}
    print(f'  src={crit.get(\"IPV4_SRC\",{}).get(\"ip\")} life={d.get(\"life\")}s state={d.get(\"state\")}')
"

# Ver log de M6 (desde aaa-policies)
grep "security_mitigation_applied" /tmp/m6.log | tail -10

# Ver incidentes en M4 (desde monitoring)
sudo docker logs m4-security 2>&1 | tail -20

#ver incidentes en suricata:
tail -f /home/ubuntu/project-sdn-core/app/m3_monitoring/logs/eve.json | grep --line-buffered '"event_type":"alert"' | python3 -c "
import sys,json
for line in sys.stdin:
 try:
  e=json.loads(line); a=e.get('alert',{})
  print(f'SID={a.get(\"signature_id\")} SRC={e.get(\"src_ip\")} >> {a.get(\"signature\")}')
 except: pass
"
#levantar dashboard
ssh -L 8088:192.168.201.251:8080 -p 5851 ubuntu@10.20.11.32

#url
http://127.0.0.1:8088/m6/dashboard

```

---

## Cobertura OWASP Top 10

| # | Categoría OWASP | SID | Técnica |
|---|---|---|---|
| A01 | Broken Access Control | 9000014 | Path traversal `%2e%2e%2f` |
| A03 | Injection | 9000002 | SQL Injection `OR '1'='1'` |
| A03 | Injection | 9000051 | XSS `<script>alert(1)</script>` en URI |
| A03 | Injection | 9000053 | OS Command Injection `cmd=ls|cat /etc/passwd` |
| A06 | Vulnerable/Outdated Components | 9000050 | Spring4Shell RCE (CVE-2022-22965) |
| A10 | SSRF | 9000052 | `redirect=http://IP_interna/admin` |
