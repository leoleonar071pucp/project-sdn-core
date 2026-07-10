# Guia De Exposicion: Demo SDN Completa

Esta guia ordena los pasos para mostrar, en vivo, las partes principales del proyecto:

```text
1. Estado base de la red y dashboards.
2. Login de usuario y acceso academico.
3. Suricata -> M4 -> M6 -> mitigacion T0.
4. DDoS/ruido de puerto -> M6 self-monitor -> meter T0.
5. Caida de SW2/SW3 -> failover/ruta alternativa.
6. Limpieza final.
```

Regla de oro: **nunca tocar `ens3`**. `ens3` es acceso de gestion/SSH.

## 1. Mapa Rapido De VMs

| VM | SSH | Uso |
|---|---:|---|
| ONOS | `5800` | Controlador |
| SW1 | `5801` | Troncal / salida a monitoring |
| SW2 | `5802` | Switch intermedio |
| SW3 | `5803` | Switch intermedio / GRE |
| SW4 | `5804` | Borde usuarios H1/H2/H3 |
| SW5 | `5805` | Borde servidores |
| H1 | `5811` | Host demo Telecom `192.168.100.55` |
| H2 | `5812` | Host demo |
| H3 | `5813` | Host demo Informatica |
| AAA / Policies | `5851` | Portal, M6, OPA, MySQL |
| Monitoring | `5852` | Suricata, Evebox, M4 |

Todos usan:

```bash
ssh -p PUERTO ubuntu@10.20.11.32
```

Password usual:

```text
ubuntu
```

## 2. Dashboards Para Mostrar

### 2.1 Dashboard M6

En tu PC local:

```bash
ssh -L 8080:127.0.0.1:8080 -p 5851 ubuntu@10.20.11.32
```

Abrir:

```text
http://127.0.0.1:8080/m6/dashboard
```

Sirve para mostrar:

- sesiones activas;
- flows por switch/tabla;
- mitigaciones;
- rate-limits/meters si el dashboard ya los expone;
- topologia/failover si aparece la vista.

Importante: el dashboard puede **mostrar y analizar** failover. Para bajar fisicamente SW2/SW3, por ahora usa comandos `ovs-ofctl` en terminal.

### 2.2 Evebox / Suricata

En tu PC local:

```bash
ssh -L 8183:192.168.201.252:8181 -p 5852 ubuntu@10.20.11.32
```

Abrir:

```text
https://127.0.0.1:8183/
```

Tambien puedes ver alertas por terminal en Monitoring:

```bash
ssh -p 5852 ubuntu@10.20.11.32
cd /home/ubuntu/project-sdn-core/app/m3_monitoring
tail -f logs/eve.json | grep --line-buffered '"event_type":"alert"'
```

## 3. Precheck Antes De La Expo

### 3.1 AAA / M6

En AAA:

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Esperado:

```text
status: ok
devices_onos: 5 switches
onos_reads_enabled: true
onos_writes_enabled: true
self_monitor.running: true
```

Ver mitigaciones y meters activos antes de empezar:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/mitigations?active=1' \
  | python3 -m json.tool

curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

Ideal:

```text
mitigations: []
rate_limits: []
```

### 3.2 M4 / Suricata / Evebox

En Monitoring:

```bash
ssh -p 5852 ubuntu@10.20.11.32
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -sS --max-time 5 http://127.0.0.1:8084/health | python3 -m json.tool
```

Esperado:

```text
suricata/evebox/event-forwarder/m4 vivos
M4 health: ok
```

### 3.3 GRE De Monitoreo

En AAA:

```bash
curl -sS --max-time 10 -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/gre-status \
  | python3 -m json.tool
```

Si falta GRE:

```bash
curl -sS --max-time 10 -X POST \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/ensure-gre \
  | python3 -m json.tool
```

## 4. Demo Base: Login Y Acceso Academico

Usa H1 Telecom.

En H1:

```bash
ssh -p 5811 ubuntu@10.20.11.32
python3 cli.py
```

Credenciales:

```text
usuario: 20192434
password: pass_teleco123
```

Probar acceso:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'telecom_8001=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
telecom_8001=200 exit=0
```

Para mostrar flows:

En SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=2
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=3
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=4
```

Idea a explicar:

```text
T1: sesion valida host -> push_vlan -> T2
T2: permisos normales
T3: excepciones
T4: fallback TCP hacia M6
```

## 5. Demo Seguridad: Suricata -> M4 -> M6

Esta demo prueba una regla real de Suricata que termina en drop T0.

### 5.1 Ver Alertas En Vivo

En Monitoring:

```bash
ssh -p 5852 ubuntu@10.20.11.32
cd /home/ubuntu/project-sdn-core/app/m3_monitoring
tail -f logs/eve.json | grep --line-buffered '"event_type":"alert"'
```

### 5.2 Lanzar SQLi Desde H1

En H1, ya logueado:

```bash
curl --path-as-is -m 8 \
  'http://192.168.100.101:8001/?id=2%27%20OR%20%272%27=%272'
```

Esperado:

```text
Suricata alerta SID 9000002
M4 recibe evento
M6 instala mitigacion T0
```

### 5.3 Ver Mitigacion En M6

En AAA:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/mitigations?active=1' \
  | python3 -m json.tool
```

Esperado:

```text
sid: 9000002
mitigation_action: block_tcp_to_dest_port
src_ip: 192.168.100.55
dst_ip: 192.168.100.101
dst_port: 8001
```

### 5.4 Ver Drop En SW4

En SW4:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 39000
```

Esperado:

```text
priority=39000 ... nw_src=192.168.100.55,nw_dst=192.168.100.101,tp_dst=8001 actions=drop
```

### 5.5 Quitar Mitigacion

En AAA:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/mitigations?active=1' \
  | python3 -m json.tool
```

Copiar `incident_id` y ejecutar:

```bash
INCIDENT_ID='PEGAR_INCIDENT_ID_AQUI'

curl -sS --max-time 8 -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  -d "{\"incident_id\":\"$INCIDENT_ID\"}" \
  http://127.0.0.1:8080/m6/security/unmitigate \
  | python3 -m json.tool
```

## 6. Demo DDoS/Ruido: M6 Self-Monitor -> Meter

Esta demo no depende de Suricata. M6 mira contadores de ONOS, detecta PPS alto y aplica meter temporal.

### 6.1 Ver Que El Monitor Esta Activo

En AAA:

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Esperado:

```text
self_monitor.running: true
self_monitor.actions_enabled: true
self_monitor.threshold_pps: 300
```

### 6.2 Ejecutar Ataque De Ruido En H1

El script debe existir en:

```text
/home/ubuntu/demo_ddos_curl.sh
/tmp/demo_ddos_curl.sh
```

Si falta, crearlo en H1:

```bash
cat > /home/ubuntu/demo_ddos_curl.sh <<'EOF'
#!/usr/bin/env bash
TARGET="${1:-http://192.168.100.101:8001/}"
DURATION="${2:-20}"
PARALLEL="${3:-40}"
end=$((SECONDS + DURATION))

while [ "$SECONDS" -lt "$end" ]; do
  for i in $(seq 1 "$PARALLEL"); do
    curl -s -o /dev/null --max-time 1 "$TARGET" &
  done
  wait
done
EOF

chmod +x /home/ubuntu/demo_ddos_curl.sh
```

Ejecutar:

```bash
ssh -p 5811 ubuntu@10.20.11.32
/home/ubuntu/demo_ddos_curl.sh http://192.168.100.101:8001/ 20 40
```

En la prueba real esto genero:

```text
pps: 1491.34
threshold_pps: 300
```

Explicacion corta para la expo:

```text
H1 genera muchas conexiones HTTP.
M6 ve por ONOS que el puerto de H1 supera el umbral.
M6 instala un meter temporal en T0 de SW4 para limitar ese puerto.
```

### 6.3 Ver Meter En M6

En AAA:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

Esperado:

```text
status: EXECUTED
device: of:00006a0757adfc4e
port: 1
src_ip: 192.168.100.55
rate_pps: 50
priority: 38900
```

### 6.4 Ver Meter En SW4

En SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 38900
sudo ovs-ofctl -O OpenFlow13 dump-meters sw4
```

Esperado:

```text
priority=38900 ... actions=meter:1,goto_table:1
meter=1 pktps rate=50 burst_size=100
```

### 6.5 Quitar Meter

En AAA:

```bash
python3 - <<'PY'
import requests, json
headers={'X-Security-Token':'change-me'}
payload={"device":"of:00006a0757adfc4e","port":1,"event":"port_traffic_stress"}
r=requests.post(
    'http://127.0.0.1:8080/m6/security/rate-limit/remove',
    headers=headers,
    json=payload,
    timeout=8,
)
print(json.dumps(r.json(), indent=2))
PY
```

Confirmar:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

Esperado:

```text
rate_limits: []
```

## 7. Demo Failover: Caida SW2 / SW3

Objetivo: demostrar que si cae SW2 o SW3, la sesion no se borra y M6 puede recalcular/reinstalar flows si existe ruta alternativa.

Nota: el comando de H1 de la demo DDoS **no tumba SW2/SW3**. Ese comando solo genera trafico para activar un meter. Para demostrar caida de switches se usan comandos en SW2 o SW3.

### 7.1 Ver Topologia Antes De Tumbar

En AAA:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/failover/topology \
  | python3 -m json.tool
```

En dashboard M6, abrir:

```text
http://127.0.0.1:8080/m6/dashboard
```

Vista sugerida:

```text
Failover / Topologia
```

### 7.2 Como Funciona El Dashboard De Failover

En la vista **Failover** del dashboard de M6 hay dos botones importantes:

| Boton | Que hace | Cambia flows reales? | Cuando usarlo |
|---|---|---|---|
| `Analizar` | Simula logicamente que el switch elegido fallo y llama a `/m6/failover/analyze`. | No. Es dry-run. | Para mostrar impacto: sesiones afectadas, permisos afectados y si existe ruta alternativa. |
| `Plan recovery` | Llama a `/m6/failover/recover` con `apply=false`. | No. No borra ni instala flows. | Para mostrar que M6 puede construir un plan de recuperacion sin tocar la red. |

`Analizar` no tumba ningun switch. Solo responde preguntas como:

```text
Si SW2 cae, que sesiones se afectan?
Hay ruta alternativa?
GRE hacia monitoreo sigue recuperable?
Que permisos tendrian que reinstalarse?
```

`Plan recovery` tampoco aplica cambios. Genera un plan de recuperacion, pero no instala flows porque usa:

```json
{"apply": false}
```

Para recuperacion real automatica se necesita:

```text
ONOS detecta evento real -> topology-events -> M6 /m6/failover/event
M6 recibe el evento, analiza sesiones afectadas y reinstala por ruta alternativa si existe.
```

Por seguridad de exposicion, el dashboard debe usarse solo con:

```text
SW2
SW3
```

No usar como demo real:

| Switch | Por que no se debe tumbar en demo |
|---|---|
| SW1 | Es troncal/salida hacia monitoring; puede romper GRE/Suricata y rutas centrales. |
| SW4 | Es borde de usuarios H1/H2/H3; si cae, los hosts pierden entrada a la red. |
| SW5 | Es borde de servidores; si cae, los recursos academicos dejan de estar disponibles. |

Resumen para explicar al profesor:

```text
El dashboard analiza y muestra impacto.
La caida real controlada de SW2/SW3 se hace por terminal.
```

### 7.3 Mantener H1 Probando Acceso

Antes de tumbar un switch, deja este comando corriendo en H1. Sirve para demostrar que el usuario sigue autenticado y que el curso vuelve a responder sin relogin.

En H1:

```bash
ssh -p 5811 ubuntu@10.20.11.32
for i in $(seq 1 12); do
  date -Is
  curl -sS --max-time 5 -o /dev/null \
    -w 'h1_8001 http=%{http_code} exit=%{exitcode} time=%{time_total}\n' \
    http://192.168.100.101:8001/ || true
  sleep 5
done
```

Esperado:

```text
Antes de la caida: http=200.
Durante la convergencia: puede aparecer 1 timeout.
Despues: vuelve a http=200 sin ejecutar login otra vez.
```

### 7.4 Tumbar SW2 Con Rollback Automatico

En otra terminal, en SW2:

```bash
ssh -p 5802 ubuntu@10.20.11.32
cat > /tmp/sw2_failover_safe_test.sh <<'EOF'
#!/usr/bin/env bash
set -u
PORTS='ens4 ens5 ens6 ens7'
{
  echo "$(date -Is) DOWN sw2 data ports: $PORTS"
  for p in $PORTS; do echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw2 "$p" down; done
  sleep 35
  echo "$(date -Is) UP sw2 data ports: $PORTS"
  for p in $PORTS; do echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw2 "$p" up; done
  echo "$(date -Is) DONE"
} > /tmp/sw2_failover_safe_test.log 2>&1
EOF

chmod +x /tmp/sw2_failover_safe_test.sh
nohup /tmp/sw2_failover_safe_test.sh >/dev/null 2>&1 &
```

No toca `ens3`.

Demostrar que SW2 bajo:

```bash
sudo ovs-ofctl -O OpenFlow13 show sw2 | egrep 'ens4|ens5|ens6|ens7'
```

Esperado:

```text
ens4/ens5/ens6/ens7 aparecen DOWN durante unos segundos.
Luego el script los sube automaticamente.
```

Ver log de SW2:

```bash
cat /tmp/sw2_failover_safe_test.log
sudo ovs-ofctl -O OpenFlow13 show sw2 | egrep 'ens4|ens5|ens6|ens7'
```

### 7.5 Tumbar SW3 Con Rollback Automatico

En otra terminal, en SW3:

```bash
ssh -p 5803 ubuntu@10.20.11.32
cat > /tmp/sw3_failover_safe_test.sh <<'EOF'
#!/usr/bin/env bash
set -u
PORTS='ens4 ens5 ens6 ens7'
{
  echo "$(date -Is) DOWN sw3 data ports: $PORTS"
  for p in $PORTS; do echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw3 "$p" down; done
  sleep 35
  echo "$(date -Is) UP sw3 data ports: $PORTS"
  for p in $PORTS; do echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw3 "$p" up; done
  echo "$(date -Is) DONE"
} > /tmp/sw3_failover_safe_test.log 2>&1
EOF

chmod +x /tmp/sw3_failover_safe_test.sh
nohup /tmp/sw3_failover_safe_test.sh >/dev/null 2>&1 &
```

Demostrar que SW3 bajo:

```bash
sudo ovs-ofctl -O OpenFlow13 show sw3 | egrep 'ens4|ens5|ens6|ens7'
```

Mientras tanto, mira la terminal de H1 del paso 7.3. Lo que quieres mostrar es:

```text
La sesion no se borra.
No se vuelve a ejecutar cli.py.
El acceso al recurso vuelve a 200 cuando M6/ONOS reconvergen.
```

### 7.6 Ver Logs De M6

En AAA:

```bash
grep -nE 'failover|FAILOVER|recover|reinstall|GRE|gre|SW2|SW3|link|device' \
  /home/ubuntu/logs/m6_*.log /home/ubuntu/m6_traductor.log 2>/dev/null | tail -n 120
```

### 7.7 Reasegurar GRE Despues Del Failover

En AAA:

```bash
curl -sS --max-time 10 -X POST \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/ensure-gre \
  | python3 -m json.tool
```

## 8. Limpieza Final Despues De La Expo

### 8.1 Quitar Rate-Limits

En AAA:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

Si hay uno en SW4 puerto 1:

```bash
python3 - <<'PY'
import requests, json
headers={'X-Security-Token':'change-me'}
payload={"device":"of:00006a0757adfc4e","port":1,"event":"port_traffic_stress"}
r=requests.post(
    'http://127.0.0.1:8080/m6/security/rate-limit/remove',
    headers=headers,
    json=payload,
    timeout=8,
)
print(json.dumps(r.json(), indent=2))
PY
```

### 8.2 Subir Puertos SW2/SW3

En SW2:

```bash
ssh -p 5802 ubuntu@10.20.11.32
for p in ens4 ens5 ens6 ens7; do
  echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw2 "$p" up
done
```

En SW3:

```bash
ssh -p 5803 ubuntu@10.20.11.32
for p in ens4 ens5 ens6 ens7; do
  echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw3 "$p" up
done
```

### 8.3 Verificar Limpio

En AAA:

```bash
curl -sS http://127.0.0.1:8080/m6/status | python3 -m json.tool
curl -sS -H 'X-Security-Token: change-me' \
  'http://127.0.0.1:8080/m6/security/rate-limits?active=1' \
  | python3 -m json.tool
```

En SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 38900 || true
sudo ovs-ofctl -O OpenFlow13 dump-meters sw4 || true
```

Esperado:

```text
rate_limits: []
sin priority=38900
sin meters activos
```

## 9. Guion Verbal Corto Para Profesores

```text
1. H1 se autentica en el portal. M6 instala sesion y permisos.
2. Suricata observa trafico espejado por GRE/DPDK.
3. Si Suricata detecta SQLi, M4 crea incidente y M6 instala drop T0.
4. Si H1 genera demasiado trafico, M6 self-monitor detecta PPS alto por ONOS y aplica meter T0.
5. Si cae SW2/SW3, ONOS informa cambio de topologia; M6 analiza impacto y reinstala rutas si hay camino alternativo.
6. Todo castigo es temporal y se puede levantar por endpoint/dashboard.
```
