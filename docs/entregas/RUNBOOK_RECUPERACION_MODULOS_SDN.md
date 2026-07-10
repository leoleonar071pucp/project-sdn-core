# Runbook de Recuperacion de Modulos SDN

Esta guia contiene comandos rapidos para diagnosticar, levantar o reiniciar los
modulos principales del laboratorio sin tocar configuraciones peligrosas.

Objetivo:

```text
Recuperar portal cautivo, M6, M4, monitoreo y flows base
sin cambiar netplan, rutas, DNS, DHCP, OPA, ONOS apps ni reglas de red.
```

> Nota: los comandos son para laboratorio. No compartir este archivo fuera del
> equipo si contiene accesos o tokens.

## 0. Reglas antes de tocar algo

No ejecutar estas acciones salvo que se indique explicitamente:

```bash
sudo netplan apply
sudo ip route add ...
sudo ip route del ...
sudo ovs-ofctl del-flows ...
sudo ovs-vsctl del-br ...
docker system prune -a
git reset --hard
```

Primero hacer siempre revision de solo lectura:

```bash
ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head -20
ss -ltnp
free -h
df -h
```

Que hace:

- `ps`: muestra procesos y consumo de CPU/RAM.
- `ss -ltnp`: muestra puertos TCP escuchando y que proceso los usa.
- `free -h`: revisa memoria disponible.
- `df -h`: revisa disco disponible.

## 1. Acceso rapido a VMs

Todas las VMs se alcanzan con:

```bash
ssh -p <PUERTO> ubuntu@10.20.11.32
```

Password SSH y sudo:

```text
ubuntu
```

| VM | Puerto SSH | Funcion |
|---|---:|---|
| ONOS | `5800` | Controlador ONOS |
| SW1 | `5801` | Switch troncal |
| SW3 | `5803` | Switch intermedio/monitoreo GRE |
| SW4 | `5804` | Borde de usuarios H1/H2/H3 |
| SW5 | `5805` | Borde servidor/recursos |
| H1 | `5811` | Host usuario `192.168.100.55` |
| H2 | `5812` | Host usuario `192.168.100.56` |
| H3 | `5813` | Host usuario `192.168.100.54` |
| AAA / Policies | `5851` | Portal, M6, OPA, MySQL, sync |
| Monitoring | `5852` | Suricata/M3, Evebox, M4 |

## 2. Mapa de servicios actuales

Estado actual esperado:

| Modulo | VM | Puerto | Como corre hoy |
|---|---|---:|---|
| Portal cautivo `web.py` | AAA | `8282` | Proceso Python directo |
| M6 traductor | AAA | `8080` | Proceso Python directo |
| OPA | AAA | `8182` | Proceso `opa` |
| MySQL | AAA | `3306` | Servicio local |
| M4 mitigacion | Monitoring | `8084` | `uvicorn app.main:app` directo |
| Evebox | Monitoring | `8181` | Proceso/contenedor segun despliegue |
| Suricata | Monitoring | N/A | Proceso/contenedor DPDK |

Importante:

```text
M6 y M4 no dependen de Docker en el estado actual.
M6 corre como python3 -u /home/ubuntu/m6_traductor.py.
M4 corre como uvicorn app.main:app --host 0.0.0.0 --port 8084.
```

## 3. Diagnostico global rapido

Ejecutar desde cada VM cuando algo parezca caido:

```bash
hostname
date
uptime
free -h
df -h /
ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head -20
ss -ltnp
```

Interpretacion:

| Senal | Significado probable | Siguiente paso |
|---|---|---|
| `load average` muy alto | Proceso consumiendo CPU | Ver `ps --sort=-%cpu` |
| RAM disponible baja | Riesgo de proceso pesado o fuga | Ver `%mem`, logs y contenedores |
| Disco `Use%` alto | Logs creciendo demasiado | Revisar `/home/ubuntu/logs` o `/var/log` |
| Puerto no aparece en `ss` | Servicio caido | Reiniciar el servicio especifico |
| Proceso vivo pero endpoint falla | App colgada o error interno | Revisar logs y reiniciar |

## 4. Recuperar M6

M6 instala flows, administra sesiones, portal sync, T1/T2/T3/T4 y mitigaciones.

### 4.1 Revisar si M6 esta vivo

En AAA:

```bash
ssh -p 5851 ubuntu@10.20.11.32

pgrep -af 'm6_traductor.py'
ss -ltnp | grep 8080
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Que hace:

- `pgrep -af`: confirma si el proceso existe.
- `ss ... 8080`: confirma si escucha en el puerto de API.
- `curl /m6/status`: confirma que la API responde.

Estado esperado:

```text
status=ok
network_actions_enabled=true
onos_reads_enabled=true
onos_writes_enabled=true
reactive_data_flows_enabled=true
startup_flow_install_enabled=false
session_idle_timeout=5400
```

### 4.2 Reiniciar M6 sin tocar otros servicios

Usar si:

- `/m6/status` no responde.
- M6 no escucha en `8080`.
- Se reinicio ONOS y quieres reasegurar flows base desde M6.
- Las mitigaciones o dashboard no responden.

Comando:

```bash
ssh -p 5851 ubuntu@10.20.11.32

mkdir -p /home/ubuntu/logs
python3 -m py_compile /home/ubuntu/m6_traductor.py

pkill -f 'python3 -u /home/ubuntu/m6_traductor.py' || true
sleep 2

cd /home/ubuntu
nohup env \
  NETWORK_ACTIONS_ENABLED=true \
  ONOS_READS_ENABLED=true \
  ONOS_WRITES_ENABLED=true \
  MYSQL_SECURITY_READS_ENABLED=true \
  STARTUP_FLOW_INSTALL_ENABLED=false \
  REACTIVE_DATA_FLOWS_ENABLED=true \
  SESSION_EXPIRE_ON_T1_REMOVED=true \
  SESSION_IDLE_TIMEOUT=5400 \
  DATA_FLOW_TIMEOUT=300 \
  PORTAL_SYNC_INTERVAL=60 \
  PORTAL_FORWARD_PERMANENT=true \
  PORTAL_RETURN_TIMEOUT=5400 \
  SESSION_CLEANUP_ON_STARTUP=true \
  MONITORING_GRE_INSTALL_ON_STARTUP=true \
  python3 -u /home/ubuntu/m6_traductor.py \
  > /home/ubuntu/logs/m6_manual_restart.log 2>&1 < /dev/null &
```

Que hace cada parte:

- `python3 -m py_compile`: valida sintaxis antes de reiniciar.
- `pkill`: mata solo el proceso M6.
- `STARTUP_FLOW_INSTALL_ENABLED=false`: evita reinstalar el modelo viejo.
- `SESSION_IDLE_TIMEOUT=5400`: T1 sesion expira por idle a 90 minutos.
- `DATA_FLOW_TIMEOUT=300`: T2/T3 datos expiran por idle a 5 minutos.
- `PORTAL_SYNC_INTERVAL=60`: M6 reasegura portal periodicamente.
- `MONITORING_GRE_INSTALL_ON_STARTUP=true`: reasegura flows GRE al arrancar M6.
- `nohup`: deja M6 vivo aunque cierres SSH.

Verificar:

```bash
sleep 3
pgrep -af 'm6_traductor.py'
ss -ltnp | grep 8080
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
tail -80 /home/ubuntu/logs/m6_manual_restart.log
```

### 4.3 Ver dashboard M6

Desde la PC local, abrir tunel:

```bash
ssh -L 8080:127.0.0.1:8080 -p 5851 ubuntu@10.20.11.32
```

Luego abrir:

```text
http://127.0.0.1:8080/m6/dashboard
```

Sirve para ver:

- Sesiones.
- Portal flows.
- Mitigaciones.
- Flows por switch/tabla.
- Eventos recientes.

### 4.4 Reasegurar GRE de monitoreo desde M6

Usar si:

- Reiniciaste ONOS.
- Suricata dejo de ver trafico.
- Las flows `nw_proto=47` desaparecieron de SW4/SW3/SW1.

En AAA:

```bash
curl -sS --max-time 10 -X POST \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/ensure-gre \
  | python3 -m json.tool
```

Que hace:

- Pide a M6 verificar e instalar solo las 3 flows GRE base faltantes.
- Es idempotente: si ya existen, no debe duplicarlas.
- No borra flows.

Ver estado:

```bash
curl -sS --max-time 10 \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/gre-status \
  | python3 -m json.tool
```

## 5. Recuperar portal cautivo

El portal cautivo es `web.py` en AAA y usa puerto `8282`.

### 5.1 Sintoma: `cli.py` dice que no puede conectar al portal

Mensaje tipico:

```text
No se pudo conectar al portal cautivo (http://192.168.100.110:8282).
Esta corriendo web.py?
```

Primero revisar desde AAA:

```bash
ssh -p 5851 ubuntu@10.20.11.32

pgrep -af 'web.py'
ss -ltnp | grep 8282
curl -sS --max-time 5 http://127.0.0.1:8282/ | head
```

Interpretacion:

| Resultado | Significado | Accion |
|---|---|---|
| No hay proceso `web.py` | Portal caido | Levantar `web.py` |
| No aparece `:8282` | Portal no escucha | Levantar `web.py` |
| `127.0.0.1:8282` responde pero H1 no | Problema de flows portal | Reasegurar portal desde M6 |
| API responde lento | Primer paquete puede estar reactivando flows | Esperar y revisar T1/SW4 |

### 5.2 Identificar que `web.py` esta activo

Hay dos posibles copias historicas:

```text
/home/ubuntu/web.py
/home/ubuntu/project-sdn-core/app/m1_auth/web.py
```

Para saber cual esta corriendo:

```bash
PID=$(pgrep -f 'web.py' | head -1)
readlink -f /proc/$PID/cwd
tr '\0' '\n' < /proc/$PID/environ | head
```

Que hace:

- `readlink .../cwd`: muestra desde que carpeta se lanzo `web.py`.
- `environ`: muestra variables de entorno usadas por el proceso.

### 5.3 Levantar `web.py`

Usar si el proceso no existe o el puerto `8282` no escucha.

Opcion segura: levantar desde la carpeta activa del repo si existe:

```bash
ssh -p 5851 ubuntu@10.20.11.32

cd /home/ubuntu/project-sdn-core/app/m1_auth
python3 -m py_compile web.py

pkill -f 'python.*web.py' || true
sleep 2

nohup python3 -u web.py > /home/ubuntu/web.log 2>&1 < /dev/null &
```

Si esa copia falla por dependencias, probar la copia directa:

```bash
cd /home/ubuntu
python3 -m py_compile web.py

pkill -f 'python.*web.py' || true
sleep 2

nohup python3 -u web.py > /home/ubuntu/web.log 2>&1 < /dev/null &
```

Verificar:

```bash
ss -ltnp | grep 8282
curl -sS --max-time 5 http://127.0.0.1:8282/ | head
tail -80 /home/ubuntu/web.log
```

### 5.4 Reasegurar flows del portal

Usar si `web.py` responde localmente, pero H1/H2/H3 no llegan al portal.

En AAA:

```bash
curl -sS --max-time 10 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Luego esperar hasta 60 segundos porque `PORTAL_SYNC_INTERVAL=60` reasegura
flows del portal. Si quieres forzar una llamada indirecta, reinicia solo M6 con
la seccion 4.2.

Ver en SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1 | grep '192.168.100.110'
```

Esperado:

```text
priority=40100,tcp,nw_dst=192.168.100.110,tp_dst=8282 actions=output:ens8
priority=40100,tcp,in_port=ens8,nw_src=192.168.100.110,nw_dst=192.168.100.55,tp_src=8282 actions=output:ens4
priority=40100,tcp,in_port=ens8,nw_src=192.168.100.110,nw_dst=192.168.100.56,tp_src=8282 actions=output:ens5
priority=40100,tcp,in_port=ens8,nw_src=192.168.100.110,nw_dst=192.168.100.54,tp_src=8282 actions=output:ens6
```

## 6. Recuperar M4

M4 recibe alertas de Suricata, decide mitigaciones y llama a M6.

### 6.1 Revisar si M4 esta vivo

En monitoring:

```bash
ssh -p 5852 ubuntu@10.20.11.32

pgrep -af 'uvicorn app.main:app'
ss -ltnp | grep 8084
curl -sS --max-time 5 http://127.0.0.1:8084/health
```

Si `/health` no existe en esa version:

```bash
curl -sS --max-time 5 http://127.0.0.1:8084/docs | head
```

### 6.2 Ver desde que carpeta corre M4

Antes de reiniciar, identificar la carpeta exacta:

```bash
PID=$(pgrep -f 'uvicorn app.main:app' | head -1)
readlink -f /proc/$PID/cwd
tr '\0' '\n' < /proc/$PID/environ | grep -E 'M4|M6|SECURITY|SURICATA|ONOS|NETWORK'
```

Que hace:

- `cwd`: evita reiniciar M4 desde una carpeta equivocada.
- `environ`: muestra flags actuales, por ejemplo `M4_AUTOMATIC_ACTIONS_ENABLED`.

### 6.3 Reiniciar M4

Usar si:

- Puerto `8084` no escucha.
- M4 no recibe eventos.
- M4 no llama a M6.
- Cambiaste configuracion de M4.

Comando:

```bash
ssh -p 5852 ubuntu@10.20.11.32

M4_DIR=$(readlink -f /proc/$(pgrep -f 'uvicorn app.main:app' | head -1)/cwd 2>/dev/null || echo /home/ubuntu/m4-security)
echo "$M4_DIR"

cd "$M4_DIR"
python3 -m py_compile app/main.py

pkill -f 'uvicorn app.main:app.*8084' || true
sleep 2

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
pgrep -af 'uvicorn app.main:app'
tail -80 /home/ubuntu/m4.log
```

### 6.4 Probar M4 con alerta fake

Usar para confirmar cadena M4 -> M6 sin depender de Suricata real.

Primero debe haber una sesion activa en M6 para el host que quieres castigar.
Luego, desde monitoring:

```bash
curl -sS --max-time 10 -X POST http://127.0.0.1:8084/m4/events/suricata \
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

Luego en AAA:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/security/mitigations \
  | python3 -m json.tool
```

## 7. Quitar mitigaciones

Usar si un profesor hizo una prueba y quieres desbloquear al host sin esperar
el TTL.

En AAA:

```bash
curl -sS --max-time 10 -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/security/unmitigate \
  -d '{"incident_id":"ID_DEL_INCIDENTE"}' \
  | python3 -m json.tool
```

Si no sabes el ID:

```bash
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/security/mitigations \
  | python3 -m json.tool
```

Ver en SW4 si quedan drops de castigo:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 'priority=39000'
```

Si no sale nada, no hay mitigaciones T0 activas en SW4.

## 8. Recuperar Suricata / M3 / Evebox

### 8.1 Revisar CPU y procesos

En monitoring:

```bash
ssh -p 5852 ubuntu@10.20.11.32

ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head -20
ss -ltnp | grep -E '8181|8084'
```

Interpretacion:

| Resultado | Significado |
|---|---|
| Suricata al 100% CPU | Puede ser normal por DPDK/busy polling, pero esta usando un core completo |
| Evebox escucha `8181` | Dashboard de alertas disponible |
| M4 escucha `8084` | API de mitigacion disponible |

### 8.2 Ver alertas Suricata

```bash
sudo tail -f /var/log/suricata/eve.json | grep --line-buffered '"event_type":"alert"'
```

Si el despliegue usa logs dentro del repo:

```bash
cd /home/ubuntu/project-sdn-core/app/m3_monitoring
tail -f logs/eve.json | grep --line-buffered '"event_type":"alert"'
```

### 8.3 Ver Evebox desde la PC local

Crear tunel:

```bash
ssh -L 8183:192.168.201.252:8181 -p 5852 ubuntu@10.20.11.32
```

Abrir:

```text
https://127.0.0.1:8183/
```

Si no abre:

```bash
ssh -p 5852 ubuntu@10.20.11.32
ss -ltnp | grep 8181
ps -eo pid,cmd,%cpu,%mem | grep -i evebox
```

## 9. Revisar ONOS

En ONOS VM:

```bash
ssh -p 5800 ubuntu@10.20.11.32

docker ps
docker exec onos bash -lc 'curl -s -u onos:rocks --max-time 8 http://127.0.0.1:8181/onos/v1/devices | python3 -m json.tool'
docker exec onos bash -lc 'curl -s -u onos:rocks --max-time 8 http://127.0.0.1:8181/onos/v1/applications/org.onosproject.fwd'
docker exec onos bash -lc 'curl -s -u onos:rocks --max-time 10 http://127.0.0.1:8181/onos/v1/flows | grep -c "OUTPUT.*NORMAL"'
```

Esperado:

```text
5 switches
org.onosproject.fwd INSTALLED, no ACTIVE
OUTPUT.NORMAL = 0
```

Si reiniciaste ONOS:

1. Esperar que los 5 switches reconecten.
2. Reiniciar M6 o ejecutar `/m6/monitoring/ensure-gre`.
3. Probar portal.
4. Probar login.
5. Probar recurso permitido.

## 10. Revisar flows en SW4

SW4 es el borde de usuarios. Debe verse asi:

```text
T0: control, GRE y tcp -> T1
T1: portal cautivo y session gates
T2: permisos normales
T3: excepciones
T4: fallback TCP packet-in y drop
```

Comandos:

```bash
ssh -p 5804 ubuntu@10.20.11.32

sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=2
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=3
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=4
```

Chequeos rapidos:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep NORMAL
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=0 | grep 'priority=39000'
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1 | grep '192.168.100.110'
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=4 | grep CONTROLLER
```

Interpretacion:

| Comando | Esperado |
|---|---|
| `grep NORMAL` | No debe devolver nada |
| `priority=39000` | Solo aparece si hay mitigacion activa |
| Portal en T1 | Debe aparecer ida y vuelta del portal |
| T4 CONTROLLER | Debe aparecer fallback TCP hacia M6 |

## 11. Problemas comunes y solucion

### 11.1 `cli.py` demora mucho al iniciar

Posibles causas:

- Primer paquete despierta flows reactivas.
- Portal sync todavia no reaseguro vuelta.
- `web.py` esta lento o recien levantado.
- Hay una sesion vieja o flow vieja.

Comandos:

```bash
ssh -p 5851 ubuntu@10.20.11.32
ss -ltnp | grep 8282
curl -sS --max-time 5 http://127.0.0.1:8282/ | head
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Si todo esta vivo, revisar SW4 T1:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1 | grep '192.168.100.110'
```

### 11.2 Login funciona pero curso no responde

Posibles causas:

- T2/T3 expiro y necesita reactivacion.
- ONOS olvido el host recurso.
- M6 no resolvio camino.
- Hay mitigacion activa.

Comandos:

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS --max-time 8 -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/security/mitigations \
  | python3 -m json.tool

ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=2
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=3
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=4
```

Si no hay mitigacion y T2/T3 estan vacias, probar logout/login o generar acceso
al recurso para que T4 despierte a M6.

### 11.3 Hay una flow `priority=39900` aunque el usuario se deslogueo

Posible sesion vieja en T1. Revisar M6:

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Si M6 no tiene sesiones activas, ejecutar limpieza segura:

```bash
curl -sS --max-time 10 -X POST \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/sessions/cleanup-stale \
  | python3 -m json.tool
```

Que hace:

- Elimina session gates T1 huerfanos.
- No borra portal.
- No borra GRE.
- No toca control ARP/DHCP/LLDP.

### 11.4 Suricata esta al 100% CPU

No necesariamente es fuga de RAM. Con DPDK puede consumir un core por diseno.
Pero si la VM se pone lenta:

```bash
ssh -p 5852 ubuntu@10.20.11.32
ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head -20
free -h
df -h /
```

Revisar mirror en SW4:

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-vsctl list mirror
sudo ovs-vsctl --format=table --columns=_uuid,name list port
```

Si `gre_mon` aparece dentro de `select_src_port` o `select_dst_port`, eso seria
malo porque podria espejar el trafico espejado. En el estado esperado actual,
`gre_mon` solo debe ser `output_port`.

### 11.5 Reinicie ONOS y se perdieron flows

Secuencia recomendada:

```bash
# 1. Confirmar ONOS y switches
ssh -p 5800 ubuntu@10.20.11.32
docker ps
docker exec onos bash -lc 'curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/devices | grep -o "of:" | wc -l'

# 2. Reasegurar GRE desde AAA
ssh -p 5851 ubuntu@10.20.11.32
curl -sS -X POST -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/ensure-gre \
  | python3 -m json.tool

# 3. Confirmar M6 y portal
curl -sS http://127.0.0.1:8080/m6/status | python3 -m json.tool
curl -sS --max-time 5 http://127.0.0.1:8282/ | head
```

Luego probar desde H1:

```bash
ssh -p 5811 ubuntu@10.20.11.32
curl -sS --max-time 8 -o /dev/null -w 'portal=%{http_code} exit=%{exitcode}\n' http://192.168.100.110:8282/
```

## 12. Docker: cuando usarlo y cuando no

Estado actual:

```text
M6: no corre en Docker.
M4: no corre en Docker en el estado observado; corre como uvicorn directo.
```

Verificar:

```bash
docker ps
docker images
```

Si no sale nada para M6/M4, no intentes reiniciarlos con Docker. Usa las
secciones 4 y 6.

Docker es buena opcion futura para M4 porque es una API aislada. Para M6 hay que
tener mas cuidado porque conoce sesiones, ONOS, MySQL, OPA, portal sync y flows.

## 13. Comandos rapidos por sintoma

| Sintoma | Comando principal | Que arregla o confirma |
|---|---|---|
| Portal no abre | `ss -ltnp | grep 8282` en AAA | Confirma si `web.py` vive |
| `cli.py` no conecta | `curl http://127.0.0.1:8282/` en AAA | Distingue app caida vs red/flows |
| M6 caido | `ss -ltnp | grep 8080` en AAA | Confirma API M6 |
| M4 caido | `ss -ltnp | grep 8084` en monitoring | Confirma API M4 |
| Suricata pesado | `ps --sort=-%cpu` en monitoring | Confirma CPU |
| No hay alertas | `tail -f eve.json` | Confirma Suricata |
| No hay mitigacion | `/m6/security/mitigations` | Lista castigos activos |
| Host castigado | `grep priority=39000` en SW4 T0 | Ver drop T0 |
| Quitar castigo | `/m6/security/unmitigate` | Elimina mitigacion |
| ONOS reiniciado | `/m6/monitoring/ensure-gre` | Reinstala GRE base |
| Sesion vieja | `/m6/sessions/cleanup-stale` | Limpia T1 huerfano |

## 14. Orden recomendado de recuperacion

Si la red esta rara, seguir este orden:

1. Revisar AAA: `web.py`, M6, OPA, MySQL.
2. Revisar ONOS: contenedor vivo, 5 switches, `OUTPUT.NORMAL=0`.
3. Revisar SW4: T0/T1/T4.
4. Probar portal desde H1.
5. Probar login.
6. Probar recurso permitido.
7. Revisar monitoring/M4 solo si el problema es de alertas o mitigaciones.

Este orden evita reiniciar Suricata/monitoring cuando el problema real era el
portal o una flow de SW4.
