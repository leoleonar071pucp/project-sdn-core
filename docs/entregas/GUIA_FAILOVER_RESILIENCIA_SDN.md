# Guia Breve: Failover Y Resiliencia SDN

Objetivo: evaluar que pasaria si cae un switch o enlace sin apagar VMs ni tocar flows. Esta fase usa M6 en modo **dry-run**: consulta ONOS/MySQL/OPA y calcula impacto, pero no instala ni elimina reglas.

La fase actual agrega un endpoint de **recovery controlado**. Por defecto solo genera el plan de reinstalacion; no aplica cambios mientras `FAILOVER_AUTO_REINSTALL_ENABLED=false`.

## Estado Esperado

En AAA:

```bash
curl -sS http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Campos importantes:

```text
failover_analysis_enabled: true
failover_auto_reinstall_enabled: false
onos_reads_enabled: true
onos_writes_enabled: true
```

`failover_auto_reinstall_enabled=false` significa que M6 solo analiza. No reconfigura la red automaticamente.

## DPIDs

| Switch | DPID |
|---|---|
| SW1 | `of:00007e3892af7141` |
| SW2 | `of:0000e2ecb0ea0445` |
| SW3 | `of:0000eadb63449748` |
| SW4 | `of:00006a0757adfc4e` |
| SW5 | `of:0000ca126249d546` |

## Ver Topologia Actual

En AAA:

```bash
curl -sS -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/failover/topology \
  | python3 -m json.tool
```

Resultado esperado si la red esta sana:

```text
available_devices: 5 switches
unavailable_devices: []
links_count: enlaces vistos por ONOS
hosts_count: hosts aprendidos por ONOS
```

## Simular Caida De SW2

En AAA:

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/analyze \
  -d '{"failed_devices":["of:0000e2ecb0ea0445"]}' \
  | python3 -m json.tool
```

Interpretacion:

| Campo | Significado |
|---|---|
| `dry_run: true` | No se tocaron flows. |
| `impacted_sessions` | Sesiones que usan rutas afectadas por la caida simulada. |
| `recoverable_sessions` | Sesiones con ruta alternativa calculable. |
| `unavailable_sessions` | Sesiones sin ruta alternativa segun ONOS. |

## Simular Caida De SW3

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/analyze \
  -d '{"failed_devices":["of:0000eadb63449748"]}' \
  | python3 -m json.tool
```

## Simular Caida De Un Link

Ejemplo: simular caida del enlace SW4 puerto 5 hacia SW2 puerto 1.

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/analyze \
  -d '{
    "failed_links": [
      {
        "src_device": "of:00006a0757adfc4e",
        "src_port": 5,
        "dst_device": "of:0000e2ecb0ea0445",
        "dst_port": 1
      }
    ]
  }' \
  | python3 -m json.tool
```

## Ver En Dashboard

Abrir un tunel desde tu PC:

```bash
ssh -L 8080:127.0.0.1:8080 -p 5851 ubuntu@10.20.11.32
```

Luego abrir:

```text
http://127.0.0.1:8080/m6/dashboard
```

Usar token:

```text
change-me
```

Entrar a la pestana:

```text
Failover
```

Alli puedes elegir `SW2`, `SW3`, etc. y presionar `Analizar`.

Tambien puedes presionar `Plan recovery` para ver que sesiones y permisos reinstalaria M6 en la topologia real actual. Ese boton no borra ni instala flows.

## Plan De Recovery Sin Aplicar Cambios

En AAA:

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/recover \
  -d '{"apply":false}' \
  | python3 -m json.tool
```

Resultado esperado:

```text
ok: true
dry_run: true
applied: false
auto_reinstall_enabled: false
planned: sesiones activas que M6 podria reinstalar
```

Este comando sirve para demostrar que M6 ya sabe reconstruir la intencion de las sesiones activas:

| Campo | Significado |
|---|---|
| `planned` | Sesiones que se evaluaron para reinstalar. |
| `permissions` | Permisos T2 normales y T3 que ya estaban activos. |
| `table` | Tabla destino: `T2` normal o `T3` excepcion ya usada. |
| `dry_run` | Si es `true`, no se borro ni instalo ninguna flow. |

## Evento Automatico Seguro

M6 tambien acepta eventos de topologia en:

```text
POST /m6/failover/event
```

Este endpoint esta pensado para que una app ONOS o un script de monitoreo avise:

```text
device_down
link_down
topology_change
```

Con el flag por defecto:

```text
FAILOVER_AUTO_REINSTALL_ENABLED=false
```

el evento **solo analiza**. No borra ni instala flows.

Ejemplo de evento simulado de caida de SW2:

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/event \
  -d '{
    "event_type": "device_down",
    "device_id": "of:0000e2ecb0ea0445",
    "source": "manual-demo"
  }' \
  | python3 -m json.tool
```

Resultado esperado con auto-reinstall apagado:

```text
ok: true
applied: false
reason: auto_reinstall_disabled
analysis.summary: impacto calculado
recoverable_ips: IPs que M6 podria recuperar si se activa apply
```

Ejemplo observado en la maqueta con SW2:

```text
applied: false
reason: auto_reinstall_disabled
recoverable_ips: ["192.168.100.55"]
analysis.summary:
  impacted_sessions: 2
  recoverable_sessions: 1
  unaffected_sessions: 0
  unavailable_sessions: 1
```

El endpoint tiene deduplicacion por ventana:

```text
FAILOVER_EVENT_DEDUP_WINDOW=15
```

Si llega el mismo evento muchas veces, M6 responde `duplicate: true` y no vuelve a calcular/aplicar inmediatamente. Esto evita bucles por eventos repetidos de ONOS.

Para confirmar la deduplicacion, repetir el mismo curl inmediatamente. Esperado:

```text
duplicate: true
applied: false
retry_after_seconds: valor restante de la ventana
```

## Intentar Aplicar Con El Flag Apagado

Este comando debe fallar de forma segura:

```bash
curl -sS -i -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/recover \
  -d '{"apply":true}'
```

Resultado esperado:

```text
HTTP/1.1 409 CONFLICT
failover_auto_reinstall_disabled
```

Eso significa que la red esta protegida contra una reinstalacion accidental. Para una prueba real controlada se tendria que reiniciar M6 con:

```bash
FAILOVER_AUTO_REINSTALL_ENABLED=true
```

No se recomienda dejarlo activo permanentemente hasta probar cooldown, limites de sesiones y rollback manual con el profesor.

## Prueba Controlada De Apply Para Una Sola IP

Usar solo en ventana de prueba. La idea es encender el flag, aplicar recovery a una IP concreta, validar y volver a apagarlo.

1. Levantar M6 temporalmente con apply habilitado:

```bash
pkill -f 'python3 -u /home/ubuntu/m6_traductor.py'

NETWORK_ACTIONS_ENABLED=true \
ONOS_READS_ENABLED=true \
ONOS_WRITES_ENABLED=true \
MYSQL_SECURITY_READS_ENABLED=true \
STARTUP_FLOW_INSTALL_ENABLED=false \
REACTIVE_DATA_FLOWS_ENABLED=true \
SESSION_EXPIRE_ON_T1_REMOVED=true \
SESSION_IDLE_TIMEOUT=5400 \
DATA_FLOW_TIMEOUT=300 \
FAILOVER_ANALYSIS_ENABLED=true \
FAILOVER_AUTO_REINSTALL_ENABLED=true \
nohup python3 -u /home/ubuntu/m6_traductor.py \
  > /home/ubuntu/logs/m6_failover_recover_apply_test.log 2>&1 &
```

2. Aplicar recovery solo a H1, por ejemplo:

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/recover \
  -d '{"apply":true,"src_ips":["192.168.100.55"]}' \
  | python3 -m json.tool
```

Resultado esperado:

```text
applied: true
sessions_seen: 1
reinstalled: installed_flows > 0
failed: []
```

3. Validar en SW4:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1 | grep '192.168.100.55'
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=2 | grep 'dl_vlan=220'
```

Ejemplo esperado para H1 Informatica:

```text
T1: in_port + MAC + IP -> push_vlan:220,goto_table:2
T2 ida: dl_vlan=220,nw_dst=192.168.100.101,tp_dst=8002 -> output
T2 vuelta: dl_vlan=220,nw_src=192.168.100.101,nw_dst=192.168.100.55,tp_src=8002 -> pop_vlan,output
```

4. Probar desde H1:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'info8002=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8002/

curl -sS --max-time 8 -o /dev/null \
  -w 'telecom8001=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8001/
```

Esperado:

```text
info8002=200 exit=0
telecom8001=000 exit=28
```

5. Volver a modo seguro:

```bash
pkill -f 'python3 -u /home/ubuntu/m6_traductor.py'

NETWORK_ACTIONS_ENABLED=true \
ONOS_READS_ENABLED=true \
ONOS_WRITES_ENABLED=true \
MYSQL_SECURITY_READS_ENABLED=true \
STARTUP_FLOW_INSTALL_ENABLED=false \
REACTIVE_DATA_FLOWS_ENABLED=true \
SESSION_EXPIRE_ON_T1_REMOVED=true \
SESSION_IDLE_TIMEOUT=5400 \
DATA_FLOW_TIMEOUT=300 \
FAILOVER_ANALYSIS_ENABLED=true \
FAILOVER_AUTO_REINSTALL_ENABLED=false \
nohup python3 -u /home/ubuntu/m6_traductor.py \
  > /home/ubuntu/logs/m6_failover_recover.log 2>&1 &
```

6. Confirmar que apply quedo bloqueado otra vez:

```bash
curl -sS -i -X POST \
  -H 'X-Security-Token: change-me' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/m6/failover/recover \
  -d '{"apply":true,"src_ips":["192.168.100.55"]}' \
  | head
```

Esperado:

```text
HTTP/1.1 409 CONFLICT
failover_auto_reinstall_disabled
```

## Confirmar Que No Se Toco La Red

Antes/despues del dry-run:

```bash
curl -sS -u onos:rocks --max-time 15 \
  http://192.168.201.200:8181/onos/v1/flows \
  | grep -c 'OUTPUT.*NORMAL'
```

Esperado:

```text
0
```

Confirmar que los hosts siguen llegando al portal:

```bash
timeout 4 bash -lc '</dev/tcp/192.168.100.110/8282' && echo portal_ok || echo portal_fail
```

## App ONOS Emisora De Eventos

Se agrego un modulo nuevo:

```text
app/onos_topology_events
```

Su responsabilidad es escuchar eventos reales dentro de ONOS:

```text
DeviceEvent
LinkEvent
```

y llamar a M6:

```text
POST http://192.168.201.251:8080/m6/failover/event
```

La app ONOS no instala ni borra flows; solo avisa. M6 sigue siendo el unico modulo que decide si analiza o recupera.

### Compilar App ONOS

Requiere JDK 11 y Maven:

```bash
cd app/onos_topology_events
mvn clean package
```

Artefacto esperado:

```text
target/onos-topology-events-1.0.0.oar
```

### Instalar En ONOS

```bash
curl -u onos:rocks -X POST \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @target/onos-topology-events-1.0.0.oar \
  'http://192.168.201.200:8181/onos/v1/applications?activate=true'
```

### Verificar Instalacion

```bash
curl -sS -u onos:rocks \
  http://192.168.201.200:8181/onos/v1/applications/pe.edu.pucp.sdn.topology-events \
  | python3 -m json.tool
```

Resultado observado:

```text
name: pe.edu.pucp.sdn.topology-events
version: 1.0.0
state: ACTIVE
features: ["pucp-sdn-topology-events"]
```

Despues de instalar se verifico:

```text
ONOS ve 5 switches disponibles
M6 status ok
FAILOVER_AUTO_REINSTALL_ENABLED=false
OUTPUT:NORMAL=0
```

### Modo De Prueba Recomendado

Primero dejar M6 asi:

```text
FAILOVER_AUTO_REINSTALL_ENABLED=false
```

Entonces, si ONOS detecta una caida real:

```text
ONOS -> app topology-events -> M6 /failover/event
```

M6 debe responder/registrar:

```text
applied: false
reason: auto_reinstall_disabled
analysis.summary: impacto calculado
```

Despues de validar que los eventos reales llegan sin bucles, se puede hacer una prueba controlada con:

```text
FAILOVER_AUTO_REINSTALL_ENABLED=true
```

solo durante una ventana de demo y con pocas sesiones activas.

## Conclusion Esperada

Esta fase responde:

```text
Si cae SW2/SW3, que sesiones se afectan?
Hay camino alternativo?
El usuario podria recuperarse sin relogin?
```

Sin instalar la app ONOS y sin activar el flag, todavia no hace:

```text
reinstalar flows automaticamente ante una caida real
borrar flows viejas
apagar puertos
reiniciar ONOS
```

Si se invoca `recover` con `apply=true` y el flag apagado, no instala nada. Si se manda una falla simulada en `failed_devices` o `failed_links`, M6 lo trata como dry-run y no aplica cambios, porque aplicar debe hacerse contra la topologia real que ONOS ve despues de la falla.

## GRE De Monitoreo En Failover

M6 tambien analiza y reasegura GRE de monitoreo. El estado normal usa la
ruta base:

```text
SW4 -> SW3 -> SW1 -> monitoring
```

Ver estado:

```bash
curl -sS --max-time 10 \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/gre-status \
  | python3 -m json.tool
```

Simular SW3 caido sin aplicar cambios:

```bash
curl -sS --max-time 15 -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/failover/analyze \
  -d '{"failed_devices":["of:0000eadb63449748"]}' \
  | python3 -m json.tool
```

Resultado esperado para GRE si existe camino alternativo:

```text
gre.mode: dynamic_path
gre.recoverable: true
gre.route: SW4 -> SW2 -> SW1
```

Si `FAILOVER_AUTO_REINSTALL_ENABLED=true` y llega un evento real desde ONOS,
M6 puede limpiar solo las flows GRE conflictivas e instalar la ruta alternativa.
No usa polling, no crea threads nuevos y no toca portal, mitigaciones, M4, M5,
Suricata, netplan ni `ens3`.

## Estado Actual Esperado

```text
FAILOVER_AUTO_REINSTALL_ENABLED=true
MONITORING_GRE_INSTALL_ON_STARTUP=true
dedup de evento: 15s
cooldown por MAC: 10s
max sesiones por recovery: 20
```

Si llega una falla real:

```text
ONOS -> topology-events -> M6 /m6/failover/event
M6 analiza sesiones y GRE
M6 reinstala solo si hay ruta alternativa
si no hay ruta alternativa, mantiene sesion activa y reporta no recuperable
```
