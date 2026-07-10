# Guia Demo: Resiliencia Ante Caida De SW2/SW3

Esta guia explica que se implemento para que la red SDN pueda seguir funcionando cuando cae un switch intermedio o un enlace, y como probarlo sin apagar VMs ni tocar la interfaz de gestion `ens3`.

## 1. Objetivo

Validar que, si cae SW2 o SW3:

- las sesiones de usuarios se mantienen activas;
- M6 no desloguea al usuario por una falla de topologia;
- ONOS informa eventos de enlace/switch a M6;
- M6 limpia/recalcula/reinstala flows afectadas;
- el usuario vuelve a acceder al recurso permitido sin reloguearse;
- el tunel GRE de monitoreo se puede reasegurar.

El comportamiento esperado no es cero perdida de paquetes. Es normal que el primer intento durante la caida haga timeout mientras ONOS/M6 detectan y reinstalan. Lo importante es que el siguiente intento vuelva a responder.

## 2. Componentes

| Componente | Funcion |
|---|---|
| ONOS | Detecta `DeviceEvent`/`LinkEvent` y mantiene la topologia. |
| `app/onos_topology_events` | App ONOS que envia eventos de topologia a M6. |
| M6 | Recibe eventos, analiza impacto, recalcula rutas y reinstala flows. |
| SW4 | Borde de usuarios H1/H2/H3. |
| SW2/SW3 | Switches intermedios con rutas alternativas. |
| SW5 | Borde de servidores academicos. |
| SW1 | Salida hacia monitoreo/GRE. |

## 3. Cambios Implementados

### 3.1 Endpoints De Failover En M6

M6 tiene endpoints para inspeccionar, simular y recuperar:

```text
GET  /m6/failover/topology
POST /m6/failover/analyze
POST /m6/failover/recover
POST /m6/failover/event
```

El flujo real es:

```text
ONOS detecta cambio
        |
        v
topology-events envia evento a M6
        |
        v
M6 deduplica evento
        |
        v
M6 identifica sesiones afectadas
        |
        v
M6 invalida caches/flows que usaban el switch/enlace caido
        |
        v
M6 recalcula ruta con links actuales de ONOS
        |
        v
M6 reinstala T1/T2/T3/troncales/retorno si hay ruta alternativa
```

### 3.2 Sesiones

La sesion no se borra solo porque cae SW2/SW3.

Ejemplo:

```text
H3 esta logueado como Informatica
H3 tiene permiso a 192.168.100.101:8002
SW2 cae
M6 recalcula ruta alternativa
H3 sigue autenticado
H3 vuelve a acceder a 8002 sin relogin
```

### 3.3 GRE De Monitoreo

M6 tambien puede asegurar las flows base del tunel GRE:

```text
POST /m6/monitoring/ensure-gre
GET  /m6/monitoring/gre-status
```

Ruta base esperada:

```text
SW4 -> SW3 -> SW1 -> monitoring
```

Flows GRE base:

```text
SW4 T0: ip,nw_proto=47,nw_dst=192.168.200.213 -> output hacia SW3
SW3 T0: in_port desde SW4, ip,nw_proto=47,nw_dst=192.168.200.213 -> output hacia SW1
SW1 T0: in_port desde SW3, ip,nw_proto=47,nw_dst=192.168.200.213 -> output hacia monitoring
```

## 4. Flags Importantes En M6

En la VM AAA/M6:

```text
FAILOVER_ANALYSIS_ENABLED=true
FAILOVER_AUTO_REINSTALL_ENABLED=true
FAILOVER_RECOVERY_COOLDOWN=10
FAILOVER_RECOVERY_MAX_SESSIONS=20
FAILOVER_EVENT_DEDUP_WINDOW=15
MONITORING_GRE_INSTALL_ON_STARTUP=true
```

Significado:

| Flag | Significado |
|---|---|
| `FAILOVER_ANALYSIS_ENABLED` | Permite analizar impacto de caidas. |
| `FAILOVER_AUTO_REINSTALL_ENABLED` | Permite reinstalar flows automaticamente cuando llega un evento real. |
| `FAILOVER_RECOVERY_COOLDOWN` | Evita reinstalar muchas veces seguidas por la misma sesion. |
| `FAILOVER_RECOVERY_MAX_SESSIONS` | Limita cuantas sesiones intenta recuperar por evento. |
| `FAILOVER_EVENT_DEDUP_WINDOW` | Deduplica eventos repetidos de ONOS. |
| `MONITORING_GRE_INSTALL_ON_STARTUP` | Reasegura GRE al arrancar M6. |

## 5. Precheck Antes De Probar

### 5.1 Ver Que M6 Este Vivo

En AAA:

```bash
curl -sS http://127.0.0.1:8080/m6/status | python3 -m json.tool
```

Campos esperados:

```text
status: ok
onos_reads_enabled: true
onos_writes_enabled: true
failover_analysis_enabled: true
failover_auto_reinstall_enabled: true
```

### 5.2 Ver Topologia

```bash
curl -sS -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/failover/topology \
  | python3 -m json.tool
```

Esperado:

```text
5 switches disponibles
links activos entre SW4/SW2/SW3/SW5/SW1
```

### 5.3 Ver GRE

```bash
curl -sS -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/gre-status \
  | python3 -m json.tool
```

Esperado:

```text
recoverable: true
sw4_gre_to_sw3 present: true
sw3_gre_to_sw1 present: true
sw1_gre_to_monitoring present: true
```

Si falta alguna:

```bash
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/ensure-gre \
  | python3 -m json.tool
```

## 6. Preparar Usuario De Prueba

Ejemplo con H3 Informatica.

Entrar a H3:

```bash
ssh -p 5813 ubuntu@10.20.11.32
```

Login por portal:

```bash
python3 cli.py
```

Credenciales:

```text
usuario: 20200101
password: pass_info123
```

Probar recurso permitido:

```bash
curl -sS --max-time 8 -o /dev/null \
  -w 'info8002=%{http_code} exit=%{exitcode}\n' \
  http://192.168.100.101:8002/
```

Esperado:

```text
info8002=200 exit=0
```

## 7. Prueba Segura De Caida De SW2

No apagar la VM. Solo bajar puertos de datos. No tocar `ens3`.

Entrar a SW2:

```bash
ssh -p 5802 ubuntu@10.20.11.32
```

Ejecutar prueba con rollback automatico:

```bash
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

Mientras tanto, desde H3 probar cada pocos segundos:

```bash
for i in $(seq 1 9); do
  date -Is
  curl -sS --max-time 5 -o /dev/null \
    -w 'h3_8002 http=%{http_code} exit=%{exitcode} time=%{time_total}\n' \
    http://192.168.100.101:8002/ || true
  sleep 5
done
```

Resultado esperado:

```text
Primer intento durante la caida: puede dar timeout
Siguientes intentos: h3_8002 http=200 exit=0
```

Ver rollback:

```bash
cat /tmp/sw2_failover_safe_test.log
sudo ovs-ofctl -O OpenFlow13 show sw2 | egrep 'ens4|ens5|ens6|ens7'
```

## 8. Prueba Segura De Caida De SW3

Entrar a SW3:

```bash
ssh -p 5803 ubuntu@10.20.11.32
```

Ejecutar prueba con rollback automatico:

```bash
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

Desde H3:

```bash
for i in $(seq 1 9); do
  date -Is
  curl -sS --max-time 5 -o /dev/null \
    -w 'h3_8002 http=%{http_code} exit=%{exitcode} time=%{time_total}\n' \
    http://192.168.100.101:8002/ || true
  sleep 5
done
```

Resultado esperado:

```text
Primer intento durante la caida: puede dar timeout
Siguientes intentos: h3_8002 http=200 exit=0
```

Ver rollback:

```bash
cat /tmp/sw3_failover_safe_test.log
sudo ovs-ofctl -O OpenFlow13 show sw3 | egrep 'ens4|ens5|ens6|ens7'
```

## 9. Ver Flows Reinstaladas

### 9.1 En SW4

```bash
ssh -p 5804 ubuntu@10.20.11.32
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=1
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=2
```

Esperado para H3 Informatica:

```text
T1: in_port=3,dl_src=MAC_H3,nw_src=192.168.100.54 -> push_vlan:220,goto_table:2
T2 ida: dl_vlan=220,nw_dst=192.168.100.101,tp_dst=8002 -> output hacia core
T2 vuelta: dl_vlan=220,nw_src=192.168.100.101,nw_dst=192.168.100.54,tp_src=8002 -> pop_vlan,output:H3
```

### 9.2 En SW2 O SW3

Segun la ruta activa, debe aparecer forwarding agregado:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw2 table=0 | egrep '192.168.100.101|192.168.200.213'
sudo ovs-ofctl -O OpenFlow13 dump-flows sw3 table=0 | egrep '192.168.100.101|192.168.200.213'
```

Ejemplos:

```text
tcp,in_port=X,nw_dst=192.168.100.101 -> output:Y
tcp,in_port=Y,nw_src=192.168.100.101 -> output:X
ip,nw_proto=47,nw_dst=192.168.200.213 -> output:Z
```

## 10. Ver Logs De M6

En AAA:

```bash
ssh -p 5851 ubuntu@10.20.11.32
grep -nE 'failover|FAILOVER|recover|reinstall|GRE|gre|SW2|SW3' \
  /home/ubuntu/logs/m6_failover_gre_dynamic.log | tail -n 120
```

Debes ver eventos `POST /m6/failover/event` enviados por ONOS y reinstalaciones de flows en SW2/SW3 segun la ruta disponible.

## 11. Resultado Que Se Obtuvo En La Prueba Real

Prueba realizada con H3 Informatica contra:

```text
192.168.100.101:8002
```

Resultado SW2:

```text
Primer intento: timeout
Luego: HTTP 200 sin relogin
Rollback: puertos ens4/ens5/ens6/ens7 restaurados
```

Resultado SW3:

```text
Primer intento: timeout
Luego: HTTP 200 sin relogin
Rollback: puertos ens4/ens5/ens6/ens7 restaurados
```

GRE final:

```text
sw4_gre_to_sw3 present=true
sw3_gre_to_sw1 present=true
sw1_gre_to_monitoring present=true
```

## 12. Que No Debe Tocarse

No tocar:

```text
ens3
netplan
rutas Linux
DHCP
DNS
gateway
org.onosproject.fwd
OUTPUT:NORMAL
```

No usar:

```bash
sudo reboot
sudo systemctl restart networking
sudo ip link set ens3 down
```

## 13. Recuperacion Manual Si Algo Queda Mal

### 13.1 Subir Puertos De SW2

```bash
ssh -p 5802 ubuntu@10.20.11.32
for p in ens4 ens5 ens6 ens7; do
  echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw2 "$p" up
done
```

### 13.2 Subir Puertos De SW3

```bash
ssh -p 5803 ubuntu@10.20.11.32
for p in ens4 ens5 ens6 ens7; do
  echo ubuntu | sudo -S ovs-ofctl -O OpenFlow13 mod-port sw3 "$p" up
done
```

### 13.3 Reasegurar GRE

```bash
ssh -p 5851 ubuntu@10.20.11.32
curl -sS -X POST \
  -H 'X-Security-Token: change-me' \
  http://127.0.0.1:8080/m6/monitoring/ensure-gre \
  | python3 -m json.tool
```

### 13.4 Verificar Servicio Academico

En `srv1-academicos`:

```bash
ssh -p 5821 ubuntu@10.20.11.32
sudo docker ps --filter name=sdn-srv-academicos
sudo ss -ltnp | egrep ':8001|:8002|:8003|:1443|:2443|:3443'
```

Si no esta levantado:

```bash
cd /home/ubuntu/srv1-academicos
sudo docker compose up -d
```

## 14. Interpretacion Final

La red queda resiliente a caidas de SW2/SW3 cuando existe ruta alternativa visible por ONOS.

No significa que nunca habra perdida de paquetes. Significa:

```text
la sesion no se borra,
M6 no obliga a relogin,
M6 recalcula ruta,
M6 reinstala flows,
el acceso vuelve automaticamente.
```

Si no existe ruta alternativa, M6 no debe instalar flows a ciegas ni entrar en bucle. Debe marcar la sesion como no recuperable temporalmente y esperar a que vuelva la topologia.
