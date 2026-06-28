# Acceso VMs y Runbook de Pruebas SDN

> Nota de seguridad: este archivo contiene passwords de laboratorio. No subir a
> un repositorio publico ni compartir fuera del equipo del proyecto.

## Reglas de Seguridad

- No tocar `netplan`.
- No cambiar IPs, DHCP, DNS, gateway ni rutas.
- No activar `org.onosproject.fwd`.
- No instalar flows con `OUTPUT:NORMAL`.
- No ejecutar `DROP`, `TRUNCATE` ni recargar el SQL completo.
- Antes de modificar código en una VM, hacer backup del archivo vivo.
- Para pruebas de red, empezar siempre con comandos de solo lectura.

## Gateway SSH

Las VMs se alcanzan por SSH usando el gateway/lab host:

```bash
ssh -p <PUERTO> ubuntu@10.20.11.32
```

Password SSH:

```text
ubuntu
```

Password `sudo` en VMs Ubuntu:

```text
ubuntu
```

## Mapa de VMs Usadas

| VM | Puerto SSH | Usuario | Funcion |
|---|---:|---|---|
| ONOS | `5800` | `ubuntu` / password `ubuntu` | Controlador ONOS en Docker |
| AAA / Policies | `5851` | `ubuntu` / password `ubuntu` | `web.py`, `m6_traductor.py`, OPA/M2, MySQL |
| H3 | `5813` | `ubuntu` / password `ubuntu` | Host de pruebas |

> Agregar H1/H2 si se necesita repetir pruebas en esos hosts.

## ONOS VM

Entrar:

```bash
ssh -p 5800 ubuntu@10.20.11.32
sudo -i
```

Ver contenedor:

```bash
docker ps
```

El contenedor esperado se llama:

```text
onos
```

La imagen esperada:

```text
onosproject/onos:2.7.0
```

Comandos de verificacion:

```bash
docker exec onos bash -lc 'curl -s -u onos:rocks --max-time 8 http://127.0.0.1:8181/onos/v1/devices'
docker exec onos bash -lc 'curl -s -u onos:rocks --max-time 8 http://127.0.0.1:8181/onos/v1/applications/org.onosproject.fwd'
docker exec onos bash -lc 'curl -s -u onos:rocks --max-time 10 http://127.0.0.1:8181/onos/v1/flows | grep -c "OUTPUT.*NORMAL"'
```

Estado esperado:

- ONOS ve 5 switches.
- `org.onosproject.fwd` debe estar `INSTALLED`, no `ACTIVE`.
- `OUTPUT.NORMAL` debe ser `0`.

Ver flows de SW4:

```bash
docker exec onos bash -lc 'curl -s -u onos:rocks --max-time 10 http://127.0.0.1:8181/onos/v1/flows/of:00006a0757adfc4e'
```

## AAA / Policies VM

Entrar:

```bash
ssh -p 5851 ubuntu@10.20.11.32
```

Archivos principales:

```text
/home/ubuntu/web.py
/home/ubuntu/m6_traductor.py
/home/ubuntu/sync.py
/home/ubuntu/policy.rego
```

Ver estado M6:

```bash
curl -sS --max-time 8 http://127.0.0.1:8080/m6/status
```

Estado esperado:

```text
network_actions_enabled=true
onos_reads_enabled=true
onos_writes_enabled=true
reactive_data_flows_enabled=true
session_expire_on_t1_removed=true
startup_flow_install_enabled=false
session_idle_timeout=600
```

Ver procesos:

```bash
ps -eo pid,cmd,%mem,%cpu --sort=-%cpu | head -10
```

Logs utiles:

```bash
ls -lt /home/ubuntu/logs | head
tail -120 /home/ubuntu/logs/m6_t2_hybrid.log
```

Reiniciar solo M6, si el usuario lo aprueba:

```bash
cp /home/ubuntu/m6_traductor.py /home/ubuntu/m6_traductor.py.bak.$(date +%Y%m%d_%H%M%S)
python3 -m py_compile /home/ubuntu/m6_traductor.py
pkill -f 'python3 -u m6_traductor.py' || true
sleep 2
NETWORK_ACTIONS_ENABLED=true \
ONOS_READS_ENABLED=true \
ONOS_WRITES_ENABLED=true \
POLICY_QUERIES_ENABLED=true \
MYSQL_SECURITY_READS_ENABLED=true \
STARTUP_FLOW_INSTALL_ENABLED=false \
REACTIVE_DATA_FLOWS_ENABLED=true \
SESSION_EXPIRE_ON_T1_REMOVED=true \
SESSION_IDLE_TIMEOUT=600 \
DATA_FLOW_TIMEOUT=300 \
PORTAL_IP=192.168.100.110 \
PORTAL_SYNC_INTERVAL=30 \
PACKET_IN_DEDUP_WINDOW=2 \
PACKET_IN_RATE_LIMIT_WINDOW=10 \
PACKET_IN_RATE_LIMIT_MAX_EVENTS=80 \
PACKET_IN_RATE_LIMIT_MAX_PORTS=30 \
PACKET_IN_RATE_LIMIT_MAX_DESTINATIONS=15 \
nohup python3 -u m6_traductor.py > /home/ubuntu/logs/m6_t2_hybrid.log 2>&1 &
```

## H3 VM

Entrar:

```bash
ssh -p 5813 ubuntu@10.20.11.32
```

Ver IPs:

```bash
ip -br addr
```

Estado esperado visto en pruebas:

```text
ens3 192.168.201.213/24
ens4 192.168.100.54/24
```

Probar portal:

```bash
curl -sS --max-time 8 -o /dev/null -w 'portal=%{http_code}\n' http://192.168.100.110:8282/
```

Login de prueba H3 Informatica:

```bash
curl -sS --max-time 20 \
  -H 'Content-Type: application/json' \
  -d '{"usuario":"<REDACTED>","password":"<REDACTED>"}' \
  http://192.168.100.110:8282/auth/login
```

Ver sesion actual:

```bash
curl -sS --max-time 8 http://192.168.100.110:8282/auth/sesion/actual
```

Probar recurso permitido Informatica:

```bash
curl -sS --max-time 12 -o /dev/null -w 'info8002=%{http_code}\n' http://192.168.100.101:8002
```

Resultado esperado:

```text
info8002=200
```

Probar recurso no permitido para Informatica:

```bash
curl -sS --max-time 8 -o /dev/null -w 'electro8003=%{http_code}\n' http://192.168.100.101:8003 || true
```

Resultado esperado:

```text
timeout / 000
```

Logout limpio:

```bash
curl -sS --max-time 12 \
  -H 'Content-Type: application/json' \
  -d '{"mac":"FA:16:3E:B6:F8:7D","id_usuario":<REDACTED>,"codigo_pucp":"<REDACTED>","ip_asignada":"192.168.100.54","es_visitante":false}' \
  http://192.168.100.110:8282/auth/logout
```

## Verificacion del Modelo T2 Hibrido

Despues del login y antes de navegar al recurso, revisar SW4 tabla 2:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows sw4 table=2
```

Tambien se puede revisar desde ONOS:

```bash
docker exec onos bash -lc 'curl -s -u onos:rocks --max-time 10 http://127.0.0.1:8181/onos/v1/flows/of:00006a0757adfc4e | sed "s/},{/}\n{/g" | grep "tableId\":2" -A18'
```

Estado esperado para un estudiante de Informatica:

- Tabla 1: una flow T1 de sesion con idle timeout 600.
- Tabla 2: flows T2 reales priority 110 para recursos normales del rol.
- Tabla 3: vacia, salvo que se use una excepcion JP/doble carrera.
- Tabla 4: una flow TCP IPv4 wildcard priority 5 hacia CONTROLLER y una default drop.
- Tabla 0: portal/control/rutas exactas de ida/vuelta; no packet-in reactivo priority 5.

## Como Interpretar Las Tablas

| Tabla | Sentido | Funcion |
|---|---|---|
| T0 | Ida y vuelta | Portal/control, clasificacion exacta, troncales y retorno |
| T1 | Ida | Sesion valida del usuario, MAC/puerto y VLAN logica |
| T2 | Ida | Permisos normales hibridos: proactivos al login y reactivos si expiran |
| T3 | Ida | Excepciones por usuario/sesion, solo bajo demanda |
| T4 | Ida | Fallback TCP IPv4 wildcard hacia ONOS/M6 y default drop |

T2/T3 no manejan el retorno. El retorno viaja por T0 exacta.

## Packet-In Reactivo En T4

La app ONOS `pe.edu.pucp.sdn.m6-onos-events` instala en SW4 table 4:

```text
priority=5,tcp,ip actions=CONTROLLER
priority=0 actions=drop
```

La flow priority 5 no es permiso directo. Es el despertador reactivo para TCP IPv4
que llega hasta T4 despues de no encontrar permiso especifico en T2/T3.

Funcionan asi:

1. Si existe una flow especifica de mayor prioridad, esa flow gana.
2. Si no existe, el paquete pasa por `T2 miss -> T3 miss -> T4`.
3. La app ONOS avisa a M6.
4. M6 valida sesion y politica OPA/M2.
5. Si corresponde, M6 instala las flows reales.
6. Si no corresponde, M6 no instala allow y registra denial/burst.

## Riesgos Conocidos A Revisar

- Hay flows antiguas de portal con prioridad 500 y duracion muy larga. No borrarlas sin identificar appId/cookie.
- Aparecio una flow GRE `nw_proto=47`; revisar origen antes de tocarla.
- La VM de monitoreo tuvo disco lleno en algun momento; limpiar aparte si se vuelve a usar monitoreo.

## Proximos Pasos Recomendados

1. Probar usuarios JP y doble carrera.
2. Confirmar que T3 aparece solo al usar recurso extra.
3. Confirmar que logout limpia T1/T3 de borde.
4. Esperar 5 minutos y verificar que T2/T0 de datos expiren por idle timeout.
5. Esperar 10 minutos sin trafico y verificar que T1 expire, M6 cierre sesion y CLI vuelva a cuarentena.
6. Documentar resultado final antes de limpiar backups.
