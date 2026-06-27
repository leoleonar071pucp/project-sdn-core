# Estado actual del portal cautivo SDN

Fecha de referencia: 2026-06-26  
Workspace: `C:\Users\ACER\Downloads\SDN-PROJECT`

Este documento resume los cambios realizados durante la estabilizacion del laboratorio, que funciona ahora, que faltaba inicialmente, que falta todavia y que precauciones se mantienen para evitar bucles, saturacion de ONOS o consumo excesivo de memoria.

## Resumen ejecutivo

El portal cautivo ya funciona con DHCP de ONOS, descubrimiento de hosts, acceso automatico al portal y flows explicitos por rol.

Flujo validado:

```text
Host nuevo
  -> DHCP ONOS
  -> IP 192.168.100.x
  -> ONOS aprende MAC/IP/switch/puerto
  -> M6 portal sync instala ruta host <-> portal TCP/8282
  -> usuario hace login
  -> M6 instala flows por rol hacia recursos permitidos
  -> logout borra flows de sesion
```

Se mantiene apagado:

```text
org.onosproject.fwd
STARTUP_FLOW_INSTALL_ENABLED=true
```

Esto es intencional para no volver al escenario de saturacion de ONOS/packet-in y bucles en la topologia mallada.

## Archivos modificados en el repo

| Archivo | Proposito |
|---|---|
| `app/m6_traductor/m6_traductor.py` | Calculo de rutas explicitas, flows por sesion, lectura correcta de politicas MySQL, portal sync automatico y endpoint `/m6/portal/sync`. |
| `app/m1_auth/m1_auth.py` | M1 envia `session_timeout` a M6 y queda con `M6_HABILITADO=True` para operar con ONOS real. |
| `app/m1_auth/cli.py` | Cliente CLI apunta por defecto al portal real `192.168.100.110:8282`. |
| `docs/entregas/ESTADO_ACTUAL_PORTAL_CAUTIVO_SDN.md` | Este documento de estado. |

Rutas absolutas principales:

```text
C:\Users\ACER\Downloads\SDN-PROJECT\app\m6_traductor\m6_traductor.py
C:\Users\ACER\Downloads\SDN-PROJECT\app\m1_auth\m1_auth.py
C:\Users\ACER\Downloads\SDN-PROJECT\app\m1_auth\cli.py
C:\Users\ACER\Downloads\SDN-PROJECT\docs\entregas\ESTADO_ACTUAL_PORTAL_CAUTIVO_SDN.md
```

## Cambios tecnicos realizados

### M6: rutas explicitas

Antes M6 instalaba flows post-login demasiado amplios, por ejemplo `OUTPUT NORMAL` en el switch de acceso del host. Eso era peligroso en una topologia con bucles y no programaba el camino completo.

Ahora M6:

- Consulta ONOS `/onos/v1/hosts`.
- Consulta ONOS `/onos/v1/links`.
- Calcula camino hop-by-hop con BFS.
- Instala flows en todos los switches del camino.
- Instala ida y retorno.
- Hace match estricto por `IN_PORT`, `ETH_SRC`, `ETH_DST`, `IPV4_SRC`, `IPV4_DST`, `TCP_DST` o `TCP_SRC`.

Ejemplo conceptual:

```text
H2/SW4 -> SW2 -> SW5 -> srv1
srv1/SW5 -> SW2 -> SW4 -> H2
```

### M6: flows por sesion

Cada usuario tiene sus propios flow IDs guardados por MAC:

```text
flows_por_sesion = {
  "mac_h1": [(sw, flow_id), ...],
  "mac_h2": [(sw, flow_id), ...]
}
```

Al hacer logout, M6 borra solo los flows de esa MAC/sesion. Esto evita que un usuario desconecte a otro aunque compartan servidor o camino fisico.

### M6: politicas MySQL corregidas

Antes M6 esperaba columnas que no existen en el esquema real (`rec.ip_dst`, `p.accion`), por eso caia a hardcoded antiguo.

Ahora lee el esquema real:

```text
politicas_rbac -> recursos -> servidores.ip_servidor
```

Puertos validados:

| Rol | Recursos |
|---|---|
| `Estudiante_Telecom` | `192.168.100.101:8001`, `192.168.100.101:1443` |
| `Estudiante_Informatica` | `192.168.100.101:8002`, `192.168.100.101:2443`, `192.168.100.102:8080` |
| `Estudiante_Electronica` | `192.168.100.101:8003`, `192.168.100.101:3443` |

### M6: acceso automatico al portal

Se agrego:

```text
POST /m6/portal/sync
PORTAL_SYNC_INTERVAL=30
```

M6 lee hosts aprendidos por ONOS y crea flows minimos:

```text
host -> portal TCP dst 8282
portal -> host TCP src 8282
```

No abre ICMP, no abre acceso a recursos, no usa `NORMAL`.

### M1: timeout real de RADIUS

M1 ahora envia `session_timeout` a M6. Los flows post-login usan el timeout de la sesion RADIUS, por ejemplo `7200` segundos, en lugar de quedar con un valor fijo largo.

### CLI

El CLI queda apuntando por defecto a:

```text
http://192.168.100.110:8282
```

El CLI fue copiado y probado en H1/H2/H3.

## Configuracion viva en las VMs

Estas configuraciones son importantes y no viven todas como codigo del repo. Algunas estan aplicadas directamente en ONOS o al arrancar procesos.

### ONOS

ONOS corre en Docker:

```text
container: onos
image: onosproject/onos:2.7.0
```

Apps relevantes:

| App | Estado deseado |
|---|---|
| `org.onosproject.dhcp` | `ACTIVE` |
| `org.onosproject.hostprovider` | `ACTIVE` |
| `org.onosproject.fwd` | `INSTALLED`, no `ACTIVE` |

Configuracion DHCP de ONOS:

```text
DHCP server IP: 192.168.100.254
Pool: 192.168.100.20 - 192.168.100.80
Subnet: 255.255.255.0
Broadcast: 192.168.100.255
Router configurado: 192.168.100.1
Lease: 300 segundos
```

Configuraciones activadas:

```text
org.onosproject.dhcp.impl.DhcpManager allowHostDiscovery=true
org.onosproject.provider.host.impl.HostLocationProvider useDhcp=true
```

### AAA

Procesos esperados:

```text
python3 /home/ubuntu/web.py
python3 /home/ubuntu/m6_traductor.py
```

M6 se debe levantar con:

```bash
NETWORK_ACTIONS_ENABLED=true \
ONOS_READS_ENABLED=true \
ONOS_WRITES_ENABLED=true \
STARTUP_FLOW_INSTALL_ENABLED=false \
PORTAL_SYNC_INTERVAL=30 \
PORTAL_IP=192.168.100.110 \
python3 /home/ubuntu/m6_traductor.py
```

Portal:

```bash
python3 /home/ubuntu/web.py
```

## Estado validado

### DHCP

H2 recibio IP desde ONOS:

```text
DHCPACK of 192.168.100.56 from 192.168.100.254
ens4 UP 192.168.100.56/24
```

### Portal

Desde H2 con IP DHCP:

```text
curl http://192.168.100.110:8282/
portal HTTP 200
```

### Login y recursos

| Host | IP validada | Usuario | Rol | Recurso probado | Resultado |
|---|---:|---|---|---|---|
| H1 | `192.168.100.14` y luego ONOS mostro DHCP `.55` | `20192434` | Telecom | `192.168.100.101:8001` | `HTTP 200` |
| H2 | `192.168.100.56` por DHCP ONOS | `20200202` | Electronica | `192.168.100.101:8003` | `HTTP 200` |
| H3 | `192.168.100.12` durante prueba estatica | `20200101` | Informatica | `192.168.100.101:8002` | `HTTP 200` |

Nota: para una operacion limpia con DHCP, conviene que H1/H2/H3 dejen de usar IPs estaticas temporales y renueven IP desde ONOS.

## Diferencias contra el estado inicial

| Antes | Ahora |
|---|---|
| H1 no conectaba al portal por IP equivocada `192.168.100.100`. | CLI apunta a `192.168.100.110`. |
| ONOS estaba saturado/colgado con sintomas de memoria y packet-in. | ONOS estable, `fwd` apagado y flows controlados. |
| No habia DHCP operativo para hosts. | ONOS DHCP entrega IPs del pool `.20-.80`. |
| M6 usaba `OUTPUT NORMAL` para recursos. | M6 calcula ruta explicita por `/hosts` y `/links`. |
| M6 instalaba solo en switch de acceso del host. | M6 instala flows en todos los switches del camino. |
| Logout podia ser confuso por flows amplios. | Logout borra flow IDs de la sesion/MAC especifica. |
| M6 leia mal el esquema MySQL y caia a hardcoded antiguo. | M6 lee `politicas_rbac`, `recursos` y `servidores` reales. |
| Acceso inicial al portal se hacia manual por host. | M6 tiene `/m6/portal/sync` y sync periodico. |

## Lo que falta

### Persistir configuracion de ONOS

La config de ONOS aplicada por REST debe quedar documentada o automatizada en script. Si el contenedor ONOS se recrea desde cero, puede perderse:

```text
DHCP pool 192.168.100.20-80
allowHostDiscovery=true
HostLocationProvider useDhcp=true
```

Pendiente recomendado:

```text
scripts/configurar_onos_dhcp.ps1
scripts/configurar_onos_dhcp.sh
```

### Automatizar arranque de AAA

Hoy M6/web se levantan manualmente con `nohup`. Conviene crear:

```text
scripts/run_m6_safe.sh
scripts/run_portal.sh
```

o servicios `systemd`.

### Limpiar IPs estaticas temporales

Para simular laptops reales, H1/H2/H3 deben depender de DHCP:

```bash
sudo ip addr flush dev ens4
sudo dhclient -1 -v ens4
```

### Automatizar limpieza de hosts stale

ONOS puede retener hosts viejos si una VM cambia IP/MAC o si se hicieron pruebas con IPs duplicadas. Falta un flujo seguro para limpiar hosts stale sin hacerlo a mano.

### Validar todos los roles

Probado:

```text
Telecom
Informatica
Electronica
```

Pendiente:

```text
Docente
Admin_TI
Visitante
Usuarios multi-rol
Denegaciones esperadas
```

### Persistencia de portal flows

Los flows de portal tienen timeout. M6 los re-sincroniza cada 30 segundos, pero si M6 cae, esos flows expiraran. Conviene convertir el arranque de M6 en servicio estable.

### Pruebas automatizadas

Faltan pruebas automatizadas de:

```text
calculo de ruta
instalacion de ida/retorno
logout por sesion
portal_sync
lectura MySQL de politicas
```

## Riesgos de bucles, RAM y red

### Riesgos que ya se mitigaron

| Riesgo | Mitigacion aplicada |
|---|---|
| `fwd` generando packet-in/flows reactivos en una topologia con bucles | `org.onosproject.fwd` se mantiene apagado. |
| Reglas `OUTPUT NORMAL` abriendo switching tradicional | M6 usa `OUTPUT` a puerto exacto en flows nuevos. |
| Flows masivos al arranque | `STARTUP_FLOW_INSTALL_ENABLED=false`. |
| Borrar flows de otros usuarios en logout | Flows guardados por MAC/sesion. |
| IPs duplicadas por pruebas manuales | Se movio DHCP a pool `.20-.80` para no chocar con servidores/portal. |

### Riesgos que todavia existen

| Riesgo | Impacto | Recomendacion |
|---|---|---|
| Activar `fwd` accidentalmente | Puede volver a saturar ONOS y crear comportamiento peligroso en bucles. | No activar `org.onosproject.fwd`. |
| Usar `STARTUP_FLOW_INSTALL_ENABLED=true` sin revisar | Puede instalar flows amplios/antiguos. | Mantener `false` hasta refactor completo del arranque. |
| Hosts stale en ONOS | M6 podria resolver MAC/IP vieja. | Limpiar hosts stale o esperar aging; evitar IPs manuales duplicadas. |
| Reinicio total de ONOS sin reaplicar config | DHCP/host discovery podria quedar incompleto. | Crear script de configuracion ONOS. |
| M6 no corriendo | Portal flows expiran y nuevos hosts no llegan al portal. | Levantar M6 como servicio. |

## Que esta en el repo y que no

### Si esta en el repo

Codigo principal:

```text
app/m1_auth/cli.py
app/m1_auth/m1_auth.py
app/m1_auth/web.py
app/m6_traductor/m6_traductor.py
db/radius_db_pucp_sdn.sql
servicios/srv1 academicos/*
servicios/srv2 notas/*
app/security/*
```

El codigo de M6 que se desplego esta reflejado en:

```text
app/m6_traductor/m6_traductor.py
```

El cambio de `session_timeout` y `M6_HABILITADO=True` esta reflejado en:

```text
app/m1_auth/m1_auth.py
```

El CLI con portal correcto esta reflejado en:

```text
app/m1_auth/cli.py
```

### No esta completamente versionado todavia

Configuracion viva de ONOS aplicada por REST:

```text
DHCP pool
allowHostDiscovery=true
HostLocationProvider useDhcp=true
app dhcp active
app fwd inactive
```

Procesos vivos de AAA:

```text
nohup python3 /home/ubuntu/m6_traductor.py
nohup python3 /home/ubuntu/web.py
```

Copias de archivos en VMs:

```text
/home/ubuntu/cli.py en H1/H2/H3
/home/ubuntu/m1_auth.py en AAA
/home/ubuntu/m6_traductor.py en AAA
/home/ubuntu/web.py en AAA
```

Recomendacion: crear scripts de despliegue/configuracion para que todo sea reproducible desde el repo.

## Comandos utiles de verificacion

## Verificacion 2026-06-26

Se probo H1, H2 y H3 usando DHCP temporal en `ens4`, sin modificar netplan.

| Host | IP DHCP | Portal | Login | Recurso | Logout | Recurso despues de logout |
| --- | --- | --- | --- | --- | --- | --- |
| H1 | 192.168.100.55 | HTTP 200 | OK, Estudiante_Telecom | HTTP 200 | OK | bloqueado |
| H2 | 192.168.100.56 | HTTP 200 | OK, Estudiante_Electronica | HTTP 200 | OK | bloqueado |
| H3 | 192.168.100.54 | HTTP 200 | OK, Estudiante_Informatica | HTTP 200 | OK | bloqueado |

Fallo encontrado durante la prueba: H2 y H3 habian recibido nuevas IPs por DHCP,
pero ONOS aun tenia flows antiguos del portal que matcheaban IPs previas
(`192.168.100.13` y `192.168.100.12`). Se limpio solo ese conjunto de flows
TCP/8282 obsoleto y se reinicio M6 con `STARTUP_FLOW_INSTALL_ENABLED=false`.

M6 ahora expone `portal_ips` en `/m6/status` para confirmar que el cache de flows
del portal corresponde a la IP DHCP actual de cada MAC.

## Verificacion pipeline T0/T1/T2 2026-06-26

Se migro la instalacion de flows post-login de recursos desde una sola tabla T0
hacia un pipeline multi-tabla conservador:

| Tabla | Funcion actual |
| --- | --- |
| T0 | Clasifica el flujo exacto de sesion y hace `goto T1`. Tambien mantiene DHCP/portal base. |
| T1 | Valida el mismo flujo exacto de sesion y hace `goto T2`. |
| T2 | Aplica el permiso del recurso y hace `OUTPUT` al puerto exacto del siguiente salto. |
| T3 | Reservada para bloqueos/deny extraordinarios; no se usa en el flujo normal probado. |

No se activo `org.onosproject.fwd`, no se uso `OUTPUT NORMAL` para recursos y no
se modifico netplan. Los flows de datos usan `DATA_FLOW_TIMEOUT=300` segundos.

Resultado probado:

| Host | Portal | Login | Recurso | Logout | Resultado posterior |
| --- | --- | --- | --- | --- | --- |
| H1 | HTTP 200 | OK | HTTP 200 | OK | recurso bloqueado |
| H2 | HTTP 200 | OK | HTTP 200 | OK | recurso bloqueado |
| H3 | HTTP 200 | OK | HTTP 200 | OK | recurso bloqueado |

Durante una sesion activa se observaron flows reales en T0, T1 y T2. Al cerrar
sesion, `sesiones_activas` quedo vacio y ONOS volvio a mantener solo flows base
en T0. El contenedor ONOS se observo estable despues de las pruebas:

```text
CPU aproximada: 2.51%
Memoria: 1.294 GiB / 3.823 GiB
fwd: INSTALLED, no ACTIVE
STARTUP_FLOW_INSTALL_ENABLED=false
```

### ONOS

```bash
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/applications/org.onosproject.dhcp
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/network/configuration
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/hosts
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/links
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/flows
```

### AAA

```bash
curl http://127.0.0.1:8080/m6/status | python3 -m json.tool
curl -X POST http://127.0.0.1:8080/m6/portal/sync | python3 -m json.tool
curl http://127.0.0.1:8282/
```

### Host

```bash
sudo ip addr flush dev ens4
sudo dhclient -1 -v ens4
ip -br addr
curl -v http://192.168.100.110:8282/
python3 /home/ubuntu/cli.py
```

## Reglas de oro para no romper la red

1. No activar `org.onosproject.fwd`.
2. No activar `STARTUP_FLOW_INSTALL_ENABLED=true` hasta revisar todos los flows de arranque.
3. No usar `OUTPUT NORMAL` para trafico de usuarios o recursos.
4. Usar DHCP de ONOS con pool fuera de IPs de servidores y portal.
5. Evitar IPs manuales duplicadas.
6. Mantener M6 vivo con `PORTAL_SYNC_INTERVAL=30`.
7. Validar siempre logout: los flows de sesion deben desaparecer.
8. Si ONOS vuelve a colgarse, revisar primero `docker logs onos`, packet processors y cantidad de flows antes de activar cualquier app reactiva.
