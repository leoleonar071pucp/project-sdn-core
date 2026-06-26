# Topologia y despliegue del proyecto SDN

Este documento resume la topologia del laboratorio y la relaciona con los
componentes que existen en el repositorio. La idea es tener una guia unica para
saber que VM, switch, host o servidor ejecuta cada modulo.

## Resumen general

La infraestructura esta dividida en tres planos:

- Red de usuarios/datos: `192.168.100.0/24`
- Red de control SDN: `192.168.200.0/24`
- Red de gestion OOB: `192.168.201.0/24`

Inventario esperado:

- 3 VMs de gestion/control: autenticacion-politicas, ONOS y seguridad.
- 5 switches Open vSwitch/OpenFlow: SW1 a SW5.
- 3 clientes: H1, H2 y H3.
- 2 servidores de aplicacion: `srv1_academicos` y `srv2_notas`.
- 1 gateway de salida.

## Observaciones de consistencia

La topologia propuesta esta bien como base, pero conviene ajustar dos puntos
para que coincida con el codigo del repositorio:

- `192.168.100.0/24` se usa como red de usuarios/datos. En la base de datos,
  el portal cautivo aparece como `192.168.100.2`, los clientes como
  `192.168.100.10-12`, los servidores como `192.168.100.101-102` y el gateway
  como `192.168.100.1`.
- El codigo de M6 documenta ONOS con IP de control `192.168.200.200` y OOB
  `192.168.201.200`. Tambien documenta la VM de autenticacion con control
  `192.168.200.211` y OOB `192.168.201.251`. Por eso, no deberia tratarse
  `192.168.100.2` como OOB de la VM Auth, sino como IP de datos del portal
  cautivo.

Si el diagrama original usa `192.168.100.2` para la VM de autenticacion, lo mas
preciso es interpretarlo como su IP en la red de usuarios/datos, no como la IP
de gestion OOB.

## VMs y componentes

### VM de Autenticacion, Autorizacion y Politicas

Rol funcional:

- Portal cautivo y autenticacion de usuarios.
- Autorizacion RBAC y excepciones temporales.
- Traduccion de decisiones a reglas OpenFlow mediante M6.
- Base de datos principal `radius_db`.

IPs relevantes:

- Datos/portal: `192.168.100.2` segun `db/radius_db_pucp_sdn.sql`.
- Control SDN: `192.168.200.211` segun comentarios de `app/m6_traductor/m6_traductor.py`.
- OOB: `192.168.201.251` segun comentarios de `app/m6_traductor/m6_traductor.py`.

Interfaces esperadas:

- `ens3`: gestion OOB.
- `ens4`: red de control hacia SW1.
- Interfaz de datos si el portal cautivo se expone en `192.168.100.2`.

Componentes del repo que deberian vivir aqui:

- M1 Autenticacion:
  - `app/m1_auth/m1_auth.py`
  - `app/m1_auth/web.py`
  - `app/m1_auth/cli.py`
- M2 Politicas:
  - `app/m2_policies/m2_policies/opa/policy.rego`
  - `app/m2_policies/m2_policies/sync/sync.py`
  - `app/m2_policies/m2_policies/docker-compose.yaml`
- M6 Traductor:
  - `app/m6_traductor/m6_traductor.py`
- Base de datos:
  - `db/radius_db_pucp_sdn.sql`

Servicios esperados:

- MySQL `radius_db` en `localhost:3306`.
- FreeRADIUS en `127.0.0.1:1812` y accounting en `1813`.
- M6 Flask API en `0.0.0.0:8080`.
- OPA para M2 en `:8182`.
- `m2-sync`, que sincroniza MySQL hacia OPA.

Flujo principal:

1. El usuario llega al portal cautivo.
2. M1 consulta FreeRADIUS y MySQL.
3. M1 pide a M6 resolver el host en ONOS.
4. M1 registra la sesion en `sesiones_activas` e `ip_mac_binding`.
5. M1 envia el token de rol a M6.
6. M6 consulta M2/OPA o MySQL y prepara las reglas OpenFlow.
7. M6 instala reglas en ONOS cuando los flags de red estan habilitados.

### VM Controlador ONOS

Rol funcional:

- Controlador SDN.
- Descubrimiento de hosts, dispositivos y puertos.
- API REST para que M6 consulte o instale flows.
- Posible DHCP, segun el esquema SQL figura como `dhcp_server`.

IPs relevantes:

- Control SDN: `192.168.200.200`.
- OOB: `192.168.201.200` segun M6.

Interfaces esperadas:

- `ens3`: gestion OOB.
- `ens4`: red de control hacia SW1 `ens4`.

Servicios esperados:

- ONOS REST API en `http://192.168.201.200:8181`.
- Credenciales por defecto en codigo: `onos/rocks`.

Relacion con otros modulos:

- M6 es el unico modulo que debe hablar directamente con ONOS.
- M1, M2 y M4 no deberian instalar flows por su cuenta.
- ONOS informa hosts para `/m6/resolver_host`.
- ONOS recibe flows para cuarentena, autenticacion, politicas y mitigacion.

### VM de Monitoreo, Deteccion y Mitigacion

Rol funcional:

- Deteccion de eventos de seguridad.
- Correlacion multi-fuente.
- Solicitud de mitigacion a M6.
- Gestion de mirrors via Telemetry Manager.

IP propuesta:

- OOB/gestion: `192.168.100.3` en tu resumen. Validar si realmente pertenece a
  OOB o si debe moverse a `192.168.201.0/24`.

Interfaces esperadas:

- `ens3`: gestion OOB.
- `ens4`: red de control hacia SW1 `ens5`.

Componentes del repo que deberian vivir aqui:

- M4 Correlador:
  - `app/security/m4/`
- Suricata:
  - `app/security/suricata/`
- Event Forwarder:
  - `app/security/event_forwarder/`
- Flow Collector:
  - `app/security/flow_collector/`
- Telemetry Manager:
  - `app/security/telemetry_manager/`
- Esquema de seguridad:
  - `app/security/sql/security_schema.sql`
- Compose del stack:
  - `app/security/docker-compose.yml`

Servicios esperados:

- M4 API en `8084`.
- Telemetry Manager en `8090`.
- sFlow collector en UDP `6343`.
- NetFlow collector en UDP `2055`.
- Suricata en `network_mode: host`.

Estado actual segun repo:

- El stack de seguridad esta preparado con perfil Docker `deployment`.
- Por defecto trabaja en modo seguro/simulado.
- No instala flows, no ejecuta OVSDB y no modifica switches salvo que se
  habiliten explicitamente los flags de red.

## Switches

Todos los switches tienen una interfaz de gestion OOB (`ens3`) y enlaces de
control/troncal hacia otros switches o VMs. Los puertos de usuario/datos se
conectan a hosts, servidores o gateway.

### SW1

IP de control: `192.168.200.201`

Interfaces:

- `ens3`: gestion OOB.
- `ens4`: control hacia ONOS `ens4`.
- `ens5`: control hacia VM Monitoreo `ens4`.
- `ens6`: red de usuarios hacia Gateway `ens4`.
- `ens7`: control hacia SW3 `ens4`.
- `ens8`: control hacia SW2 `ens4`.
- `ens9`: control hacia VM Auth/AAA `ens4`.

### SW2

IP de control: `192.168.200.202`

Interfaces:

- `ens3`: gestion OOB.
- `ens4`: control hacia SW1 `ens8`.
- `ens5`: control hacia SW3 `ens7`.
- `ens6`: control hacia SW5 `ens5`.
- `ens7`: control hacia SW4 `ens4`.

### SW3

IP de control: `192.168.200.203`

Interfaces:

- `ens3`: gestion OOB.
- `ens4`: control hacia SW1 `ens7`.
- `ens5`: control hacia SW5 `ens4`.
- `ens6`: control hacia SW4 `ens5`.
- `ens7`: control hacia SW2 `ens5`.

### SW4 - acceso clientes

IP de control: `192.168.200.204`

Interfaces:

- `ens3`: gestion OOB.
- `ens4`: control hacia SW2 `ens7`.
- `ens5`: control hacia SW3 `ens6`.
- `ens6`: datos hacia H3 `ens4`.
- `ens7`: datos hacia H2 `ens4`.
- `ens8`: datos hacia H1 `ens4`.

### SW5 - acceso servidores

IP de control: `192.168.200.205`

Interfaces:

- `ens3`: gestion OOB.
- `ens4`: control hacia SW3 `ens5`.
- `ens5`: control hacia SW2 `ens6`.
- `ens6`: datos hacia servidor Recursos Academicos `ens4`.
- `ens8`: datos hacia servidor Sistema de Notas `ens4`.

## Clientes

Los clientes pertenecen a la red de usuarios/datos y obtienen o usan una IP del
pool `192.168.100.0/24`. M1/M6 mantienen la misma IP y cambian el tratamiento
por VLAN/rol.

| Host | IP | Gestion | Datos |
| --- | --- | --- | --- |
| H1 | `192.168.100.10` | `ens3` OOB | `ens4` hacia SW4 `ens8` |
| H2 | `192.168.100.11` | `ens3` OOB | `ens4` hacia SW4 `ens7` |
| H3 | `192.168.100.12` | `ens3` OOB | `ens4` hacia SW4 `ens6` |

Roles/VLAN definidos:

| Rol | VLAN | Timeout RADIUS |
| --- | ---: | ---: |
| Cuarentena | 90 | N/A |
| Visitante | 100 | 1800 s por logica de M1 |
| Estudiante_Telecom | 210 | 7200 s |
| Estudiante_Informatica | 220 | 7200 s |
| Estudiante_Electronica | 230 | 7200 s |
| Docente | 300 | 7200 s |
| Admin_TI | 400 | 43200 s |

## Servidores de aplicacion

### srv1 academicos

IP: `192.168.100.101`

Conexion:

- `ens3`: gestion OOB.
- `ens4`: datos hacia SW5 `ens6`.

Ruta en repo:

- `servicios/srv1 academicos/`

Servicios Nginx:

| Recurso | Puerto |
| --- | ---: |
| `telecom-http` | 8001 |
| `telecom-https` | 1443 |
| `info-http` | 8002 |
| `info-https` | 2443 |
| `electro-http` | 8003 |
| `electro-https` | 3443 |

Arranque:

```bash
cd "servicios/srv1 academicos"
docker compose up -d
```

### srv2 notas

IP: `192.168.100.102`

Conexion:

- `ens3`: gestion OOB.
- `ens4`: datos hacia SW5 `ens8`.

Ruta en repo:

- `servicios/srv2 notas/`

Servicios Nginx:

| Recurso | Puerto |
| --- | ---: |
| `notas-http` | 8080 |
| `notas-https` | 443 |
| `admin-http` | 8081 |
| `admin-https` | 8443 |

Arranque:

```bash
cd "servicios/srv2 notas"
docker compose up -d
```

## Gateway / salida a Internet

IP de datos: `192.168.100.1`

Interfaces:

- `ens3`: red externa, indicada en el resumen como subred `192.168.201.0`.
- `ens4`: red de usuarios hacia SW1 `ens6`.
- `ens5`: salida directa a Internet.

Observacion:

- Si `192.168.201.0/24` es OOB, conviene no llamarla "red externa" en el
  diagrama. Para evitar confusion, validar si `ens3` del gateway es OOB o WAN.

## Matriz de despliegue por nodo

| Nodo | Componentes principales | Rutas del repo |
| --- | --- | --- |
| VM Auth/AAA/Policies | M1, M2, M6, MySQL, FreeRADIUS, portal cautivo | `app/m1_auth/`, `app/m2_policies/`, `app/m6_traductor/`, `db/` |
| VM ONOS | Controlador ONOS, REST API, descubrimiento de hosts/switches | No versionado en repo; M6 consume `http://192.168.201.200:8181` |
| VM Monitoring/Security | M4, Suricata, Event Forwarder, Flow Collector, Telemetry Manager | `app/security/` |
| srv1 academicos | Nginx con servicios de cursos por facultad | `servicios/srv1 academicos/` |
| srv2 notas | Nginx con notas y panel admin | `servicios/srv2 notas/` |
| SW1-SW5 | OVS/OpenFlow, puertos de acceso y transito | Configuracion operativa fuera del repo |
| H1-H3 | Clientes de prueba | Configuracion operativa fuera del repo |
| Gateway | Salida a Internet y ruta de datos | Configuracion operativa fuera del repo |

## Flujo de autenticacion y autorizacion

```text
Cliente -> Portal/M1 -> FreeRADIUS -> MySQL
                    |
                    v
             M6 /resolver_host -> ONOS
                    |
                    v
          MySQL sesiones_activas + ip_mac_binding
                    |
                    v
             M6 /token_rol -> M2/OPA
                    |
                    v
                  ONOS -> switches
```

## Flujo de seguridad

```text
Suricata / sFlow / NetFlow / M6 events
                 |
                 v
                M4
                 |
        +--------+---------+
        |                  |
        v                  v
Telemetry Manager       M6 /mitigacion
        |                  |
        v                  v
     mirror              ONOS -> DROP T0
```

## Archivos importantes

- `db/radius_db_pucp_sdn.sql`: esquema central de usuarios, roles, recursos,
  politicas, sesiones, RADIUS y binding IP-MAC.
- `app/m1_auth/m1_auth.py`: logica de autenticacion, bloqueo, sesiones,
  visitantes y llamada a M6.
- `app/m2_policies/m2_policies/docker-compose.yaml`: OPA y sincronizador M2.
- `app/m2_policies/m2_policies/opa/policy.rego`: reglas de autorizacion.
- `app/m6_traductor/m6_traductor.py`: API M6, integracion ONOS, OPA, MySQL y
  mitigacion.
- `app/security/docker-compose.yml`: stack de seguridad para M4, Suricata,
  forwarder, collectors y telemetry-manager.
- `servicios/srv1 academicos/docker-compose.yml`: servicios academicos.
- `servicios/srv2 notas/docker-compose.yml`: servicios de notas y admin.
- `connect_vms.txt`: accesos SSH por puerto al laboratorio.

## Pendientes de validacion

- Confirmar IP real OOB de VM Auth, VM Monitoring, hosts, servidores y switches.
- Confirmar si `192.168.201.0/24` es exclusivamente OOB o tambien se usa como
  red externa del gateway.
- Confirmar si ONOS/DHCP corren ambos en `192.168.200.200`.
- Confirmar DPIDs reales actuales de SW1-SW5 contra ONOS.
- Confirmar nombres de interfaces reales con `ip -br addr` en cada VM.
- Confirmar que M6 debe llamar ONOS por OOB `192.168.201.200:8181` y no por
  control `192.168.200.200:8181`.
