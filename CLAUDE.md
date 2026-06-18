# CLAUDE.md — SDN Zero Trust PUCP | Grupo 2 TEL354
# Mark Valencia (20221747) | Handoff completo para continuidad entre sesiones/máquinas

## RESUMEN DEL PROYECTO

Sistema SDN Zero Trust para control de acceso a recursos académicos PUCP.
Autenticación RADIUS + políticas RBAC en MySQL + enforcement dinámico via OpenFlow 1.3 en ONOS 2.7.0.

Curso: TEL354 | Grupo 2 | Integrante principal de infraestructura: Mark Valencia

---

## TOPOLOGÍA FINAL (slice asignado — implementación real pendiente)

La topología real asignada por el VNRT PUCP tiene 5 switches, 3 hosts y 2 servidores:

```
Internet → Gateway (SSH :22)
                ↓
           SW1 (core)  ← ONOS Controller (SSH :5800)
          /          \     AAA-policies (SSH :5851)
       SW2           SW3   VM-Monitor (SSH :5852)
      /    \        /    \
   SW4     SW5  (distribución)
  / | \        \
H1  H2  H3    recursos_academicos (srv1)
              sistema_notas (srv2)
```

### Puertos SSH al gateway (10.20.12.113 o IP del GW):
| VM | Puerto SSH |
|---|---|
| Gateway | 22 |
| ONOS (VM-Controller) | 5800 |
| AAA-policies (VM-Auth) | 5851 |
| VM-Monitor | 5852 |
| SW1 | 5801 |
| SW2 | 5802 |
| SW3 | 5803 |
| SW4 | 5804 |
| SW5 | 5805 |
| H1 | 5811 |
| H2 | 5812 |
| H3 | 5813 |
| recursos_academicos (srv1) | 5821 |
| sistema_notas (srv2) | 5822 |

### Recursos de cada VM:
- VM-Controller: 4 vCPU, 4GB RAM, 15GB disco — ONOS 2.7.0 + M6
- VM-Auth: 4 vCPU, 4GB RAM, 15GB disco — FreeRADIUS + MySQL + M1 portal
- VM-Monitor: 4 vCPU, 4GB RAM, 15GB disco — monitoreo
- SW1-SW4: 2 vCPU, 1GB RAM, 10GB — OVS
- SW5: 2 vCPU, 1GB RAM, 15GB — OVS
- H1-H3: 2 vCPU, 2GB RAM, 8GB — hosts estudiantes
- srv1/srv2: 2 vCPU, 4GB RAM, 10GB — servidores académicos

### IMPORTANTE — diferencias vs VNRT demo:
- En la demo usamos 3 switches; la topología real tiene 5 (SW1 core, SW2-SW3 distribución, SW4-SW5 acceso)
- En la demo el controller y el Auth estaban en la misma VM; ahora son VMs separadas
- En la demo teníamos H1/H2 como hosts; ahora H1/H2/H3
- recursos_academicos = equivalente a H3 (cursos Telecom) del demo
- sistema_notas = equivalente a H4 (cursos Informatica/Notas) del demo
- La línea roja en el diagrama (SW1-SW2 directa) es el enlace redundante/especial

### IPs pendientes de descubrir:
Los IPs reales de las VMs en el plano de datos NO se conocen aún.
Al conectarse, ejecutar en cada VM: `ip addr show ens4` o `ip addr show`
Los DPIDs de los 5 switches también son desconocidos — consultar ONOS:
`curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/devices`

---

## TOPOLOGÍA VNRT DEMO (referencia — ya funciona)

Usada para la demo de sustentación. Todo probado y funcionando.

```
SW1 (core/troncal)     DPID: of:00005ec76ec6114c
SW2 (acceso hosts)     DPID: of:000072e0807e854c
SW3 (acceso servers)   DPID: of:0000f220f9454c4e

Hosts:
  H1 (Telecom):       192.168.100.41  MAC: FA:16:3E:53:F8:E8  SW2 puerto 2
  H2 (Informatica):   192.168.100.42  MAC: FA:16:3E:68:A7:44  SW2 puerto 3 (DHCP ONOS)

Servidores:
  H3 (cursos Telecom): 192.168.100.200  SW3
  H4 (cursos Info):    192.168.100.201  SW3

Controller/Portal:      192.168.100.1   (ens4 del controller VNRT)
Gateway acceso:         10.20.12.113    puerto 5800
```

---

## ARQUITECTURA DE MÓDULOS

### Principio fundamental:
**M6 es la ÚNICA interfaz con ONOS. M1, M2, M4 NUNCA tocan ONOS directamente.**

```
M1 (portal_cautivo.py)  →  RADIUS auth  →  token_rol  →  M6
M2 (politicas_rbac)     →  MySQL RBAC   →  consultado por M6
M4 (detección ataques)  →  mitigacion   →  M6
M5 (auditoría)          →  log events   ←  M6
M6 (m6_traductor.py)    →  ONOS REST API → OpenFlow flows
```

### M1 — `portal_cautivo.py`
Portal cautivo CLI (acceso vía SSH al controller/auth VM).
Clases:
- `RadiusClient` — envía Access-Request a FreeRADIUS puerto 1812 vía pyrad, recibe Filter-Id (nombre_rol)
- `RoleMapper` — nombre_rol → VLAN ID
- `UserManager` — verifica cuenta bloqueada, intentos fallidos (máx 3)
- `DatabaseManager` — conexión MySQL
- `SessionManager` — INSERT sesiones_activas, historial_sesiones; notifica M6 en logout
- `TokenEmitter` — POST http://<m6_url>/m6/token_rol con {codigo_pucp, nombre_rol, vlan_id, ip_asignada}

Config en portal_cautivo.py:
```python
RADIUS_HOST = "127.0.0.1"   # ← cambiar a IP de VM-Auth en topología real
RADIUS_PORT = 1812
RADIUS_SECRET = b"testing123"
M6_URL = "http://127.0.0.1:8080/m6/token_rol"  # ← cambiar a IP de VM-Controller
```

### M6 — `app/modules/m6/m6_traductor.py`
Módulo traductor SDN. Flask en puerto 8080.

Endpoints:
- `POST /m6/token_rol` — recibe token de M1, instala flows de sesión
- `POST /m6/cerrar_sesion` — elimina flows de sesión (llamado por M1 en logout)
- `POST /m6/arranque` — instala flows proactivos (también se llama automáticamente al iniciar)
- `POST /m6/mitigacion` — bloquea atacante con T0 prio=5000 (llamado por M4)
- `GET /m6/status` — healthcheck

Clases principales:
- `Config` — constantes: DPIDs, IPs, prioridades, VLANs por rol
- `FlowBuilder` — fábrica de JSON flow entries para cada caso del pipeline
- `ONOSClient` — wrapper REST ONOS: instalar_flow, eliminar_flow, get_access_ports
- `PolicyEngine` — OPA → MySQL politicas_rbac → hardcoded por VLAN (cadena fallback)
- `M6Translator` — lógica principal, cache flows_por_sesion {mac: [(device_id, flow_id)]}

Config crítica en m6_traductor.py (actualizar para nueva topología):
```python
ONOS_URL = "http://127.0.0.1:8181"  # mismo host si M6 corre en VM-Controller
SW1 = "of:00005ec76ec6114c"  # ← ACTUALIZAR con DPIDs reales nuevos
SW2 = "of:000072e0807e854c"  # ← ACTUALIZAR
SW3 = "of:0000f220f9454c4e"  # ← ACTUALIZAR (y añadir SW4, SW5)
PORTAL_IP = "192.168.100.1"  # ← ACTUALIZAR con IP real de VM-Auth en plano de datos
SERVER_CURSOS = "192.168.100.200"  # ← ACTUALIZAR con IP real de srv1
SERVER_NOTAS  = "192.168.100.201"  # ← ACTUALIZAR con IP real de srv2
```

IP_MAPPING_M2 (traduce IPs del diseño M2 a IPs reales):
```python
"10.0.0.21": "192.168.100.200",  # cursos_telecom → srv1
"10.0.0.22": "192.168.100.201",  # cursos_info    → srv2
"10.0.0.23": "192.168.100.200",  # cursos_electro → srv1
"10.0.0.30": "192.168.100.201",  # servidor_notas → srv2
```

---

## PIPELINE OPENFLOW (diseño probado en VNRT)

```
T0 (tabla 0): Enforcement directo por MAC+IP
  prio=40000  ARP/LLDP/DHCP → CONTROLLER        (instalado por ONOS automáticamente)
  prio=35000  ETH_SRC=MAC + IPV4_DST=srv → OUTPUT  (ALLOW por sesión, timeout 8h)
  prio=35000  ETH_SRC=MAC + IPV4_DST=srv → DROP    (DENY por sesión, timeout 8h)
  prio=5000   ETH_SRC=MAC_atacante → DROP           (mitigación M4, permanente)
  prio=500    ETH_TYPE=ARP → OUTPUT:NORMAL           (ARP pass-through)
  prio=200    IN_PORT=acceso, IPV4_DST=portal → OUTPUT:trunk  (ruta al portal)
  prio=200    IN_PORT=trunk, IPV4_SRC=portal → OUTPUT:NORMAL  (retorno del portal)
  prio=200    IN_PORT=1, ETH_DST=MAC → OUTPUT:puerto_host     (retorno servidor→host)
  prio=1      (vacío) → OUTPUT:NORMAL               (table-miss en SW tránsito)

T1 (tabla 1): Cuarentena VLAN 90
  prio=40000  IN_PORT+ETH_SRC+VLAN90 → SET_FIELD vlan_rol, goto T2  (post-auth)
  prio=500    VLAN90+UDP_DST=67 → CONTROLLER         (DHCP en cuarentena)
  prio=100    VLAN90+TCP+IPV4_DST=portal → NORMAL    (portal en cuarentena)
  prio=10     IN_PORT=acceso+ETH_TYPE=IP → PUSH VLAN90+NORMAL  (push cuarentena)
  prio=5      VLAN90 → DROP                          (default drop cuarentena)

T2 (tabla 2): ALLOW proactivo por VLAN de rol
  prio=100    VLAN210+IPV4_DST=srv1+TCP80 → NORMAL   (Telecom → cursos)
  prio=100    VLAN210+IPV4_DST=srv1+TCP443 → NORMAL
  prio=100    VLAN220+IPV4_DST=srv2+TCP80 → NORMAL   (Informatica → notas)
  prio=100    VLAN220+IPV4_DST=srv2+TCP443 → NORMAL
  ... (todos los roles × servidores × puertos)

T3 (tabla 3): DENY explícito por sesión
  prio=200    ETH_SRC+IPV4_SRC+IPV4_DST → DROP  (timeout 8h)
```

**NOTA CRÍTICA**: En el slice VNRT, el tráfico IP normal de los hosts no alcanza T1 automáticamente.
M6 usa flows directos en T0 para portal y enforcement. T1/T2/T3 se usan para la cuarentena VLAN.
En la nueva topología con 5 switches verificar si esto cambia.

---

## VLANS POR ROL

```python
VLANS_POR_ROL = {
    "Visitante":              100,
    "Estudiante_Telecom":     210,
    "Estudiante_Informatica": 220,
    "Estudiante_Electronica": 230,
    "Docente":                300,
    "Admin_TI":               400,
    VLAN_CUARENTENA:           90,  # todos los hosts al arrancar
}
```

---

## POLITICAS RBAC (MySQL radius_db)

Tabla `politicas_rbac` con columnas: id_rol, id_recurso, accion (ALLOW/DENY), tabla_of, activo.
Tabla `recursos` con: id_recurso, nombre_recurso, ip_dst, puerto, protocolo.
Tabla `roles_facultad` con: id_rol, nombre_rol.
Tabla `sesiones_activas` con: id_sesion, id_usuario, mac_address, ip_asignada, vlan_id, nombre_rol, switch_dpid, in_port, login_timestamp.
Tabla `historial_sesiones` — archivo de sesiones cerradas.
Tabla `ip_mac_binding` — binding activo IP↔MAC.

### Política de acceso:
- Estudiante_Telecom: ALLOW srv1 (cursos_telecom), DENY srv2
- Estudiante_Informatica: ALLOW srv2 (cursos_info), DENY srv1
- Estudiante_Electronica: ALLOW srv1, DENY srv2
- Docente: ALLOW srv1 + srv2
- Admin_TI: ALLOW srv1 + srv2

---

## BUGS CORREGIDOS (no repetir estos errores)

### En m6_traductor.py vs m6.py original:
1. **OPA puerto collision** — m6.py original usaba 8181 (igual que ONOS). Fix: M6 usa 8182 para OPA.
2. **_post_flow wrapper** — m6.py envolvía el flow con `{"flows": [...]}`. ONOS espera el flow DIRECTO en `POST /onos/v1/flows/{deviceId}`. Envolver da HTTP 400.
3. **Portal IP errónea** — m6.py tenía "10.0.0.10". El portal real está en la IP de ens4 del controller.
4. **Tabla-1 no alcanzable** — tráfico IP normal no llega a T1 en VNRT. Fix: flows directos en T0.
5. **Host fallback** — si ONOS no conoce el host (IP manual), M6 tiene HOSTS_VNRT como fallback.
6. **Sin fallback OPA** — OPA no corre. Fix: PolicyEngine con cadena OPA→MySQL→hardcoded.
7. **ALLOW+DENY misma IP** — cursos_info y cursos_electro mapeaban a misma IP que cursos_telecom. Fix: eliminar del deny_map las IPs que ya están en allow_map.
8. **Sin table-miss SW1/SW3** — tráfico H1→H3 se perdía en SW1 sin flow. Fix: t0_table_miss_normal() en switches de tránsito.
9. **Sin return flow** — respuestas H3→H1 no tenían flow de retorno en SW2. Fix: t0_return_flow() instalado al hacer login, eliminado al logout.

### Bug DHCP (reportado por compañera Sheila):
T1 prio=500 DHCP requiere VLAN_VID ya seteado. Paquetes DHCP llegan sin VLAN.
Fix correcto: mover DHCP match a T0 sin requerir VLAN_VID.
En VNRT esto no afectó porque ONOS DHCP app instala automáticamente T0 prio=40000 DHCP→CONTROLLER.
En nueva topología verificar que ONOS DHCP app esté activo.

### Descubrimiento dinámico de puertos (ya implementado):
`get_access_ports(device_id)` consulta `/onos/v1/devices/{id}/ports` y resta trunk ports
detectados en `/onos/v1/links` (LLDP). Esto hace las rutas del portal dinámicas.

---

## ESTRUCTURA DE ARCHIVOS

```
project-sdn-core/
├── CLAUDE.md                          ← este archivo (contexto completo)
├── PROGRESS.md                        ← estado de avance sesión a sesión
├── portal_cautivo.py                  ← M1: portal cautivo CLI (corre en VM-Auth)
├── app/
│   ├── main.py                        ← entrypoint FastAPI (no usado en demo)
│   ├── config.py                      ← config global
│   ├── modules/
│   │   ├── m1_auth/                   ← estructura FastAPI M1 (alternativa al CLI)
│   │   │   ├── router.py
│   │   │   ├── service.py
│   │   │   └── models.py
│   │   ├── m2_policies/
│   │   │   └── sync/sync.py           ← sincronización OPA←MySQL (tiene bug, NO usar)
│   │   └── m6/
│   │       └── m6_traductor.py        ← M6: traductor SDN (corre en VM-Controller)
│   ├── common/
│   │   ├── database.py
│   │   ├── exceptions.py
│   │   └── logger.py
│   └── dhcp_manager.py
├── logica_demo/                       ← scripts de prueba/demo (no producción)
│   ├── dhcp_manager.py
│   ├── dhcp_simulado.py
│   └── test_radius.py
└── radius_db_pucp_sdn.sql             ← schema completo de la base de datos
```

### Archivos que corren en producción (controller VNRT):
- `/root/m6_traductor.py` — copia del archivo local (sincronizar con git)
- `/root/portal_cautivo.py` — copia del archivo local

---

## CÓMO CORRER EL SISTEMA

### En VM-Controller (ONOS):
```bash
# M6 en primer plano (visible para demo) — instala flows proactivos automáticamente
cd /root && python3 -u m6_traductor.py 2>&1 | tee /tmp/m6.log
```

### En VM-Auth (o controller si están juntos):
```bash
# Portal cautivo CLI
cd /root && python3 portal_cautivo.py
```

### En servidores (srv1/srv2):
```bash
# HTTP
cd /tmp/www && nohup python3 -m http.server 80 > /tmp/http.log 2>&1 &

# HTTPS (requiere /tmp/cert.pem y /tmp/key.pem)
nohup python3 /tmp/https_server.py > /tmp/https.log 2>&1 &
```

Script https_server.py:
```python
import http.server, ssl, os
os.chdir('/tmp/www-ssl')  # directorio con contenido diferenciado para HTTPS
httpd = http.server.HTTPServer(('', 443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/cert.pem', '/tmp/key.pem')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
```

Generar cert:
```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem \
  -days 365 -nodes -subj "/CN=<IP_SERVIDOR>"
```

---

## VERIFICACIÓN RÁPIDA DEL SISTEMA

```bash
# ONOS switches conectados
curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/devices | python3 -c "
import json,sys
for d in json.load(sys.stdin)['devices']:
    print(f'  {d[\"id\"][-4:]} available:{d[\"available\"]}')"

# Hosts descubiertos
curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/hosts | python3 -c "
import json,sys
for h in json.load(sys.stdin)['hosts']:
    print(f'  {h[\"mac\"]}  {h.get(\"ipAddresses\",[])}  puerto:{h.get(\"locations\",[{}])[0].get(\"port\",\"?\")}')"

# Flows por tabla
curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/flows | python3 -c "
import json,sys
flows=json.load(sys.stdin)['flows']
t={}
[t.__setitem__(x.get('tableId','?'), t.get(x.get('tableId','?'),0)+1) for x in flows]
print(f'Total: {len(flows)}')
[print(f'T{k}: {v}') for k,v in sorted(t.items())]"

# M6 corriendo
curl -s http://localhost:8080/m6/status

# Arranque manual si flows = 0
curl -s -X POST http://localhost:8080/m6/arranque | python3 -m json.tool
```

---

## DEPENDENCIAS PYTHON

### VM-Controller (M6):
```
flask
requests
mysql-connector-python
```

### VM-Auth (M1/portal):
```
pyrad
mysql-connector-python
```

Instalar: `pip3 install flask requests mysql-connector-python pyrad`

---

## ONOS — CONFIGURACIÓN

### Credenciales: `onos` / `rocks`
### URL REST: `http://127.0.0.1:8181`
### Karaf CLI: `ssh -p 8101 karaf@localhost` (password: karaf)
### UI: `http://127.0.0.1:8181/onos/ui/#/topo2`
### OpenFlow listener: puerto 6653

### Apps ONOS necesarias (verificar con `curl -u onos:rocks http://127.0.0.1:8181/onos/v1/applications?active=true`):
- `org.onosproject.openflow` — driver OpenFlow
- `org.onosproject.dhcp` — servidor DHCP (para IPs dinámicas)
- `org.onosproject.lldpprovider` — descubrimiento de enlaces inter-switch

### DHCP estático (si un host necesita IP fija):
```bash
ssh -p 8101 karaf@localhost
dhcp-set-static-mapping <MAC> <IP>
# Ejemplo: dhcp-set-static-mapping FA:16:3E:68:A7:44 192.168.100.42
```

### Error conocido ONOS: `"Field \"staticmappings\" is invalid"`
El JSON config de ONOS 2.7.0 NO soporta `staticmappings` en el campo de red.
Usar Karaf CLI en su lugar.

---

## ACCESO SSH A LA INFRAESTRUCTURA

```bash
# Acceder a controller (ONOS)
ssh ubuntu@<GATEWAY_IP> -p 5800

# Tunnel para ONOS UI desde laptop
ssh -L 8181:<IP_CONTROLLER_INTERNA>:8181 ubuntu@<GATEWAY_IP> -p 5800 -N

# Acceder a VM-Auth
ssh ubuntu@<GATEWAY_IP> -p 5851

# Acceder a servidor 1
ssh ubuntu@<GATEWAY_IP> -p 5821
```

**IPs internas pendientes de descubrir al conectarse.**

---

## PRÓXIMOS PASOS PARA LA TOPOLOGÍA REAL

1. **Conectarse a cada VM** vía SSH (puertos 5800-5822) y descubrir IPs internas (`ip addr`)
2. **Actualizar Config en m6_traductor.py**:
   - Nuevos DPIDs de SW1-SW5 (`curl -u onos:rocks .../onos/v1/devices`)
   - Nuevas IPs de srv1, srv2, portal (VM-Auth)
   - Definir qué switch hace acceso de hosts (SW4/SW5) y cuál de servidores (SW2/SW3)
3. **Actualizar portal_cautivo.py**:
   - `RADIUS_HOST` → IP de VM-Auth
   - `M6_URL` → IP de VM-Controller + puerto 8080
4. **Verificar OVS en switches**:
   - `ovs-vsctl show` — confirmar bridges y controller configurado
   - `ovs-vsctl set-controller <bridge> tcp:<IP_CONTROLLER>:6653`
5. **Instalar dependencias** en VM-Controller y VM-Auth
6. **Configurar MySQL** en VM-Auth con `radius_db_pucp_sdn.sql`
7. **Configurar FreeRADIUS** en VM-Auth con usuarios y Filter-Id por rol
8. **Copiar archivos**:
   - `m6_traductor.py` → VM-Controller
   - `portal_cautivo.py` → VM-Auth
9. **Configurar servidores** srv1/srv2 con contenido HTTP/HTTPS diferenciado
10. **Adaptar pipeline para 5 switches**: SW4/SW5 hacen acceso de hosts (VLAN push),
    SW1 es core (table-miss NORMAL), SW2/SW3 son distribución (table-miss NORMAL),
    solo el switch de acceso hace enforcement y portal redirect.

---

## NOTAS IMPORTANTES

- **OPA no corre** — disco lleno en VNRT (18MB libres). PolicyEngine usa MySQL directamente.
  En la nueva topología con más recursos, evaluar si OPA se puede activar.
- **M6 no usa Intents ONOS** — instala flows directos via REST API. 0 Intents es correcto.
- **Portal es CLI via SSH** — no es un web server. Los hosts SSHean al IP del portal (VM-Auth).
- **Flows con hard_timeout=28800** (8 horas). Al logout se eliminan manualmente via DELETE.
- **DROP en ONOS** = `{"clearDeferred": true, "instructions": []}`. NO usar `{"type": "DROP"}` que da HTTP 400.
- **sync.py de M2 tiene un bug** — no filtra `accion = 'ALLOW'` en la query, incluye DENYs.
  No usar sync.py sin corregir primero.
