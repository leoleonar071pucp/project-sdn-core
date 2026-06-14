# CONTEXTO COMPLETO — SDN PUCP TEL354 Grupo 2
# Para Claude Code — Módulo M6 Traductor

## PROYECTO
Red de campus Zero Trust con SDN para PUCP.
Curso: TEL354 Ingeniería de Redes Definidas por Software
Stack: ONOS 2.7.0 + OVS + OpenFlow 1.3 + FreeRADIUS + MySQL + OPA (M2)
Alumno responsable de M6: Mark Valencia (20221747)

## REGLA CRÍTICA DE ARQUITECTURA
M6 es el ÚNICO módulo que habla con ONOS.
M1, M2, M4 nunca tocan el controlador directamente.
Todo pasa por M6 que traduce instrucciones de negocio a flow entries JSON.

## INFRAESTRUCTURA REAL — VNRT (VPN + slice asignado)

### Red de control (ens3) — para SSH y gestión
Controller ONOS: 192.168.200.200
SW1 troncal:     192.168.200.201
SW2 acceso:      192.168.200.202
SW3 acceso:      192.168.200.203

### Red SDN (ens4) — plano de datos OpenFlow
Controller ens4: fa:16:3e:be:01:02

### Switches conectados a ONOS (deviceIds reales del slice)
SW1: of:00005ec76ec6114c  (192.168.200.201) — troncal
SW2: of:000072e0807e854c  (192.168.200.202) — acceso hosts
SW3: of:0000f220f9454c4e  (192.168.200.203) — acceso servidores

### Puertos de cada switch
SW1 puertos:
  puerto 1 (ens4) → Controller ONOS (192.168.200.200)
  puerto 2 (ens5) → SW2 (link INDIRECT)
  puerto 3 (ens6) → SW3 (link DIRECT)
  puerto 4 (ens7) → libre

SW2 puertos:
  puerto 1 (ens4) → SW1 puerto 2
  puerto 2 (ens5) → H1 cliente (FA:16:3E:53:F8:E8, IP 192.168.100.41)
  puerto 3 (ens6) → libre o segundo host

SW3 puertos:
  puerto 1 (ens4) → SW1 puerto 3
  puerto 2 (ens5) → host/servidor (FA:16:3E:17:68:15, IP 192.168.201.203)
  puerto 3 (ens6) → libre

### Hosts confirmados por ONOS
H1 cliente: MAC=FA:16:3E:53:F8:E8, IP=192.168.100.41
            ubicado en SW2 puerto 2
Controller: MAC=FA:16:3E:BE:01:02, IP=192.168.200.200
            ubicado en SW1 puerto 1

### Topología de links
SW2 puerto 1 ←→ SW1 puerto 2 (INDIRECT)
SW3 puerto 1 ←→ SW1 puerto 3 (DIRECT)

## ONOS
URL REST API: http://127.0.0.1:8181 (desde el Controller)
              http://192.168.200.200:8181 (desde otras VMs)
Auth: onos:rocks
DHCP app: org.onosproject.dhcp — ACTIVA y funcionando
DHCP pool: 192.168.100.10 → 192.168.100.100
DHCP MAC controller: fa:16:3e:be:01:02
H1 ya tiene IP 192.168.100.41 asignada por ONOS DHCP ✓

## VLANS POR ROL
Cuarentena:             VLAN 90  (pre-auth, todos los dispositivos nuevos)
Visitante:              VLAN 100
Estudiante_Telecom:     VLAN 210
Estudiante_Informatica: VLAN 220
Estudiante_Electronica: VLAN 230
Docente:                VLAN 300
Admin_TI:               VLAN 400

## SERVIDORES (IPs actualizadas — en rango 192.168.100.200+)
H3 servidor cursos:  192.168.100.200 (IP fija)
H4 servidor notas:   192.168.100.201 (IP fija)
Portal cautivo:      VM Auth, accesible por SSH

## PIPELINE OPENFLOW T0-T4
T0: Seguridad — DROP atacantes prio 5000+, instalado por M4 via M6
T1: Identidad — reglas cuarentena VLAN 90 + SET_FIELD vlan_vid post-auth
T2: Políticas VLAN — ALLOW por VLAN_VID hacia ip_dst, permanente
T3: Denegaciones — DROP MAC+ip_src/32+ip_dst, hard_timeout=sesión
T4: Table-miss → packet-in (no usado en flujo normal, todo proactivo)

## REGLAS T1 DE CUARENTENA (instaladas al arrancar)
Regla base  prio 10:  IN_PORT=X + ETH_TYPE=0x0800 → VLAN_PUSH 90 + OUTPUT NORMAL
Regla DHCP  prio 500: VLAN_VID=90 + IP_PROTO=17 + UDP_DST=67 → OUTPUT CONTROLLER
Regla portal prio 100: VLAN_VID=90 + ETH_TYPE=0x0800 + IPV4_DST=portal/32 + IP_PROTO=6 → OUTPUT puerto_portal
Regla DROP  prio 5:   VLAN_VID=90 → treatment vacío (DROP implícito en ONOS)

NOTA ONOS: DROP en ONOS NO se hace con {"type":"DROP"} — eso da error 400.
Se hace con treatment: {"clearDeferred": true, "instructions": []}

## ERRORES ONOS CONOCIDOS Y SOLUCIONES
Error: "Instruction type DROP is not supported"
Fix:   usar treatment: {"clearDeferred": true, "instructions": []}

Error: "No enum constant org.onosproject.net.PortNumber.Logical.PUERTO_X"
Fix:   usar número entero del puerto, NO strings con nombres

## CONTRATOS DE INTERFAZ M6

### M1 → M6: Token de Rol (POST /m6/token_rol)
Request body:
{
  "codigo_pucp": "20192434",
  "nombre_rol":  "Estudiante_Telecom",
  "vlan_id":     210,
  "ip_asignada": "192.168.100.41"
}
Response esperada:
{
  "mac":         "FA:16:3E:53:F8:E8",
  "switch_dpid": "of:000072e0807e854c",
  "in_port":     2
}
Qué hace M6 internamente:
  1. GET /onos/v1/hosts → busca host por ip_asignada → obtiene mac/switch/puerto
  2. POST /onos/v1/flows → instala SET_FIELD vlan_vid=210 en T1
  3. POST OPA:8181 → obtiene permisos T2 y denegaciones T3
  4. POST /onos/v1/flows → instala T2 y T3
  5. Devuelve {mac, switch_dpid, in_port} a M1

### M1 → M6: Cerrar sesión (POST /m6/cerrar_sesion)
Request: {"mac": "FA:16:3E:53:F8:E8"}
Acción:  DELETE todos los flows T1/T2/T3 del usuario en ONOS

### M4 → M6: Mitigación (POST /m6/mitigacion)
Request:
{
  "ip_atacante":  "192.168.100.X",
  "tipo":         "drop_total",
  "switch_dpid":  "of:000072e0807e854c",
  "prioridad":    5000,
  "ttl_segundos": 600
}
Acción: instala T0 DROP prio 5000+ + notifica M1 para revocar sesión

### M6 → ONOS REST API endpoints usados
POST   /onos/v1/flows/{deviceId}         instalar flow entry
POST   /onos/v1/flows                    batch múltiples flows
DELETE /onos/v1/flows/{deviceId}/{flowId} eliminar flow
GET    /onos/v1/flows/{deviceId}         consultar flows activos
GET    /onos/v1/hosts                    buscar host por IP
GET    /onos/v1/devices                  listar switches

## EJEMPLO JSON FLOW ENTRY REAL (funcionando en el slice)
### PUSH VLAN 90 en SW2 puerto 2 (regla cuarentena):
POST http://127.0.0.1:8181/onos/v1/flows/of:000072e0807e854c
{
  "priority": 10,
  "isPermanent": true,
  "deviceId": "of:000072e0807e854c",
  "treatment": {
    "instructions": [
      {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
      {"type": "L2MODIFICATION", "subtype": "VLAN_ID", "vlanId": 90},
      {"type": "OUTPUT", "port": "NORMAL"}
    ]
  },
  "selector": {
    "criteria": [
      {"type": "IN_PORT",  "port": 2},
      {"type": "ETH_TYPE", "ethType": "0x0800"}
    ]
  }
}

### SET_FIELD vlan_vid post-auth (cambio VLAN 90 → 210):
{
  "priority": 40000,
  "isPermanent": false,
  "timeout": 28800,
  "deviceId": "of:000072e0807e854c",
  "tableId": 1,
  "treatment": {
    "instructions": [
      {"type": "L2MODIFICATION", "subtype": "VLAN_ID", "vlanId": 210},
      {"type": "TABLE", "tableId": 2}
    ]
  },
  "selector": {
    "criteria": [
      {"type": "IN_PORT",  "port": "2"},
      {"type": "ETH_SRC",  "mac": "FA:16:3E:53:F8:E8"},
      {"type": "VLAN_VID", "vlanId": 90}
    ]
  }
}

## ARCHIVO portal_cautivo.py (M1) — estado actual
Ubicación: en la VM Controller o VM Auth
Estado: FUNCIONAL pero M6 no integrado aún
Punto de integración exacto: clase TokenEmitter, método emit()
  - Línea ~515: token = {codigo_pucp, nombre_rol, vlan_id, ip_asignada}
  - Línea ~517: M6_URL comentado en Config
  - Línea ~519-533: código de llamada HTTP a M6 comentado
  - Retorna None si M6 no disponible (usa valores demo)
  - Espera recibir de M6: {mac, switch_dpid, in_port}

Clases en portal_cautivo.py:
  Config          — configuración (RADIUS, MySQL, M6_URL)
  DatabaseManager — conexión MySQL
  RadiusClient    — envía Access-Request a FreeRADIUS
  RoleMapper      — mapea Filter-Id → vlan_id (VLAN_POR_ROL dict)
  UserManager     — bloqueo cuentas, intentos fallidos
  SessionManager  — registro sesión, binding, cierre, recursos RBAC
  TokenEmitter    — emite token a M6 (PENDIENTE DE INTEGRACIÓN)
  CaptivePortal   — orquesta todo, loop principal CLI

## OPA (M2)
Puerto: 8181 (mismo que ONOS — VERIFICAR si están en la misma VM o diferente)
Endpoint: POST /v1/data/rbac/allow
Input:
{
  "input": {
    "codigo_pucp": "20192434",
    "rol": "Estudiante_Telecom",
    "ip_asignada": "192.168.100.41",
    "vlan_id": 210,
    "mac_address": "FA:16:3E:53:F8:E8",
    "switch_dpid": "of:000072e0807e854c"
  }
}
Output esperado:
{
  "result": {
    "allow": true,
    "permisos": [
      {"recurso": "cursos_telecom", "ip_dst": "192.168.100.200",
       "puertos": [80, 443], "protocolo": "tcp",
       "tabla": "T2", "prioridad": 100, "timeout": null, "accion": "ALLOW"}
    ],
    "denegaciones": [
      {"ip_dst": "192.168.100.201", "puertos": [80,443],
       "tabla": "T3", "prioridad": 200, "accion": "DROP"}
    ]
  }
}

## FREERADIUS
Host: 127.0.0.1 puerto 1812
Secret: testing123
Tablas MySQL (radius_db):
  radcheck        — credenciales usuario/contraseña
  radusergroup    — usuario → grupo/rol
  radgroupreply   — grupo → Filter-Id + Session-Timeout
  sesiones_activas — {id_usuario, mac, ip, vlan_id, nombre_rol, switch_dpid, in_port}
  ip_mac_binding  — anti-spoofing {ip, mac, id_usuario, switch_dpid, in_port}
  historial_sesiones — log de sesiones cerradas
  politicas_rbac  — permisos ALLOW/DENY por rol y recurso

## PRIORIDADES OPENFLOW ACORDADAS
T0 bloqueo ataque:    5000+
T1 sesión post-auth:  40000
T1 DHCP cuarentena:   500
T1 portal cautivo:    100
T1 PUSH VLAN base:    10
T1 DROP default:      5
T2 ALLOW por VLAN:    100
T3 DENY por usuario:  200

## LO QUE FALTA IMPLEMENTAR (tarea de Mark)
1. m6.py — módulo completo desde cero con:
   - Flask API con endpoints: /m6/token_rol, /m6/cerrar_sesion,
     /m6/mitigacion, /m6/arranque, /m6/status
   - ONOSClient — toda comunicación con ONOS REST API
   - FlowBuilder — construye JSON de flow entries para cada caso
   - Cola backoff exponencial (1s→2s→4s, máx 3 intentos)
   - Cache local de flow_ids por sesión para eliminar al cerrar
   - Log asíncrono hacia M5

2. Modificar portal_cautivo.py:
   - Descomentar M6_URL en Config
   - En TokenEmitter.emit(): descomentar bloque HTTP hacia M6
   - Agregar llamada a /m6/cerrar_sesion en SessionManager.close_session()

3. Instalar reglas cuarentena en switches del slice:
   - SW2 (of:000072e0807e854c): puertos 2 y 3
   - SW3 (of:0000f220f9454c4e): puertos 2 y 3
   - SW1 (of:00005ec76ec6114c): según topología

## DEPENDENCIAS PYTHON NECESARIAS
pip3 install flask requests pyrad mysql-connector-python

## COMANDOS ÚTILES EN EL SLICE
# Ver flows activos en un switch
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/flows/of:000072e0807e854c | python3 -m json.tool

# Ver hosts detectados por ONOS
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/hosts | python3 -m json.tool

# Ver dispositivos
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/devices | python3 -m json.tool

# Borrar todos los flows de un switch (reset)
curl -u onos:rocks -X DELETE http://127.0.0.1:8181/onos/v1/flows/of:000072e0807e854c

# Ver dhcp assignments
onos@root> dhcp-list