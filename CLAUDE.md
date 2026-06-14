# SDN PUCP TEL354 — Red Campus Zero Trust
# Contexto completo para implementación de M6

## Arquitectura general
Sistema SDN Zero Trust para red universitaria PUCP.
Stack: ONOS 2.7.0 + OVS + OpenFlow 1.3 + FreeRADIUS + MySQL + OPA.
6 módulos: M1 Identidad, M2 Políticas, M3 Monitoreo, 
M4 Detección/Mitigación, M5 Auditoría, M6 Traducción.
REGLA CRÍTICA: M6 es el único módulo que habla con ONOS.

## Infraestructura real (VirtualBox)
Controller ONOS:  192.168.56.104  (REST API puerto 8181)
Auth ONOS:        onos:rocks
SW1 troncal:      of:000072e0807e854c  (192.168.200.201)
SW2 acceso:       of:000072e0807e854c  (192.168.200.202)
SW3 acceso:       (192.168.200.203)
SW4 acceso:       (192.168.200.204)
SW5 acceso:       (192.168.200.205)
Portal cautivo:   10.0.0.10 (VM Auth, SSH TCP 22)

## Hosts y servidores (Slide - 4 hosts máximo)
H1: 192.168.100.13  (cliente)
H2: 192.168.100.43  (cliente)
H3: 192.168.100.200 (servidor - IP FIJA)
H4: 192.168.100.201 (servidor - IP FIJA)

## DHCP
Módulo: org.onosproject.dhcp integrado en ONOS Controller
Pool:   192.168.100.10 → 192.168.100.100
Una sola asignación DHCP por sesión. La IP no cambia al autenticar.
El rol se diferencia por VLAN tag, no por IP.

## VLANs por rol
Cuarentena:            VLAN 90   (pre-auth, todos los dispositivos nuevos)
Visitante:             VLAN 100
Estudiante Telecom:    VLAN 210
Estudiante Informatica:VLAN 220
Estudiante Electronica:VLAN 230
Docente:               VLAN 300
Admin TI:              VLAN 400

## Servidores y quién accede
H3 (192.168.100.200): servidor cursos  → VLAN 210, 220, 230, 300, 400
H4 (192.168.100.201): servidor notas   → VLAN 300, 400
Portal cautivo (10.0.0.10): VLAN 90 solamente

## Pipeline OpenFlow T0-T4
T0: Seguridad — DROP atacantes, prio 5000+, instalado por M4 via M6
T1: Identidad — reglas cuarentena VLAN 90 + SET_FIELD vlan_vid post-auth
T2: Políticas VLAN — ALLOW por VLAN_VID hacia ip_dst, permanente, instalado al arrancar
T3: Denegaciones — DROP MAC+ip_src/32+ip_dst, hard_timeout=duración sesión
T4: Table-miss → packet-in al controlador (no usado en flujo normal, todo proactivo)

## Reglas proactivas T1 instaladas al arrancar ONOS
Regla base  prio 1:   IN_PORT=cualquiera, sin VLAN tag → PUSH_VLAN 90
Regla DHCP  prio 500: VLAN_VID=90 + UDP dst=67 + IP=255.255.255.255 → OUTPUT Controller
Regla portal prio 100: VLAN_VID=90 + TCP + ip_dst=10.0.0.10 → OUTPUT puerto portal
Regla DROP  prio 1:   VLAN_VID=90 + otro → DROP

## Reglas T2 instaladas al arrancar (proactivas por rol)
VLAN 210 → ip_dst=192.168.100.200, TCP 80/443, OUTPUT puerto H3, prio 100
VLAN 220 → ip_dst=192.168.100.200, TCP 80/443, OUTPUT puerto H3, prio 100
VLAN 230 → ip_dst=192.168.100.200, TCP 80/443, OUTPUT puerto H3, prio 100
VLAN 300 → ip_dst=192.168.100.200, TCP 80/443, OUTPUT puerto H3, prio 100
VLAN 300 → ip_dst=192.168.100.201, TCP 80/443, OUTPUT puerto H4, prio 100
VLAN 400 → ip_dst=192.168.100.200, TCP 80/443, OUTPUT puerto H3, prio 100
VLAN 400 → ip_dst=192.168.100.201, TCP 80/443, OUTPUT puerto H4, prio 100

## Contrato M1 → M6: Token de Rol
Cuándo: después de autenticación exitosa en FreeRADIUS
Campos: {
  codigo_pucp: str,
  nombre_rol:  str,      # "Estudiante_Telecom", "Docente", etc.
  vlan_id:     int,      # 210, 300, etc.
  ip_asignada: str,      # "192.168.100.X" (del pool DHCP)
  mac_address: str,      # "aa:bb:cc:dd:ee:ff"
  switch_dpid: str,      # "of:000072e0807e854c"
  in_port:     int,      # puerto físico del switch
  hora:        str       # ISO 8601
}
Respuesta M6 → M1: {exito: bool, flow_id: str, error: str|None}

## Contrato M2 (OPA) → M6
OPA corre en puerto 8181 como microservicio.
M6 hace POST a http://localhost:8181/v1/data/rbac/allow
Body: {"input": {codigo_pucp, rol, ip_asignada, cidr_rol, mac_address, switch_dpid, in_port, hora}}
Respuesta OPA: {
  result: {
    allow: bool,
    permisos: [{recurso, ip_dst, puertos, protocolo, tabla, prioridad, timeout, accion}],
    denegaciones: [{ip_dst, puertos, tabla, prioridad, accion}]
  }
}
M6 traduce permisos → flow entries T2 (ALLOW)
M6 traduce denegaciones → flow entries T3 (DROP con hard_timeout)

## Contrato M4 → M6: DirectivaMitigacion
Campos: {
  ip_atacante:     str,  # IP exacta /32
  tipo:            str,  # "drop_total" | "rate_limit"
  switch_dpid:     str,
  prioridad:       int,  # 5000+
  ttl_segundos:    int,  # 300-900
  rate_limit_kbps: int|None
}
M6 hace DOS cosas simultáneas:
1. POST /onos/v1/flows → T0 DROP ip_atacante prio 5000+ TTL ttl_segundos
2. Notifica a M1 → revocar_sesion(mac_atacante)
   M1 responde → M6 ejecuta DELETE flows T1 y T3 del atacante en ONOS

## ONOS REST API endpoints que usa M6
POST   /onos/v1/flows/{deviceId}     instalar flow entry en switch específico
POST   /onos/v1/flows                batch al arrancar (múltiples switches)
DELETE /onos/v1/flows/{deviceId}/{flowId}  eliminar regla al cerrar sesión
GET    /onos/v1/flows/{deviceId}     reconciliar estado post-caída ONOS
POST   /onos/v1/packet-out           reenviar paquete original (caso reactivo)
GET    /onos/v1/devices              descubrir switches al arrancar

## JSON flow entry real (ejemplo cambio VLAN post-auth)
POST /onos/v1/flows/of:000072e0807e854c
{
  "priority": 40000,
  "isPermanent": false,
  "tableId": 1,
  "deviceId": "of:000072e0807e854c",
  "selector": {
    "criteria": [
      {"type": "IN_PORT", "port": "2"},
      {"type": "ETH_SRC", "mac": "aa:bb:cc:dd:ee:ff"},
      {"type": "VLAN_VID", "vlanId": "90"}
    ]
  },
  "treatment": {
    "instructions": [
      {"type": "L2MODIFICATION", "subtype": "VLAN_ID", "vlanId": 210},
      {"type": "TABLE", "tableId": 2}
    ]
  }
}

## JSON flow entry real (ejemplo VLAN push inicial - regla base T1)
{
  "priority": 1,
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
      {"type": "IN_PORT", "port": 2},
      {"type": "ETH_TYPE", "ethType": "0x0800"}
    ]
  }
}

## Resiliencia M6
Cola backoff exponencial: 1s → 2s → 4s, máx 3 intentos ante error ONOS
Cache local flow_ids: {switch_dpid: {tabla: [flow_id]}} para reconciliación
Cola offline M5: hasta 10,000 logs en memoria, flush cuando M5 recupera
Fail-secure: si ONOS cae, usuarios activos mantienen acceso, nuevos no pueden entrar

## Lo que NO hace M6
- No gestiona DHCP (eso es ONOS org.onosproject.dhcp)
- No valida credenciales (eso es M1 + FreeRADIUS)
- No evalúa políticas (eso es M2 + OPA)
- No detecta ataques (eso es M3 + M4)
- No implementa OpenFlow directamente (ONOS lo hace)

## Estado actual del código
El código en el repositorio puede tener lógica CIDR en vez de VLAN.
CIDR debe reemplazarse por VLAN_VID en todos los flow entries de T2.
El actor DHCP debe ser ONOS Controller, no un servicio externo.
Las IPs de servidores son 192.168.100.200 y 192.168.100.201 (no 10.0.0.x).