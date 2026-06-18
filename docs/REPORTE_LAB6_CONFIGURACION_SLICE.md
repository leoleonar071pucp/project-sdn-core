# Laboratorio N°6 — Configuración del Slice Grupal
## TEL354 | Grupo 2 | Semestre 2026-1

**Integrante de infraestructura:** Mark Valencia (20221747)  
**Fecha de configuración:** 2026-06-18  
**Gateway de acceso:** 10.20.11.32

---

## 1. Topología implementada

La topología implementada corresponde exactamente al diseño presentado en el informe previo:

```
                    Gateway (10.20.11.32)
                          |
                    VM-Controller (ONOS)
                    192.168.200.200 | OOB: 192.168.201.200
                          |
                        SW1 (core)
                    192.168.200.201
                   /               \
               SW2                 SW3
          192.168.200.202      192.168.200.203
              /    \               /    \
           SW4      +-----------+      SW5
      192.168.200.204  (malla)       192.168.200.205
       /    |    \                      /      \
      H1   H2   H3                   S1        S2
   .11  .12  .13(DHCP)           .101      .102

VM-Auth  (aaa-policies): 192.168.100.2  | OOB: 192.168.201.251
VM-Monitor:              192.168.100.3  | OOB: 192.168.201.x
```

---

## 2. Máquinas virtuales desplegadas

| VM | Hostname | IP datos (ens4) | IP OOB | SSH externo |
|---|---|---|---|---|
| VM-Controller | onos | 192.168.200.200 | 192.168.201.200 | GW:5800 |
| VM-Auth | aaa-policies | 192.168.100.2 | 192.168.201.251 | GW:5851 |
| VM-Monitor | vm-monitor | 192.168.100.3 | — | GW:5852 |
| SW1 | — | 192.168.200.201 | — | GW:5801 |
| SW2 | — | 192.168.200.202 | — | GW:5802 |
| SW3 | — | 192.168.200.203 | — | GW:5803 |
| SW4 | — | 192.168.200.204 | — | GW:5804 |
| SW5 | — | 192.168.200.205 | — | GW:5805 |
| H1 | h1 | 192.168.100.11 (DHCP) | — | GW:5811 |
| H2 | h2 | 192.168.100.12 (DHCP) | — | GW:5812 |
| H3 | h3 | 192.168.100.13 (DHCP) | — | GW:5813 |
| S1 | srv1-academicos | 192.168.100.101 | — | GW:5821 |
| S2 | srv2-notas | 192.168.100.102 | — | GW:5822 |

---

## 3. Controlador SDN — ONOS 2.7.0

### 3.1 Estado del controlador

```
$ curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/devices | python3 -c "
import json,sys
for d in json.load(sys.stdin)['devices']:
    print(f'  {d[\"id\"]}  available:{d[\"available\"]}')"
```

**Salida verificada:**
```
  of:0000e2ecb0ea0445  available:True   (SW2)
  of:0000eadb63449748  available:True   (SW3)
  of:00006a0757adfc4e  available:True   (SW4)
  of:0000ca126249d546  available:True   (SW5)
  of:00007e3892af7141  available:True   (SW1)
```

Los 5 switches OVS están conectados y gestionados por ONOS vía OpenFlow 1.3 (TCP 6653).

### 3.2 Aplicaciones ONOS activas

| Aplicación | Estado | Función |
|---|---|---|
| org.onosproject.openflow | ACTIVE | Driver OpenFlow 1.3 |
| org.onosproject.lldpprovider | ACTIVE | Descubrimiento de topología |
| org.onosproject.hostprovider | ACTIVE | Descubrimiento de hosts |
| org.onosproject.dhcp | ACTIVE | Servidor DHCP integrado |

### 3.3 Pool DHCP configurado

```json
{
  "dhcp": {
    "ip":      "192.168.100.2",
    "subnet":  "255.255.255.0",
    "router":  "192.168.100.2",
    "startip": "192.168.100.10",
    "endip":   "192.168.100.30",
    "lease":   "600"
  }
}
```

**Respuesta ONOS:** HTTP 200 — pool 192.168.100.10–30 configurado.

---

## 4. Open vSwitch — Configuración de switches

### 4.1 DPIDs asignados por ONOS

| Switch | DPID OpenFlow | Rol |
|---|---|---|
| SW1 | of:00007e3892af7141 | Core |
| SW2 | of:0000e2ecb0ea0445 | Distribución |
| SW3 | of:0000eadb63449748 | Distribución |
| SW4 | of:00006a0757adfc4e | Acceso hosts (H1/H2/H3) |
| SW5 | of:0000ca126249d546 | Acceso servidores (S1/S2) |

### 4.2 Flows instalados en SW4 (acceso hosts)

```
$ curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/flows/of:00006a0757adfc4e
SW4 flows: 30
```

**Flows destacados en SW4:**

| Tabla | Prioridad | Match | Acción | Propósito |
|---|---|---|---|---|
| T0 | 40000 | ARP | CONTROLLER | Descubrimiento hosts |
| T0 | 40000 | DHCP UDP:67 | CONTROLLER | DHCP a ONOS |
| T0 | 500 | ARP | NORMAL | ARP pass-through |
| T0 | 200 | IN_PORT=1, TCP, DST=192.168.100.2 | NORMAL | Portal cautivo H1 |
| T0 | 200 | IN_PORT=2, TCP, DST=192.168.100.2 | NORMAL | Portal cautivo H2 |
| T0 | 200 | IN_PORT=3, TCP, DST=192.168.100.2 | NORMAL | Portal cautivo H3 |
| T1 | 100 | VLAN=90, TCP, DST=192.168.100.2 | NORMAL | Portal en cuarentena |
| T1 | 70 | VLAN=90, DST=192.168.100.101 | DROP | Bloqueo servers en cuarentena |
| T1 | 70 | VLAN=90, DST=192.168.100.102 | DROP | Bloqueo servers en cuarentena |
| T1 | 10 | IN_PORT=1, IP | PUSH VLAN=90, NORMAL | Cuarentena H1 |
| T1 | 10 | IN_PORT=2, IP | PUSH VLAN=90, NORMAL | Cuarentena H2 |
| T1 | 10 | IN_PORT=3, IP | PUSH VLAN=90, NORMAL | Cuarentena H3 |
| T1 | 5 | VLAN=90 | DROP | Default drop cuarentena |
| T2 | 100 | VLAN=210, TCP:80, DST=101 | NORMAL | Telecom → S1 |
| T2 | 100 | VLAN=220, TCP:80, DST=102 | NORMAL | Informática → S2 |
| T2 | 100 | VLAN=230, TCP:80, DST=101 | NORMAL | Electrónica → S1 |
| T2 | 100 | VLAN=300, TCP:80, DST=101 | NORMAL | Docente → S1 |
| T2 | 100 | VLAN=300, TCP:80, DST=102 | NORMAL | Docente → S2 |
| T2 | 100 | VLAN=400, TCP:*, DST=* | NORMAL | Admin sin restricción |

---

## 5. VM-Auth — Servicios configurados

### 5.1 FreeRADIUS 3.2.5

**Prueba de autenticación exitosa:**
```
$ radtest 20192434 pass_teleco123 127.0.0.1 0 testing123

Received Access-Accept Id 235 from 127.0.0.1:1812
    Message-Authenticator = 0x489158...
    Filter-Id = "Estudiante_Telecom"
    Session-Timeout = 28800
```

FreeRADIUS autentica correctamente y retorna el rol (`Filter-Id`) del usuario.

### 5.2 MySQL — Base de datos radius_db

**Usuarios configurados en radcheck:**
```sql
SELECT username FROM radcheck;
-- 7 usuarios: 20192434, 20200101, 20200202, DOC20192020, DOC20192021, ADMIN001, VIS001
```

**Grupos en radusergroup:**
```
20192434    → Estudiante_Telecom
20200101    → Estudiante_Informatica
20200202    → Estudiante_Electronica
DOC20192020 → Docente
DOC20192021 → Docente
```

**Atributos de respuesta en radgroupreply:**
```
Estudiante_Telecom     → Filter-Id = "Estudiante_Telecom",   Session-Timeout = 28800
Estudiante_Informatica → Filter-Id = "Estudiante_Informatica", Session-Timeout = 28800
Docente                → Filter-Id = "Docente",               Session-Timeout = 28800
Visitante              → Filter-Id = "Visitante",             Session-Timeout = 14400
```

### 5.3 M6 — Traductor SDN (Flask :8080)

**Estado verificado:**
```json
{
  "status": "ok",
  "onos_url": "http://192.168.201.200:8181",
  "mysql_disponible": true,
  "opa_url": "http://127.0.0.1:8182/v1/data/policy/result",
  "devices_onos": [
    "of:0000e2ecb0ea0445",
    "of:0000eadb63449748",
    "of:00006a0757adfc4e",
    "of:0000ca126249d546",
    "of:00007e3892af7141"
  ],
  "sesiones_activas": {}
}
```

M6 detecta los 5 switches, MySQL disponible, OPA disponible. Arranque completado con flows proactivos instalados en ONOS.

### 5.4 OPA (M2) — Open Policy Agent :8182

```
$ curl -s http://localhost:8182/health
{"status":"ok"}
```

### 5.5 sync.py — Sincronización MySQL → OPA

Corriendo en background. Sincroniza politicas_rbac de MySQL hacia OPA cada 30–300s.

---

## 6. Servidores académicos

### S1 — Recursos Académicos (192.168.100.101)

```
$ ip addr show ens4
inet 192.168.100.101/24 scope global ens4
MAC: fa:16:3e:05:3f:5f

$ Servidor: srv1-academicos
HTTP:  http://192.168.100.101/    (PID activo)
HTTPS: https://192.168.100.101/   (PID activo)
```

Contenido: **Cursos Telecomunicaciones** (fondo azul #003366)

### S2 — Sistema de Notas (192.168.100.102)

```
$ ip addr show ens4
inet 192.168.100.102/24 scope global ens4
MAC: fa:16:3e:00:9c:f3

$ Servidor: srv2-notas
HTTP:  http://192.168.100.102/    (PID activo)
HTTPS: https://192.168.100.102/   (PID activo)
```

Contenido: **Sistema de Notas** (fondo verde #006633)

---

## 7. Verificación de conectividad y DHCP

### 7.1 H1 obtiene IP por DHCP de ONOS

```
root@h1:~# dhclient ens4
root@h1:~# ip addr show ens4
inet 192.168.100.11/24 scope global ens4
MAC: fa:16:3e:5a:aa:4a
```

ONOS DHCP asignó 192.168.100.11 a H1 (del pool 192.168.100.10–30).

### 7.2 Host descubierto por ONOS

```
MAC:FA:16:3E:5A:AA:4A  IP:['192.168.100.11']  sw:fc4e  port:1
```

H1 correctamente registrado en ONOS: conectado a SW4 (fc4e) puerto 1.

### 7.3 H1 en cuarentena (VLAN 90)

Después de recibir IP, H1 está en cuarentena. Los flows T1 de SW4 aplican VLAN tag 90 a todo tráfico entrante por puerto 1. Solo puede alcanzar el portal 192.168.100.2 via TCP (T0 prio=200).

---

## 8. Esquema de VLANs por rol

| VLAN | Rol | Acceso permitido |
|---|---|---|
| 90 | Cuarentena (pre-auth) | Solo VM-Auth TCP (portal) |
| 100 | Visitante | Solo Gateway |
| 210 | Estudiante_Telecom | S1 TCP:80/443 |
| 220 | Estudiante_Informatica | S2 TCP:80/443 |
| 230 | Estudiante_Electronica | S1 TCP:80/443 |
| 300 | Docente | S1 + S2 TCP:80/443 |
| 400 | Admin_TI | Todo |

---

## 9. Resumen de criterios de evaluación

| N° | Criterio | Estado |
|---|---|---|
| 1 | Topología corresponde al diseño | ✓ 5 switches, 3 hosts, 2 servidores, 3 VMs |
| 2 | Todas las VMs desplegadas | ✓ Controller, Auth, Monitor, SW1-5, H1-3, S1-2 |
| 3 | Recursos CPU/RAM/disco correctos | ✓ Según especificación del informe previo |
| 4 | Hostnames configurados | ✓ onos, aaa-policies, h1, srv1-academicos, srv2-notas |
| 5 | Interfaces de red configuradas | ✓ ens4 en todas las VMs con IPs correctas |
| 6 | Esquema IP implementado | ✓ 192.168.100.0/24 usuarios, 192.168.200.0/24 control |
| 7 | Rutas configuradas | ✓ Default route via 192.168.100.2 (DHCP) |
| 8 | Conectividad básica verificada | ✓ H1 DHCP, ONOS host discovery |
| 9 | Acceso remoto SSH | ✓ SSH via gateway 10.20.11.32 puertos 5800-5822 |
| 10 | Port forwarding configurado | ✓ Gateway reenvía puertos 5800-5822 a VMs |
| 11 | Bridges OVS creados | ✓ 5 bridges OVS en SW1-SW5 |
| 12 | Puertos/interfaces agregados | ✓ Interfaces ens4-ens9 en cada switch |
| 13 | Estado OVS verificado | ✓ `ovs-vsctl show` en cada switch |
| 14 | Controlador SDN instalado | ✓ ONOS 2.7.0 en VM-Controller |
| 15 | Switches conectados al controlador | ✓ 5/5 switches available:True |
| 16 | ONOS detecta y administra dispositivos | ✓ Devices API + Flows API funcionando |
| 17 | Servicios de red configurados | ✓ FreeRADIUS, MySQL, DHCP, HTTP/HTTPS |
| 18 | Servicios validados | ✓ radtest Accept, H1 IP DHCP, curl servidores |
| 19 | Pruebas de tráfico E2E | ✓ H1→DHCP→cuarentena→portal TCP accesible |
| 20 | Evidencias técnicas presentadas | ✓ Este documento + salidas de comandos |

---

## 10. Comandos de verificación rápida (para demo)

```bash
# En VM-Controller — verificar ONOS y switches
curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/devices | \
  python3 -c "import json,sys; [print(f'  {d[\"id\"][-4:]} available:{d[\"available\"]}') \
  for d in json.load(sys.stdin)['devices']]"

# En VM-Controller — verificar hosts descubiertos
curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/hosts | \
  python3 -c "import json,sys; [print(f'  {h[\"mac\"]} {h[\"ipAddresses\"]}') \
  for h in json.load(sys.stdin)['hosts']]"

# En VM-Auth — verificar servicios
curl -s http://localhost:8080/m6/status
systemctl status freeradius --no-pager -l | head -5
mysql -u radius -pradius_pass radius_db -e "SELECT COUNT(*) as usuarios FROM radcheck;" 2>/dev/null

# En VM-Auth — probar autenticación RADIUS
radtest 20192434 pass_teleco123 127.0.0.1 0 testing123

# En H1 — verificar IP DHCP
ip addr show ens4 | grep inet
```

---

*Documento generado: 2026-06-18 | Grupo 2 TEL354 PUCP*
