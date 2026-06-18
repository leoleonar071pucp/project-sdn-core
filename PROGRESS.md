# PROGRESS.md — Estado de avance sesión a sesión
# SDN Zero Trust PUCP | Grupo 2 TEL354

---

## SESIÓN 2026-06-14 a 2026-06-17 — Demo VNRT + Slice final asignado

### COMPLETADO EN ESTA SESIÓN ✓

#### M6 (m6_traductor.py) — reescritura completa desde m6.py original
- [x] Corregidos 9 bugs del original (ver CLAUDE.md sección BUGS CORREGIDOS)
- [x] Pipeline T0/T1/T2/T3 implementado y probado
- [x] Descubrimiento dinámico de puertos de acceso via ONOS REST (`get_access_ports`)
- [x] Rutas del portal cautivo dinámicas (no hardcodeadas)
- [x] PolicyEngine con cadena OPA → MySQL → hardcoded fallback
- [x] Cache de flows por sesión con threading.Lock para concurrencia
- [x] Return flow automático al hacer login (eliminado al logout)
- [x] Table-miss NORMAL en switches de tránsito (SW1, SW3)
- [x] IP_MAPPING_M2 corregido: 10.0.0.22 → 192.168.100.201 (H4/Informatica, no H3)
- [x] Fix Bug 7: ALLOW gana sobre DENY para misma IP (eliminar del deny_map si está en allow_map)
- [x] T2 políticas diferenciadas por carrera (Telecom→H3, Informatica→H4)
- [x] Flask API en puerto 8080 con 5 endpoints

#### M1 (portal_cautivo.py) — completado y probado
- [x] RADIUS auth via pyrad
- [x] RoleMapper: nombre_rol → VLAN ID
- [x] UserManager: bloqueo por intentos fallidos
- [x] SessionManager: INSERT sesiones_activas, historial_sesiones, notifica M6 en logout
- [x] TokenEmitter: POST a M6 /m6/token_rol
- [x] Logout automático al cerrar SSH (M6 elimina flows)

#### Infraestructura VNRT (demo)
- [x] ONOS DHCP configurado para H2 (MAC FA:16:3E:68:A7:44 → 192.168.100.42)
  via Karaf CLI: `dhcp-set-static-mapping FA:16:3E:68:A7:44 192.168.100.42`
- [x] Servidores H3/H4 con HTTP:80 + HTTPS:443 (Python http.server + ssl)
- [x] Contenido diferenciado: HTTP muestra título, HTTPS agrega banner "Conexion HTTPS activa"
- [x] H3: fondo azul (#003366), Cursos Telecomunicaciones
- [x] H4: fondo verde (#006633), Cursos Informatica
- [x] Certificados autofirmados generados con openssl
- [x] https_server.py sirve desde /tmp/www-ssl (distinto de /tmp/www para HTTP)

#### Demo verificada funcionando
- [x] H1 (Telecom) → H3 ✓ ALLOW, H4 ✗ BLOQUEADO
- [x] H2 (Informatica) → H4 ✓ ALLOW, H3 ✗ BLOQUEADO
- [x] Login vía SSH al portal → flows instalados en tiempo real
- [x] Logout → flows eliminados, host vuelve a cuarentena
- [x] ONOS UI accesible via SSH tunnel (ssh -L 8181:192.168.201.200:8181 ubuntu@GW -p 5800 -N)
- [x] M6 corriendo en primer plano con python3 -u (output sin buffering)

---

### SLICE FINAL ASIGNADO — pendiente de implementar

**Fecha de asignación:** 2026-06-17

**Topología:** 5 switches (SW1-SW5), 3 hosts (H1-H3), 2 servidores (srv1/srv2)
- SW1: core
- SW2/SW3: distribución  
- SW4/SW5: acceso
- VM-Controller: ONOS + M6 (puerto SSH 5800)
- VM-Auth: FreeRADIUS + MySQL + M1 portal (puerto SSH 5851)
- VM-Monitor: monitoreo (puerto SSH 5852)

**Estado:** No conectado aún. IPs internas desconocidas. DPIDs desconocidos.

---

### PRÓXIMOS PASOS INMEDIATOS

#### PASO 1 — Reconocimiento de la nueva infraestructura
```bash
# Desde laptop, conectar a cada VM:
ssh ubuntu@<GATEWAY> -p 5800  # controller
ssh ubuntu@<GATEWAY> -p 5851  # auth
ssh ubuntu@<GATEWAY> -p 5821  # srv1
ssh ubuntu@<GATEWAY> -p 5822  # srv2

# En cada VM, obtener IP del plano de datos:
ip addr show  # buscar interfaz ens3 o ens4

# En controller, obtener DPIDs de los 5 switches:
curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/devices | python3 -m json.tool

# En cada switch VM, verificar OVS:
ovs-vsctl show
```

#### PASO 2 — Llenar esta tabla (completar al conectarse)
| VM | IP interna (ens4) | Notas |
|---|---|---|
| VM-Controller | ??? | ONOS + M6 |
| VM-Auth | ??? | FreeRADIUS + MySQL + Portal |
| VM-Monitor | ??? | |
| SW1 | ??? | bridge name: ??? |
| SW2 | ??? | |
| SW3 | ??? | |
| SW4 | ??? | acceso hosts? |
| SW5 | ??? | acceso servidores? |
| H1 | ??? | |
| H2 | ??? | |
| H3 | ??? | |
| srv1 (recursos_academicos) | ??? | |
| srv2 (sistema_notas) | ??? | |

#### PASO 3 — DPIDs a registrar (completar al conectarse)
| Switch | DPID ONOS |
|---|---|
| SW1 | of:???????????? |
| SW2 | of:???????????? |
| SW3 | of:???????????? |
| SW4 | of:???????????? |
| SW5 | of:???????????? |

#### PASO 4 — Actualizar m6_traductor.py Config
```python
# Cambiar estos valores con los datos reales descubiertos:
SW1 = "of:???"  # core
SW2 = "of:???"  # distribución
SW3 = "of:???"  # distribución
SW4 = "of:???"  # acceso hosts (H1/H2/H3)
SW5 = "of:???"  # acceso servidores

PORTAL_IP     = "???"  # IP ens4 de VM-Auth
SERVER_CURSOS = "???"  # IP srv1 (recursos_academicos)
SERVER_NOTAS  = "???"  # IP srv2 (sistema_notas)

# Añadir SW4 y SW5 a SWITCH_NOMBRES
SWITCH_NOMBRES = {
    "of:???": "SW1",
    "of:???": "SW2",
    "of:???": "SW3",
    "of:???": "SW4",
    "of:???": "SW5",
}
```

#### PASO 5 — Actualizar portal_cautivo.py Config
```python
RADIUS_HOST = "???"  # IP interna de VM-Auth
M6_URL = "http://???:8080/m6/token_rol"  # IP de VM-Controller
```

#### PASO 6 — Adaptar pipeline para 5 switches
- SW4/SW5: switches de acceso → instalar T1 VLAN push en puertos de acceso
- SW1, SW2, SW3: switches de tránsito → solo table-miss NORMAL y ARP pass-through
- Portal redirect: rutas en SW4/SW5 (hacia hosts) y en el camino hacia VM-Auth
- Enforcement: en SW4 (acceso H1/H2/H3) + posiblemente SW5 (acceso srv)

#### PASO 7 — Instalar dependencias en VMs
```bash
# VM-Controller
pip3 install flask requests mysql-connector-python

# VM-Auth
pip3 install pyrad mysql-connector-python

# Si MySQL no está en VM-Auth:
sudo apt-get install mysql-server
mysql -u root < radius_db_pucp_sdn.sql
```

#### PASO 8 — Verificar FreeRADIUS en VM-Auth
```bash
# Probar autenticación
radtest <codigo_pucp> <password> 127.0.0.1 0 testing123

# Ver usuarios configurados
mysql -u radius -pradius_pass radius_db -e "SELECT codigo_pucp, nombre FROM usuarios;"
```

#### PASO 9 — Copiar archivos al slice
```bash
# Desde laptop (git pull en controller/auth)
# O copiar directamente:
scp -P 5800 app/modules/m6/m6_traductor.py ubuntu@<GW>:/root/m6_traductor.py
scp -P 5851 portal_cautivo.py ubuntu@<GW>:/root/portal_cautivo.py
```

#### PASO 10 — Primera prueba de conectividad
```bash
# Desde H1 SSH al portal (debe redirigir tráfico o funcionar directo)
ssh <user>@<IP_VM_AUTH>

# Login y verificar que M6 instala flows
# En VM-Controller: tail -f /tmp/m6.log
```

---

### DECISIONES ARQUITECTURALES YA TOMADAS (no cambiar)

1. **M6 corre en VM-Auth** (misma VM que M1, M2, FreeRADIUS, MySQL)
   - ONOS_URL = "http://192.168.201.200:8181" (VM-Controller por red OOB)
   - VM-Controller solo ejecuta ONOS, nada más
2. Portal cautivo (M1) corre en VM-Auth — FreeRADIUS local (127.0.0.1:1812)
3. OPA (M2) corre en VM-Auth puerto 8182 (no 8181, ese es ONOS)
4. M6 instala flows DIRECTOS (no Intents ONOS) — necesario para multi-tabla y timeouts
5. Flows con hard_timeout=28800 — eliminación automática si no hay logout explícito
6. DROP = `{"clearDeferred": true, "instructions": []}` en ONOS (no "type":"DROP")
7. PolicyEngine: OPA primero, MySQL fallback, hardcoded último recurso
8. Descubrimiento dinámico de puertos de acceso (no hardcoded)

---

### OBSTÁCULOS CONOCIDOS

- **OPA no corre en VNRT** (disco lleno). En nueva topología evaluar si instalar.
- **sync.py de M2 tiene bug** — query no filtra `accion = 'ALLOW'`. No usar sin fix.
- **DHCP bug en T1** — T1 prio=500 requiere VLAN_VID ya set. ONOS DHCP app lo cubre
  con T0 prio=40000 automático, pero en nueva topología verificar que DHCP app esté activo.
- **Disco lleno puede afectar** a VMs con poco espacio — monitorear con `df -h`.

---

### ARCHIVOS CLAVE Y SU UBICACIÓN

| Archivo | Repositorio | Destino en producción |
|---|---|---|
| m6_traductor.py | app/modules/m6/m6_traductor.py | VM-Auth:/root/ |
| portal_cautivo.py | portal_cautivo.py (raíz) | VM-Auth:/root/ |
| sync.py (M2) | app/modules/m2_policies/sync/sync.py | VM-Auth:/root/m2/ |
| policy.rego (M2) | app/modules/m2_policies/opa/policy.rego | VM-Auth:/root/m2/ |
| schema BD | sql/radius_db_pucp_sdn (2).sql | VM-Auth:MySQL (radius_db) |
| setup script | setup/setup_vm_auth.sh | ejecutar en VM-Auth |
| run script | setup/run_services.sh | ejecutar en VM-Auth post-setup |

---

## SESIÓN 2026-06-18 — Preparación slice final (5 switches)

### COMPLETADO EN ESTA SESIÓN ✓

#### Corrección arquitectural
- [x] M6 movido a VM-Auth (junto a M1, M2, FreeRADIUS, MySQL)
- [x] ONOS_URL corregido: `http://192.168.201.200:8181` (VM-Controller por red OOB)

#### M2 (sync.py) — bug corregido
- [x] Fix: `AND pr.accion = 'ALLOW'` en query de condiciones (evitaba que DENYs aparecieran como condiciones de acceso en OPA)
- [x] Fix: defaults Docker → bare metal (host:localhost, user:radius, pass:radius_pass)
- [x] Fix: OPA_URL → `http://127.0.0.1:8182` (mismo host, puerto 8182)

#### m6_traductor.py — actualización para 5 switches
- [x] DPIDs reales del slice asignado configurados (SW1-SW5)
- [x] IPs reales: PORTAL_IP=192.168.100.2, SERVER_CURSOS=192.168.100.101, SERVER_NOTAS=192.168.100.102
- [x] dhcp_al_controller() movido a T0 sin VLAN_VID (fix DHCP bug)
- [x] bloqueo_servidor_cuarentena() en T1 prio=70 (evita acceso a servidores en cuarentena)
- [x] t0_return_flow() sin restricción IN_PORT (independiente de topología)
- [x] instalar_cuarentena_arranque() totalmente dinámico: classifica ACCESS vs TRANSIT via LLDP
- [x] T0 ALLOW flows usan OUTPUT:NORMAL (no puerto hardcodeado)

#### Archivos de deployment creados
- [x] `setup/setup_vm_auth.sh` — setup automático VM-Auth (MySQL + FreeRADIUS + OPA + Python + copia archivos)
- [x] `setup/run_services.sh` — arranca OPA, sync.py, M6 con logs en /tmp/

---

### PENDIENTE — al conectarse a VMs

#### 1. Reconocimiento (ejecutar en cada VM via SSH)
```bash
# VM-Auth (puerto 5851)
ip addr show          # buscar IP en ens4 o ens3 — debe ser 192.168.100.2
hostname

# VM-Controller (puerto 5800)
ip addr show          # debe ser 192.168.200.200 o 192.168.201.200
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/devices | python3 -m json.tool

# En cada switch (puertos 5801-5805)
ovs-vsctl show        # confirmar bridge y controller apuntando a VM-Controller
```

#### 2. Actualizar DPIDs en m6_traductor.py (una vez descubiertos)
```python
# En Config class — cambiar con DPIDs reales:
SW1 = "of:00007e3892af7141"   # ← verificar o actualizar
SW2 = "of:0000e2ecb0ea0445"
SW3 = "of:0000eadb63449748"
SW4 = "of:00006a0757adfc4e"   # acceso H1/H2/H3
SW5 = "of:0000ca126249d546"   # acceso srv1/srv2
```

#### 3. Copiar repo a VM-Auth y ejecutar setup
```bash
# Desde laptop — clonar/copiar repo
scp -rP 5851 . ubuntu@<GW>:/root/project-sdn-core/

# En VM-Auth como root
cd /root/project-sdn-core
bash setup/setup_vm_auth.sh

# Arrancar servicios
bash setup/run_services.sh
```

#### 4. ONOS DHCP para H1/H2/H3 (en VM-Controller)
```bash
# Verificar que ONOS DHCP app esté activa
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/applications | \
    python3 -c "import json,sys; [print(a['name']) for a in json.load(sys.stdin)['applications'] if 'dhcp' in a['name'].lower()]"

# Una vez que los hosts se conecten y sus MACs sean conocidos,
# configurar mapeos estáticos via Karaf CLI:
ssh -p 8101 karaf@localhost  # password: karaf
# dhcp-set-static-mapping <MAC_H1> 192.168.100.10
# dhcp-set-static-mapping <MAC_H2> 192.168.100.11
# dhcp-set-static-mapping <MAC_H3> 192.168.100.12
```

#### 5. Servidores srv1/srv2 (puertos 5821/5822)
```bash
# srv1 (recursos_academicos — cursos Telecom/Electro)
mkdir -p /tmp/www /tmp/www-ssl
echo '<html style="background:#003366"><h1>Cursos Telecomunicaciones</h1></html>' > /tmp/www/index.html
echo '<html style="background:#003366"><h1>Cursos Telecom — HTTPS activo</h1></html>' > /tmp/www-ssl/index.html
cd /tmp/www && nohup python3 -m http.server 80 &
openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem \
    -days 365 -nodes -subj "/CN=192.168.100.101"
# Copiar https_server.py y arrancar

# srv2 (sistema_notas — cursos Informatica)
# Mismo proceso con fondo verde #006633
```

---

_Última actualización: 2026-06-18_
_Próxima sesión: conectarse al slice, descubrir DPIDs/IPs, ejecutar setup_vm_auth.sh_
