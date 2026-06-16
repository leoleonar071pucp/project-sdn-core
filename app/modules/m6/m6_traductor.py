#!/usr/bin/env python3
"""
m6_traductor.py — Módulo Traductor SDN PUCP | Grupo 2 TEL354
Mark V

Única interfaz entre la lógica de negocio y ONOS Controller.
M1, M2 y M4 NUNCA tocan ONOS directamente — todo pasa por M6.

Pipeline OpenFlow implementado:
  T0 (tabla 0): Rutas directas portal + enforcement por MAC + bloqueo atacantes
  T1 (tabla 1): Cuarentena VLAN 90 + SET_FIELD post-auth
  T2 (tabla 2): ALLOW proactivo por VLAN → servidor (instalado al arrancar)
  T3 (tabla 3): DENY por sesión MAC+IP con hard_timeout

NOTA ONOS: DROP = {"clearDeferred": true, "instructions": []}
           ({"type": "DROP"} da error HTTP 400)

NOTA VNRT: el tráfico IP normal de los hosts no llega a tabla-1 automáticamente
           en este slice. Las rutas tabla-0 para portal son las que funcionan
           (verificado con SSH desde H1 a 192.168.100.1).
"""

import time
import threading
import requests
from collections import deque
from flask import Flask, request, jsonify

try:
    import mysql.connector
    MYSQL_OK = True
except ImportError:
    MYSQL_OK = False


# ─── Configuración ────────────────────────────────────────────────────────────
class Config:
    # ONOS (puerto 8181)
    ONOS_URL  = "http://127.0.0.1:8181"
    ONOS_AUTH = ("onos", "rocks")

    # OPA — puerto 8182 (distinto de ONOS que usa 8181)
    # Endpoint real de M2: package policy → /v1/data/policy/result
    OPA_URL = "http://127.0.0.1:8182/v1/data/policy/result"

    # Mapeo IPs diseño M2 (10.0.0.x) → IPs reales VNRT (192.168.100.x)
    # M2's init.sql usa IPs del diseño original; VNRT tiene 2 servidores reales.
    IP_MAPPING_M2 = {
        "10.0.0.21": "192.168.100.200",  # cursos_telecom → H3
        "10.0.0.22": "192.168.100.201",  # cursos_info    → H4 (VLAN 220)
        "10.0.0.23": "192.168.100.200",  # cursos_electro → H3
        "10.0.0.30": "192.168.100.201",  # servidor_notas → H4
        "10.0.0.40": "192.168.100.201",  # panel_admin    → H4
        "10.0.0.10": "192.168.100.1",    # portal_cautivo → controller
    }

    # M5 auditoría
    M5_URL = "http://127.0.0.1:5002/m5/log"

    # M6 propio
    M6_HOST = "0.0.0.0"
    M6_PORT = 8080

    # MySQL (fallback cuando OPA no disponible)
    MYSQL_HOST = "localhost"
    MYSQL_USER = "radius"
    MYSQL_PASS = "radius_pass"
    MYSQL_DB   = "radius_db"

    # Resiliencia
    MAX_REINTENTOS = 3
    BACKOFF_BASE   = 1        # segundos, backoff exponencial: 1→2→4
    MAX_COLA_LOGS  = 10000

    # IPs del plano de datos (verificadas en el slice VNRT)
    PORTAL_IP     = "192.168.100.1"    # controller / portal cautivo en ens4
    SERVER_CURSOS = "192.168.100.200"  # H3 — servidor cursos (IP fija)
    SERVER_NOTAS  = "192.168.100.201"  # H4 — servidor notas  (IP fija)

    # DPIDs reales del slice VNRT
    SW1 = "of:00005ec76ec6114c"   # core
    SW2 = "of:000072e0807e854c"   # acceso hosts
    SW3 = "of:0000f220f9454c4e"   # acceso servidores

    SWITCH_NOMBRES = {
        "of:00005ec76ec6114c": "SW1",
        "of:000072e0807e854c": "SW2",
        "of:0000f220f9454c4e": "SW3",
    }

    # Fallback hosts: cuando ONOS no tiene el host (IP asignada manualmente)
    HOSTS_VNRT = {
        "192.168.100.23": {
            "mac":         "FA:16:3E:14:78:63",
            "switch_dpid": "of:000072e0807e854c",
            "in_port":     2
        },
        "192.168.100.100": {
            "mac":         "FA:16:3E:E9:BF:92",
            "switch_dpid": "of:000072e0807e854c",
            "in_port":     3
        }
    }


    # Prioridades OpenFlow (acordadas en diseño de arquitectura)
    PRIO_VLAN_PUSH  = 10      # T1: sin tag → PUSH VLAN 90
    PRIO_DHCP       = 500     # T1: DHCP → CONTROLLER
    PRIO_PORTAL_T1  = 100     # T1: portal en cuarentena (tabla 1)
    PRIO_DROP_T1    = 5       # T1: DROP default cuarentena
    PRIO_SESION_T1  = 40000   # T1: SET_FIELD post-auth
    PRIO_T2_ALLOW   = 100     # T2: ALLOW proactivo por VLAN
    PRIO_T3_DENY    = 200     # T3: DROP por sesión
    PRIO_T0_PORTAL  = 200     # T0: ruta directa portal (VERIFICADA en VNRT)
    PRIO_T0_USUARIO = 35000   # T0: enforcement por MAC post-auth
    PRIO_T0_ATAQUE  = 5000    # T0: bloqueo atacante (instalado por M4)

    # VLANs por rol
    VLAN_CUARENTENA = 90
    VLANS_POR_ROL = {
        "Visitante":              100,
        "Estudiante_Telecom":     210,
        "Estudiante_Informatica": 220,
        "Estudiante_Electronica": 230,
        "Docente":                300,
        "Admin_TI":               400,
    }


# ─── Constructor de flow entries ──────────────────────────────────────────────
class FlowBuilder:
    """Construye los JSON de flow entries para cada caso del pipeline."""

    # ── T1: Cuarentena (tabla 1) ─────────────────────────────────────────────

    def vlan_push_cuarentena(self, device_id, in_port):
        """T1 prio10 — IP sin tag en in_port → PUSH VLAN 90 + OUTPUT NORMAL."""
        return {
            "priority":    Config.PRIO_VLAN_PUSH,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "IN_PORT",  "port": in_port},
                {"type": "ETH_TYPE", "ethType": "0x0800"}
            ]},
            "treatment": {"instructions": [
                {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
                {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                 "vlanId": Config.VLAN_CUARENTENA},
                {"type": "OUTPUT", "port": "NORMAL"}
            ]}
        }

    def dhcp_al_controller(self, device_id):
        """T1 prio500 — VLAN 90 + UDP dst=67 → CONTROLLER."""
        return {
            "priority":    Config.PRIO_DHCP,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "VLAN_VID", "vlanId": Config.VLAN_CUARENTENA},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 17},
                {"type": "UDP_DST",  "udpPort": 67}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": "CONTROLLER"}
            ]}
        }

    def portal_cuarentena_t1(self, device_id, ip_portal=None):
        """T1 prio100 — VLAN 90 + TCP + dst=portal → OUTPUT NORMAL."""
        if ip_portal is None:
            ip_portal = Config.PORTAL_IP
        return {
            "priority":    Config.PRIO_PORTAL_T1,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "VLAN_VID", "vlanId": Config.VLAN_CUARENTENA},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{ip_portal}/32"}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": "NORMAL"}
            ]}
        }

    def drop_default_cuarentena(self, device_id):
        """T1 prio5 — VLAN 90 + cualquier cosa → DROP."""
        return {
            "priority":    Config.PRIO_DROP_T1,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "VLAN_VID", "vlanId": Config.VLAN_CUARENTENA}
            ]},
            "treatment": {"clearDeferred": True, "instructions": []}
        }

    # ── T0: Rutas directas (tabla 0) ─────────────────────────────────────────

    def ruta_directa_t0(self, device_id, in_port, tipo_match, ip,
                         out_port, prio=None):
        """
        Tabla 0 routing directo — portal cautivo y enforcement post-auth.
        tipo_match: 'dst' = match IPV4_DST  |  'src' = match IPV4_SRC
        out_port:   int → OUTPUT ese puerto  |  None → DROP
        """
        if prio is None:
            prio = Config.PRIO_T0_PORTAL
        tipo_ip = "IPV4_DST" if tipo_match == "dst" else "IPV4_SRC"
        if out_port is not None:
            treatment = {"instructions": [{"type": "OUTPUT", "port": out_port}]}
        else:
            treatment = {"clearDeferred": True, "instructions": []}
        return {
            "priority":    prio,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "IN_PORT",  "port": in_port},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": tipo_ip,    "ip": f"{ip}/32"},
                {"type": "IP_PROTO", "protocol": 6}
            ]},
            "treatment": treatment
        }

    # ── T1: SET_FIELD post-auth (tabla 1) ────────────────────────────────────

    def set_vlan_post_auth(self, device_id, mac, in_port, vlan_nuevo,
                            session_timeout=28800):
        """T1 prio40000 — MAC+VLAN90+IN_PORT → SET_FIELD vlan_nuevo + goto T2."""
        return {
            "priority":    Config.PRIO_SESION_T1,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "IN_PORT",  "port": in_port},
                {"type": "ETH_SRC",  "mac":  mac},
                {"type": "VLAN_VID", "vlanId": Config.VLAN_CUARENTENA}
            ]},
            "treatment": {"instructions": [
                {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                 "vlanId": vlan_nuevo},
                {"type": "TABLE", "tableId": 2}
            ]}
        }

    # ── T2: ALLOW proactivo por VLAN (tabla 2) ───────────────────────────────

    def t2_allow_vlan(self, device_id, vlan_id, ip_dst, tcp_port):
        """T2 prio100 — VLAN_VID + IP_DST + TCP_PORT → OUTPUT NORMAL."""
        return {
            "priority":    Config.PRIO_T2_ALLOW,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     2,
            "selector": {"criteria": [
                {"type": "VLAN_VID", "vlanId": vlan_id},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{ip_dst}/32"},
                {"type": "TCP_DST",  "tcpPort": tcp_port}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": "NORMAL"}
            ]}
        }

    # ── T3: DENY por sesión (tabla 3) ────────────────────────────────────────

    def t3_deny_sesion(self, device_id, mac, ip_src, ip_dst,
                        session_timeout=28800):
        """T3 prio200 — MAC+IP_SRC/32+IP_DST/32 → DROP con hard_timeout."""
        return {
            "priority":    Config.PRIO_T3_DENY,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     3,
            "selector": {"criteria": [
                {"type": "ETH_SRC",  "mac":  mac},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_SRC", "ip": f"{ip_src}/32"},
                {"type": "IPV4_DST", "ip": f"{ip_dst}/32"}
            ]},
            "treatment": {"clearDeferred": True, "instructions": []}
        }

    # ── T0: Enforcement por MAC post-auth (tabla 0) ──────────────────────────
    # Estos flows son los que realmente hacen enforcement en este slice VNRT,
    # ya que tabla-1/2/3 no son alcanzadas por tráfico IP normal en este entorno.

    def t0_allow_usuario(self, device_id, mac, ip_dst, out_port,
                          session_timeout=28800):
        """Tabla 0 prio35000 — ETH_SRC=MAC + IP_DST → OUTPUT (ALLOW efectivo)."""
        return {
            "priority":    Config.PRIO_T0_USUARIO,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_SRC",  "mac":  mac},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{ip_dst}/32"}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": out_port}
            ]}
        }

    def t0_deny_usuario(self, device_id, mac, ip_dst, session_timeout=28800):
        """Tabla 0 prio35000 — ETH_SRC=MAC + IP_DST → DROP (DENY efectivo)."""
        return {
            "priority":    Config.PRIO_T0_USUARIO,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_SRC",  "mac":  mac},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{ip_dst}/32"}
            ]},
            "treatment": {"clearDeferred": True, "instructions": []}
        }

    def t0_allow_arp(self, device_id):
        """T0 prio500 — ARP broadcast/unicast → OUTPUT NORMAL (resolución MAC)."""
        return {
            "priority":    500,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0806"}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": "NORMAL"}
            ]}
        }

    # ── T0: Bloqueo atacante (tabla 0) ───────────────────────────────────────

    def t0_bloqueo_ataque(self, device_id, ip_atacante, ttl=600, prio=None):
        """T0 prio5000+ — IP_SRC/32 atacante → DROP con timeout."""
        if prio is None:
            prio = Config.PRIO_T0_ATAQUE
        return {
            "priority":    prio,
            "isPermanent": False,
            "timeout":     ttl,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IPV4_SRC", "ip": f"{ip_atacante}/32"}
            ]},
            "treatment": {"clearDeferred": True, "instructions": []}
        }

    def t0_table_miss_normal(self, device_id):
        """T0 prio1 — table-miss → NORMAL (forwarding por defecto en SW tránsito)."""
        return {
            "priority":    1,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     0,
            "selector":    {"criteria": []},
            "treatment":   {"instructions": [{"type": "OUTPUT", "port": "NORMAL"}]}
        }

    def t0_return_flow(self, device_id, dst_mac, out_port, session_timeout=28800):
        """T0 prio200 — respuesta de servidores → host (IN_PORT=1=uplink, ETH_DST=MAC)."""
        return {
            "priority":    200,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "IN_PORT",  "port": 1},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "ETH_DST",  "mac":  dst_mac}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": out_port}
            ]}
        }


# ─── Log asíncrono hacia M5 ───────────────────────────────────────────────────
class M5Logger:

    def __init__(self):
        self.cola = deque(maxlen=Config.MAX_COLA_LOGS)

    def log(self, evento):
        """Envía a M5 en thread daemon para no bloquear la respuesta a M1."""
        threading.Thread(
            target=self._enviar, args=(evento,), daemon=True
        ).start()

    def _enviar(self, evento):
        try:
            resp = requests.post(Config.M5_URL, json=evento, timeout=3)
            if resp.status_code not in (200, 201):
                self.cola.append(evento)
        except Exception:
            self.cola.append(evento)

    def flush(self):
        """Reenvía todos los logs encolados cuando M5 se recupera."""
        while self.cola:
            self._enviar(self.cola.popleft())


# ─── Motor de políticas: OPA → MySQL → hardcoded ─────────────────────────────
class PolicyEngine:
    """
    Obtiene {permisos, denegaciones} para un usuario autenticado.
    Cadena de fallback: OPA (M2) → MySQL (radius_db) → tabla hardcoded por VLAN.
    """

    def get_policies(self, payload_opa):
        """
        payload_opa: {"input": {codigo_pucp, rol, vlan_id, ip_asignada, ...}}
        Retorna: {"permisos": [...], "denegaciones": [...]}

        Cadena de fallback: OPA M2 → MySQL → hardcoded por VLAN
        """
        input_data  = payload_opa.get("input", {})
        codigo_pucp = input_data.get("codigo_pucp", "")
        nombre_rol  = input_data.get("rol", "")
        vlan_id     = int(input_data.get("vlan_id", 0))

        # 1. OPA (M2) — usa políticas RBAC completas con excepciones temporales
        #    M2 espera: {usuario: str, roles: [str]}  (NO codigo_pucp/rol directos)
        #    M2 retorna: {permisos: [{recurso:{ip_dst,puerto,nombre}, tabla, ...}]}
        opa_payload = {
            "input": {
                "usuario": codigo_pucp,
                "roles":   [nombre_rol]   # M2 Rego requiere array
            }
        }
        try:
            resp = requests.post(Config.OPA_URL, json=opa_payload, timeout=3)
            if resp.status_code == 200:
                resultado    = resp.json().get("result", {})
                m2_permisos  = resultado.get("permisos")
                if m2_permisos is not None:
                    print(f"  [PolicyEngine] Políticas desde OPA M2 "
                          f"({len(m2_permisos)} permisos)")
                    return self._convertir_permisos_m2(m2_permisos, vlan_id)
        except Exception as e:
            print(f"  [PolicyEngine] OPA no disponible: {e}")

        # 2. MySQL — fallback si OPA no está corriendo
        pol_mysql = self._desde_mysql(nombre_rol)
        if pol_mysql is not None:
            return pol_mysql

        # 3. Hardcoded por VLAN — siempre disponible
        print(f"  [PolicyEngine] Políticas hardcoded para VLAN {vlan_id}")
        return self._hardcoded(vlan_id)

    def _normalizar_ip(self, ip_raw):
        """Traduce IPs del diseño M2 (10.0.0.x) a IPs reales VNRT."""
        return Config.IP_MAPPING_M2.get(ip_raw, ip_raw)

    def _convertir_permisos_m2(self, m2_permisos, vlan_id):
        """
        Convierte la respuesta de OPA M2 al formato interno de M6.
        M2: [{recurso:{ip_dst,puerto,nombre}, tabla:'T2'|'T3', ...}]
        M6: {permisos:[{ip_dst,puertos:[]}], denegaciones:[{ip_dst,puertos:[]}]}
        """
        allow_map = {}
        for p in m2_permisos:
            recurso = p.get("recurso", {})
            ip_raw  = recurso.get("ip_dst", "")
            puerto  = recurso.get("puerto")
            if not ip_raw or puerto is None:
                continue
            ip_dst = self._normalizar_ip(ip_raw)
            allow_map.setdefault(ip_dst, set()).add(int(puerto))

        permisos = [{"ip_dst": ip, "puertos": sorted(ps)}
                    for ip, ps in allow_map.items()]

        # Denegaciones: servidores VNRT conocidos que NO están en permisos
        all_vnrt  = {Config.SERVER_CURSOS, Config.SERVER_NOTAS}
        denied_ips = all_vnrt - set(allow_map.keys())
        denegaciones = [{"ip_dst": ip, "puertos": [80, 443]}
                        for ip in sorted(denied_ips)]

        return {"permisos": permisos, "denegaciones": denegaciones}

    def _desde_mysql(self, nombre_rol):
        """Consulta politicas_rbac en radius_db. Retorna dict o None si falla."""
        if not MYSQL_OK or not nombre_rol:
            return None
        try:
            conn = mysql.connector.connect(
                host=Config.MYSQL_HOST, user=Config.MYSQL_USER,
                password=Config.MYSQL_PASS, database=Config.MYSQL_DB,
                connection_timeout=3
            )
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT p.accion, rec.ip_dst, rec.puerto
                FROM politicas_rbac p
                JOIN recursos rec      ON p.id_recurso = rec.id_recurso
                JOIN roles_facultad rf ON p.id_rol     = rf.id_rol
                WHERE rf.nombre_rol = %s
                  AND p.accion IN ('ALLOW', 'DENY')
                ORDER BY p.accion, rec.ip_dst, rec.puerto
            """, (nombre_rol,))
            rows = cur.fetchall()
            conn.close()

            if not rows:
                return None

            allow_map, deny_map = {}, {}
            for row in rows:
                # Normalizar IP: M2 DB tiene 10.0.0.x, VNRT usa 192.168.100.x
                ip_raw = row["ip_dst"]
                ip     = self._normalizar_ip(ip_raw)
                puerto = int(row["puerto"])
                accion = row["accion"]
                (allow_map if accion == "ALLOW" else deny_map).setdefault(
                    ip, []
                ).append(puerto)

            # El mapeo N→1 de IPs (cursos_telecom/info/electro → mismo servidor)
            # puede generar ALLOW y DENY para la misma IP real. ALLOW prevalece.
            for ip in list(deny_map.keys()):
                if ip in allow_map:
                    del deny_map[ip]

            print(f"  [PolicyEngine] MySQL — {nombre_rol}: "
                  f"{len(allow_map)} destinos ALLOW, {len(deny_map)} DENY")
            return {
                "permisos":    [{"ip_dst": ip, "puertos": sorted(set(ps))}
                                for ip, ps in allow_map.items()],
                "denegaciones":[{"ip_dst": ip, "puertos": sorted(set(ps))}
                                for ip, ps in deny_map.items()]
            }
        except Exception as e:
            print(f"  [PolicyEngine] MySQL error: {e}")
            return None

    def _hardcoded(self, vlan_id):
        """Políticas por defecto — espejo de la arquitectura de acceso PUCP."""
        cursos, notas = Config.SERVER_CURSOS, Config.SERVER_NOTAS
        if vlan_id in (210, 220, 230):    # Estudiantes — solo cursos
            return {
                "permisos":    [{"ip_dst": cursos, "puertos": [80, 443]}],
                "denegaciones":[{"ip_dst": notas,  "puertos": [80, 443]}]
            }
        elif vlan_id in (300, 400):        # Docentes y Admin — cursos + notas
            return {
                "permisos": [
                    {"ip_dst": cursos, "puertos": [80, 443]},
                    {"ip_dst": notas,  "puertos": [80, 443]}
                ],
                "denegaciones": []
            }
        else:   # Visitante
            # TODO: Visitante debería tener acceso a internet externo (VLAN 100 → gateway)
            # Requiere configurar NAT en el controller (192.168.201.210 vía ens3)
            # que está fuera del plano SDN. Por ahora se permite acceso al portal únicamente.
            return {
                "permisos":    [],
                "denegaciones": [
                    {"ip_dst": Config.SERVER_CURSOS, "puertos": [80, 443]},
                    {"ip_dst": Config.SERVER_NOTAS,  "puertos": [80, 443]}
                ]
            }


# ─── Cliente ONOS ─────────────────────────────────────────────────────────────
class ONOSClient:
    """Toda la comunicación con ONOS REST API pasa por aquí."""

    def __init__(self):
        self.url  = Config.ONOS_URL
        self.auth = Config.ONOS_AUTH

    def _post_flow(self, device_id, flow_entry, reintentos=0):
        """
        POST /onos/v1/flows/{deviceId}
        El flow se envía DIRECTAMENTE como body (sin wrapper {"flows": [...]}).
        El wrapper es exclusivo del endpoint batch POST /onos/v1/flows.
        Retorna el flowId asignado por ONOS, o None si falló.
        """
        endpoint = f"{self.url}/onos/v1/flows/{device_id}"
        try:
            resp = requests.post(
                endpoint, json=flow_entry,
                auth=self.auth, timeout=5
            )
            if resp.status_code in (200, 201):
                # ONOS 2.7.0 devuelve HTTP 201 con body VACÍO.
                # El flowId real viene en el header Location:
                #   /onos/v1/flows/{deviceId}/{flowId}
                flow_id = None
                location = resp.headers.get("Location", "")
                if location:
                    flow_id = location.rstrip("/").split("/")[-1]
                if not flow_id:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {}
                    flow_id = (data.get("id") or
                               data.get("flowId") or
                               (data.get("flows") or [{}])[0].get("id") or
                               (data.get("flows") or [{}])[0].get("flowId"))
                if not flow_id:
                    flow_id = f"onos-{resp.status_code}-{int(time.time())}"
                nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-8:])
                print(f"    [ONOS] ✓ {nombre} T{flow_entry.get('tableId','?')} "
                      f"prio={flow_entry.get('priority')}  id={flow_id}")
                return flow_id
            else:
                raise Exception(f"HTTP {resp.status_code}: {resp.text[:300]}")

        except Exception as e:
            if reintentos < Config.MAX_REINTENTOS:
                espera = Config.BACKOFF_BASE * (2 ** reintentos)
                print(f"    [ONOS] Reintento {reintentos+1}/{Config.MAX_REINTENTOS}"
                      f" en {espera}s: {e}")
                time.sleep(espera)
                return self._post_flow(device_id, flow_entry, reintentos + 1)
            print(f"    [ONOS] ✗ Fallo definitivo: {e}")
            return None

    def _delete_flow(self, device_id, flow_id):
        endpoint = f"{self.url}/onos/v1/flows/{device_id}/{flow_id}"
        try:
            resp = requests.delete(endpoint, auth=self.auth, timeout=5)
            if resp.status_code in (200, 204):
                nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-8:])
                print(f"  [ONOS] Flow {flow_id} eliminado de {nombre}")
                return True
            print(f"  [ONOS] Error al eliminar {flow_id}: "
                  f"HTTP {resp.status_code}")
            return False
        except Exception as e:
            print(f"  [ONOS] Error al eliminar {flow_id}: {e}")
            return False

    def get_host_by_ip(self, ip_asignada):
        """
        Busca host en ONOS por IP → {mac, switch_dpid, in_port}.
        Si ONOS no lo tiene (IP asignada fuera de ONOS DHCP), usa HOSTS_VNRT.
        """
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/hosts", auth=self.auth, timeout=2
            )
            if resp.status_code == 200:
                for host in resp.json().get("hosts", []):
                    if ip_asignada in host.get("ipAddresses", []):
                        locs = host.get("locations", [])
                        if locs:
                            return {
                                "mac":         host["mac"],
                                "switch_dpid": locs[0]["elementId"],
                                "in_port":     int(locs[0]["port"])
                            }
        except Exception as e:
            print(f"  [ONOS] Error GET /hosts: {e}")

        # Fallback a hosts conocidos del slice
        if ip_asignada in Config.HOSTS_VNRT:
            h = Config.HOSTS_VNRT[ip_asignada]
            print(f"  [ONOS] Fallback VNRT para {ip_asignada}: mac={h['mac']}")
            return dict(h)

        print(f"  [ONOS] Host {ip_asignada} no encontrado")
        return None

    def get_devices(self):
        """Lista de deviceIds disponibles en ONOS."""
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/devices", auth=self.auth, timeout=5
            )
            if resp.status_code == 200:
                return [d["id"] for d in resp.json().get("devices", [])]
        except Exception as e:
            print(f"  [ONOS] Error GET /devices: {e}")
        return []

    def get_access_ports(self, device_id):
        """
        Devuelve los puertos de acceso (hacia hosts) de un switch.
        Consulta ONOS para obtener todos los puertos y resta los enlaces
        inter-switch (trunks) detectados por LLDP en /onos/v1/links.
        """
        all_ports = set()
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/devices/{device_id}/ports",
                auth=self.auth, timeout=3
            )
            if resp.status_code == 200:
                for p in resp.json().get("ports", []):
                    num = p.get("port", "")
                    if str(num).isdigit() and int(num) < 65534:
                        all_ports.add(int(num))
        except Exception as e:
            print(f"  [ONOS] Error GET /devices/{device_id}/ports: {e}")
            return []

        trunk_ports = set()
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/links", auth=self.auth, timeout=3
            )
            if resp.status_code == 200:
                for link in resp.json().get("links", []):
                    for endpoint in ("src", "dst"):
                        ep = link.get(endpoint, {})
                        if ep.get("device") == device_id:
                            try:
                                trunk_ports.add(int(ep["port"]))
                            except (ValueError, KeyError):
                                pass
        except Exception as e:
            print(f"  [ONOS] Error GET /links: {e}")

        access_ports = sorted(all_ports - trunk_ports)
        nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-8:])
        print(f"  [ONOS] {nombre} — acceso={access_ports} trunk={sorted(trunk_ports)}")
        return access_ports

    def instalar_flow(self, device_id, flow_entry):
        return self._post_flow(device_id, flow_entry)

    def eliminar_flow(self, device_id, flow_id):
        return self._delete_flow(device_id, flow_id)


# ─── Lógica principal ─────────────────────────────────────────────────────────
class M6Translator:

    def __init__(self):
        self.onos     = ONOSClient()
        self.builder  = FlowBuilder()
        self.logger   = M5Logger()
        self.policies = PolicyEngine()
        # Cache flows por sesión: {mac: [(device_id, flow_id), ...]}
        # Protegido por lock para acceso concurrente (Flask threaded)
        self._lock = threading.Lock()
        self.flows_por_sesion = {}

    def _instalar_y_cachear(self, device_id, flow_entry, mac=None):
        """Instala un flow y lo registra en el cache de sesión si se provee mac."""
        fid = self.onos.instalar_flow(device_id, flow_entry)
        if fid and mac is not None:
            with self._lock:
                self.flows_por_sesion.setdefault(mac, [])
                self.flows_por_sesion[mac].append((device_id, fid))
        return fid

    # ── Arranque ──────────────────────────────────────────────────────────────

    def instalar_cuarentena_arranque(self):
        """
        Instala al arrancar:
          1. T1 cuarentena en todos los switches (VLAN 90)
          2. T0 rutas directas portal en SW1 y SW2 (funcionan en VNRT)
          3. T2 ALLOW proactivo por VLAN → servidor en SW2
        """
        devices     = self.onos.get_devices()
        devices_set = set(devices)
        SEP = "─" * 47

        print(f"\n[M6] {SEP}")
        print(f"[M6]  Cuarentena arranque — {len(devices)} switch(es)")
        print(f"[M6] {SEP}")

        # T1: Cuarentena VLAN 90 en todos los switches
        # VLAN push solo en SW2 (host access); puertos descubiertos dinámicamente
        sw2_access_ports = (self.onos.get_access_ports(Config.SW2)
                            if Config.SW2 in devices_set else [])

        for device_id in devices:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id)
            print(f"\n  → {nombre}")

            self.onos.instalar_flow(device_id,
                self.builder.dhcp_al_controller(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.portal_cuarentena_t1(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.drop_default_cuarentena(device_id))
            if device_id == Config.SW2:
                for puerto in sw2_access_ports:
                    self.onos.instalar_flow(device_id,
                        self.builder.vlan_push_cuarentena(device_id, puerto))
                print(f"    T1 VLAN push cuarentena → puertos acceso: {sw2_access_ports}")

        # T0: Rutas directas portal (tabla 0) — verificadas con SSH H1→portal
        #  Forward: SW2 IN_PORT=<acceso>, dst=portal → OUTPUT 1 (dinámico por host)
        #           SW1 IN_PORT=2, dst=portal → OUTPUT 1 (hacia ctrl/portal)
        #  Return:  SW1 IN_PORT=1, src=portal → OUTPUT 2 (hacia SW2)
        #           SW2 IN_PORT=1, src=portal → NORMAL   (OVS L2 entrega al host correcto)
        PORTAL_IP   = Config.PORTAL_IP
        rutas_portal = [
            (Config.SW2, p, "dst", PORTAL_IP, 1, f"SW2 p{p}→portal")
            for p in sw2_access_ports
        ] + [
            (Config.SW2, 1, "src", PORTAL_IP, "NORMAL", "SW2 portal→hosts NORMAL"),
            (Config.SW1, 2, "dst", PORTAL_IP, 1,        "SW1 SW2→ctrl"),
            (Config.SW1, 1, "src", PORTAL_IP, 2,        "SW1 ctrl→SW2"),
        ]
        print(f"\n  [T0] Rutas directas portal ({PORTAL_IP}):")
        for dpid, in_port, tipo, ip, out_port, desc in rutas_portal:
            if dpid in devices_set:
                flow = self.builder.ruta_directa_t0(
                    dpid, in_port, tipo, ip, out_port,
                    prio=Config.PRIO_T0_PORTAL
                )
                self.onos.instalar_flow(dpid, flow)
                print(f"    ✓ {desc}")
            else:
                sw = Config.SWITCH_NOMBRES.get(dpid, dpid)
                print(f"    ⚠  {sw} no disponible — omitiendo: {desc}")

        # T0: ARP pass-through en todos los switches (necesario para resolución MAC)
        print(f"\n  [T0] ARP pass-through (0x0806 → NORMAL):")
        for device_id in devices:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id)
            self.onos.instalar_flow(device_id, self.builder.t0_allow_arp(device_id))
            print(f"    ✓ {nombre}")

        # T0: table-miss NORMAL en SW1 y SW3 (switches de tránsito — no hacen enforcement)
        # Sin esto, el tráfico de H1→H3 se pierde al no matchear ningún flow en SW1/SW3.
        print(f"\n  [T0] Table-miss NORMAL en switches de tránsito (SW1, SW3):")
        for device_id in [Config.SW1, Config.SW3]:
            if device_id in devices_set:
                self.onos.instalar_flow(device_id,
                    self.builder.t0_table_miss_normal(device_id))
                nombre = Config.SWITCH_NOMBRES.get(device_id, device_id)
                print(f"    ✓ {nombre}")
            else:
                nombre = Config.SWITCH_NOMBRES.get(device_id, device_id)
                print(f"    ⚠  {nombre} no disponible")

        # T2: ALLOW proactivo por VLAN (tabla 2, permanente, instalado una vez)
        POLITICAS_T2 = [
            (210, Config.SERVER_CURSOS, "Est.Telecom → H3 cursos_telecom"),
            (220, Config.SERVER_NOTAS,  "Est.Informatica → H4 cursos_info"),
            (230, Config.SERVER_CURSOS, "Est.Electronica → H3 cursos_electro"),
            (300, Config.SERVER_CURSOS, "Docente → H3 cursos"),
            (300, Config.SERVER_NOTAS,  "Docente → H4 notas"),
            (400, Config.SERVER_CURSOS, "Admin_TI → H3 cursos"),
            (400, Config.SERVER_NOTAS,  "Admin_TI → H4 notas"),
        ]
        print(f"\n  [T2] Políticas VLAN proactivas (tabla 2):")
        if Config.SW2 in devices_set:
            for vlan, ip_dst, desc in POLITICAS_T2:
                for tcp_port in [80, 443]:
                    self.onos.instalar_flow(
                        Config.SW2,
                        self.builder.t2_allow_vlan(Config.SW2, vlan, ip_dst, tcp_port)
                    )
                print(f"    ✓ VLAN {vlan} → {ip_dst}  [{desc}]")
        else:
            print("    ⚠  SW2 no disponible — T2 omitido")

        print(f"\n[M6] {SEP}")
        print("[M6]  Arranque completado")
        print(f"[M6] {SEP}\n")

    # ── Procesamiento de token de M1 ─────────────────────────────────────────

    def procesar_token_rol(self, token):
        """
        Punto de entrada desde M1 tras autenticación exitosa.
        token = {codigo_pucp, nombre_rol, vlan_id, ip_asignada,
                mac, switch_dpid, in_port}
        M1 ya resolvió el host vía /m6/resolver_host antes de llamar aquí.
        Instala flows en ONOS y retorna {"ok": True}.
        """
        codigo_pucp = token["codigo_pucp"]
        nombre_rol  = token["nombre_rol"]
        vlan_id     = int(token["vlan_id"])
        ip_asignada = token["ip_asignada"]
        mac         = token["mac"]
        switch_dpid = token["switch_dpid"]
        in_port     = int(token["in_port"])

        nombre_sw = Config.SWITCH_NOMBRES.get(switch_dpid, switch_dpid[-8:])
        print(f"\n[M6] ── Token de M1 ──────────────────────────────")
        print(f"  usuario={codigo_pucp}  rol={nombre_rol}  "
            f"vlan={vlan_id}  ip={ip_asignada}")
        print(f"  host: mac={mac}  switch={nombre_sw}  puerto={in_port}")

        # 1. T1 SET_FIELD: VLAN 90 → vlan_id del rol
        print(f"  [T1] SET_FIELD VLAN {Config.VLAN_CUARENTENA}→{vlan_id}...")
        self._instalar_y_cachear(
            switch_dpid,
            self.builder.set_vlan_post_auth(switch_dpid, mac, in_port, vlan_id),
            mac
        )

        # T0 return flow: respuestas de servidores → host
        print(f"  [T0] Return flow → puerto {in_port}...")
        self._instalar_y_cachear(
            switch_dpid,
            self.builder.t0_return_flow(switch_dpid, mac, in_port),
            mac
        )

        # 2. Obtener políticas (OPA → MySQL → hardcoded)
        payload_opa = {
            "input": {
                "codigo_pucp": codigo_pucp,
                "rol":         nombre_rol,
                "ip_asignada": ip_asignada,
                "vlan_id":     vlan_id,
                "mac_address": mac,
                "switch_dpid": switch_dpid
            }
        }
        politicas = self.policies.get_policies(payload_opa)

        # 3. Instalar flows de política
        n_allow, n_deny = 0, 0
        print(f"  Instalando enforcement...")

        for permiso in politicas.get("permisos", []):
            ip_dst = permiso["ip_dst"]
            self._instalar_y_cachear(
                switch_dpid,
                self.builder.t0_allow_usuario(
                    switch_dpid, mac, ip_dst, out_port=1
                ),
                mac
            )
            n_allow += 1

        for denegacion in politicas.get("denegaciones", []):
            ip_dst = denegacion["ip_dst"]
            self._instalar_y_cachear(
                switch_dpid,
                self.builder.t3_deny_sesion(switch_dpid, mac, ip_asignada, ip_dst),
                mac
            )
            self._instalar_y_cachear(
                switch_dpid,
                self.builder.t0_deny_usuario(switch_dpid, mac, ip_dst),
                mac
            )
            n_deny += 1

        n_total = len(self.flows_por_sesion.get(mac, []))
        print(f"  ✓ Sesión activada — {n_total} flows  "
            f"(T1:1  T0-ALLOW:{n_allow}  T3+T0-DENY:{n_deny*2})")

        self.logger.log({
            "modulo":  "M6", "evento": "sesion_activada",
            "usuario": codigo_pucp, "rol": nombre_rol,
            "vlan":    vlan_id, "mac": mac,
            "switch":  switch_dpid, "puerto": in_port,
            "n_flows": n_total
        })
        return {"ok": True}

    # ── Cierre de sesión ──────────────────────────────────────────────────────

    def cerrar_sesion(self, mac):
        """
        Elimina todos los flows de la sesión (T1, T3, T0 ALLOW/DENY por MAC).
        Llamado por M1 al hacer logout.
        """
        with self._lock:
            flows = self.flows_por_sesion.pop(mac, [])
        print(f"\n[M6] Cerrando sesión MAC={mac} — {len(flows)} flows")
        for device_id, flow_id in flows:
            self.onos.eliminar_flow(device_id, flow_id)
        self.logger.log({
            "modulo":           "M6",
            "evento":           "sesion_cerrada",
            "mac":              mac,
            "flows_eliminados": len(flows)
        })

    # ── Mitigación de ataques (M4) ────────────────────────────────────────────

    def procesar_mitigacion(self, directiva):
        """
        Instala T0 DROP de alta prioridad para el IP del atacante.
        directiva = {ip_atacante, tipo, switch_dpid, prioridad, ttl_segundos}
        """
        ip_atacante = directiva["ip_atacante"]
        switch_dpid = directiva.get("switch_dpid")
        ttl         = directiva.get("ttl_segundos", 600)
        prio        = directiva.get("prioridad", Config.PRIO_T0_ATAQUE)

        print(f"\n[M6] DirectivaMitigacion: ip={ip_atacante} ttl={ttl}s prio={prio}")
        devices = [switch_dpid] if switch_dpid else self.onos.get_devices()
        for device_id in devices:
            self.onos.instalar_flow(
                device_id,
                self.builder.t0_bloqueo_ataque(device_id, ip_atacante, ttl, prio)
            )
        self.logger.log({
            "modulo":      "M6",
            "evento":      "mitigacion_aplicada",
            "ip_atacante": ip_atacante,
            "ttl":         ttl,
            "prio":        prio
        })


# ─── Flask API ────────────────────────────────────────────────────────────────
app = Flask(__name__)
m6  = M6Translator()

# se añade un nuevo end point  para conocer el dpid, port y mac del user antes de mandar el token 
# a m6 y valisar sus campos de sesiones activas y ip_mac binding
@app.route("/m6/resolver_host", methods=["POST"])
def endpoint_resolver_host():
    """
    M1 llama aquí ANTES de registrar la sesión en DB.
    Solo consulta ONOS y devuelve {mac, switch_dpid, in_port}.
    No instala ningún flow.
    """
    data = request.json or {}
    ip_asignada = data.get("ip_asignada")
    if not ip_asignada:
        return jsonify({"error": "falta campo: ip_asignada"}), 400
    host = m6.onos.get_host_by_ip(ip_asignada)
    if not host:
        return jsonify({"error": f"host {ip_asignada} no encontrado"}), 404
    return jsonify(host), 200

@app.route("/m6/token_rol", methods=["POST"])
def endpoint_token_rol():
    """
    M1 llama aquí DESPUÉS de registrar la sesión en DB.
    Recibe token completo e instala flows en ONOS.
    """
    token = request.json
    if not token:
        return jsonify({"error": "body vacío"}), 400
    for campo in ("codigo_pucp", "nombre_rol", "vlan_id",
                  "ip_asignada", "mac", "switch_dpid", "in_port"):
        if campo not in token:
            return jsonify({"error": f"falta campo: {campo}"}), 400
    resultado = m6.procesar_token_rol(token)
    if resultado:
        return jsonify(resultado), 200
    return jsonify({"error": "no se pudo procesar (ver logs de M6)"}), 500


@app.route("/m6/cerrar_sesion", methods=["POST"])
def endpoint_cerrar_sesion():
    """M1 llama aquí al cerrar sesión del usuario."""
    data = request.json or {}
    mac  = data.get("mac")
    if not mac:
        return jsonify({"error": "falta campo: mac"}), 400
    m6.cerrar_sesion(mac)
    return jsonify({"ok": True}), 200


@app.route("/m6/mitigacion", methods=["POST"])
def endpoint_mitigacion():
    """M4 llama aquí al detectar un atacante."""
    directiva = request.json
    if not directiva or "ip_atacante" not in directiva:
        return jsonify({"error": "falta ip_atacante"}), 400
    m6.procesar_mitigacion(directiva)
    return jsonify({"ok": True}), 200


@app.route("/m6/arranque", methods=["POST"])
def endpoint_arranque():
    """Reinstala reglas de cuarentena y proactivas en todos los switches."""
    m6.instalar_cuarentena_arranque()
    return jsonify({"ok": True}), 200


@app.route("/m6/status", methods=["GET"])
def endpoint_status():
    """Healthcheck — estado de ONOS y sesiones activas."""
    devices = m6.onos.get_devices()
    with m6._lock:
        sesiones = {mac: len(flows)
                    for mac, flows in m6.flows_por_sesion.items()}
    return jsonify({
        "status":           "ok",
        "onos_url":         Config.ONOS_URL,
        "opa_url":          Config.OPA_URL,
        "mysql_disponible": MYSQL_OK,
        "devices_onos":     devices,
        "sesiones_activas": sesiones
    }), 200


# ─── Main (modo desarrollo — para producción usa run_m6.sh con gunicorn) ──────
if __name__ == "__main__":
    SEP = "═" * 55
    print(f"\n{SEP}")
    print("  M6 — Módulo Traductor SDN PUCP")
    print("  Grupo 2 TEL354 | Mark Valencia (20221747)")
    print(SEP)
    print(f"  ONOS  : {Config.ONOS_URL}")
    print(f"  OPA   : {Config.OPA_URL}")
    print(f"  MySQL : {Config.MYSQL_HOST}/{Config.MYSQL_DB}  "
          f"[{'connector OK' if MYSQL_OK else 'sin conector'}]")
    print(f"  Puerto: {Config.M6_PORT}  (threaded)")
    print(SEP)

    m6.instalar_cuarentena_arranque()

    print(f"[M6] API escuchando en {Config.M6_HOST}:{Config.M6_PORT}\n")
    # threaded=True: permite requests simultáneos de M1, M4, M5 sin cola
    app.run(host=Config.M6_HOST, port=Config.M6_PORT,
            debug=False, threaded=True)
