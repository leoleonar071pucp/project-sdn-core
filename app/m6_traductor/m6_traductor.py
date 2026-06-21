#!/usr/bin/env python3
"""
m6_traductor.py — Módulo Traductor SDN PUCP | Grupo 2 TEL354
Mark V (base) + ajustes de integración M1 (Sheila J)

Única interfaz entre la lógica de negocio y ONOS Controller.
M1, M2 y M4 NUNCA tocan ONOS directamente — todo pasa por M6.

Topología real (confirmada):
  VM-Controller (ONOS): control SDN 192.168.200.200, OOB 192.168.201.200
  VM-Auth (M1/M6/RADIUS/MySQL): control SDN 192.168.200.211, OOB 192.168.201.251
  M6 llama a la REST API de ONOS por la red OOB (192.168.201.0/24), ya
  verificado con curl que responde por esa ruta.

Pipeline OpenFlow implementado:
  T0 (tabla 0): Rutas directas portal + enforcement por MAC + bloqueo atacantes
  T1 (tabla 1): Cuarentena VLAN 90 + SET_FIELD post-auth
  T2 (tabla 2): ALLOW proactivo por VLAN → servidor (instalado al arrancar)
  T3 (tabla 3): DENY por sesión MAC+IP con hard_timeout

Flujo M1 ↔ M6 (DOS llamadas, en este orden):
  1. POST /m6/resolver_host  {ip_asignada}
     → M6 SOLO consulta ONOS (GET /onos/v1/hosts). No instala flows.
     → Retorna {mac, switch_dpid, in_port}
     → M1 usa esto para registrar la sesión en MySQL (sesiones_activas,
       ip_mac_binding) ANTES de tocar la red.
  2. POST /m6/token_rol {codigo_pucp, nombre_rol, vlan_id, ip_asignada,
                          mac, switch_dpid, in_port}
     → Solo se llama DESPUÉS de que M1 confirmó el registro en MySQL.
     → M6 instala todos los flows (T1 SET_FIELD, T0 return, T0/T3 políticas).
  Este orden es deliberado: ningún flow se instala para una sesión que no
  esté ya persistida en la base de datos (evita acceso de red "fantasma"
  si el registro en MySQL llega a fallar).

NOTA ONOS: DROP = {"clearDeferred": true, "instructions": []}
           ({"type": "DROP"} da error HTTP 400)
"""

import os
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


#  Configuración base
class Config:
    # ONOS corre en VM-Controller; M6 corre en VM-Auth y lo llama por la red OOB (192.168.201.0/24) — verificado con curl que responde ahí.
    # Configurable via env si se necesita cambiar de red (ej. a la decontrol SDN 192.168.200.0/24) sin tocar código:
    # export ONOS_URL=http://192.168.200.200:8181
    ONOS_URL  = os.environ.get("ONOS_URL", "http://192.168.201.200:8181")
    ONOS_AUTH = ("onos", "rocks")

    # OPA (M2) — corre en la misma VM-Auth que M6, puerto 8182
    OPA_URL = os.environ.get("OPA_URL", "http://127.0.0.1:8182/v1/data/policy/result")

    # Mapeo IPs diseño M2 (10.0.0.x) → IPs reales del slice
    @classmethod
    def get_ip_mapping_m2(cls):
        return {
            "10.0.0.21": cls.SERVER_CURSOS,  # cursos_telecom → srv1
            "10.0.0.22": cls.SERVER_NOTAS,   # cursos_info    → srv2
            "10.0.0.23": cls.SERVER_CURSOS,  # cursos_electro → srv1
            "10.0.0.30": cls.SERVER_NOTAS,   # servidor_notas → srv2
            "10.0.0.40": cls.SERVER_NOTAS,   # panel_admin    → srv2
            "10.0.0.10": cls.PORTAL_IP,      # portal_cautivo → VM-Auth
        }

    # M5 auditoría
    M5_URL = os.environ.get("M5_URL", "http://127.0.0.1:5002/m5/log")

    # M6 propio
    M6_HOST = "0.0.0.0"
    M6_PORT = int(os.environ.get("M6_PORT", "8080"))

    # MySQL (fallback cuando OPA no disponible)
    MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
    MYSQL_USER = os.environ.get("MYSQL_USER", "radius")
    MYSQL_PASS = os.environ.get("MYSQL_PASS", "radius_pass")
    MYSQL_DB   = os.environ.get("MYSQL_DB",   "radius_db")

    # Resiliencia
    MAX_REINTENTOS = 3
    BACKOFF_BASE   = 1        # segundos, backoff exponencial: 1→2→4
    MAX_COLA_LOGS  = 10000

    # IPs del plano de datos — configurables via variables de entorno.
    # PORTAL_IP es la IP de VM-Auth en la red de datos (192.168.100.x),
    # donde corre web.py (portal cautivo). Ajustar si el slice cambia:
    #   export PORTAL_IP=192.168.100.X SERVER_CURSOS=192.168.100.Y SERVER_NOTAS=192.168.100.Z
    PORTAL_IP     = os.environ.get("PORTAL_IP",     "192.168.100.2")
    SERVER_CURSOS = os.environ.get("SERVER_CURSOS", "192.168.100.200")  # H3
    SERVER_NOTAS  = os.environ.get("SERVER_NOTAS",  "192.168.100.201")  # H4

    # DPIDs reales confirmados (curl a /onos/v1/devices, slice actual).
    # Solo se usan para nombrar en logs — la clasificación acceso/tránsito
    # es DINÁMICA vía LLDP (get_access_ports), no depende de este mapeo.
    SWITCH_NOMBRES = {
        "of:00007e3892af7141": "SW1",
        "of:0000e2ecb0ea0445": "SW2",
        "of:0000eadb63449748": "SW3",
        "of:00006a0757adfc4e": "SW4",
        "of:0000ca126249d546": "SW5",
    }

    # Prioridades OpenFlow (acordadas en diseño de arquitectura)
    PRIO_VLAN_PUSH  = 10      # T1: sin tag → PUSH VLAN 90
    PRIO_DHCP       = 500     # T0: DHCP → CONTROLLER
    PRIO_PORTAL_T1  = 100     # T1: portal en cuarentena (tabla 1)
    PRIO_DROP_T1    = 5       # T1: DROP default cuarentena
    PRIO_SESION_T1  = 40000   # T1: SET_FIELD post-auth
    PRIO_T2_ALLOW   = 100     # T2: ALLOW proactivo por VLAN
    PRIO_T3_DENY    = 200     # T3: DROP por sesión
    PRIO_T0_PORTAL  = 200     # T0: ruta directa portal
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
        """T0 prio500 — UDP dst=67 → CONTROLLER (sin VLAN_VID, llega sin tag)."""
        return {
            "priority":    Config.PRIO_DHCP,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 17},
                {"type": "UDP_DST",  "udpPort": 67}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": "CONTROLLER"}
            ]}
        }

    def bloqueo_servidor_cuarentena(self, device_id, ip_servidor):
        """T1 prio70 — VLAN 90 + dst=servidor_académico → DROP.
        Bloqueo explícito durante cuarentena, aunque otro flow haga NORMAL."""
        return {
            "priority":    70,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "VLAN_VID", "vlanId": Config.VLAN_CUARENTENA},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IPV4_DST", "ip": f"{ip_servidor}/32"}
            ]},
            "treatment": {"clearDeferred": True, "instructions": []}
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
        """T0 prio200 — respuesta de servidores → host por ETH_DST (sin restricción de IN_PORT)."""
        return {
            "priority":    200,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "ETH_DST",  "mac":  dst_mac}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": out_port}
            ]}
        }

    def t0_return_portal_flow(self, device_id, portal_ip):
        """T0 prio199 — respuesta del portal (IPV4_SRC=portal) → NORMAL.
        Permanente. Sin IN_PORT: el SYN-ACK llega por trunk port (variable).
        Prio 199 < 200 (portal dst) para no interceptar tráfico hacia el portal."""
        return {
            "priority":    199,
            "isPermanent": True,
            "timeout":     0,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IPV4_SRC", "ip": f"{portal_ip}/32"},
            ]},
            "treatment": {"instructions": [{"type": "OUTPUT", "port": "NORMAL"}]}
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
        input_data  = payload_opa.get("input", {})
        codigo_pucp = input_data.get("codigo_pucp", "")
        nombre_rol  = input_data.get("rol", "")
        vlan_id     = int(input_data.get("vlan_id", 0))

        # 1. OPA (M2)
        opa_payload = {
            "input": {
                "usuario": codigo_pucp,
                "roles":   [nombre_rol]
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
        """Traduce IPs del diseño M2 (10.0.0.x) a IPs reales."""
        return Config.get_ip_mapping_m2().get(ip_raw, ip_raw)

    def _convertir_permisos_m2(self, m2_permisos, vlan_id):
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

        all_servidores  = {Config.SERVER_CURSOS, Config.SERVER_NOTAS}
        denied_ips = all_servidores - set(allow_map.keys())
        denegaciones = [{"ip_dst": ip, "puertos": [80, 443]}
                        for ip in sorted(denied_ips)]

        return {"permisos": permisos, "denegaciones": denegaciones}

    def _desde_mysql(self, nombre_rol):
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
                ip_raw = row["ip_dst"]
                ip     = self._normalizar_ip(ip_raw)
                puerto = int(row["puerto"])
                accion = row["accion"]
                (allow_map if accion == "ALLOW" else deny_map).setdefault(
                    ip, []
                ).append(puerto)

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
        else:
            # Visitante — sin acceso a servidores académicos.
            # TODO: acceso a internet externo requiere NAT en
            # 192.168.201.210 vía ens3, fuera del plano SDN (pendiente).
            return {
                "permisos": [],
                "denegaciones": [
                    {"ip_dst": cursos, "puertos": [80, 443]},
                    {"ip_dst": notas,  "puertos": [80, 443]}
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
        Retorna el flowId asignado por ONOS, o None si falló.
        """
        endpoint = f"{self.url}/onos/v1/flows/{device_id}"
        try:
            resp = requests.post(
                endpoint, json=flow_entry,
                auth=self.auth, timeout=5
            )
            if resp.status_code in (200, 201):
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
        ONOS aprende los hosts dinámicamente vía DHCP/ARP.
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

        print(f"  [ONOS] Host {ip_asignada} no encontrado en ONOS")
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
        Clasificación DINÁMICA vía LLDP: consulta todos los puertos del
        switch y resta los enlaces inter-switch (trunks) detectados en
        /onos/v1/links. No depende de qué DPID sea cuál — funciona igual
        para cualquier topología que ONOS vea vía LLDP.
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
        self._lock = threading.Lock()
        self.flows_por_sesion = {}  # {mac: [(device_id, flow_id), ...]}

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
        Instala flows proactivos al arrancar. Clasificación DINÁMICA de switches:
          - ACCESO: tiene puertos no-trunk (detectados via LLDP) → enforcement + VLAN push
          - TRÁNSITO: todos sus puertos son trunk → table-miss NORMAL

        No se hardcodea qué switch es cuál. Funciona con los 5 switches
        reales (SW1-SW5) o con cualquier topología que ONOS vea vía LLDP.
        """
        devices = self.onos.get_devices()
        SEP = "─" * 47

        print(f"\n[M6] {SEP}")
        print(f"[M6]  Cuarentena arranque — {len(devices)} switch(es)")
        print(f"[M6] {SEP}")

        access_switches  = {}   # device_id → [puertos_acceso]
        transit_switches = []   # device_id

        print(f"\n  Clasificando switches (LLDP):")
        for device_id in devices:
            nombre  = Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])
            puertos = self.onos.get_access_ports(device_id)
            if puertos:
                access_switches[device_id] = puertos
                print(f"    {nombre}: ACCESO  puertos={puertos}")
            else:
                transit_switches.append(device_id)
                print(f"    {nombre}: TRÁNSITO")

        PORTAL_IP    = Config.PORTAL_IP
        SRV_CURSOS   = Config.SERVER_CURSOS
        SRV_NOTAS    = Config.SERVER_NOTAS

        # ── T0: DHCP → CONTROLLER en TODOS ────────────────────────────────────
        print(f"\n  [T0] DHCP → CONTROLLER:")
        for device_id in devices:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])
            self.onos.instalar_flow(device_id, self.builder.dhcp_al_controller(device_id))
            print(f"    ✓ {nombre}")

        # ── T0: ARP pass-through en TODOS ─────────────────────────────────────
        print(f"\n  [T0] ARP pass-through:")
        for device_id in devices:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])
            self.onos.instalar_flow(device_id, self.builder.t0_allow_arp(device_id))
            print(f"    ✓ {nombre}")

        # ── T0: Table-miss NORMAL en switches de TRÁNSITO ────────────────────
        print(f"\n  [T0] Table-miss NORMAL (tránsito):")
        for device_id in transit_switches:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])
            self.onos.instalar_flow(device_id, self.builder.t0_table_miss_normal(device_id))
            print(f"    ✓ {nombre}")

        # ── T0: Rutas portal en switches de ACCESO ────────────────────────────
        print(f"\n  [T0] Rutas portal ({PORTAL_IP}) en acceso:")
        for device_id, puertos_acceso in access_switches.items():
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])
            for puerto in puertos_acceso:
                flow = self.builder.ruta_directa_t0(
                    device_id, puerto, "dst", PORTAL_IP, "NORMAL",
                    prio=Config.PRIO_T0_PORTAL
                )
                self.onos.instalar_flow(device_id, flow)
            print(f"    ✓ {nombre} puertos={puertos_acceso}")

        # ── T0: Return flow portal en switches de ACCESO ──────────────────────
        print(f"\n  [T0] Return flow portal ({PORTAL_IP} → hosts):")
        for device_id in access_switches:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])
            self.onos.instalar_flow(device_id,
                self.builder.t0_return_portal_flow(device_id, PORTAL_IP))
            print(f"    ✓ {nombre}")

        # ── T1: Cuarentena VLAN 90 en TODOS + VLAN push en ACCESO ────────────
        print(f"\n  [T1] Cuarentena VLAN 90:")
        for device_id in devices:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])
            self.onos.instalar_flow(device_id,
                self.builder.bloqueo_servidor_cuarentena(device_id, SRV_CURSOS))
            self.onos.instalar_flow(device_id,
                self.builder.bloqueo_servidor_cuarentena(device_id, SRV_NOTAS))
            self.onos.instalar_flow(device_id,
                self.builder.portal_cuarentena_t1(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.drop_default_cuarentena(device_id))
            if device_id in access_switches:
                for puerto in access_switches[device_id]:
                    self.onos.instalar_flow(device_id,
                        self.builder.vlan_push_cuarentena(device_id, puerto))
                print(f"    ✓ {nombre} (VLAN push p{access_switches[device_id]})")
            else:
                print(f"    ✓ {nombre}")

        # ── T2: ALLOW proactivo por VLAN en switches de ACCESO ───────────────
        POLITICAS_T2 = [
            (210, SRV_CURSOS, "Est.Telecom → srv1 cursos"),
            (220, SRV_NOTAS,  "Est.Informatica → srv2 notas"),
            (230, SRV_CURSOS, "Est.Electronica → srv1 cursos"),
            (300, SRV_CURSOS, "Docente → srv1 cursos"),
            (300, SRV_NOTAS,  "Docente → srv2 notas"),
            (400, SRV_CURSOS, "Admin_TI → srv1 cursos"),
            (400, SRV_NOTAS,  "Admin_TI → srv2 notas"),
        ]
        print(f"\n  [T2] Políticas VLAN proactivas (tabla 2):")
        for device_id in access_switches:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])
            for vlan, ip_dst, _ in POLITICAS_T2:
                for tcp_port in [80, 443]:
                    self.onos.instalar_flow(
                        device_id,
                        self.builder.t2_allow_vlan(device_id, vlan, ip_dst, tcp_port)
                    )
            print(f"    ✓ {nombre} ({len(POLITICAS_T2)} políticas × 2 puertos TCP)")

        print(f"\n[M6] {SEP}")
        print("[M6]  Arranque completado")
        print(f"[M6] {SEP}\n")

    # ── Resolución de host (primera llamada de M1) ────────────────────────────

    def resolver_host(self, ip_asignada):
        """
        Primera llamada desde M1 — SOLO consulta ONOS, no instala flows.
        M1 usa el resultado para registrar la sesión en MySQL ANTES de
        llamar a procesar_token_rol().
        """
        return self.onos.get_host_by_ip(ip_asignada)

    # ── Procesamiento de token de M1 (segunda llamada) ───────────────────────

    def procesar_token_rol(self, token):
        """
        Segunda llamada desde M1 — SOLO se invoca después de que M1 ya
        registró la sesión en MySQL (sesiones_activas, ip_mac_binding)
        usando el resultado de resolver_host(). Este orden es deliberado:
        ningún flow se instala para una sesión que no esté ya persistida.

        token = {codigo_pucp, nombre_rol, vlan_id, ip_asignada,
                  mac, switch_dpid, in_port}
        Retorna {"ok": True} si se instalaron los flows correctamente.
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

        # 1. T1 SET_FIELD: VLAN 90 → vlan_id del rol (tabla 1, per-sesión)
        print(f"  [T1] SET_FIELD VLAN {Config.VLAN_CUARENTENA}→{vlan_id}...")
        self._instalar_y_cachear(
            switch_dpid,
            self.builder.set_vlan_post_auth(switch_dpid, mac, in_port, vlan_id),
            mac
        )

        # T0 return flow: respuestas de servidores → host (per-sesión)
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
                    switch_dpid, mac, ip_dst, out_port="NORMAL"
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
            "modulo":    "M6",
            "evento":    "sesion_activada",
            "usuario":   codigo_pucp,
            "rol":       nombre_rol,
            "vlan":      vlan_id,
            "mac":       mac,
            "switch":    switch_dpid,
            "puerto":    in_port,
            "n_flows":   n_total
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
    host = m6.resolver_host(ip_asignada)
    if not host:
        return jsonify({"error": f"host {ip_asignada} no encontrado"}), 404
    return jsonify(host), 200


@app.route("/m6/token_rol", methods=["POST"])
def endpoint_token_rol():
    """
    M1 llama aquí DESPUÉS de registrar la sesión en DB.
    Recibe token completo (incluye mac/switch_dpid/in_port ya resueltos
    por la llamada anterior a /m6/resolver_host) e instala flows en ONOS.
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
    print("  Grupo 2 TEL354")
    print(SEP)
    print(f"  ONOS  : {Config.ONOS_URL}")
    print(f"  OPA   : {Config.OPA_URL}")
    print(f"  MySQL : {Config.MYSQL_HOST}/{Config.MYSQL_DB}  "
          f"[{'connector OK' if MYSQL_OK else 'sin conector'}]")
    print(f"  Puerto: {Config.M6_PORT}  (threaded)")
    print(SEP)

    m6.instalar_cuarentena_arranque()

    print(f"[M6] API escuchando en {Config.M6_HOST}:{Config.M6_PORT}\n")
    app.run(host=Config.M6_HOST, port=Config.M6_PORT,
            debug=False, threaded=True)