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
  T0 (tabla 0): Control/seguridad y entrada TCP controlada al pipeline en bordes.
  T1 (tabla 1): Sesion valida, cuarentena VLAN 90 y marcado de VLAN logica.
  T2 (tabla 2): Permisos normales hibridos; proactivos al login y reactivos si expiran.
  T3 (tabla 3): Excepciones por usuario/sesion bajo demanda.
  T4 (tabla 4): Fallback TCP IPv4 wildcard hacia ONOS/M6 + default drop.

Flujo M1 ↔ M6 (DOS llamadas, en este orden):
  1. POST /m6/resolver_host  {ip_asignada}
     → M6 SOLO consulta ONOS (GET /onos/v1/hosts). No instala flows.
     → Retorna {mac, switch_dpid, in_port}
     → M1 usa esto para registrar la sesión en MySQL (sesiones_activas,
       ip_mac_binding) ANTES de tocar la red.
  2. POST /m6/token_rol {codigo_pucp, nombre_rol, vlan_id, ip_asignada,
                          mac, switch_dpid, in_port}
     → Solo se llama DESPUÉS de que M1 confirmó el registro en MySQL.
     → M6 instala sesion, pipeline base y caminos T2 normales de la vida principal.
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
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from flask import Flask, request, jsonify

try:
    import mysql.connector
    MYSQL_OK = True
except ImportError:
    MYSQL_OK = False


#  Configuración base
class Config:
    @staticmethod
    def env_bool(name, default=False):
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    # ONOS corre en VM-Controller; M6 corre en VM-Auth y lo llama por la red OOB (192.168.201.0/24) — verificado con curl que responde ahí.
    # Configurable via env si se necesita cambiar de red (ej. a la decontrol SDN 192.168.200.0/24) sin tocar código:
    # export ONOS_URL=http://192.168.200.200:8181
    ONOS_URL  = os.environ.get("ONOS_URL", "http://192.168.201.200:8181")
    ONOS_AUTH = (
        os.getenv("ONOS_USERNAME", "onos"),
        os.getenv("ONOS_PASSWORD", "rocks"),
    )

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

    # M4 seguridad
    M4_URL = os.getenv("M4_URL", "http://127.0.0.1:8084")
    SECURITY_TOKEN = os.getenv("SECURITY_TOKEN", "change-me")

    # M6 propio
    M6_HOST = "0.0.0.0"
    M6_PORT = int(os.environ.get("M6_PORT", "8080"))

    # MySQL (fallback cuando OPA no disponible)
    MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
    MYSQL_USER = os.environ.get("MYSQL_USER", "radius")
    MYSQL_PASS = os.getenv("MYSQL_PASSWORD", os.getenv("MYSQL_PASS", "radius_pass"))
    MYSQL_DB   = os.getenv("MYSQL_DATABASE", os.getenv("MYSQL_DB", "radius_db"))

    # Interruptores de seguridad. Todos permanecen apagados por defecto.
    NETWORK_ACTIONS_ENABLED = env_bool.__func__("NETWORK_ACTIONS_ENABLED", False)
    ONOS_WRITES_ENABLED = env_bool.__func__("ONOS_WRITES_ENABLED", False)
    ONOS_READS_ENABLED = env_bool.__func__("ONOS_READS_ENABLED", False)
    OVSDB_ACTIONS_ENABLED = env_bool.__func__("OVSDB_ACTIONS_ENABLED", False)
    M4_AUTOMATIC_ACTIONS_ENABLED = env_bool.__func__(
        "M4_AUTOMATIC_ACTIONS_ENABLED", False
    )
    M4_EVENTS_ENABLED = env_bool.__func__("M4_EVENTS_ENABLED", False)
    M5_LOGGING_ENABLED = env_bool.__func__("M5_LOGGING_ENABLED", False)
    MYSQL_SECURITY_READS_ENABLED = env_bool.__func__(
        "MYSQL_SECURITY_READS_ENABLED", False
    )
    POLICY_QUERIES_ENABLED = env_bool.__func__("POLICY_QUERIES_ENABLED", True)
    STARTUP_FLOW_INSTALL_ENABLED = env_bool.__func__(
        "STARTUP_FLOW_INSTALL_ENABLED", False
    )
    PORTAL_SYNC_INTERVAL = int(os.getenv("PORTAL_SYNC_INTERVAL", "0"))
    REACTIVE_DATA_FLOWS_ENABLED = env_bool.__func__(
        "REACTIVE_DATA_FLOWS_ENABLED", False
    )
    SESSION_EXPIRE_ON_T1_REMOVED = env_bool.__func__(
        "SESSION_EXPIRE_ON_T1_REMOVED", False
    )
    SESSION_IDLE_TIMEOUT = int(os.getenv("SESSION_IDLE_TIMEOUT", "5400"))
    PACKET_IN_DEDUP_WINDOW = float(os.getenv("PACKET_IN_DEDUP_WINDOW", "2"))
    PACKET_IN_RATE_LIMIT_WINDOW = float(os.getenv(
        "PACKET_IN_RATE_LIMIT_WINDOW", "10"
    ))
    PACKET_IN_RATE_LIMIT_MAX_EVENTS = int(os.getenv(
        "PACKET_IN_RATE_LIMIT_MAX_EVENTS", "80"
    ))
    PACKET_IN_RATE_LIMIT_MAX_PORTS = int(os.getenv(
        "PACKET_IN_RATE_LIMIT_MAX_PORTS", "30"
    ))
    PACKET_IN_RATE_LIMIT_MAX_DESTINATIONS = int(os.getenv(
        "PACKET_IN_RATE_LIMIT_MAX_DESTINATIONS", "15"
    ))
    M1_INTERNAL_URL = os.getenv("M1_INTERNAL_URL", "http://127.0.0.1:8282")

    # Resiliencia
    MAX_REINTENTOS = 3
    BACKOFF_BASE   = 1        # segundos, backoff exponencial: 1→2→4
    MAX_COLA_LOGS  = 10000

    # IPs del plano de datos — configurables via variables de entorno.
    # PORTAL_IP es la IP de VM-Auth en la red de datos (192.168.100.x),
    # donde corre web.py (portal cautivo). Ajustar si el slice cambia:
    #   export PORTAL_IP=192.168.100.X SERVER_CURSOS=192.168.100.Y SERVER_NOTAS=192.168.100.Z
    PORTAL_IP     = os.environ.get("PORTAL_IP",     "192.168.100.110")
    SERVER_CURSOS = os.environ.get("SERVER_CURSOS", "192.168.100.101")
    SERVER_NOTAS  = os.environ.get("SERVER_NOTAS",  "192.168.100.102")

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
    PRIO_PORTAL_EDGE_T1 = 40100  # T1: portal cautivo gana al session gate
    PRIO_T2_DATA_ALLOW = 110  # T2: ALLOW real con salida exacta
    PRIO_T3_ALLOW   = 150     # T3: ALLOW excepcional por sesión
    PRIO_T3_DENY    = 200     # T3: DROP por sesión
    PRIO_PIPELINE_MISS = 0     # T2/T3/T4: fallback controlado
    PRIO_T0_TRANSPORT = 1000   # T0: transporte agregado en troncales
    PRIO_T0_USUARIO = 35000   # T0: enforcement por MAC post-auth
    PRIO_T1_SESSION_GATE = 39900  # T1: flow marcador de sesion idle
    PRIO_T0_ATAQUE  = 5000    # T0: bloqueo atacante (instalado por M4)
    DATA_FLOW_TIMEOUT = int(os.getenv("DATA_FLOW_TIMEOUT", "300"))

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

    def t1_portal_edge_forward(self, device_id, out_port,
                               ip_portal=None, session_timeout=900):
        """T1 borde usuario — cualquier host puede ir al portal cautivo."""
        if ip_portal is None:
            ip_portal = Config.PORTAL_IP
        return {
            "priority":    Config.PRIO_PORTAL_EDGE_T1,
            "isPermanent": False,
            "timeout":     int(session_timeout),
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{ip_portal}/32"},
                {"type": "TCP_DST", "tcpPort": 8282},
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": int(out_port)}
            ]}
        }

    def t1_portal_edge_return(self, device_id, in_port, out_port,
                              host_ip, ip_portal=None, session_timeout=900):
        """T1 borde usuario — respuesta del portal vuelve al puerto del host."""
        if ip_portal is None:
            ip_portal = Config.PORTAL_IP
        return {
            "priority":    Config.PRIO_PORTAL_EDGE_T1,
            "isPermanent": False,
            "timeout":     int(session_timeout),
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "IN_PORT", "port": int(in_port)},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_SRC", "ip": f"{ip_portal}/32"},
                {"type": "IPV4_DST", "ip": f"{host_ip}/32"},
                {"type": "TCP_SRC", "tcpPort": 8282},
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": int(out_port)}
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

    def t1_session_gate(self, device_id, mac, in_port, vlan_nuevo, ip_src=None,
                        session_timeout=600):
        """
        T1 marcador de sesion: si expira por idle, M6 puede cerrar la sesion.
        El enforcement real sigue en T2/T3; este flow solo mantiene viva la
        sesion cuando trafico autenticado atraviesa el borde.
        """
        criteria = [
            {"type": "IN_PORT",  "port": int(in_port)},
            {"type": "ETH_SRC",  "mac":  mac},
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IP_PROTO", "protocol": 6},
        ]
        if ip_src:
            criteria.append({"type": "IPV4_SRC", "ip": f"{ip_src}/32"})

        return {
            "priority":    Config.PRIO_T1_SESSION_GATE,
            "isPermanent": False,
            "timeout":     int(session_timeout),
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": criteria},
            "treatment": {"instructions": [
                {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
                {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                 "vlanId": int(vlan_nuevo)},
                {"type": "TABLE", "tableId": 2}
            ]}
        }

    def t0_allow_tcp_path(self, device_id, in_port, src_mac, dst_mac,
                          src_ip, dst_ip, tcp_port, out_port,
                          direction="dst", session_timeout=28800):
        """
        Tabla 0 prio35000 — flow estricto para un salto del camino.
        direction='dst' usa TCP_DST (ida cliente→servidor);
        direction='src' usa TCP_SRC (retorno servidor→cliente).
        """
        tcp_match = (
            {"type": "TCP_SRC", "tcpPort": int(tcp_port)}
            if direction == "src"
            else {"type": "TCP_DST", "tcpPort": int(tcp_port)}
        )
        return {
            "priority":    Config.PRIO_T0_USUARIO,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "IN_PORT",  "port": int(in_port)},
                {"type": "ETH_SRC",  "mac":  src_mac},
                {"type": "ETH_DST",  "mac":  dst_mac},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_SRC", "ip": f"{src_ip}/32"},
                {"type": "IPV4_DST", "ip": f"{dst_ip}/32"},
                tcp_match
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": int(out_port)}
            ]}
        }

    def tcp_path_table_flow(self, device_id, table_id, in_port, src_mac=None,
                            dst_mac=None, src_ip=None, dst_ip=None,
                            tcp_port=None, out_port=None, direction="dst",
                            next_table=None, session_timeout=300,
                            priority=None, set_vlan=None, match_vlan=None,
                            pop_vlan=False):
        """
        Flow estricto para pipeline multi-tabla.
        - Si next_table existe: valida el match y hace goto a la siguiente tabla.
        - Si out_port existe: entrega al puerto exacto del siguiente salto.
        """
        criteria = [{"type": "IN_PORT", "port": int(in_port)}]
        if match_vlan is not None:
            criteria.append({"type": "VLAN_VID", "vlanId": int(match_vlan)})
        if src_mac:
            criteria.append({"type": "ETH_SRC", "mac": src_mac})
        if dst_mac:
            criteria.append({"type": "ETH_DST", "mac": dst_mac})
        criteria.extend([
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IP_PROTO", "protocol": 6},
        ])
        if src_ip:
            criteria.append({"type": "IPV4_SRC", "ip": f"{src_ip}/32"})
        if dst_ip:
            criteria.append({"type": "IPV4_DST", "ip": f"{dst_ip}/32"})
        if tcp_port is not None:
            criteria.append(
                {"type": "TCP_SRC", "tcpPort": int(tcp_port)}
                if direction == "src"
                else {"type": "TCP_DST", "tcpPort": int(tcp_port)}
            )

        instructions = []
        if set_vlan is not None:
            instructions.extend([
                {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
                {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                 "vlanId": int(set_vlan)},
            ])
        if next_table is not None:
            instructions.append({"type": "TABLE", "tableId": int(next_table)})
        elif out_port is not None:
            if pop_vlan:
                instructions.append({"type": "L2MODIFICATION",
                                     "subtype": "VLAN_POP"})
            instructions.append({"type": "OUTPUT", "port": int(out_port)})

        return {
            "priority":    priority or Config.PRIO_T0_USUARIO,
            "isPermanent": False,
            "timeout":     int(session_timeout),
            "deviceId":    device_id,
            "tableId":     int(table_id),
            "selector": {"criteria": criteria},
            "treatment": {"instructions": instructions}
        }

    def tcp_policy_vlan_dst_flow(self, device_id, table_id, vlan_id,
                                 dst_ip, tcp_port, out_port,
                                 session_timeout=300, priority=None):
        """T2 ida agregada: VLAN logica + recurso/puerto -> siguiente salto."""
        return {
            "priority":    priority or Config.PRIO_T2_DATA_ALLOW,
            "isPermanent": False,
            "timeout":     int(session_timeout),
            "deviceId":    device_id,
            "tableId":     int(table_id),
            "selector": {"criteria": [
                {"type": "VLAN_VID", "vlanId": int(vlan_id)},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{dst_ip}/32"},
                {"type": "TCP_DST", "tcpPort": int(tcp_port)},
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": int(out_port)}
            ]}
        }

    def t0_tcp_transport_aggregate(self, device_id, in_port, out_port,
                                   server_ip, direction="dst",
                                   tcp_port=None, session_timeout=300,
                                   priority=None):
        """
        T0 para switches troncales: transporte agregado por IP de servidor.
        No hace match por host/MAC/VLAN para evitar multiplicar flows por sesion.
        """
        criteria = [
            {"type": "IN_PORT", "port": int(in_port)},
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IP_PROTO", "protocol": 6},
        ]
        if direction == "src":
            criteria.append({"type": "IPV4_SRC", "ip": f"{server_ip}/32"})
            if tcp_port is not None:
                criteria.append({"type": "TCP_SRC", "tcpPort": int(tcp_port)})
        else:
            criteria.append({"type": "IPV4_DST", "ip": f"{server_ip}/32"})
            if tcp_port is not None:
                criteria.append({"type": "TCP_DST", "tcpPort": int(tcp_port)})

        return {
            "priority":    priority or Config.PRIO_T0_TRANSPORT,
            "isPermanent": False,
            "timeout":     int(session_timeout),
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": criteria},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": int(out_port)}
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

    def t0_tcp_miss_goto_t1(self, device_id):
        """T0 prio0 — TCP IPv4 elegible entra al pipeline; control queda arriba."""
        return {
            "priority":    Config.PRIO_PIPELINE_MISS,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
            ]},
            "treatment": {"instructions": [
                {"type": "TABLE", "tableId": 1}
            ]}
        }

    def t1_miss_goto_t2(self, device_id):
        """T1 miss — trafico ya marcado o no clasificado sigue a politicas T2."""
        return self._pipeline_goto(device_id, 1, 2)

    def t1_server_response_gate(self, device_id, in_port, server_mac, src_ip,
                                dst_ip, tcp_port, vlan_nuevo,
                                next_table=2, session_timeout=5400):
        """T1 borde servidor — respuesta server->host se marca con VLAN logica."""
        return {
            "priority":    Config.PRIO_T1_SESSION_GATE,
            "isPermanent": False,
            "timeout":     int(session_timeout),
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "IN_PORT",  "port": int(in_port)},
                {"type": "ETH_SRC",  "mac":  server_mac},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_SRC", "ip": f"{src_ip}/32"},
                {"type": "IPV4_DST", "ip": f"{dst_ip}/32"},
                {"type": "TCP_SRC", "tcpPort": int(tcp_port)},
            ]},
            "treatment": {"instructions": [
                {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
                {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                 "vlanId": int(vlan_nuevo)},
                {"type": "TABLE", "tableId": int(next_table)}
            ]}
        }

    def t2_miss_goto_t3(self, device_id):
        """T2 miss — permisos normales no resolvieron → T3."""
        return self._pipeline_goto(device_id, 2, 3)

    def t3_miss_goto_t4(self, device_id):
        """T3 miss — excepciones no resolvieron → T4."""
        return self._pipeline_goto(device_id, 3, 4)

    def t4_default_drop(self, device_id):
        """T4 default — todo fallback no reconocido se descarta."""
        return {
            "priority":    Config.PRIO_PIPELINE_MISS,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     4,
            "selector":    {"criteria": []},
            "treatment":   {"clearDeferred": True, "instructions": []}
        }

    def _pipeline_goto(self, device_id, table_id, next_table):
        return {
            "priority":    Config.PRIO_PIPELINE_MISS,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     int(table_id),
            "selector":    {"criteria": []},
            "treatment":   {"instructions": [
                {"type": "TABLE", "tableId": int(next_table)}
            ]}
        }


    # ── T0: Bloqueo atacante (tabla 0) ───────────────────────────────────────

    def t0_bloqueo_ataque(
        self,
        device_id,
        ip_atacante=None,
        mac_atacante=None,
        in_port=None,
        ttl=600,
        prio=None,
    ):
        """T0 de ataque: combina IP, MAC y puerto cuando están disponibles."""
        if prio is None:
            prio = Config.PRIO_T0_ATAQUE
        criteria = [{"type": "ETH_TYPE", "ethType": "0x0800"}]
        if in_port is not None:
            criteria.append({"type": "IN_PORT", "port": int(in_port)})
        if mac_atacante:
            criteria.append({"type": "ETH_SRC", "mac": mac_atacante})
        if ip_atacante:
            criteria.append({"type": "IPV4_SRC", "ip": f"{ip_atacante}/32"})
        return {
            "priority":    prio,
            "isPermanent": False,
            "timeout":     ttl,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": criteria},
            "treatment": {"clearDeferred": True, "instructions": []}
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

# ─── Log asíncrono hacia M5 ───────────────────────────────────────────────────
class M5Logger:

    def __init__(self):
        self.cola = deque(maxlen=Config.MAX_COLA_LOGS)

    def log(self, evento):
        """Envía a M5 en thread daemon para no bloquear la respuesta a M1."""
        if not Config.M5_LOGGING_ENABLED:
            self.cola.append({**evento, "status": "SIMULATED"})
            return
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

        if not Config.POLICY_QUERIES_ENABLED:
            print(
                f"  [PolicyEngine] SIMULATED: políticas hardcoded para VLAN {vlan_id}"
            )
            return self._hardcoded(vlan_id)

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
            tabla = str(p.get("tabla") or "T2").upper()
            if tabla not in ("T2", "T3"):
                tabla = "T2"
            expires_at = p.get("expires_at")
            ip_raw  = (
                recurso.get("ip_dst")
                or recurso.get("ip_srv")
                or recurso.get("ip_servidor")
                or ""
            )
            puerto  = recurso.get("puerto")
            if not ip_raw or puerto is None:
                continue
            ip_dst = self._normalizar_ip(ip_raw)
            allow_map.setdefault((ip_dst, tabla, expires_at), set()).add(int(puerto))

        permisos = [
            {
                "ip_dst": ip,
                "puertos": sorted(ps),
                "tabla": tabla,
                "expires_at": expires_at,
            }
            for (ip, tabla, expires_at), ps in allow_map.items()
        ]

        all_servidores  = {Config.SERVER_CURSOS, Config.SERVER_NOTAS}
        allowed_ips = {ip for ip, _, _ in allow_map.keys()}
        denied_ips = all_servidores - allowed_ips
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
                SELECT srv.ip_servidor AS ip_dst, rec.puerto
                FROM politicas_rbac p
                JOIN recursos rec      ON p.id_recurso  = rec.id_recurso
                JOIN servidores srv    ON rec.id_servidor = srv.id_servidor
                JOIN roles_facultad rf ON p.id_rol      = rf.id_rol
                WHERE rf.nombre_rol = %s
                  AND p.activo = 1
                  AND rec.protocolo = 'TCP'
                ORDER BY srv.ip_servidor, rec.puerto
            """, (nombre_rol,))
            rows = cur.fetchall()
            conn.close()

            if not rows:
                return None

            allow_map = {}
            for row in rows:
                ip_raw = row["ip_dst"]
                ip     = self._normalizar_ip(ip_raw)
                puerto = int(row["puerto"])
                allow_map.setdefault(ip, []).append(puerto)

            print(f"  [PolicyEngine] MySQL — {nombre_rol}: "
                  f"{len(allow_map)} destinos ALLOW")
            return {
                "permisos":    [{"ip_dst": ip, "puertos": sorted(set(ps))}
                                for ip, ps in allow_map.items()],
                "denegaciones":[]
            }
        except Exception as e:
            print(f"  [PolicyEngine] MySQL error: {e}")
            return None

    def _hardcoded(self, vlan_id):
        """Políticas por defecto — espejo de la arquitectura de acceso PUCP."""
        cursos, notas = Config.SERVER_CURSOS, Config.SERVER_NOTAS
        if vlan_id == 210:                # Telecom
            return {
                "permisos":    [{"ip_dst": cursos, "puertos": [8001, 1443]}],
                "denegaciones":[]
            }
        if vlan_id == 220:                # Informatica
            return {
                "permisos": [
                    {"ip_dst": cursos, "puertos": [8002, 2443]},
                    {"ip_dst": notas,  "puertos": [8080]},
                ],
                "denegaciones": []
            }
        if vlan_id == 230:                # Electronica
            return {
                "permisos":    [{"ip_dst": cursos, "puertos": [8003, 3443]}],
                "denegaciones":[]
            }
        elif vlan_id in (300, 400):        # Docentes y Admin — cursos + notas
            return {
                "permisos": [
                    {"ip_dst": cursos, "puertos": [8001, 1443, 8002, 2443, 8003, 3443]},
                    {"ip_dst": notas,  "puertos": [8080]}
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
                    {"ip_dst": cursos, "puertos": [8001, 1443, 8002, 2443, 8003, 3443]},
                    {"ip_dst": notas,  "puertos": [8080]}
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
        if not (
            Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
        ):
            flow_id = f"simulated-{uuid4()}"
            print(
                f"    [ONOS] SIMULATED T{flow_entry.get('tableId', '?')} "
                f"device={device_id} id={flow_id}"
            )
            return flow_id

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
        if not (
            Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
        ):
            print(f"  [ONOS] SIMULATED delete {flow_id} from {device_id}")
            return True
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

    def flow_exists(self, device_id, flow_id):
        """ONOS is the source of truth for reusable/cacheable flows."""
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return True
        if not flow_id:
            return False
        endpoint = f"{self.url}/onos/v1/flows/{device_id}"
        try:
            resp = requests.get(endpoint, auth=self.auth, timeout=3)
            if resp.status_code == 200:
                flow_id = str(flow_id)
                for flow in resp.json().get("flows", []):
                    if str(flow.get("id")) == flow_id:
                        return flow.get("state") == "ADDED"
                return False
            print(f"  [ONOS] No se pudo validar flow {flow_id}: "
                  f"HTTP {resp.status_code}")
            return False
        except Exception as e:
            print(f"  [ONOS] Error validando flow {flow_id}: {e}")
            return False

    def get_host_by_ip(self, ip_asignada):
        """
        Busca host en ONOS por IP → {mac, switch_dpid, in_port}.
        ONOS aprende los hosts dinámicamente vía DHCP/ARP.
        """
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return None
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

    def get_hosts(self):
        """Devuelve la lista cruda de hosts aprendidos por ONOS."""
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return []
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/hosts", auth=self.auth, timeout=3
            )
            if resp.status_code == 200:
                return resp.json().get("hosts", [])
            print(f"  [ONOS] Error GET /hosts: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [ONOS] Error GET /hosts: {e}")
        return []

    def get_links(self):
        """Devuelve la lista cruda de enlaces inter-switch vistos por ONOS."""
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return []
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/links", auth=self.auth, timeout=3
            )
            if resp.status_code == 200:
                return resp.json().get("links", [])
            print(f"  [ONOS] Error GET /links: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [ONOS] Error GET /links: {e}")
        return []

    def calcular_pasos(self, src_switch, src_port, dst_switch, dst_port):
        """
        Calcula pasos hop-by-hop usando /onos/v1/links.
        Retorna [(device_id, in_port, out_port), ...].
        """
        if src_switch == dst_switch:
            return [(src_switch, int(src_port), int(dst_port))]

        links = self.get_links()
        adjacency = defaultdict(list)
        link_by_pair = {}
        for link in links:
            src = link.get("src", {})
            dst = link.get("dst", {})
            src_dev, dst_dev = src.get("device"), dst.get("device")
            src_p, dst_p = src.get("port"), dst.get("port")
            if not (src_dev and dst_dev and str(src_p).isdigit()
                    and str(dst_p).isdigit()):
                continue
            adjacency[src_dev].append(dst_dev)
            link_by_pair.setdefault((src_dev, dst_dev), (int(src_p), int(dst_p)))

        queue = deque([(src_switch, [src_switch])])
        visited = {src_switch}
        path = None
        while queue:
            current, current_path = queue.popleft()
            for neighbor in sorted(adjacency.get(current, [])):
                if neighbor in visited:
                    continue
                next_path = current_path + [neighbor]
                if neighbor == dst_switch:
                    path = next_path
                    queue.clear()
                    break
                visited.add(neighbor)
                queue.append((neighbor, next_path))

        if not path:
            print(f"  [ONOS] Sin camino {src_switch} → {dst_switch}")
            return []

        steps = []
        in_port = int(src_port)
        for current, nxt in zip(path, path[1:]):
            link_ports = link_by_pair.get((current, nxt))
            if not link_ports:
                print(f"  [ONOS] Link incompleto {current} → {nxt}")
                return []
            out_port, next_in_port = link_ports
            steps.append((current, in_port, out_port))
            in_port = next_in_port
        steps.append((dst_switch, in_port, int(dst_port)))
        return steps

    def get_devices(self):
        """Lista de deviceIds disponibles en ONOS."""
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return [Config.SW1, Config.SW2, Config.SW3]
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
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return [2, 3] if device_id == Config.SW2 else []
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
        self.flows_portal = {}      # {mac: [(device_id, flow_id), ...]}
        self.portal_ips = {}        # {mac: ip_asignada}
        self.flows_t0_shared = {}   # {policy_key: (device_id, flow_id, expires_at)}
        self.session_gates = {}     # {mac: (device_id, flow_id, expires_at)}
        self.pipeline_fallback_flows = {}  # {device_id: [(device_id, flow_id), ...]}
        self.mitigaciones = {}
        self._security_windows = defaultdict(deque)
        self._packet_in_seen = {}

    def _flow_debug(self, flow_entry):
        selector = flow_entry.get("selector", {}).get("criteria", [])
        treatment = flow_entry.get("treatment", {}).get("instructions", [])
        return {
            "device": flow_entry.get("deviceId"),
            "table": flow_entry.get("tableId"),
            "prio": flow_entry.get("priority"),
            "timeout": flow_entry.get("timeout"),
            "selector": selector,
            "treatment": treatment,
        }

    def _trace_flow(self, label, flow_entry, flow_id=None, reused=False):
        detail = self._flow_debug(flow_entry)
        estado = "REUSED" if reused else ("ADDED" if flow_id else "FAILED")
        print(
            f"    [TRACE-FLOW] {label} {estado} id={flow_id} "
            f"dev={detail['device']} T{detail['table']} "
            f"prio={detail['prio']} idle={detail['timeout']}"
        )
        print(f"      selector={detail['selector']}")
        print(f"      treatment={detail['treatment']}")

    def _instalar_y_cachear(self, device_id, flow_entry, mac=None):
        """Instala un flow y lo registra en el cache de sesión si se provee mac."""
        fid = self.onos.instalar_flow(device_id, flow_entry)
        if fid and mac is not None:
            mac = mac.lower()
            with self._lock:
                self.flows_por_sesion.setdefault(mac, [])
                self.flows_por_sesion[mac].append((device_id, fid))
        return fid

    def _instalar_t0_compartido(self, key, device_id, flow_entry, ttl):
        """
        Instala o reutiliza un flow T0 compartido para troncales/core.
        No se borra en logout: expira por idle timeout y puede servir a otros
        usuarios que compartan el mismo tramo y recurso.
        """
        now = time.time()
        with self._lock:
            cached = self.flows_t0_shared.get(key)
            if cached and self.onos.flow_exists(cached[0], cached[1]):
                self.flows_t0_shared[key] = (
                    cached[0], cached[1], now + int(ttl)
                )
                return cached[1], True
            if cached:
                self.flows_t0_shared.pop(key, None)

        if cached:
            self.onos.eliminar_flow(cached[0], cached[1])

        fid = self.onos.instalar_flow(device_id, flow_entry)
        if fid:
            with self._lock:
                self.flows_t0_shared[key] = (device_id, fid, now + int(ttl))
        return fid, False

    def _instalar_session_gate(self, mac, switch_dpid, in_port, vlan_id,
                               ip_src=None):
        """Instala el marcador T1 que representa sesion viva por idle timeout."""
        mac_key = mac.lower()
        now = time.time()
        with self._lock:
            cached = self.session_gates.get(mac_key)
            if cached and self.onos.flow_exists(cached[0], cached[1]):
                self.session_gates[mac_key] = (
                    cached[0],
                    cached[1],
                    now + Config.SESSION_IDLE_TIMEOUT,
                )
                return cached[1]
            if cached:
                self.session_gates.pop(mac_key, None)
        flow = self.builder.t1_session_gate(
            switch_dpid,
            mac,
            in_port,
            vlan_id,
            ip_src=ip_src,
            session_timeout=Config.SESSION_IDLE_TIMEOUT,
        )
        fid = self._instalar_y_cachear(switch_dpid, flow, mac)
        if fid:
            with self._lock:
                self.session_gates[mac_key] = (
                    switch_dpid,
                    fid,
                    now + Config.SESSION_IDLE_TIMEOUT,
                )
        return fid

    def _asegurar_pipeline_fallback_en_borde(self, switch_dpid):
        """Instala T0→T1→T2→T3→T4 base una sola vez por switch de borde."""
        with self._lock:
            cached = list(self.pipeline_fallback_flows.get(switch_dpid, []))
        if self._flows_existen_en_onos(cached):
            return 0
        if cached:
            for device_id, flow_id in cached:
                self.onos.eliminar_flow(device_id, flow_id)
            with self._lock:
                self.pipeline_fallback_flows.pop(switch_dpid, None)
        with self._lock:
            if self.pipeline_fallback_flows.get(switch_dpid):
                return 0
        flows = [
            self.builder.t0_tcp_miss_goto_t1(switch_dpid),
            self.builder.t1_miss_goto_t2(switch_dpid),
            self.builder.t2_miss_goto_t3(switch_dpid),
            self.builder.t3_miss_goto_t4(switch_dpid),
            self.builder.t4_default_drop(switch_dpid),
        ]
        instalados = 0
        flow_ids = []
        for flow in flows:
            fid = self.onos.instalar_flow(switch_dpid, flow)
            if fid:
                instalados += 1
                flow_ids.append((switch_dpid, fid))
        if instalados == len(flows):
            with self._lock:
                self.pipeline_fallback_flows[switch_dpid] = flow_ids
        return instalados

    def _es_packet_in_duplicado(self, data):
        """Deduplicacion corta para evitar tormentas de Packet-In repetidos."""
        window = Config.PACKET_IN_DEDUP_WINDOW
        if window <= 0:
            return False
        key = (
            str(data.get("src_mac", "")).lower(),
            data.get("src_ip"),
            data.get("dst_ip"),
            int(data.get("dst_port") or 0),
            data.get("switch_dpid"),
            int(data.get("in_port") or 0),
        )
        now = time.time()
        with self._lock:
            last = self._packet_in_seen.get(key)
            if last and now - last < window:
                return True
            self._packet_in_seen[key] = now
            stale = [
                item_key
                for item_key, ts in self._packet_in_seen.items()
                if now - ts > max(window * 10, 30)
            ]
            for item_key in stale:
                self._packet_in_seen.pop(item_key, None)
        return False

    def _packet_in_excede_rate_limit(self, data):
        """
        Limita bursts antes de consultar politicas. Esto evita que un scan TCP
        convierta T4 wildcard en muchas consultas OPA/MySQL por segundo.
        """
        window = Config.PACKET_IN_RATE_LIMIT_WINDOW
        if window <= 0:
            return False, {}
        now = time.time()
        key = (
            data.get("src_mac"),
            data.get("src_ip"),
            data.get("switch_dpid"),
            data.get("in_port"),
        )
        bucket = self._security_windows[key]
        bucket.append((now, data.get("dst_ip"), data.get("dst_port")))
        while bucket and now - bucket[0][0] > window:
            bucket.popleft()

        destinations = {item[1] for item in bucket if item[1]}
        ports = {item[2] for item in bucket if item[2] is not None}
        exceeded = (
            len(bucket) >= Config.PACKET_IN_RATE_LIMIT_MAX_EVENTS
            or len(ports) >= Config.PACKET_IN_RATE_LIMIT_MAX_PORTS
            or len(destinations) >= Config.PACKET_IN_RATE_LIMIT_MAX_DESTINATIONS
        )
        return exceeded, {
            "events": len(bucket),
            "unique_destinations": len(destinations),
            "unique_ports": len(ports),
            "window_seconds": window,
        }

    def _ttl_permiso(self, session_timeout, expires_at=None):
        """Calcula TTL seguro para flows de datos y capea por expiración OPA."""
        ttl = min(int(session_timeout or Config.DATA_FLOW_TIMEOUT),
                  Config.DATA_FLOW_TIMEOUT)
        if not expires_at:
            return ttl
        try:
            exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            remaining = int((exp - datetime.now(timezone.utc)).total_seconds())
            if remaining <= 0:
                return 0
            return max(1, min(ttl, remaining))
        except Exception:
            return ttl

    def _instalar_camino_tcp(self, mac_sesion, src_host, dst_host,
                             src_ip, dst_ip, tcp_port, vlan_id,
                             session_timeout, target_table="T2",
                             expires_at=None):
        """
        Instala ida y retorno para un permiso TCP usando rutas explicitas.
        Pipeline edge-policy:
          Borde usuario: T0/T1 solo clasifican; T2/T3 autorizan ida y vuelta.
          Troncales: T0 transporta por IP de servidor, agregado por tramo.
          Borde servidor: T2/T3 entrega al servidor; T1 marca la respuesta.
        Usa solo salidas exactas o transiciones de tabla.
        """
        target_table_id = 3 if str(target_table).upper() == "T3" else 2
        target_label = "T3" if target_table_id == 3 else "T2"
        target_prio = (
            Config.PRIO_T3_ALLOW
            if target_table_id == 3 else Config.PRIO_T2_DATA_ALLOW
        )
        data_timeout = self._ttl_permiso(session_timeout, expires_at)
        if data_timeout <= 0:
            print(f"    ! {dst_ip}:{tcp_port} — permiso expirado; se omite")
            return 0
        ida = self.onos.calcular_pasos(
            src_host["switch_dpid"], src_host["in_port"],
            dst_host["switch_dpid"], dst_host["in_port"]
        )
        retorno = self.onos.calcular_pasos(
            dst_host["switch_dpid"], dst_host["in_port"],
            src_host["switch_dpid"], src_host["in_port"]
        )
        if not ida or not retorno:
            return 0

        print(
            f"  [TRACE-PATH] {src_ip}/{src_host['mac']} -> "
            f"{dst_ip}/{dst_host['mac']} tcp={tcp_port} "
            f"tabla={target_table} vlan={vlan_id} ttl={data_timeout}"
        )
        print(f"    ida={ida}")
        print(f"    retorno={retorno}")

        instalados = 0
        self._asegurar_pipeline_fallback_en_borde(src_host["switch_dpid"])
        self._asegurar_pipeline_fallback_en_borde(dst_host["switch_dpid"])

        for idx, (device_id, in_port, out_port) in enumerate(ida):
            es_borde_usuario = idx == 0
            es_borde_servidor = idx == len(ida) - 1

            if es_borde_usuario and target_table_id == 2:
                flow = self.builder.tcp_policy_vlan_dst_flow(
                    device_id, target_table_id, vlan_id,
                    dst_ip=dst_ip,
                    tcp_port=tcp_port,
                    out_port=out_port,
                    session_timeout=data_timeout,
                    priority=target_prio,
                )
                key = (
                    "t2-edge-fwd-vlan-dst", device_id, int(vlan_id),
                    dst_ip, int(tcp_port), int(out_port)
                )
                fid, reused = self._instalar_t0_compartido(
                    key, device_id, flow, data_timeout
                )
                self._trace_flow("IDA-BORDE-T2-AGG", flow, fid, reused)
                if fid:
                    instalados += 1
                continue

            if es_borde_usuario or es_borde_servidor:
                flow = self.builder.tcp_path_table_flow(
                    device_id, target_table_id, in_port,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    tcp_port=tcp_port,
                    out_port=out_port,
                    direction="dst",
                    session_timeout=data_timeout,
                    priority=target_prio,
                    match_vlan=vlan_id,
                    pop_vlan=es_borde_servidor,
                )
                fid = self._instalar_y_cachear(device_id, flow, mac_sesion)
                self._trace_flow(f"IDA-BORDE-{target_label}", flow, fid)
                if fid:
                    instalados += 1
                continue

            flow = self.builder.t0_tcp_transport_aggregate(
                device_id, in_port, out_port,
                server_ip=dst_ip,
                direction="dst",
                session_timeout=data_timeout,
            )
            key = (
                "fwd-core-server", device_id, int(in_port), int(out_port),
                dst_ip
            )
            fid, reused = self._instalar_t0_compartido(
                key, device_id, flow, data_timeout
            )
            self._trace_flow("IDA-TRONCAL-T0-SERVER", flow, fid, reused)
            if fid:
                instalados += 1

        for idx, (device_id, in_port, out_port) in enumerate(retorno):
            es_borde_servidor_retorno = idx == 0
            es_borde_usuario_retorno = idx == len(retorno) - 1

            if es_borde_servidor_retorno:
                gate = self.builder.t1_server_response_gate(
                    device_id, in_port,
                    dst_host["mac"], dst_ip, src_ip, tcp_port, vlan_id,
                    next_table=target_table_id,
                    session_timeout=Config.SESSION_IDLE_TIMEOUT,
                )
                fid_gate = self._instalar_y_cachear(device_id, gate, mac_sesion)
                self._trace_flow(f"RET-SRV-T1-{target_label}", gate, fid_gate)
                if fid_gate:
                    instalados += 1

            if es_borde_servidor_retorno or es_borde_usuario_retorno:
                flow = self.builder.tcp_path_table_flow(
                    device_id, target_table_id, in_port,
                    src_ip=dst_ip,
                    dst_ip=src_ip,
                    tcp_port=tcp_port,
                    out_port=out_port,
                    direction="src",
                    session_timeout=data_timeout,
                    priority=target_prio,
                    match_vlan=vlan_id,
                    pop_vlan=es_borde_usuario_retorno,
                )
                fid = self._instalar_y_cachear(device_id, flow, mac_sesion)
                self._trace_flow(f"RET-BORDE-{target_label}", flow, fid)
                if fid:
                    instalados += 1
                continue

            flow = self.builder.t0_tcp_transport_aggregate(
                device_id, in_port, out_port,
                server_ip=dst_ip,
                direction="src",
                session_timeout=data_timeout,
            )
            key = (
                "ret-core-server", device_id, int(in_port), int(out_port),
                dst_ip
            )
            fid, reused = self._instalar_t0_compartido(
                key, device_id, flow, data_timeout
            )
            self._trace_flow("RET-TRONCAL-T0-SERVER", flow, fid, reused)
            if fid:
                instalados += 1

        return instalados

    def _eliminar_flows_portal(self, mac):
        mac = mac.lower()
        with self._lock:
            flows = self.flows_portal.pop(mac, [])
            self.portal_ips.pop(mac, None)
        for device_id, flow_id in flows:
            self.onos.eliminar_flow(device_id, flow_id)
        return len(flows)

    def _asegurar_portal_ida_borde(self, host, portal_host, ttl=900):
        """Asegura la ida generica T1 host-edge -> portal."""
        ida = self.onos.calcular_pasos(
            host["switch_dpid"], host["in_port"],
            portal_host["switch_dpid"], portal_host["in_port"]
        )
        if not ida:
            return None
        device_id, _in_port, out_port = ida[0]
        key = (
            "portal-edge-t1-dst", device_id, int(out_port),
            Config.PORTAL_IP, 8282
        )
        with self._lock:
            cached = self.flows_t0_shared.get(key)
        if cached and self.onos.flow_exists(cached[0], cached[1]):
            return cached[1]
        if cached:
            with self._lock:
                self.flows_t0_shared.pop(key, None)

        flow = self.builder.t1_portal_edge_forward(
            device_id, out_port,
            ip_portal=Config.PORTAL_IP,
            session_timeout=ttl,
        )
        fid = self.onos.instalar_flow(device_id, flow)
        if fid:
            with self._lock:
                self.flows_t0_shared[key] = (
                    device_id, fid, time.time() + int(ttl)
                )
            print(f"    [PORTAL] T1 ida generica {device_id} -> {out_port}")
        return fid

    def _instalar_camino_portal(self, host, portal_host, ip_host, ttl=900):
        """
        Instala cuarentena minima host<->portal TCP/8282. Estos flows no son
        de sesion autenticada. Solo el borde usuario queda por host; el tramo
        troncal/portal se agrega para no multiplicar flows por usuario.
        """
        mac = host["mac"].lower()
        self._eliminar_flows_portal(mac)

        ida = self.onos.calcular_pasos(
            host["switch_dpid"], host["in_port"],
            portal_host["switch_dpid"], portal_host["in_port"]
        )
        retorno = self.onos.calcular_pasos(
            portal_host["switch_dpid"], portal_host["in_port"],
            host["switch_dpid"], host["in_port"]
        )
        if not ida or not retorno:
            return 0

        instalados = []
        for idx, (device_id, in_port, out_port) in enumerate(ida):
            es_borde_usuario = idx == 0
            if es_borde_usuario:
                self._asegurar_portal_ida_borde(host, portal_host, ttl)
                continue

            flow = self.builder.t0_tcp_transport_aggregate(
                device_id, in_port, out_port,
                server_ip=Config.PORTAL_IP,
                direction="dst",
                tcp_port=8282,
                session_timeout=ttl,
            )
            key = (
                "portal-core-dst", device_id, int(in_port), int(out_port),
                Config.PORTAL_IP, 8282
            )
            self._instalar_t0_compartido(key, device_id, flow, ttl)

        for idx, (device_id, in_port, out_port) in enumerate(retorno):
            es_borde_usuario = idx == len(retorno) - 1
            if es_borde_usuario:
                fid = self.onos.instalar_flow(
                    device_id,
                    self.builder.t1_portal_edge_return(
                        device_id, in_port, out_port, ip_host,
                        ip_portal=Config.PORTAL_IP,
                        session_timeout=ttl,
                    )
                )
                if fid:
                    instalados.append((device_id, fid))
                continue

            flow = self.builder.t0_tcp_transport_aggregate(
                device_id, in_port, out_port,
                server_ip=Config.PORTAL_IP,
                direction="src",
                tcp_port=8282,
                session_timeout=ttl,
            )
            key = (
                "portal-core-src", device_id, int(in_port), int(out_port),
                Config.PORTAL_IP, 8282
            )
            self._instalar_t0_compartido(key, device_id, flow, ttl)

        if instalados:
            with self._lock:
                self.flows_portal[mac] = instalados
                self.portal_ips[mac] = ip_host
        return len(instalados)

    def _flows_existen_en_onos(self, flows):
        return bool(flows) and all(
            self.onos.flow_exists(device_id, flow_id)
            for device_id, flow_id in flows
        )

    def sincronizar_portal_cuarentena(self, force=False):
        """
        Lee hosts ONOS y prepara acceso minimo al portal para clientes de datos.
        No abre recursos y excluye servidores/portal/DHCP.
        """
        portal = self.onos.get_host_by_ip(Config.PORTAL_IP)
        if not portal:
            return {"ok": False, "error": "portal_no_aprendido_en_onos"}

        excluidas = {
            Config.PORTAL_IP,
            Config.SERVER_CURSOS,
            Config.SERVER_NOTAS,
            "192.168.100.254",
        }
        resultados = []
        vistos = set()
        for h in self.onos.get_hosts():
            locs = h.get("locations") or []
            if not locs:
                continue
            mac = h.get("mac")
            if not mac or mac.upper() == portal["mac"].upper():
                continue
            for ip in h.get("ipAddresses", []):
                if not ip.startswith("192.168.100.") or ip in excluidas:
                    continue
                key = (mac.lower(), ip)
                if key in vistos:
                    continue
                vistos.add(key)
                mac_key = mac.lower()
                with self._lock:
                    cached_flows = list(self.flows_portal.get(mac_key, []))
                    misma_ip = self.portal_ips.get(mac_key) == ip
                ya_instalado = (
                    not force and misma_ip
                    and self._flows_existen_en_onos(cached_flows)
                )
                host = {
                    "mac": mac,
                    "switch_dpid": locs[0]["elementId"],
                    "in_port": int(locs[0]["port"]),
                }
                n = (
                    len(cached_flows)
                    if ya_instalado
                    else self._instalar_camino_portal(host, portal, ip)
                )
                if ya_instalado:
                    self._asegurar_portal_ida_borde(host, portal)
                resultados.append({
                    "ip": ip,
                    "mac": mac,
                    "switch_dpid": host["switch_dpid"],
                    "in_port": host["in_port"],
                    "flows": n,
                    "reused": ya_instalado,
                })
                break
        return {"ok": True, "hosts": resultados, "total": len(resultados)}

    def iniciar_sincronizador_portal(self):
        intervalo = Config.PORTAL_SYNC_INTERVAL
        if intervalo <= 0:
            print("[M6] Portal sync periódico deshabilitado")
            return

        def loop():
            print(f"[M6] Portal sync periódico cada {intervalo}s")
            while True:
                try:
                    self.sincronizar_portal_cuarentena()
                except Exception as exc:
                    print(f"[M6] portal_sync error: {exc}")
                time.sleep(intervalo)

        threading.Thread(target=loop, daemon=True).start()

    def _buscar_sesion(self, src_ip, src_mac, switch_dpid, in_port, data):
        """Resuelve la sesión sin conectar a MySQL salvo habilitación explícita."""
        if Config.MYSQL_SECURITY_READS_ENABLED and MYSQL_OK:
            try:
                conn = mysql.connector.connect(
                    host=Config.MYSQL_HOST,
                    user=Config.MYSQL_USER,
                    password=Config.MYSQL_PASS,
                    database=Config.MYSQL_DB,
                    connection_timeout=3,
                )
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    """
                    SELECT s.*, u.codigo_pucp
                    FROM sesiones_activas s
                    JOIN usuarios u ON u.id_usuario=s.id_usuario
                    WHERE s.ip_asignada=%s
                      AND LOWER(s.mac_address)=LOWER(%s)
                      AND s.switch_dpid=%s
                      AND s.in_port=%s
                      AND s.estado='ACTIVA'
                    LIMIT 1
                    """,
                    (src_ip, src_mac, switch_dpid, in_port),
                )
                session = cur.fetchone()
                cur.close()
                conn.close()
                return session
            except Exception as exc:
                print(f"[M6] No se pudo consultar sesión: {exc}")
                return None

        if not data.get("simulated_session"):
            return None
        return {
            "codigo_pucp": data.get("codigo_pucp", "SIMULATED"),
            "nombre_rol": data.get("nombre_rol", "Estudiante_Telecom"),
            "ip_asignada": src_ip,
            "mac_address": src_mac,
            "switch_dpid": switch_dpid,
            "in_port": int(in_port),
        }

    def _evaluar_acceso_reactivo(self, session, data):
        vlan_id = int(
            data.get("vlan_id")
            or Config.VLANS_POR_ROL.get(session.get("nombre_rol"), 0)
        )
        payload = {
            "input": {
                "codigo_pucp": session.get("codigo_pucp", ""),
                "rol": session.get("nombre_rol", ""),
                "vlan_id": vlan_id,
                "ip_asignada": session.get("ip_asignada"),
                "mac_address": session.get("mac_address"),
                "switch_dpid": session.get("switch_dpid"),
            }
        }
        policies = (
            self.policies.get_policies(payload)
            if Config.POLICY_QUERIES_ENABLED
            else self.policies._hardcoded(vlan_id)
        )
        dst_ip = Config.get_ip_mapping_m2().get(
            data.get("dst_ip"), data.get("dst_ip")
        )
        dst_port = int(data.get("dst_port", 0))
        for permission in policies.get("permisos", []):
            if permission["ip_dst"] == dst_ip and (
                not permission.get("puertos")
                or dst_port in permission["puertos"]
            ):
                return True, policies, permission
        return False, policies, None

    def _registrar_evento_denegado(self, data, event_type="policy_denial"):
        now = time.time()
        key = (
            data.get("src_mac"),
            data.get("src_ip"),
            data.get("switch_dpid"),
            data.get("in_port"),
        )
        bucket = self._security_windows[key]
        bucket.append(
            (
                now,
                data.get("dst_ip"),
                data.get("dst_port"),
            )
        )
        while bucket and now - bucket[0][0] > 10:
            bucket.popleft()
        destinations = {item[1] for item in bucket if item[1]}
        ports = {item[2] for item in bucket if item[2] is not None}
        if len(bucket) >= 50 or len(ports) >= 20 or len(destinations) >= 10:
            event_type = "policy_denial_burst"

        event = {
            "idempotency_key": str(uuid4()),
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": data.get("src_ip"),
            "src_mac": data.get("src_mac"),
            "dst_ip": data.get("dst_ip"),
            "dst_port": data.get("dst_port"),
            "protocol": data.get("protocol"),
            "switch_dpid": data.get("switch_dpid"),
            "in_port": data.get("in_port"),
            "username": data.get("codigo_pucp"),
            "role": data.get("nombre_rol"),
            "severity": 80 if event_type == "invalid_ip_mac_binding" else 0,
            "metadata": {
                "denials": len(bucket),
                "unique_destinations": len(destinations),
                "unique_ports": len(ports),
                "window_seconds": 10,
            },
        }
        if Config.M4_EVENTS_ENABLED and Config.NETWORK_ACTIONS_ENABLED:
            threading.Thread(
                target=self._enviar_evento_m4,
                args=(event,),
                daemon=True,
            ).start()
        return event

    def _enviar_evento_m4(self, event):
        try:
            requests.post(
                f"{Config.M4_URL}/m4/events/m6",
                json=event,
                headers={"X-Security-Token": Config.SECURITY_TOKEN},
                timeout=3,
            ).raise_for_status()
        except Exception as exc:
            print(f"[M6] No se pudo enviar evento a M4: {exc}")

    def procesar_packet_in(self, data):
        required = (
            "src_ip",
            "src_mac",
            "dst_ip",
            "dst_port",
            "switch_dpid",
            "in_port",
        )
        missing = [field for field in required if data.get(field) is None]
        if missing:
            return {"ok": False, "error": f"faltan campos: {', '.join(missing)}"}
        print(
            "\n[M6][PACKET-IN] "
            f"{data.get('src_ip')} {data.get('src_mac')} -> "
            f"{data.get('dst_ip')} {data.get('dst_mac', '?')}:"
            f"{data.get('dst_port')} "
            f"sw={data.get('switch_dpid')} in_port={data.get('in_port')}"
        )
        if self._es_packet_in_duplicado(data):
            print("[M6][PACKET-IN] duplicado dentro de ventana; se difiere")
            return {
                "ok": True,
                "decision": "DEFER",
                "install_flow": False,
                "reason": "duplicate_packet_in",
            }

        session = self._buscar_sesion(
            data["src_ip"],
            data["src_mac"],
            data["switch_dpid"],
            int(data["in_port"]),
            data,
        )
        if not session:
            print("[M6][PACKET-IN] DENY: no hay sesion activa/binding valido")
            event = self._registrar_evento_denegado(
                data,
                event_type="invalid_ip_mac_binding",
            )
            return {
                "ok": True,
                "decision": "DENY",
                "install_flow": False,
                "reason": "invalid_ip_mac_binding",
                "security_event": event,
            }

        merged = {
            **data,
            "codigo_pucp": session.get("codigo_pucp"),
            "nombre_rol": session.get("nombre_rol"),
        }
        burst, burst_meta = self._packet_in_excede_rate_limit(merged)
        if burst:
            print(
                "[M6][PACKET-IN] BURST rate-limited antes de politica "
                f"usuario={session.get('codigo_pucp')} meta={burst_meta}"
            )
            event = self._registrar_evento_denegado(
                merged,
                event_type="policy_denial_burst",
            )
            event["metadata"].update(burst_meta)
            return {
                "ok": True,
                "decision": "DEFER",
                "install_flow": False,
                "reason": "packet_in_rate_limited",
                "security_event": event,
            }

        allowed, _, permission = self._evaluar_acceso_reactivo(session, merged)
        if not allowed:
            print(
                f"[M6][PACKET-IN] DENY por politica usuario="
                f"{session.get('codigo_pucp')} rol={session.get('nombre_rol')}"
            )
            event = self._registrar_evento_denegado(merged)
            return {
                "ok": True,
                "decision": "DENY",
                "install_flow": False,
                "reason": "denied_by_policy",
                "security_event": event,
            }

        vlan_id = int(
            data.get("vlan_id")
            or session.get("vlan_id")
            or Config.VLANS_POR_ROL.get(session.get("nombre_rol"), 0)
        )
        dst_ip = Config.get_ip_mapping_m2().get(data.get("dst_ip"), data.get("dst_ip"))
        dst_port = int(data["dst_port"])
        dst_host = self.onos.get_host_by_ip(dst_ip)
        if not dst_host:
            print(f"[M6][PACKET-IN] DEFER: dst_host no aprendido {dst_ip}")
            return {
                "ok": True,
                "decision": "DEFER",
                "install_flow": False,
                "reason": "dst_host_not_learned",
                "dst_ip": dst_ip,
            }
        print(
            f"[M6][PACKET-IN] ALLOW usuario={session.get('codigo_pucp')} "
            f"rol={session.get('nombre_rol')} vlan={vlan_id} "
            f"tabla={str(permission.get('tabla') or 'T2').upper()} "
            f"permiso={permission} dst_host={dst_host}"
        )

        src_host = {
            "mac": data["src_mac"],
            "switch_dpid": data["switch_dpid"],
            "in_port": int(data["in_port"]),
        }
        self._instalar_session_gate(
            data["src_mac"],
            data["switch_dpid"],
            int(data["in_port"]),
            vlan_id,
            ip_src=data["src_ip"],
        )
        installed = self._instalar_camino_tcp(
            data["src_mac"],
            src_host,
            dst_host,
            data["src_ip"],
            dst_ip,
            dst_port,
            vlan_id,
            int(data.get("idle_timeout", Config.DATA_FLOW_TIMEOUT)),
            target_table=str(permission.get("tabla") or "T2").upper(),
            expires_at=permission.get("expires_at"),
        )
        flow = None
        flow_id = None
        return {
            "ok": True,
            "decision": "ALLOW",
            "install_flow": True,
            "flows_installed": installed,
            "flow_id": flow_id,
            "flow": flow,
            "status": (
                "EXECUTED"
                if Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
                else "SIMULATED"
            ),
        }

    def _buscar_sesion_db_por_host(self, mac, ip=None, switch_dpid=None, in_port=None):
        if not MYSQL_OK:
            return None
        try:
            filtros = ["LOWER(s.mac_address)=LOWER(%s)", "s.estado='ACTIVA'"]
            params = [mac]
            if ip:
                filtros.append("s.ip_asignada=%s")
                params.append(ip)
            if switch_dpid:
                filtros.append("s.switch_dpid=%s")
                params.append(switch_dpid)
            if in_port is not None:
                filtros.append("s.in_port=%s")
                params.append(int(in_port))
            conn = mysql.connector.connect(
                host=Config.MYSQL_HOST,
                user=Config.MYSQL_USER,
                password=Config.MYSQL_PASS,
                database=Config.MYSQL_DB,
                connection_timeout=3,
            )
            cur = conn.cursor(dictionary=True)
            cur.execute(
                f"""
                SELECT s.*, u.codigo_pucp
                FROM sesiones_activas s
                LEFT JOIN usuarios u ON u.id_usuario=s.id_usuario
                WHERE {' AND '.join(filtros)}
                ORDER BY s.login_timestamp DESC
                LIMIT 1
                """,
                tuple(params),
            )
            row = cur.fetchone()
            cur.close()
            conn.close()
            return row
        except Exception as exc:
            print(f"[M6] Error buscando sesion para expiracion: {exc}")
            return None

    def procesar_flow_expired(self, data):
        mac = (data.get("mac") or data.get("src_mac") or "").lower()
        if not mac:
            return {"ok": False, "error": "falta mac"}
        table_id = int(data.get("tableId", data.get("table_id", 1)))
        priority = int(data.get("priority", 0))
        if table_id != 1:
            return {"ok": True, "ignored": True, "reason": "not_table_1"}
        if priority and priority != Config.PRIO_T1_SESSION_GATE:
            return {"ok": True, "ignored": True, "reason": "not_session_gate"}

        result = {
            "ok": True,
            "mac": mac,
            "session_found": False,
            "expired": False,
            "status": "DRY_RUN",
        }
        if not Config.SESSION_EXPIRE_ON_T1_REMOVED:
            return result

        session = self._buscar_sesion_db_por_host(
            mac,
            ip=data.get("ip") or data.get("src_ip"),
            switch_dpid=data.get("switch_dpid") or data.get("deviceId"),
            in_port=data.get("in_port"),
        )
        result["session_found"] = bool(session)
        if not session:
            self.cerrar_sesion(mac)
            result["status"] = "NO_ACTIVE_SESSION"
            return result

        try:
            resp = requests.post(
                f"{Config.M1_INTERNAL_URL}/auth/session/expire",
                json={
                    "mac": mac,
                    "motivo": "EXPIRACION",
                    "source": "onos_flow_removed",
                },
                headers={"X-Security-Token": Config.SECURITY_TOKEN},
                timeout=5,
            )
            result["m1_status_code"] = resp.status_code
            result["m1_response"] = resp.json() if resp.text else {}
            if resp.status_code in (200, 404):
                self.cerrar_sesion(mac)
                result["expired"] = resp.status_code == 200
                result["status"] = "EXECUTED"
            else:
                result["status"] = "M1_ERROR"
        except Exception as exc:
            result["status"] = "M1_UNREACHABLE"
            result["error"] = str(exc)
        return result

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
        session_timeout = int(token.get("session_timeout", 28800))

        nombre_sw = Config.SWITCH_NOMBRES.get(switch_dpid, switch_dpid[-8:])
        print(f"\n[M6] ── Token de M1 ──────────────────────────────")
        print(f"  usuario={codigo_pucp}  rol={nombre_rol}  "
              f"vlan={vlan_id}  ip={ip_asignada}")
        print(f"  host: mac={mac}  switch={nombre_sw}  puerto={in_port}")

        # 1. Obtener políticas (OPA → MySQL → hardcoded)
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

        # 2. Instalar flows de política
        n_allow, n_deny = 0, 0
        print(f"  Instalando enforcement...")
        host_origen = {
            "mac": mac,
            "switch_dpid": switch_dpid,
            "in_port": in_port,
        }
        n_pipeline = self._asegurar_pipeline_fallback_en_borde(switch_dpid)
        if n_pipeline:
            print(f"    ✓ Pipeline T0→T1→T2→T3→T4 base — {n_pipeline} flows")
        session_gate = self._instalar_session_gate(
            mac, switch_dpid, in_port, vlan_id, ip_src=ip_asignada
        )
        if session_gate:
            print(
                f"    ✓ T1 session gate — idle {Config.SESSION_IDLE_TIMEOUT}s"
            )
        # T0 ya tiene el fallback general tcp -> T1. No instalamos
        # clasificadores por host en T0 para mantener la tabla limpia.

        if Config.REACTIVE_DATA_FLOWS_ENABLED:
            n_t2_login = 0
            n_t2_permisos = 0
            n_t3_deferidos = 0
            for permiso in politicas.get("permisos", []):
                tabla_permiso = str(permiso.get("tabla") or "T2").upper()
                if tabla_permiso == "T3":
                    n_t3_deferidos += 1
                    continue
                if tabla_permiso != "T2":
                    tabla_permiso = "T2"

                ip_dst = permiso["ip_dst"]
                host_destino = self.onos.get_host_by_ip(ip_dst)
                if not host_destino:
                    print(f"    ! T2 {ip_dst}: destino no aprendido en ONOS; "
                          f"queda bajo demanda por T4")
                    continue

                puertos = permiso.get("puertos") or []
                if not puertos:
                    print(f"    ! T2 {ip_dst}: permiso sin puerto TCP; "
                          f"queda bajo demanda por T4")
                    continue

                for tcp_port in puertos:
                    flows = self._instalar_camino_tcp(
                        mac, host_origen, host_destino,
                        ip_asignada, ip_dst, tcp_port, vlan_id,
                        Config.DATA_FLOW_TIMEOUT,
                        target_table="T2",
                        expires_at=permiso.get("expires_at"),
                    )
                    if flows:
                        n_t2_permisos += 1
                        n_t2_login += flows
                        print(
                            f"    ✓ T2 proactivo {ip_dst}:{tcp_port} — "
                            f"{flows} flows"
                        )
                    else:
                        print(
                            f"    ! T2 {ip_dst}:{tcp_port} — sin ruta completa; "
                            "queda bajo demanda por T4"
                        )

            n_total = len(self.flows_por_sesion.get(mac.lower(), []))
            print(
                "  Modo T2 hibrido: permisos T2 normales proactivos; "
                "T3 excepciones bajo demanda"
            )
            self.logger.log({
                "modulo":    "M6",
                "evento":    "sesion_activada_t2_hibrida",
                "usuario":   codigo_pucp,
                "rol":       nombre_rol,
                "vlan":      vlan_id,
                "mac":       mac,
                "switch":    switch_dpid,
                "puerto":    in_port,
                "n_flows":   n_total,
                "t2_login":  n_t2_login,
                "t2_permisos": n_t2_permisos,
                "t3_deferidos": n_t3_deferidos,
            })
            return {
                "ok": True,
                "reactive_mode": True,
                "hybrid_t2_mode": True,
                "n_flows": n_total,
                "t2_login": n_t2_login,
                "t2_permisos": n_t2_permisos,
                "t3_deferidos": n_t3_deferidos,
            }

        for permiso in politicas.get("permisos", []):
            ip_dst = permiso["ip_dst"]
            tabla_permiso = str(permiso.get("tabla") or "T2").upper()
            if tabla_permiso not in ("T2", "T3"):
                tabla_permiso = "T2"
            host_destino = self.onos.get_host_by_ip(ip_dst)
            if not host_destino:
                print(f"    ! {ip_dst}: destino no aprendido en ONOS; "
                      f"no se instala salida de datos")
                continue

            puertos = permiso.get("puertos") or []
            if not puertos:
                print(f"    ! {ip_dst}: permiso sin puerto TCP; se omite "
                      f"para evitar allow amplio")
                continue

            for tcp_port in puertos:
                flows = self._instalar_camino_tcp(
                    mac, host_origen, host_destino,
                    ip_asignada, ip_dst, tcp_port, vlan_id,
                    session_timeout,
                    target_table=tabla_permiso,
                    expires_at=permiso.get("expires_at"),
                )
                if flows:
                    n_allow += 1
                    print(f"    ✓ {ip_dst}:{tcp_port} — {flows} flows {tabla_permiso}")
                else:
                    print(f"    ! {ip_dst}:{tcp_port} — sin ruta completa")

        for denegacion in politicas.get("denegaciones", []):
            ip_dst = denegacion["ip_dst"]
            self._instalar_y_cachear(
                switch_dpid,
                self.builder.t3_deny_sesion(
                    switch_dpid, mac, ip_asignada, ip_dst, session_timeout
                ),
                mac
            )
            n_deny += 1

        n_total = len(self.flows_por_sesion.get(mac, []))
        print(f"  ✓ Sesión activada — {n_total} flows  "
              f"(ALLOW permisos:{n_allow}  T3-DENY:{n_deny})")

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
        mac = mac.lower()
        with self._lock:
            flows = self.flows_por_sesion.pop(mac, [])
            self.session_gates.pop(mac, None)
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
        Construye o instala un DROP T0, según los interruptores de seguridad.
        """
        incident_id = directiva.get("incident_id") or str(uuid4())
        ip_atacante = directiva.get("ip_atacante")
        mac_atacante = directiva.get("mac_atacante")
        switch_dpid = directiva.get("switch_dpid")
        in_port     = directiva.get("in_port")
        ttl         = directiva.get("ttl_segundos", 600)
        prio        = directiva.get("prioridad", Config.PRIO_T0_ATAQUE)

        if not ip_atacante and not mac_atacante:
            return {"ok": False, "error": "se requiere ip_atacante o mac_atacante"}
        if not switch_dpid and not Config.ONOS_READS_ENABLED:
            return {
                "ok": False,
                "error": "switch_dpid es obligatorio con ONOS_READS_ENABLED=false",
            }

        print(
            f"\n[M6] DirectivaMitigacion: incident={incident_id} "
            f"ip={ip_atacante} mac={mac_atacante} ttl={ttl}s prio={prio}"
        )
        devices = [switch_dpid] if switch_dpid else self.onos.get_devices()
        flows = []
        for device_id in devices:
            flow = self.builder.t0_bloqueo_ataque(
                device_id,
                ip_atacante=ip_atacante,
                mac_atacante=mac_atacante,
                in_port=in_port,
                ttl=ttl,
                prio=prio,
            )
            flow_id = self.onos.instalar_flow(device_id, flow)
            if flow_id:
                flows.append(
                    {"device_id": device_id, "flow_id": flow_id, "flow": flow}
                )
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(ttl))
        status = (
            "EXECUTED"
            if Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
            else "SIMULATED"
        )
        result = {
            "ok": bool(flows),
            "incident_id": incident_id,
            "action_id": str(uuid4()),
            "status": status,
            "flow_ids": [item["flow_id"] for item in flows],
            "devices": [item["device_id"] for item in flows],
            "flows": [item["flow"] for item in flows],
            "expires_at": expires_at.isoformat(),
        }
        with self._lock:
            self.mitigaciones[incident_id] = {**result, "active": True}
        self.logger.log({
            "modulo":      "M6",
            "evento":      "mitigacion_aplicada",
            "incident_id": incident_id,
            "ip_atacante": ip_atacante,
            "mac_atacante": mac_atacante,
            "ttl":         ttl,
            "prio":        prio,
            "status":      status,
        })
        return result

    def deshacer_mitigacion(self, incident_id):
        with self._lock:
            mitigation = self.mitigaciones.get(incident_id)
        if not mitigation:
            return {"ok": False, "error": "mitigación no encontrada"}

        success = True
        for device_id, flow_id in zip(
            mitigation.get("devices", []),
            mitigation.get("flow_ids", []),
        ):
            success = self.onos.eliminar_flow(device_id, flow_id) and success

        with self._lock:
            mitigation["active"] = False
            mitigation["unblocked_at"] = datetime.now(timezone.utc).isoformat()
            mitigation["unblock_status"] = (
                "EXECUTED"
                if Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
                else "SIMULATED"
            )
        return {
            "ok": success,
            "incident_id": incident_id,
            "status": mitigation["unblock_status"],
        }

    def estado_host(self, ip=None, mac=None):
        with self._lock:
            matching = [
                mitigation
                for mitigation in self.mitigaciones.values()
                if mitigation.get("active")
                and (
                    (ip and any(
                        criterion.get("type") == "IPV4_SRC"
                        and criterion.get("ip") == f"{ip}/32"
                        for flow in mitigation.get("flows", [])
                        for criterion in flow.get("selector", {}).get("criteria", [])
                    ))
                    or (mac and any(
                        criterion.get("type") == "ETH_SRC"
                        and criterion.get("mac", "").lower() == mac.lower()
                        for flow in mitigation.get("flows", [])
                        for criterion in flow.get("selector", {}).get("criteria", [])
                    ))
                )
            ]
            session_flows = len(self.flows_por_sesion.get((mac or "").lower(), []))
        return {
            "ip": ip,
            "mac": mac,
            "blocked": bool(matching),
            "mitigations": matching,
            "flows_installed": session_flows,
            "network_mode": (
                "ENABLED"
                if Config.NETWORK_ACTIONS_ENABLED
                else "SIMULATED"
            ),
        }


# ─── Flask API ────────────────────────────────────────────────────────────────
app = Flask(__name__)
m6  = M6Translator()


def _security_token_valido():
    return request.headers.get("X-Security-Token") == Config.SECURITY_TOKEN


@app.route("/m6/packet-in", methods=["POST"])
def endpoint_packet_in():
    """Consulta reactiva originada por la futura aplicación Packet-In de ONOS."""
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    data = request.json or {}
    result = m6.procesar_packet_in(data)
    return jsonify(result), 200 if result.get("ok") else 400


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


@app.route("/m6/flow_expired", methods=["POST"])
def endpoint_flow_expired():
    """Evento desde app ONOS cuando expira/remueve el T1 session gate."""
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    data = request.json or {}
    resultado = m6.procesar_flow_expired(data)
    return jsonify(resultado), 200 if resultado.get("ok") else 400


@app.route("/m6/portal/sync", methods=["POST"])
def endpoint_portal_sync():
    """Instala rutas explicitas host<->portal TCP/8282 para hosts aprendidos."""
    force = str(request.args.get("force", "")).lower() in ("1", "true", "yes")
    resultado = m6.sincronizar_portal_cuarentena(force=force)
    return jsonify(resultado), 200 if resultado.get("ok") else 400


@app.route("/m6/mitigacion", methods=["POST"])
def endpoint_mitigacion():
    """M4 llama aquí al detectar un atacante."""
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    directiva = request.json or {}
    result = m6.procesar_mitigacion(directiva)
    return jsonify(result), 200 if result.get("ok") else 400


@app.route("/m6/unblock", methods=["POST"])
def endpoint_unblock():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    incident_id = (request.json or {}).get("incident_id")
    if not incident_id:
        return jsonify({"error": "falta incident_id"}), 400
    result = m6.deshacer_mitigacion(incident_id)
    return jsonify(result), 200 if result.get("ok") else 404


@app.route("/m6/security/host-state", methods=["GET"])
def endpoint_host_state():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    ip = request.args.get("ip")
    mac = request.args.get("mac")
    if not ip and not mac:
        return jsonify({"error": "se requiere ip o mac"}), 400
    return jsonify(m6.estado_host(ip=ip, mac=mac)), 200


@app.route("/m6/security/mitigations/<incident_id>", methods=["GET"])
def endpoint_mitigation_status(incident_id):
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    with m6._lock:
        result = m6.mitigaciones.get(incident_id)
    if result is None:
        return jsonify({"error": "mitigación no encontrada"}), 404
    return jsonify(result), 200


@app.route("/m6/arranque", methods=["POST"])
def endpoint_arranque():
    """El arranque legacy queda deshabilitado para evitar reglas obsoletas."""
    return jsonify({
        "ok": False,
        "disabled": True,
        "reason": "legacy_startup_disabled",
    }), 200


@app.route("/m6/status", methods=["GET"])
def endpoint_status():
    """Healthcheck — estado de ONOS y sesiones activas."""
    devices = m6.onos.get_devices()
    with m6._lock:
        sesiones = {mac: len(flows)
                    for mac, flows in m6.flows_por_sesion.items()}
        portal_flows = {mac: len(flows)
                        for mac, flows in m6.flows_portal.items()}
        portal_ips = dict(m6.portal_ips)
        now = time.time()
        t0_shared_flows = sum(
            1 for _, _, expires_at in m6.flows_t0_shared.values()
            if expires_at > now
        )
    return jsonify({
        "status":           "ok",
        "onos_url":         Config.ONOS_URL,
        "opa_url":          Config.OPA_URL,
        "mysql_disponible": MYSQL_OK,
        "devices_onos":     devices,
        "sesiones_activas": sesiones,
        "portal_flows":     portal_flows,
        "portal_ips":       portal_ips,
        "t0_shared_flows":  t0_shared_flows,
        "network_actions_enabled": Config.NETWORK_ACTIONS_ENABLED,
        "onos_writes_enabled": Config.ONOS_WRITES_ENABLED,
        "onos_reads_enabled": Config.ONOS_READS_ENABLED,
        "ovsdb_actions_enabled": Config.OVSDB_ACTIONS_ENABLED,
        "automatic_actions_enabled": Config.M4_AUTOMATIC_ACTIONS_ENABLED,
        "startup_flow_install_enabled": Config.STARTUP_FLOW_INSTALL_ENABLED,
        "portal_sync_interval": Config.PORTAL_SYNC_INTERVAL,
        "reactive_data_flows_enabled": Config.REACTIVE_DATA_FLOWS_ENABLED,
        "session_expire_on_t1_removed": Config.SESSION_EXPIRE_ON_T1_REMOVED,
        "session_idle_timeout": Config.SESSION_IDLE_TIMEOUT,
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

    print("[M6] Arranque legacy deshabilitado: no se instalarán flows en ONOS")

    m6.iniciar_sincronizador_portal()

    print(f"[M6] API escuchando en {Config.M6_HOST}:{Config.M6_PORT}\n")
    app.run(host=Config.M6_HOST, port=Config.M6_PORT,
            debug=False, threaded=True)
