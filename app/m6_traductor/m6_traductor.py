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
from flask import Flask, request, jsonify, Response

try:
    import mysql.connector
    MYSQL_OK = True
except ImportError:
    MYSQL_OK = False

try:
    from observability import (Observability, TelemetryConfig, Events)
except Exception as exc:
    print(f"[M6] Observability disabled: {exc}")

    class TelemetryConfig:
        def __init__(self, service_name=None, service_version=None, **_kwargs):
            self.service_name = service_name
            self.service_version = service_version

    class _NoopSpan:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Observability:
        def __init__(self, _config=None):
            pass

        def span(self, _name):
            return _NoopSpan()

        def event(self, *_args, **_kwargs):
            return None

        def update_context(self, **_kwargs):
            return None

    class Events:
        POLICY_QUERY = "policy.query"
        POLICY_QUERY_RESULT = "policy.query.result"
        FLOW_INSTALL_REQUESTED = "flow.install.requested"
        FLOW_INSTALLED = "flow.installed"
        FLOW_REMOVED = "flow.removed"

obsConfig = TelemetryConfig(
    service_name="m6-traductor",
    service_version="1.0.0",
)
obs = Observability(obsConfig)

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
    MONITORING_GRE_ENABLED = env_bool.__func__("MONITORING_GRE_ENABLED", True)
    MONITORING_GRE_INSTALL_ON_STARTUP = env_bool.__func__(
        "MONITORING_GRE_INSTALL_ON_STARTUP", False
    )
    FAILOVER_ANALYSIS_ENABLED = env_bool.__func__(
        "FAILOVER_ANALYSIS_ENABLED", True
    )
    FAILOVER_AUTO_REINSTALL_ENABLED = env_bool.__func__(
        "FAILOVER_AUTO_REINSTALL_ENABLED", False
    )
    FAILOVER_RECOVERY_COOLDOWN = int(os.getenv(
        "FAILOVER_RECOVERY_COOLDOWN", "10"
    ))
    FAILOVER_RECOVERY_MAX_SESSIONS = int(os.getenv(
        "FAILOVER_RECOVERY_MAX_SESSIONS", "20"
    ))
    FAILOVER_EVENT_DEDUP_WINDOW = int(os.getenv(
        "FAILOVER_EVENT_DEDUP_WINDOW", "15"
    ))
    PORTAL_SYNC_INTERVAL = int(os.getenv("PORTAL_SYNC_INTERVAL", "60"))
    PORTAL_FORWARD_PERMANENT = env_bool.__func__(
        "PORTAL_FORWARD_PERMANENT", True
    )
    PORTAL_RETURN_TIMEOUT = int(os.getenv("PORTAL_RETURN_TIMEOUT", "5400"))
    REACTIVE_DATA_FLOWS_ENABLED = env_bool.__func__(
        "REACTIVE_DATA_FLOWS_ENABLED", False
    )
    SESSION_EXPIRE_ON_T1_REMOVED = env_bool.__func__(
        "SESSION_EXPIRE_ON_T1_REMOVED", False
    )
    SESSION_CLEANUP_ON_STARTUP = env_bool.__func__(
        "SESSION_CLEANUP_ON_STARTUP", True
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
    M6_LOG_FILE = os.getenv("M6_LOG_FILE", "/home/ubuntu/logs/m6_portal_stable.log")

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

    MONITORING_GRE_DST = os.getenv("MONITORING_GRE_DST", "192.168.200.213")
    MONITORING_GRE_SOURCE_DEVICE = os.getenv(
        "MONITORING_GRE_SOURCE_DEVICE", "of:00006a0757adfc4e"
    )
    MONITORING_GRE_EGRESS_DEVICE = os.getenv(
        "MONITORING_GRE_EGRESS_DEVICE", "of:00007e3892af7141"
    )
    MONITORING_GRE_EGRESS_PORT = int(os.getenv(
        "MONITORING_GRE_EGRESS_PORT", "5"
    ))
    MONITORING_GRE_FLOWS = [
        {
            "name": "sw4_gre_to_sw3",
            "device_id": "of:00006a0757adfc4e",
            "in_port": None,
            "out_port": 4,
        },
        {
            "name": "sw3_gre_to_sw1",
            "device_id": "of:0000eadb63449748",
            "in_port": 1,
            "out_port": 4,
        },
        {
            "name": "sw1_gre_to_monitoring",
            "device_id": "of:00007e3892af7141",
            "in_port": 3,
            "out_port": 5,
        },
    ]

    # Prioridades OpenFlow (acordadas en diseño de arquitectura)
    PRIO_PORTAL_EDGE_T1 = 40100  # T1: portal cautivo gana al session gate
    PRIO_T2_DATA_ALLOW = 110  # T2: ALLOW real con salida exacta
    PRIO_T3_ALLOW   = 150     # T3: ALLOW excepcional por sesión
    PRIO_T3_DENY    = 200     # T3: DROP por sesión
    PRIO_PIPELINE_MISS = 0     # T2/T3/T4: fallback controlado
    PRIO_T0_TRANSPORT = 1000   # T0: transporte agregado en troncales
    PRIO_T0_MONITORING_GRE = 1000  # T0: tunel GRE hacia monitoreo/M3
    PRIO_T0_USUARIO = 35000   # T0: enforcement por MAC post-auth
    PRIO_T1_SESSION_GATE = 39900  # T1: flow marcador de sesion idle
    PRIO_T0_ATAQUE  = 39000   # T0: bloqueo atacante (instalado por M4)
    PRIO_T0_RATE_LIMIT = 38900  # T0: meter temporal por saturacion/M5
    RATE_LIMIT_DEFAULT_TTL = int(os.getenv("RATE_LIMIT_DEFAULT_TTL", "300"))
    RATE_LIMIT_DEFAULT_PPS = int(os.getenv("RATE_LIMIT_DEFAULT_PPS", "50"))
    DATA_FLOW_TIMEOUT = int(os.getenv("DATA_FLOW_TIMEOUT", "300"))

    SECURITY_MITIGATION_POLICIES = {
        9000001: {"action": "block_tcp_to_dest", "ttl": 300},
        9000008: {"action": "block_tcp_to_dest", "ttl": 300},
        9000009: {"action": "block_tcp_to_dest", "ttl": 300},
        9000010: {"action": "block_tcp_to_dest", "ttl": 300},
        9000002: {"action": "block_tcp_to_dest_port", "ttl": 900},
        9000014: {"action": "block_tcp_to_dest_port", "ttl": 900},
        9000018: {"action": "block_icmp", "ttl": 600},
        9000027: {"action": "block_tcp_port", "ttl": 600, "dst_port": 22},
        9000028: {"action": "block_tcp_port", "ttl": 600, "dst_port": 3389},
        9000029: {"action": "block_tcp_port", "ttl": 600, "dst_port": 21},
        9000015: {"action": "block_all_ip", "ttl": 900},
        9000013: {"action": "block_tcp_port", "ttl": 900, "dst_port": 22},
        9000012: {"action": "block_tcp_port", "ttl": 900, "dst_port": 3389},
        9000024: {"action": "block_tcp_to_dest_port", "ttl": 900},
        9000036: {"action": "block_tcp_port", "ttl": 900, "dst_port": 21},
    }

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
                               ip_portal=None, session_timeout=None):
        """T1 borde usuario — cualquier host puede ir al portal cautivo."""
        if ip_portal is None:
            ip_portal = Config.PORTAL_IP
        permanent = Config.PORTAL_FORWARD_PERMANENT
        timeout = 0 if permanent else int(
            session_timeout or Config.PORTAL_RETURN_TIMEOUT
        )
        return {
            "priority":    Config.PRIO_PORTAL_EDGE_T1,
            "isPermanent": permanent,
            "timeout":     timeout,
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
                              host_ip, ip_portal=None, session_timeout=None):
        """T1 borde usuario — respuesta del portal vuelve al puerto del host."""
        if ip_portal is None:
            ip_portal = Config.PORTAL_IP
        timeout = int(session_timeout or Config.PORTAL_RETURN_TIMEOUT)
        return {
            "priority":    Config.PRIO_PORTAL_EDGE_T1,
            "isPermanent": False,
            "timeout":     timeout,
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

    def t0_monitoring_gre_flow(self, device_id, out_port, dst_ip=None,
                               in_port=None):
        """T0 permanente para transportar el tunel GRE hacia monitoreo/M3."""
        criteria = [
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IP_PROTO", "protocol": 47},
            {
                "type": "IPV4_DST",
                "ip": f"{dst_ip or Config.MONITORING_GRE_DST}/32",
            },
        ]
        if in_port is not None:
            criteria.insert(0, {"type": "IN_PORT", "port": int(in_port)})
        return {
            "priority":    Config.PRIO_T0_MONITORING_GRE,
            "isPermanent": True,
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
        dst_ip=None,
        dst_port=None,
        proto=None,
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
        if dst_ip:
            criteria.append({"type": "IPV4_DST", "ip": f"{dst_ip}/32"})
        proto_normalized = str(proto or "").upper()
        if proto_normalized == "ICMP":
            criteria.append({"type": "IP_PROTO", "protocol": 1})
        elif proto_normalized == "TCP" or dst_port is not None:
            criteria.append({"type": "IP_PROTO", "protocol": 6})
            if dst_port is not None:
                criteria.append({"type": "TCP_DST", "tcpPort": int(dst_port)})
        return {
            "priority":    prio,
            "isPermanent": False,
            "timeout":     ttl,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": criteria},
            "treatment": {"clearDeferred": True, "instructions": []}
        }

    def t0_rate_limit_port(self, device_id, in_port, meter_id,
                           src_mac=None, src_ip=None, ttl=None, prio=None):
        """T0 rate-limit: aplica meter y continua el pipeline normal en T1."""
        criteria = [
            {"type": "IN_PORT", "port": int(in_port)},
            {"type": "ETH_TYPE", "ethType": "0x0800"},
        ]
        if src_mac:
            criteria.append({"type": "ETH_SRC", "mac": src_mac})
        if src_ip:
            criteria.append({"type": "IPV4_SRC", "ip": f"{src_ip}/32"})
        return {
            "priority":    int(prio or Config.PRIO_T0_RATE_LIMIT),
            "isPermanent": False,
            "timeout":     int(ttl or Config.RATE_LIMIT_DEFAULT_TTL),
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": criteria},
            "treatment": {"instructions": [
                {"type": "METER", "meterId": str(meter_id)},
                {"type": "TABLE", "tableId": 1},
            ]}
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
        obs.event(
            Events.POLICY_QUERY,
            attributes={"peer.module": "m2-policy" , "opa.payload": opa_payload},
        )
        try:
            resp = requests.post(Config.OPA_URL, json=opa_payload, timeout=3)
            if resp.status_code == 200:
                resultado    = resp.json().get("result", {})
                m2_permisos  = resultado.get("permisos")
                if m2_permisos is not None:
                    print(f"  [PolicyEngine] Políticas desde OPA M2 "
                          f"({len(m2_permisos)} permisos)")
                    nombres,ids,politicas = self._convertir_permisos_m2(m2_permisos, vlan_id)
                    permisos = politicas.get("permisos", [])
                    denegaciones = politicas.get("denegaciones", [])
                    obs.event(
                        Events.POLICY_QUERY_RESULT,
                        attributes={"peer.module": "m2-policy",
                                    "opa.allowed_services.names": nombres,
                                    "opa.allowed_services.ids": ids,
                                    "opa.allowed_services.count": len(permisos),
                                    "opa.denied_services.count": len(denegaciones),},
                    )
                    return politicas
                
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
        nombres_rcs = []
        ids_rcs = []
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
            recurso_nombre = recurso.get("nombre", "")
            nombres_rcs.append(recurso_nombre)
            recurso_id = recurso.get("id_recurso")
            ids_rcs.append(recurso_id)
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

        return nombres_rcs, ids_rcs,{"permisos": permisos, "denegaciones": denegaciones}

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

    def get_host_by_location(self, device_id, port):
        """Busca host aprendido por ONOS en un switch/puerto concreto."""
        port = str(port)
        for host in self.get_hosts():
            for loc in host.get("locations") or []:
                if loc.get("elementId") == device_id and str(loc.get("port")) == port:
                    ips = host.get("ipAddresses") or []
                    return {
                        "mac": host.get("mac"),
                        "ip": ips[0] if ips else None,
                        "switch_dpid": device_id,
                        "in_port": int(port),
                    }
        return None

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

    def get_devices_raw(self):
        """Lista cruda de devices de ONOS, incluyendo availability/metadata."""
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return []
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/devices", auth=self.auth, timeout=5
            )
            if resp.status_code == 200:
                return resp.json().get("devices", [])
            print(f"  [ONOS] Error GET /devices: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [ONOS] Error GET /devices: {e}")
        return []

    def calcular_pasos_con_fallas(self, src_switch, src_port, dst_switch,
                                  dst_port, links, failed_devices=None,
                                  failed_links=None):
        """
        Calcula pasos con una topología simulada donde algunos switches/links
        fueron removidos. No toca ONOS ni instala flows.
        """
        failed_devices = {str(d) for d in (failed_devices or []) if d}
        failed_endpoints = set()
        for link in failed_links or []:
            for endpoint in ("src", "dst"):
                ep = link.get(endpoint, {}) if isinstance(link, dict) else {}
                dev, port = ep.get("device"), ep.get("port")
                if dev and port is not None:
                    failed_endpoints.add((str(dev), str(port)))

        if src_switch in failed_devices or dst_switch in failed_devices:
            return []
        if src_switch == dst_switch:
            if (str(src_switch), str(src_port)) in failed_endpoints:
                return []
            if (str(dst_switch), str(dst_port)) in failed_endpoints:
                return []
            return [(src_switch, int(src_port), int(dst_port))]

        adjacency = defaultdict(list)
        link_by_pair = {}
        for link in links:
            if link.get("state") not in (None, "ACTIVE"):
                continue
            src = link.get("src", {})
            dst = link.get("dst", {})
            src_dev, dst_dev = src.get("device"), dst.get("device")
            src_p, dst_p = src.get("port"), dst.get("port")
            if not (src_dev and dst_dev and str(src_p).isdigit()
                    and str(dst_p).isdigit()):
                continue
            if src_dev in failed_devices or dst_dev in failed_devices:
                continue
            if (str(src_dev), str(src_p)) in failed_endpoints:
                continue
            if (str(dst_dev), str(dst_p)) in failed_endpoints:
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
            return []

        steps = []
        in_port = int(src_port)
        for current, nxt in zip(path, path[1:]):
            link_ports = link_by_pair.get((current, nxt))
            if not link_ports:
                return []
            out_port, next_in_port = link_ports
            steps.append((current, in_port, out_port))
            in_port = next_in_port
        steps.append((dst_switch, in_port, int(dst_port)))
        return steps

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

    def crear_meter_rate_limit(self, device_id, rate_pps=None):
        rate_pps = int(rate_pps or Config.RATE_LIMIT_DEFAULT_PPS)
        if not (
            Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
        ):
            return f"SIM-{device_id[-4:]}-{rate_pps}"
        payload = {
            "deviceId": device_id,
            "unit": "PKTS_PER_SEC",
            "burst": True,
            "isBurst": True,
            "bands": [{
                "type": "DROP",
                "rate": rate_pps,
                "burstSize": max(rate_pps * 2, 1),
            }],
        }
        try:
            resp = requests.post(
                f"{self.url}/onos/v1/meters/{device_id}",
                auth=self.auth,
                json=payload,
                timeout=5,
            )
            if resp.status_code not in (200, 201, 202):
                print(f"  [ONOS] Error creando meter: HTTP {resp.status_code} "
                      f"{resp.text[:300]}")
                return None
            try:
                data = resp.json()
            except ValueError:
                data = {}
            for key in ("id", "meterId"):
                if data.get(key) is not None:
                    return str(data[key])
            location = resp.headers.get("Location", "")
            if location:
                return location.rstrip("/").split("/")[-1]
            meters = self.get_meters(device_id)
            candidates = [
                meter for meter in meters
                if str(meter.get("unit")) == "PKTS_PER_SEC"
                and any(
                    int(band.get("rate", -1)) == rate_pps
                    for band in meter.get("bands", [])
                )
            ]
            if candidates:
                return str(candidates[-1].get("id") or candidates[-1].get("meterId"))
            print("  [ONOS] Meter creado, pero no se pudo resolver meter_id")
            return None
        except Exception as exc:
            print(f"  [ONOS] Error creando meter: {exc}")
            return None

    def eliminar_meter(self, device_id, meter_id):
        if not meter_id:
            return True
        if not (
            Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
        ):
            print(f"  [ONOS] SIMULATED delete meter {meter_id} from {device_id}")
            return True
        try:
            resp = requests.delete(
                f"{self.url}/onos/v1/meters/{device_id}/{meter_id}",
                auth=self.auth,
                timeout=5,
            )
            if resp.status_code in (200, 202, 204, 404):
                return True
            print(f"  [ONOS] Error eliminando meter {meter_id}: "
                  f"HTTP {resp.status_code} {resp.text[:200]}")
            return False
        except Exception as exc:
            print(f"  [ONOS] Error eliminando meter {meter_id}: {exc}")
            return False

    def get_meters(self, device_id):
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return []
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/meters/{device_id}",
                auth=self.auth,
                timeout=4,
            )
            if resp.status_code == 200:
                return resp.json().get("meters", [])
            print(f"  [ONOS] Error GET /meters/{device_id}: HTTP {resp.status_code}")
        except Exception as exc:
            print(f"  [ONOS] Error GET /meters/{device_id}: {exc}")
        return []

    def get_flows(self, device_id):
        """Devuelve flows crudas de un device ONOS."""
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return []
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/flows/{device_id}",
                auth=self.auth, timeout=3
            )
            if resp.status_code == 200:
                return resp.json().get("flows", [])
            print(f"  [ONOS] Error GET /flows/{device_id}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [ONOS] Error GET /flows/{device_id}: {e}")
        return []


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
        self.path_records = {}      # {mac: {perm_key: path metadata}}
        self.pipeline_fallback_flows = {}  # {device_id: [(device_id, flow_id), ...]}
        self.mitigaciones = {}
        self.rate_limits = {}
        self._security_windows = defaultdict(deque)
        self._packet_in_seen = {}
        self._failover_recovery_seen = {}
        self._failover_event_seen = {}

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

    @staticmethod
    def _path_to_dicts(path):
        return [
            {
                "device_id": dev,
                "in_port": None if inp is None else int(inp),
                "out_port": int(out),
            }
            for dev, inp, out in (path or [])
        ]

    def _registrar_path_sesion(self, mac, *, src_ip, dst_ip, tcp_port,
                               vlan_id, target_table, ida, retorno):
        """Guarda el último path instalado por permiso; no crece por paquete."""
        mac_key = (mac or "").lower()
        if not mac_key:
            return
        perm_key = f"{str(target_table).upper()}:{dst_ip}:{int(tcp_port)}"
        record = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "tcp_port": int(tcp_port),
            "vlan_id": int(vlan_id),
            "target_table": str(target_table).upper(),
            "ida": self._path_to_dicts(ida),
            "retorno": self._path_to_dicts(retorno),
            "updated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        with self._lock:
            self.path_records.setdefault(mac_key, {})[perm_key] = record

    @staticmethod
    def _normalizar_eth_type(value):
        if isinstance(value, str):
            value = value.strip().lower()
            if value.startswith("0x"):
                return int(value, 16)
            return int(value)
        return int(value)

    @staticmethod
    def _criterios_por_tipo(flow):
        criterios = flow.get("selector", {}).get("criteria", [])
        return {c.get("type"): c for c in criterios}

    @staticmethod
    def _output_port(flow):
        for ins in flow.get("treatment", {}).get("instructions", []):
            if ins.get("type") == "OUTPUT":
                return str(ins.get("port"))
        return None

    def _flow_equivale_monitoring_gre(self, actual, esperado):
        if int(actual.get("tableId", -1)) != int(esperado.get("tableId", -2)):
            return False
        if int(actual.get("priority", -1)) != int(esperado.get("priority", -2)):
            return False
        if self._output_port(actual) != self._output_port(esperado):
            return False

        actual_c = self._criterios_por_tipo(actual)
        esperado_c = self._criterios_por_tipo(esperado)
        for tipo in ("ETH_TYPE", "IP_PROTO", "IPV4_DST"):
            if tipo not in actual_c or tipo not in esperado_c:
                return False
        try:
            if self._normalizar_eth_type(
                actual_c["ETH_TYPE"].get("ethType")
            ) != self._normalizar_eth_type(esperado_c["ETH_TYPE"].get("ethType")):
                return False
            if int(actual_c["IP_PROTO"].get("protocol")) != int(
                esperado_c["IP_PROTO"].get("protocol")
            ):
                return False
        except (TypeError, ValueError):
            return False

        if actual_c["IPV4_DST"].get("ip") != esperado_c["IPV4_DST"].get("ip"):
            return False
        esperado_in = esperado_c.get("IN_PORT")
        actual_in = actual_c.get("IN_PORT")
        if esperado_in is None:
            return actual_in is None
        if actual_in is None:
            return False
        return str(actual_in.get("port")) == str(esperado_in.get("port"))

    def _flow_es_monitoring_gre(self, flow):
        if int(flow.get("tableId", -1)) != 0:
            return False
        if int(flow.get("priority", -1)) != Config.PRIO_T0_MONITORING_GRE:
            return False
        criteria = self._criterios_por_tipo(flow)
        try:
            return (
                self._normalizar_eth_type(
                    criteria.get("ETH_TYPE", {}).get("ethType")
                ) == 0x0800
                and int(criteria.get("IP_PROTO", {}).get("protocol")) == 47
                and criteria.get("IPV4_DST", {}).get("ip")
                == f"{Config.MONITORING_GRE_DST}/32"
                and self._output_port(flow) is not None
            )
        except (TypeError, ValueError):
            return False

    def _monitoring_gre_base_specs(self):
        specs = []
        for item in Config.MONITORING_GRE_FLOWS:
            flow = self.builder.t0_monitoring_gre_flow(
                item["device_id"],
                item["out_port"],
                dst_ip=Config.MONITORING_GRE_DST,
                in_port=item.get("in_port"),
            )
            specs.append({**item, "flow": flow})
        return specs

    def _monitoring_gre_static_afectado(self, failed_devices, failed_links):
        failed_devices = {str(d) for d in (failed_devices or []) if d}
        endpoints = self._failed_link_endpoints(failed_links)
        for spec in self._monitoring_gre_base_specs():
            device_id = str(spec["device_id"])
            if device_id in failed_devices:
                return True
            in_port = spec.get("in_port")
            out_port = spec.get("out_port")
            if in_port is not None and (device_id, str(in_port)) in endpoints:
                return True
            if out_port is not None and (device_id, str(out_port)) in endpoints:
                return True
        return False

    def _monitoring_gre_dynamic_specs(self, failed_devices=None,
                                      failed_links=None):
        failed_devices = {str(d) for d in (failed_devices or []) if d}
        failed_links = self._normalizar_failed_links(failed_links or [])
        source = Config.MONITORING_GRE_SOURCE_DEVICE
        egress = Config.MONITORING_GRE_EGRESS_DEVICE
        egress_port = Config.MONITORING_GRE_EGRESS_PORT
        if source in failed_devices or egress in failed_devices:
            return {
                "mode": "dynamic_path",
                "recoverable": False,
                "reason": "source_or_egress_device_failed",
                "route": [],
                "specs": [],
            }

        links = self.onos.get_links()
        if source == egress:
            route = [(source, None, egress_port)]
        else:
            failed_endpoints = self._failed_link_endpoints(failed_links)
            adjacency = defaultdict(list)
            link_by_pair = {}
            for link in links:
                if link.get("state") not in (None, "ACTIVE"):
                    continue
                src = link.get("src", {})
                dst = link.get("dst", {})
                src_dev, dst_dev = src.get("device"), dst.get("device")
                src_p, dst_p = src.get("port"), dst.get("port")
                if not (src_dev and dst_dev and str(src_p).isdigit()
                        and str(dst_p).isdigit()):
                    continue
                if src_dev in failed_devices or dst_dev in failed_devices:
                    continue
                if (str(src_dev), str(src_p)) in failed_endpoints:
                    continue
                if (str(dst_dev), str(dst_p)) in failed_endpoints:
                    continue
                adjacency[src_dev].append(dst_dev)
                link_by_pair.setdefault(
                    (src_dev, dst_dev), (int(src_p), int(dst_p))
                )

            queue = deque([(source, [source])])
            visited = {source}
            path = None
            while queue:
                current, current_path = queue.popleft()
                for neighbor in sorted(adjacency.get(current, [])):
                    if neighbor in visited:
                        continue
                    next_path = current_path + [neighbor]
                    if neighbor == egress:
                        path = next_path
                        queue.clear()
                        break
                    visited.add(neighbor)
                    queue.append((neighbor, next_path))

            if not path:
                return {
                    "mode": "dynamic_path",
                    "recoverable": False,
                    "reason": "no_path_to_monitoring_egress",
                    "route": [],
                    "specs": [],
                }

            route = []
            in_port = None
            for current, nxt in zip(path, path[1:]):
                link_ports = link_by_pair.get((current, nxt))
                if not link_ports:
                    return {
                        "mode": "dynamic_path",
                        "recoverable": False,
                        "reason": "incomplete_link_path",
                        "route": [],
                        "specs": [],
                    }
                out_port, next_in_port = link_ports
                route.append((current, in_port, out_port))
                in_port = next_in_port
            route.append((egress, in_port, egress_port))

        specs = []
        for index, (device_id, in_port, out_port) in enumerate(route, start=1):
            flow = self.builder.t0_monitoring_gre_flow(
                device_id,
                out_port,
                dst_ip=Config.MONITORING_GRE_DST,
                in_port=in_port,
            )
            specs.append({
                "name": (
                    f"gre_dynamic_hop_{index}_"
                    f"{Config.SWITCH_NOMBRES.get(device_id, device_id[-4:])}"
                ),
                "device_id": device_id,
                "in_port": in_port,
                "out_port": out_port,
                "flow": flow,
            })
        return {
            "mode": "dynamic_path",
            "recoverable": True,
            "reason": None,
            "route": self._path_to_dicts(route),
            "specs": specs,
        }

    def _monitoring_gre_plan(self, failed_devices=None, failed_links=None):
        failed_links = self._normalizar_failed_links(failed_links or [])
        failed_devices = {str(d) for d in (failed_devices or []) if d}
        if not self._monitoring_gre_static_afectado(failed_devices, failed_links):
            specs = self._monitoring_gre_base_specs()
            route = [
                (spec["device_id"], spec.get("in_port"), spec["out_port"])
                for spec in specs
            ]
            return {
                "mode": "static_base",
                "recoverable": True,
                "reason": None,
                "route": self._path_to_dicts(route),
                "specs": specs,
            }
        return self._monitoring_gre_dynamic_specs(
            failed_devices=failed_devices,
            failed_links=failed_links,
        )

    def _limpiar_monitoring_gre_conflictivos(self, specs):
        if not specs:
            return {"removed": [], "failed": []}
        desired_by_device = defaultdict(list)
        for spec in specs:
            desired_by_device[spec["device_id"]].append(spec["flow"])

        removed, failed = [], []
        for device_id, desired in desired_by_device.items():
            for flow in self.onos.get_flows(device_id):
                if not self._flow_es_monitoring_gre(flow):
                    continue
                if any(
                    self._flow_equivale_monitoring_gre(flow, expected)
                    for expected in desired
                ):
                    continue
                flow_id = flow.get("id")
                if not flow_id:
                    continue
                if self.onos.eliminar_flow(device_id, flow_id):
                    removed.append({"device_id": device_id, "flow_id": flow_id})
                else:
                    failed.append({"device_id": device_id, "flow_id": flow_id})
        return {"removed": removed, "failed": failed}

    def estado_monitoring_gre(self, failed_devices=None, failed_links=None):
        if not Config.MONITORING_GRE_ENABLED:
            return {"ok": True, "disabled": True, "flows": []}
        if not (Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_READS_ENABLED):
            return {
                "ok": True,
                "status": "SIMULATED",
                "disabled": True,
                "reason": "onos_reads_disabled",
                "flows": [],
            }

        plan = self._monitoring_gre_plan(
            failed_devices=failed_devices,
            failed_links=failed_links,
        )
        flows_por_device = {}
        resultados = []
        for spec in plan["specs"]:
            device_id = spec["device_id"]
            flows_por_device.setdefault(device_id, self.onos.get_flows(device_id))
            match = next(
                (
                    f for f in flows_por_device[device_id]
                    if self._flow_equivale_monitoring_gre(f, spec["flow"])
                    and f.get("state") in (None, "ADDED")
                ),
                None,
            )
            resultados.append({
                "name": spec["name"],
                "device_id": device_id,
                "present": bool(match),
                "flow_id": match.get("id") if match else None,
                "in_port": spec.get("in_port"),
                "out_port": spec["out_port"],
                "dst_ip": f"{Config.MONITORING_GRE_DST}/32",
            })
        return {
            "ok": True,
            "mode": plan["mode"],
            "recoverable": plan["recoverable"],
            "reason": plan.get("reason"),
            "dst_ip": f"{Config.MONITORING_GRE_DST}/32",
            "source_device": Config.MONITORING_GRE_SOURCE_DEVICE,
            "egress_device": Config.MONITORING_GRE_EGRESS_DEVICE,
            "egress_port": Config.MONITORING_GRE_EGRESS_PORT,
            "route": plan["route"],
            "flows": resultados,
        }

    def asegurar_monitoring_gre(self, failed_devices=None, failed_links=None,
                                cleanup_conflicts=False):
        if not Config.MONITORING_GRE_ENABLED:
            return {
                "ok": True,
                "disabled": True,
                "reason": "monitoring_gre_disabled",
                "installed": [],
                "already_present": [],
                "failed": [],
            }
        if not (
            Config.NETWORK_ACTIONS_ENABLED
            and Config.ONOS_READS_ENABLED
            and Config.ONOS_WRITES_ENABLED
        ):
            return {
                "ok": True,
                "status": "SIMULATED",
                "disabled": True,
                "reason": "onos_reads_or_writes_disabled",
                "installed": [],
                "already_present": [],
                "failed": [],
            }

        plan = self._monitoring_gre_plan(
            failed_devices=failed_devices,
            failed_links=failed_links,
        )
        if not plan["recoverable"]:
            return {
                "ok": True,
                "checked": True,
                "recoverable": False,
                "mode": plan["mode"],
                "reason": plan.get("reason"),
                "installed": [],
                "already_present": [],
                "removed_conflicts": [],
                "failed": [],
            }

        flows_por_device = {}
        cleanup = (
            self._limpiar_monitoring_gre_conflictivos(plan["specs"])
            if cleanup_conflicts else {"removed": [], "failed": []}
        )
        installed, already_present, failed = [], [], []
        for spec in plan["specs"]:
            device_id = spec["device_id"]
            flows_por_device.setdefault(device_id, self.onos.get_flows(device_id))
            existe = any(
                self._flow_equivale_monitoring_gre(f, spec["flow"])
                and f.get("state") in (None, "ADDED")
                for f in flows_por_device[device_id]
            )
            if existe:
                already_present.append(spec["name"])
                continue
            flow_id = self.onos.instalar_flow(device_id, spec["flow"])
            if flow_id:
                installed.append(spec["name"])
                flows_por_device[device_id] = self.onos.get_flows(device_id)
            else:
                failed.append(spec["name"])
        return {
            "ok": not (failed or cleanup["failed"]),
            "checked": True,
            "recoverable": True,
            "mode": plan["mode"],
            "route": plan["route"],
            "installed": installed,
            "already_present": already_present,
            "removed_conflicts": cleanup["removed"],
            "failed": failed + cleanup["failed"],
        }

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

        if instalados:
            self._registrar_path_sesion(
                mac_sesion,
                src_ip=src_ip,
                dst_ip=dst_ip,
                tcp_port=tcp_port,
                vlan_id=vlan_id,
                target_table=target_label,
                ida=ida,
                retorno=retorno,
            )

        return instalados

    def _eliminar_flows_portal(self, mac):
        mac = mac.lower()
        with self._lock:
            flows = self.flows_portal.pop(mac, [])
            self.portal_ips.pop(mac, None)
        for device_id, flow_id in flows:
            self.onos.eliminar_flow(device_id, flow_id)
        return len(flows)

    def _eliminar_flows_portal_compartidos(self):
        prefixes = {"portal-edge-t1-dst", "portal-core-dst", "portal-core-src"}
        with self._lock:
            items = [
                (key, self.flows_t0_shared.pop(key))
                for key in list(self.flows_t0_shared)
                if isinstance(key, tuple) and key and key[0] in prefixes
            ]
        for _key, value in items:
            try:
                device_id, flow_id = value[0], value[1]
            except (IndexError, TypeError):
                continue
            self.onos.eliminar_flow(device_id, flow_id)
        return len(items)

    def _asegurar_portal_ida_borde(self, host, portal_host, ttl=None):
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
                    device_id, fid, None
                )
            print(f"    [PORTAL] T1 ida generica {device_id} -> {out_port}")
        return fid

    def _instalar_camino_portal(self, host, portal_host, ip_host, ttl=None):
        """
        Instala cuarentena minima host<->portal TCP/8282. Estos flows no son
        de sesion autenticada. Solo el borde usuario queda por host; el tramo
        troncal/portal se agrega para no multiplicar flows por usuario.
        """
        if ttl is None:
            ttl = Config.PORTAL_RETURN_TIMEOUT
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
        if force:
            self._eliminar_flows_portal_compartidos()

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

    def _marcar_incidente_m4_expirado(self, incident_id):
        try:
            requests.post(
                f"{Config.M4_URL}/m4/incidents/{incident_id}/expire",
                headers={"X-Security-Token": Config.SECURITY_TOKEN},
                timeout=3,
            ).raise_for_status()
        except Exception as exc:
            print(f"[M6] No se pudo marcar incidente M4 expirado: {exc}")

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
        with obs.span("policy.decision"):
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
        with obs.span("flow.installation"):
            obs.event(
                Events.FLOW_INSTALL_REQUESTED,
                attributes={
                    "flow.table": "T1",
                    "flow.mac": mac,
                    "flow.ip": ip_asignada,
                    "flow.switch": switch_dpid,
                    "flow.vlan": vlan_id,
                }
            )
            session_gate = self._instalar_session_gate(
                mac, switch_dpid, in_port, vlan_id, ip_src=ip_asignada
            )
            if session_gate:
                print(
                    f"    ✓ T1 session gate — idle {Config.SESSION_IDLE_TIMEOUT}s"
                )
                obs.event(
                    Events.FLOW_INSTALLED,
                    attributes={
                        "flow.ip": ip_asignada,
                        "flow.switch": switch_dpid,
                        "flow.idle_timeout": Config.SESSION_IDLE_TIMEOUT,
                    }
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
        ids_flows = []
        ids_devices = []
        mac = mac.lower()
        with self._lock:
            flows = self.flows_por_sesion.pop(mac, [])
            self.session_gates.pop(mac, None)
            self.path_records.pop(mac, None)
        print(f"\n[M6] Cerrando sesión MAC={mac} — {len(flows)} flows")
        with obs.span("flow.elimination"):
            for device_id, flow_id in flows:
                ids_flows.append(flow_id)
                ids_devices.append(device_id)
                self.onos.eliminar_flow(device_id, flow_id)

            obs.event(
                Events.FLOW_REMOVED,
                attributes={
                    "user.mac": mac,
                    "devices.ids":ids_devices,
                    "flow.ids": ids_flows,
                    "flow.count": len(flows),
                }
            )
           
        self.logger.log({
            "modulo":           "M6",
            "evento":           "sesion_cerrada",
            "mac":              mac,
            "flows_eliminados": len(flows)
        })

    @staticmethod
    def _criteria_value(criteria, tipo, field):
        for criterion in criteria:
            if criterion.get("type") == tipo:
                return criterion.get(field)
        return None

    def _sesiones_activas_db_keys(self):
        """Retorna set de (mac, ip, switch, in_port) que siguen activos en DB."""
        active = set()
        if not (Config.MYSQL_SECURITY_READS_ENABLED and MYSQL_OK):
            return active
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
                SELECT mac_address, ip_asignada, switch_dpid, in_port
                FROM sesiones_activas
                WHERE estado='ACTIVA'
                """
            )
            for row in cur.fetchall():
                if not all(row.get(k) is not None for k in (
                    "mac_address", "ip_asignada", "switch_dpid", "in_port"
                )):
                    continue
                active.add((
                    str(row["mac_address"]).lower(),
                    str(row["ip_asignada"]),
                    str(row["switch_dpid"]),
                    int(row["in_port"]),
                ))
            cur.close()
            conn.close()
        except Exception as exc:
            print(f"[M6] Error leyendo sesiones activas para cleanup: {exc}")
        return active

    def cleanup_session_gates_huerfanos(self, dry_run=False):
        """
        Borra T1 session gates que siguen en ONOS pero ya no existen como
        sesiones activas en M6/DB. No toca portal, T2/T3/T4 ni control.
        """
        db_active = self._sesiones_activas_db_keys()
        stale = []
        kept = []
        adopted = []
        protected_src_ips = {
            Config.PORTAL_IP,
            Config.SERVER_CURSOS,
            Config.SERVER_NOTAS,
        }
        for device_id in self.onos.get_devices():
            for flow in self.onos.get_flows(device_id):
                if int(flow.get("tableId", -1)) != 1:
                    continue
                if int(flow.get("priority", -1)) != Config.PRIO_T1_SESSION_GATE:
                    continue
                criteria = flow.get("selector", {}).get("criteria", [])
                mac = self._criteria_value(criteria, "ETH_SRC", "mac")
                ip_src = self._criteria_value(criteria, "IPV4_SRC", "ip")
                in_port = self._criteria_value(criteria, "IN_PORT", "port")
                if not mac or not ip_src or in_port is None:
                    kept.append({
                        "device_id": device_id,
                        "flow_id": flow.get("id"),
                        "reason": "incomplete_selector",
                    })
                    continue
                ip_src = str(ip_src).split("/")[0]
                if ip_src in protected_src_ips:
                    kept.append({
                        "device_id": device_id,
                        "flow_id": flow.get("id"),
                        "mac": str(mac).lower(),
                        "ip": ip_src,
                        "reason": "server_or_portal_response_gate",
                    })
                    continue
                key = (str(mac).lower(), ip_src, device_id, int(in_port))
                if key in db_active:
                    if not dry_run:
                        with self._lock:
                            self.session_gates[key[0]] = (
                                device_id,
                                flow.get("id"),
                                time.time() + Config.SESSION_IDLE_TIMEOUT,
                            )
                            session_flows = self.flows_por_sesion.setdefault(
                                key[0], []
                            )
                            flow_ref = (device_id, flow.get("id"))
                            if flow_ref not in session_flows:
                                session_flows.append(flow_ref)
                                adopted.append({
                                    "device_id": device_id,
                                    "flow_id": flow.get("id"),
                                    "mac": key[0],
                                    "ip": key[1],
                                })
                    kept.append({
                        "device_id": device_id,
                        "flow_id": flow.get("id"),
                        "mac": key[0],
                        "ip": key[1],
                        "reason": "active_db_session",
                    })
                    continue
                stale.append({
                    "device_id": device_id,
                    "flow_id": flow.get("id"),
                    "mac": key[0],
                    "ip": key[1],
                    "in_port": key[3],
                    "priority": flow.get("priority"),
                    "tableId": flow.get("tableId"),
                })

        removed = []
        failed = []
        if not dry_run:
            for item in stale:
                ok = self.onos.eliminar_flow(item["device_id"], item["flow_id"])
                target = removed if ok else failed
                target.append(item)
            with self._lock:
                for item in stale:
                    mac = item.get("mac")
                    self.session_gates.pop(mac, None)
                    self.flows_por_sesion.pop(mac, None)
        return {
            "ok": True,
            "dry_run": bool(dry_run),
            "active_db_sessions": len(db_active),
            "stale": stale,
            "kept": kept,
            "adopted": adopted,
            "removed": removed,
            "failed": failed,
        }

    def _sesiones_activas_db_detalle(self):
        """Devuelve sesiones activas con usuario/rol para análisis de failover."""
        if not (Config.MYSQL_SECURITY_READS_ENABLED and MYSQL_OK):
            return []
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
                LEFT JOIN usuarios u ON u.id_usuario=s.id_usuario
                WHERE s.estado='ACTIVA'
                ORDER BY s.login_timestamp DESC
                """
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return rows
        except Exception as exc:
            print(f"[M6] Error leyendo sesiones activas para failover: {exc}")
            return []

    @staticmethod
    def _normalizar_failed_links(raw_links):
        normalized = []
        for link in raw_links or []:
            if not isinstance(link, dict):
                continue
            if "src" in link and "dst" in link:
                src = link.get("src") or {}
                dst = link.get("dst") or {}
            else:
                src = {
                    "device": link.get("src_device"),
                    "port": link.get("src_port"),
                }
                dst = {
                    "device": link.get("dst_device"),
                    "port": link.get("dst_port"),
                }
            if not (src.get("device") and src.get("port")
                    and dst.get("device") and dst.get("port")):
                continue
            normalized.append({
                "src": {
                    "device": str(src["device"]),
                    "port": str(src["port"]),
                },
                "dst": {
                    "device": str(dst["device"]),
                    "port": str(dst["port"]),
                },
            })
        return normalized

    @staticmethod
    def _failed_link_endpoints(failed_links):
        endpoints = set()
        for link in failed_links or []:
            for side in ("src", "dst"):
                ep = link.get(side, {})
                dev, port = ep.get("device"), ep.get("port")
                if dev and port is not None:
                    endpoints.add((str(dev), str(port)))
        return endpoints

    @staticmethod
    def _record_path_to_steps(path):
        steps = []
        for step in path or []:
            if isinstance(step, dict):
                dev = step.get("device_id")
                in_port = step.get("in_port")
                out_port = step.get("out_port")
            else:
                try:
                    dev, in_port, out_port = step
                except (TypeError, ValueError):
                    continue
            if dev is None or in_port is None or out_port is None:
                continue
            steps.append((str(dev), int(in_port), int(out_port)))
        return steps

    def _path_record_para_permiso(self, mac, dst_ip, tcp_port, target_table):
        mac_key = (mac or "").lower()
        perm_key = f"{str(target_table).upper()}:{dst_ip}:{int(tcp_port)}"
        with self._lock:
            record = self.path_records.get(mac_key, {}).get(perm_key)
            if record:
                return dict(record)
        return None

    def _path_usa_falla(self, path, failed_devices, failed_links):
        failed_devices = {str(d) for d in (failed_devices or []) if d}
        endpoints = self._failed_link_endpoints(failed_links)
        for dev, in_port, out_port in self._record_path_to_steps(path):
            if str(dev) in failed_devices:
                return True
            if (str(dev), str(in_port)) in endpoints:
                return True
            if (str(dev), str(out_port)) in endpoints:
                return True
        return False

    @staticmethod
    def _flow_usa_ip_academica(flow):
        academic_ips = {Config.SERVER_CURSOS, Config.SERVER_NOTAS}
        for criterion in flow.get("selector", {}).get("criteria", []):
            ip = criterion.get("ip")
            if ip and str(ip).split("/")[0] in academic_ips:
                return True
        return False

    @staticmethod
    def _flow_usa_endpoint(flow, device_id, failed_ports):
        failed_ports = {str(p) for p in failed_ports}
        for criterion in flow.get("selector", {}).get("criteria", []):
            if criterion.get("type") == "IN_PORT":
                if str(criterion.get("port")) in failed_ports:
                    return True
        for instruction in flow.get("treatment", {}).get("instructions", []):
            if instruction.get("type") == "OUTPUT":
                if str(instruction.get("port")) in failed_ports:
                    return True
        return False

    @staticmethod
    def _shared_key_usa_falla(key, failed_devices, failed_links):
        failed_devices = {str(d) for d in (failed_devices or []) if d}
        endpoints = M6Translator._failed_link_endpoints(failed_links)
        if not isinstance(key, tuple) or len(key) < 2:
            return False

        prefix = key[0]
        try:
            if prefix in {
                "fwd-core-server", "ret-core-server",
                "portal-core-dst", "portal-core-src",
            }:
                device_id = str(key[1])
                in_port, out_port = str(key[2]), str(key[3])
                return (
                    device_id in failed_devices
                    or (device_id, in_port) in endpoints
                    or (device_id, out_port) in endpoints
                )
            if prefix == "t2-edge-fwd-vlan-dst":
                device_id = str(key[1])
                out_port = str(key[5])
                return (
                    device_id in failed_devices
                    or (device_id, out_port) in endpoints
                )
            if prefix == "portal-edge-t1-dst":
                device_id = str(key[1])
                out_port = str(key[2])
                return (
                    device_id in failed_devices
                    or (device_id, out_port) in endpoints
                )
        except (IndexError, TypeError, ValueError):
            return False
        return False

    def _limpiar_flows_compartidos_por_falla(self, failed_devices, failed_links):
        """
        Limpia solo flows de datos compartidos que usan el switch/puerto caido.
        No toca ARP/DHCP/LLDP/BDDP, GRE ni OUTPUT:NORMAL. La busqueda por ONOS
        es acotada a los endpoints de la falla y a IPs academicas.
        """
        failed_devices = {str(d) for d in (failed_devices or []) if d}
        endpoints = self._failed_link_endpoints(failed_links)
        removed, failed = [], []

        with self._lock:
            stale_keys = [
                key for key in self.flows_t0_shared
                if self._shared_key_usa_falla(key, failed_devices, failed_links)
            ]
            stale_flows = [
                (key, self.flows_t0_shared.pop(key))
                for key in stale_keys
            ]

        for key, (device_id, flow_id, _expires_at) in stale_flows:
            if device_id in failed_devices:
                failed.append({
                    "device_id": device_id,
                    "flow_id": flow_id,
                    "reason": "device_unavailable",
                    "cache_key": str(key),
                })
                continue
            if self.onos.eliminar_flow(device_id, flow_id):
                removed.append({
                    "device_id": device_id,
                    "flow_id": flow_id,
                    "source": "shared_cache",
                    "cache_key": str(key),
                })
            else:
                failed.append({
                    "device_id": device_id,
                    "flow_id": flow_id,
                    "source": "shared_cache",
                    "cache_key": str(key),
                })

        ports_by_device = defaultdict(set)
        for device_id, port in endpoints:
            if device_id not in failed_devices:
                ports_by_device[device_id].add(str(port))

        for device_id, ports in ports_by_device.items():
            for flow in self.onos.get_flows(device_id):
                if flow.get("appId") != "org.onosproject.rest":
                    continue
                if not self._flow_usa_ip_academica(flow):
                    continue
                if not self._flow_usa_endpoint(flow, device_id, ports):
                    continue
                flow_id = flow.get("id")
                if not flow_id:
                    continue
                if self.onos.eliminar_flow(device_id, flow_id):
                    removed.append({
                        "device_id": device_id,
                        "flow_id": flow_id,
                        "source": "onos_endpoint_scan",
                    })
                else:
                    failed.append({
                        "device_id": device_id,
                        "flow_id": flow_id,
                        "source": "onos_endpoint_scan",
                    })

        if removed or failed:
            print(
                f"[M6] Failover cleanup shared flows: "
                f"removed={len(removed)} failed={len(failed)}"
            )
        return {"removed": removed, "failed": failed}

    def _topology_snapshot(self):
        devices_raw = self.onos.get_devices_raw()
        links = self.onos.get_links()
        hosts = self.onos.get_hosts()
        available = [
            d.get("id") for d in devices_raw
            if d.get("available") is True
        ]
        unavailable = [
            d.get("id") for d in devices_raw
            if d.get("available") is not True
        ]
        return {
            "ok": True,
            "devices": devices_raw,
            "available_devices": available,
            "unavailable_devices": unavailable,
            "links": links,
            "links_count": len(links),
            "hosts_count": len(hosts),
            "onos_reads_enabled": Config.ONOS_READS_ENABLED,
            "failover_analysis_enabled": Config.FAILOVER_ANALYSIS_ENABLED,
            "failover_auto_reinstall_enabled": (
                Config.FAILOVER_AUTO_REINSTALL_ENABLED
            ),
        }

    def estado_failover_topologia(self):
        if not Config.FAILOVER_ANALYSIS_ENABLED:
            return {
                "ok": True,
                "disabled": True,
                "reason": "failover_analysis_disabled",
            }
        return self._topology_snapshot()

    def _politicas_para_sesion_failover(self, session):
        payload_opa = {
            "input": {
                "codigo_pucp": session.get("codigo_pucp") or "",
                "rol": session.get("nombre_rol") or "",
                "ip_asignada": session.get("ip_asignada"),
                "vlan_id": session.get("vlan_id"),
                "mac_address": session.get("mac_address"),
                "switch_dpid": session.get("switch_dpid"),
            }
        }
        return self.policies.get_policies(payload_opa)

    def analizar_failover(self, data):
        """
        Analiza impacto de caídas simuladas. No borra ni instala flows.
        Body:
          {
            "failed_devices": ["of:..."],
            "failed_links": [
              {"src_device":"of:...","src_port":1,
               "dst_device":"of:...","dst_port":2}
            ]
          }
        """
        if not Config.FAILOVER_ANALYSIS_ENABLED:
            return {
                "ok": True,
                "disabled": True,
                "reason": "failover_analysis_disabled",
            }
        failed_devices = {
            str(d) for d in (data.get("failed_devices") or []) if d
        }
        failed_links = self._normalizar_failed_links(
            data.get("failed_links") or []
        )
        links = self.onos.get_links()
        sessions = self._sesiones_activas_db_detalle()
        impacted = []
        unaffected = 0
        recoverable = 0
        unavailable = 0

        for session in sessions:
            src_host = {
                "mac": session.get("mac_address"),
                "switch_dpid": session.get("switch_dpid"),
                "in_port": int(session.get("in_port") or 0),
            }
            if not src_host["switch_dpid"] or not src_host["in_port"]:
                impacted.append({
                    "session_id": session.get("id_sesion"),
                    "ip": session.get("ip_asignada"),
                    "mac": session.get("mac_address"),
                    "status": "invalid_session_binding",
                    "recoverable": False,
                })
                unavailable += 1
                continue

            politicas = self._politicas_para_sesion_failover(session)
            session_items = []
            session_recoverable = True
            session_impacted = False
            for permiso in politicas.get("permisos", []):
                dst_ip = permiso.get("ip_dst")
                tabla_permiso = str(permiso.get("tabla") or "T2").upper()
                if tabla_permiso not in ("T2", "T3"):
                    tabla_permiso = "T2"
                dst_host = self.onos.get_host_by_ip(dst_ip)
                if not dst_host:
                    session_items.append({
                        "dst_ip": dst_ip,
                        "status": "destination_not_learned",
                        "recoverable": False,
                    })
                    session_impacted = True
                    session_recoverable = False
                    continue

                for tcp_port in permiso.get("puertos") or []:
                    stored = self._path_record_para_permiso(
                        session.get("mac_address"), dst_ip, tcp_port,
                        tabla_permiso
                    )
                    if stored:
                        ida = self._record_path_to_steps(stored.get("ida"))
                        retorno = self._record_path_to_steps(
                            stored.get("retorno")
                        )
                    else:
                        ida = self.onos.calcular_pasos(
                            src_host["switch_dpid"], src_host["in_port"],
                            dst_host["switch_dpid"], dst_host["in_port"]
                        )
                        retorno = self.onos.calcular_pasos(
                            dst_host["switch_dpid"], dst_host["in_port"],
                            src_host["switch_dpid"], src_host["in_port"]
                        )
                    affected = (
                        self._path_usa_falla(ida, failed_devices, failed_links)
                        or self._path_usa_falla(
                            retorno, failed_devices, failed_links
                        )
                    )
                    alt_ida = self.onos.calcular_pasos_con_fallas(
                        src_host["switch_dpid"], src_host["in_port"],
                        dst_host["switch_dpid"], dst_host["in_port"],
                        links, failed_devices, failed_links
                    )
                    alt_retorno = self.onos.calcular_pasos_con_fallas(
                        dst_host["switch_dpid"], dst_host["in_port"],
                        src_host["switch_dpid"], src_host["in_port"],
                        links, failed_devices, failed_links
                    )
                    item_recoverable = bool(alt_ida and alt_retorno)
                    status = "unaffected"
                    if affected:
                        session_impacted = True
                        status = "recoverable" if item_recoverable else "unavailable"
                    if affected and not item_recoverable:
                        session_recoverable = False
                    session_items.append({
                        "dst_ip": dst_ip,
                        "tcp_port": int(tcp_port),
                        "table": tabla_permiso,
                        "status": status,
                        "recoverable": item_recoverable,
                        "path_source": "installed_record" if stored else "onos_current",
                        "current_ida": self._path_to_dicts(ida),
                        "current_retorno": self._path_to_dicts(retorno),
                        "alternative_ida": self._path_to_dicts(alt_ida),
                        "alternative_retorno": self._path_to_dicts(alt_retorno),
                    })

            if not session_impacted:
                unaffected += 1
                continue
            if session_recoverable:
                recoverable += 1
            else:
                unavailable += 1
            impacted.append({
                "session_id": session.get("id_sesion"),
                "codigo_pucp": session.get("codigo_pucp"),
                "role": session.get("nombre_rol"),
                "ip": session.get("ip_asignada"),
                "mac": session.get("mac_address"),
                "switch_dpid": session.get("switch_dpid"),
                "in_port": session.get("in_port"),
                "recoverable": session_recoverable,
                "permissions": session_items,
            })

        return {
            "ok": True,
            "dry_run": True,
            "auto_reinstall_enabled": Config.FAILOVER_AUTO_REINSTALL_ENABLED,
            "failed_devices": sorted(failed_devices),
            "failed_links": failed_links,
            "gre": self.estado_monitoring_gre(
                failed_devices=failed_devices,
                failed_links=failed_links,
            ),
            "sessions_total": len(sessions),
            "summary": {
                "unaffected_sessions": unaffected,
                "impacted_sessions": len(impacted),
                "recoverable_sessions": recoverable,
                "unavailable_sessions": unavailable,
            },
            "impacted": impacted,
            "note": (
                "Este endpoint no instala ni elimina flows. Sirve para validar "
                "failover antes de activar reinstalacion automatica."
            ),
        }

    def _permiso_ya_estaba_activo(self, mac, dst_ip, tcp_port, target_table):
        mac_key = (mac or "").lower()
        perm_key = f"{str(target_table).upper()}:{dst_ip}:{int(tcp_port)}"
        with self._lock:
            return perm_key in self.path_records.get(mac_key, {})

    def _plan_reinstalacion_sesion(self, session):
        mac = (session.get("mac_address") or "").lower()
        src_ip = session.get("ip_asignada")
        switch_dpid = session.get("switch_dpid")
        in_port = int(session.get("in_port") or 0)
        vlan_id = int(session.get("vlan_id") or 0)
        if not (mac and src_ip and switch_dpid and in_port and vlan_id):
            return {
                "ok": False,
                "reason": "invalid_session_binding",
                "session_id": session.get("id_sesion"),
                "ip": src_ip,
                "mac": mac,
            }

        politicas = self._politicas_para_sesion_failover(session)
        permisos = []
        for permiso in politicas.get("permisos", []):
            dst_ip = permiso.get("ip_dst")
            tabla_permiso = str(permiso.get("tabla") or "T2").upper()
            if tabla_permiso not in ("T2", "T3"):
                tabla_permiso = "T2"
            for tcp_port in permiso.get("puertos") or []:
                if tabla_permiso == "T3" and not self._permiso_ya_estaba_activo(
                    mac, dst_ip, tcp_port, tabla_permiso
                ):
                    continue
                permisos.append({
                    "dst_ip": dst_ip,
                    "tcp_port": int(tcp_port),
                    "table": tabla_permiso,
                    "expires_at": permiso.get("expires_at"),
                })

        return {
            "ok": True,
            "session_id": session.get("id_sesion"),
            "codigo_pucp": session.get("codigo_pucp"),
            "role": session.get("nombre_rol"),
            "ip": src_ip,
            "mac": mac,
            "switch_dpid": switch_dpid,
            "in_port": in_port,
            "vlan_id": vlan_id,
            "permissions": permisos,
        }

    def _limpiar_flows_sesion_para_recovery(self, mac):
        mac_key = (mac or "").lower()
        with self._lock:
            flows = self.flows_por_sesion.pop(mac_key, [])
            self.session_gates.pop(mac_key, None)
            self.path_records.pop(mac_key, None)
        removed, failed = [], []
        for device_id, flow_id in flows:
            if self.onos.eliminar_flow(device_id, flow_id):
                removed.append({"device_id": device_id, "flow_id": flow_id})
            else:
                failed.append({"device_id": device_id, "flow_id": flow_id})
        return removed, failed

    def _cooldown_failover_recovery(self, mac):
        cooldown = Config.FAILOVER_RECOVERY_COOLDOWN
        if cooldown <= 0:
            return False, 0
        now = time.time()
        mac_key = (mac or "").lower()
        with self._lock:
            last = self._failover_recovery_seen.get(mac_key)
            stale = [
                key for key, ts in self._failover_recovery_seen.items()
                if now - ts > max(cooldown * 6, 60)
            ]
            for key in stale:
                self._failover_recovery_seen.pop(key, None)
            if last and now - last < cooldown:
                return True, int(cooldown - (now - last))
            self._failover_recovery_seen[mac_key] = now
        return False, 0

    def recuperar_failover(self, data):
        """
        Reinstala caminos de sesiones activas de forma controlada.
        Por seguridad, apply=true solo trabaja contra la topologia real actual;
        fallas simuladas se aceptan solo como dry-run con /analyze.
        """
        if not Config.FAILOVER_ANALYSIS_ENABLED:
            return {
                "ok": True,
                "disabled": True,
                "reason": "failover_analysis_disabled",
            }

        apply = bool(data.get("apply") is True)
        failed_devices = data.get("failed_devices") or []
        failed_links = data.get("failed_links") or []
        cleanup_failed_devices = data.get("cleanup_failed_devices") or []
        cleanup_failed_links = self._normalizar_failed_links(
            data.get("cleanup_failed_links") or []
        )
        if failed_devices or failed_links:
            analysis = self.analizar_failover(data)
            analysis["recover_endpoint"] = "dry_run_only"
            analysis["note"] = (
                "Las fallas simuladas no se aplican. Para reinstalar flows, "
                "ejecuta recover con apply=true sin failed_devices/failed_links, "
                "despues de que ONOS ya vea la topologia real."
            )
            return analysis

        if apply and not Config.FAILOVER_AUTO_REINSTALL_ENABLED:
            return {
                "ok": False,
                "error": "failover_auto_reinstall_disabled",
                "dry_run": False,
                "applied": False,
                "hint": (
                    "Activa FAILOVER_AUTO_REINSTALL_ENABLED=true solo para "
                    "una prueba controlada."
                ),
            }

        sessions = self._sesiones_activas_db_detalle()
        requested_ips = {
            str(ip) for ip in (data.get("src_ips") or []) if ip
        }
        requested_macs = {
            str(mac).lower() for mac in (data.get("macs") or []) if mac
        }
        if requested_ips or requested_macs:
            sessions = [
                s for s in sessions
                if s.get("ip_asignada") in requested_ips
                or (s.get("mac_address") or "").lower() in requested_macs
            ]

        limit = max(1, Config.FAILOVER_RECOVERY_MAX_SESSIONS)
        limited = len(sessions) > limit
        sessions = sessions[:limit]

        cleanup_result = {"removed": [], "failed": []}
        if apply and (cleanup_failed_devices or cleanup_failed_links):
            cleanup_result = self._limpiar_flows_compartidos_por_falla(
                cleanup_failed_devices,
                cleanup_failed_links,
            )
        gre_result = (
            self.asegurar_monitoring_gre(
                failed_devices=cleanup_failed_devices,
                failed_links=cleanup_failed_links,
                cleanup_conflicts=apply,
            )
            if apply else
            self.estado_monitoring_gre(
                failed_devices=cleanup_failed_devices,
                failed_links=cleanup_failed_links,
            )
        )

        planned, reinstalled, skipped, failed = [], [], [], []
        for session in sessions:
            plan = self._plan_reinstalacion_sesion(session)
            planned.append(plan)
            if not apply:
                continue
            if not plan.get("ok"):
                failed.append(plan)
                continue
            cooldown, retry_after = self._cooldown_failover_recovery(plan["mac"])
            if cooldown:
                skipped.append({
                    "mac": plan["mac"],
                    "ip": plan["ip"],
                    "reason": "cooldown",
                    "retry_after_seconds": retry_after,
                })
                continue

            removed, remove_failed = self._limpiar_flows_sesion_para_recovery(
                plan["mac"]
            )
            host_origen = {
                "mac": plan["mac"],
                "switch_dpid": plan["switch_dpid"],
                "in_port": plan["in_port"],
            }
            self._asegurar_pipeline_fallback_en_borde(plan["switch_dpid"])
            gate = self._instalar_session_gate(
                plan["mac"], plan["switch_dpid"], plan["in_port"],
                plan["vlan_id"], ip_src=plan["ip"]
            )
            installed = 1 if gate else 0
            details = []
            for permiso in plan["permissions"]:
                dst_host = self.onos.get_host_by_ip(permiso["dst_ip"])
                if not dst_host:
                    details.append({
                        **permiso,
                        "installed": 0,
                        "status": "destination_not_learned",
                    })
                    continue
                count = self._instalar_camino_tcp(
                    plan["mac"], host_origen, dst_host,
                    plan["ip"], permiso["dst_ip"], permiso["tcp_port"],
                    plan["vlan_id"], Config.DATA_FLOW_TIMEOUT,
                    target_table=permiso["table"],
                    expires_at=permiso.get("expires_at"),
                )
                installed += count
                details.append({
                    **permiso,
                    "installed": count,
                    "status": "ok" if count else "install_failed",
                })

            reinstalled.append({
                "session_id": plan["session_id"],
                "ip": plan["ip"],
                "mac": plan["mac"],
                "removed_flows": len(removed),
                "remove_failed": remove_failed,
                "installed_flows": installed,
                "permissions": details,
            })

        return {
            "ok": True,
            "dry_run": not apply,
            "applied": apply,
            "auto_reinstall_enabled": Config.FAILOVER_AUTO_REINSTALL_ENABLED,
            "sessions_seen": len(sessions),
            "limited": limited,
            "max_sessions": limit,
            "cleanup": cleanup_result,
            "gre": gre_result,
            "planned": planned,
            "reinstalled": reinstalled,
            "skipped": skipped,
            "failed": failed,
            "note": (
                "Sin apply=true no se instalan ni borran flows."
                if not apply else
                "Se reinstalaron solo flows registrados por sesion; no se "
                "tocaron portal ni control; GRE se reaseguro solo si era "
                "necesario por la topologia actual."
            ),
        }

    def _failover_event_key(self, data, failed_devices, failed_links):
        event_type = str(data.get("event_type") or data.get("type") or "unknown")
        return (
            event_type.lower(),
            tuple(sorted(str(d) for d in failed_devices)),
            tuple(
                sorted(
                    (
                        str(link.get("src", {}).get("device")),
                        str(link.get("src", {}).get("port")),
                        str(link.get("dst", {}).get("device")),
                        str(link.get("dst", {}).get("port")),
                    )
                    for link in failed_links
                )
            ),
        )

    def _failover_event_duplicado(self, key):
        window = Config.FAILOVER_EVENT_DEDUP_WINDOW
        if window <= 0:
            return False, 0
        now = time.time()
        with self._lock:
            last = self._failover_event_seen.get(key)
            stale = [
                item_key
                for item_key, ts in self._failover_event_seen.items()
                if now - ts > max(window * 4, 60)
            ]
            for item_key in stale:
                self._failover_event_seen.pop(item_key, None)
            if last and now - last < window:
                return True, int(window - (now - last))
            self._failover_event_seen[key] = now
        return False, 0

    def _failed_devices_desde_topologia(self):
        try:
            return [
                d.get("id")
                for d in self.onos.get_devices_raw()
                if d.get("id") and d.get("available") is not True
            ]
        except Exception:
            return []

    @staticmethod
    def _ips_recuperables_desde_analisis(analysis):
        ips = []
        for item in analysis.get("impacted") or []:
            if item.get("recoverable") and item.get("ip"):
                ips.append(item["ip"])
        return sorted(set(ips))

    def procesar_failover_event(self, data):
        """
        Entrada para eventos reales de topologia. No hace polling ni crea hilos.
        Si auto-reinstall esta apagado, solo analiza. Si esta encendido, aplica
        recovery a las sesiones recuperables calculadas por el analisis.
        """
        if not Config.FAILOVER_ANALYSIS_ENABLED:
            return {
                "ok": True,
                "disabled": True,
                "reason": "failover_analysis_disabled",
            }

        event_type = str(data.get("event_type") or data.get("type") or "").lower()
        failed_devices = {
            str(d) for d in (data.get("failed_devices") or []) if d
        }
        device_id = data.get("device_id") or data.get("device")
        if device_id and event_type in {"device_down", "device_removed", "device_unavailable"}:
            failed_devices.add(str(device_id))
        if not failed_devices and event_type in {"device_down", "device_removed", "device_unavailable", "topology_change"}:
            failed_devices.update(
                str(d) for d in self._failed_devices_desde_topologia() if d
            )
        failed_links = self._normalizar_failed_links(
            data.get("failed_links") or []
        )

        event_key = self._failover_event_key(data, failed_devices, failed_links)
        duplicate, retry_after = self._failover_event_duplicado(event_key)
        if duplicate:
            return {
                "ok": True,
                "duplicate": True,
                "retry_after_seconds": retry_after,
                "applied": False,
                "auto_reinstall_enabled": Config.FAILOVER_AUTO_REINSTALL_ENABLED,
            }

        analysis_payload = {
            "failed_devices": sorted(failed_devices),
            "failed_links": failed_links,
        }
        analysis = self.analizar_failover(analysis_payload)
        recoverable_ips = self._ips_recuperables_desde_analisis(analysis)
        gre_result = (
            self.asegurar_monitoring_gre(
                failed_devices=sorted(failed_devices),
                failed_links=failed_links,
                cleanup_conflicts=True,
            )
            if Config.FAILOVER_AUTO_REINSTALL_ENABLED else
            analysis.get("gre")
        )
        result = {
            "ok": bool(analysis.get("ok")),
            "event_type": event_type or "unknown",
            "failed_devices": sorted(failed_devices),
            "failed_links": failed_links,
            "auto_reinstall_enabled": Config.FAILOVER_AUTO_REINSTALL_ENABLED,
            "recoverable_ips": recoverable_ips,
            "gre": gre_result,
            "analysis": analysis,
            "applied": False,
        }

        if not Config.FAILOVER_AUTO_REINSTALL_ENABLED:
            result["reason"] = "auto_reinstall_disabled"
            return result
        if not recoverable_ips:
            result["reason"] = "no_recoverable_sessions"
            result["applied"] = bool(
                (gre_result or {}).get("installed")
                or (gre_result or {}).get("removed_conflicts")
            )
            return result

        recovery = self.recuperar_failover({
            "apply": True,
            "src_ips": recoverable_ips,
            "cleanup_failed_devices": sorted(failed_devices),
            "cleanup_failed_links": failed_links,
        })
        result["recovery"] = recovery
        result["applied"] = bool(
            recovery.get("applied")
            or (gre_result or {}).get("installed")
            or (gre_result or {}).get("removed_conflicts")
        )
        result["ok"] = bool(recovery.get("ok"))
        return result

    # ── Mitigación de ataques (M4) ────────────────────────────────────────────

    def _buscar_sesion_db_por_ip(self, ip):
        if not (Config.MYSQL_SECURITY_READS_ENABLED and MYSQL_OK):
            return None
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
                LEFT JOIN usuarios u ON u.id_usuario=s.id_usuario
                WHERE s.ip_asignada=%s
                  AND s.estado='ACTIVA'
                ORDER BY s.login_timestamp DESC
                LIMIT 1
                """,
                (ip,),
            )
            row = cur.fetchone()
            cur.close()
            conn.close()
            return row
        except Exception as exc:
            print(f"[M6] Error buscando sesion activa por IP {ip}: {exc}")
            return None

    def _buscar_sesion_db_por_location(self, device_id, in_port):
        if not (Config.MYSQL_SECURITY_READS_ENABLED and MYSQL_OK):
            return None
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
                LEFT JOIN usuarios u ON u.id_usuario=s.id_usuario
                WHERE s.switch_dpid=%s
                  AND s.in_port=%s
                  AND s.estado='ACTIVA'
                ORDER BY s.login_timestamp DESC
                LIMIT 1
                """,
                (device_id, int(in_port)),
            )
            row = cur.fetchone()
            cur.close()
            conn.close()
            return row
        except Exception as exc:
            print(f"[M6] Error buscando sesion activa por puerto: {exc}")
            return None

    @staticmethod
    def _rate_limit_key(device_id, port, event):
        return f"{device_id}:{int(port)}:{event or 'port_traffic_stress'}"

    def _purgar_rate_limits_expirados(self):
        now = datetime.now(timezone.utc)
        expired = []
        with self._lock:
            for key, item in list(self.rate_limits.items()):
                expires_at = self._parse_iso_datetime(item.get("expires_at"))
                if expires_at and expires_at <= now:
                    expired.append((key, self.rate_limits.pop(key)))
        for _key, item in expired:
            self.onos.eliminar_flow(item.get("device"), item.get("flow_id"))
            self.onos.eliminar_meter(item.get("device"), item.get("meter_id"))
        return len(expired)

    def _resolver_rate_limit_target(self, device_id, port):
        session = self._buscar_sesion_db_por_location(device_id, port)
        if session:
            return {
                "scope": "host_session",
                "src_ip": session.get("ip_asignada"),
                "src_mac": session.get("mac_address"),
                "device": device_id,
                "port": int(port),
                "username": session.get("codigo_pucp"),
            }

        host = self.onos.get_host_by_location(device_id, port)
        if host and host.get("mac"):
            return {
                "scope": "onos_host",
                "src_ip": host.get("ip"),
                "src_mac": host.get("mac"),
                "device": device_id,
                "port": int(port),
                "username": None,
            }

        return {
            "scope": "port_only",
            "src_ip": None,
            "src_mac": None,
            "device": device_id,
            "port": int(port),
            "username": None,
            "warning": "no se encontro sesion/host ONOS; se limita el puerto completo",
        }

    def procesar_rate_limit_event(self, alerta):
        self._purgar_rate_limits_expirados()
        event = str(alerta.get("event") or "port_traffic_stress")
        status = str(alerta.get("status") or "firing").lower()
        device_id = alerta.get("device") or alerta.get("device_id")
        port = alerta.get("port") or alerta.get("in_port")
        if not device_id or port is None:
            return {"ok": False, "error": "se requiere device y port"}
        try:
            port = int(port)
        except (TypeError, ValueError):
            return {"ok": False, "error": "port debe ser numerico"}

        if status in {"resolved", "inactive", "ok", "cleared"}:
            return self.remover_rate_limit({
                "device": device_id,
                "port": port,
                "event": event,
            })
        if status != "firing":
            return {
                "ok": False,
                "error": "status no soportado",
                "status": status,
                "supported": ["firing", "resolved"],
            }

        key = self._rate_limit_key(device_id, port, event)
        now = datetime.now(timezone.utc)
        with self._lock:
            existing = dict(self.rate_limits.get(key) or {})
        expires_at = self._parse_iso_datetime(existing.get("expires_at"))
        if existing and expires_at and expires_at > now:
            existing.update({
                "ok": True,
                "status": "already_active",
                "remaining_seconds": int((expires_at - now).total_seconds()),
            })
            return existing

        target = self._resolver_rate_limit_target(device_id, port)
        ttl = Config.RATE_LIMIT_DEFAULT_TTL
        rate_pps = Config.RATE_LIMIT_DEFAULT_PPS
        meter_id = self.onos.crear_meter_rate_limit(device_id, rate_pps=rate_pps)
        if not meter_id:
            return {
                "ok": False,
                "error": "no se pudo crear meter en ONOS",
                "device": device_id,
                "port": port,
                "rate_pps": rate_pps,
            }

        flow = self.builder.t0_rate_limit_port(
            device_id,
            port,
            meter_id,
            src_mac=target.get("src_mac"),
            src_ip=target.get("src_ip"),
            ttl=ttl,
        )
        flow_id = self.onos.instalar_flow(device_id, flow)
        if not flow_id:
            self.onos.eliminar_meter(device_id, meter_id)
            return {
                "ok": False,
                "error": "no se pudo instalar flow rate-limit",
                "device": device_id,
                "port": port,
                "meter_id": meter_id,
            }

        expires_at = now + timedelta(seconds=ttl)
        result = {
            "ok": True,
            "status": (
                "EXECUTED"
                if Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
                else "SIMULATED"
            ),
            "key": key,
            "event": event,
            "severity": alerta.get("severity"),
            "category": alerta.get("category"),
            "device": device_id,
            "port": port,
            "scope": target.get("scope"),
            "src_ip": target.get("src_ip"),
            "src_mac": target.get("src_mac"),
            "username": target.get("username"),
            "warning": target.get("warning"),
            "meter_id": str(meter_id),
            "flow_id": str(flow_id),
            "rate_pps": rate_pps,
            "ttl_seconds": ttl,
            "table": 0,
            "priority": Config.PRIO_T0_RATE_LIMIT,
            "metrics": alerta.get("metrics") or {},
            "startsAt": alerta.get("startsAt"),
            "expires_at": expires_at.isoformat(),
            "flow": flow,
        }
        with self._lock:
            self.rate_limits[key] = dict(result)
        self.logger.log({
            "modulo": "M6",
            "evento": "rate_limit_applied",
            "key": key,
            "device": device_id,
            "port": port,
            "scope": target.get("scope"),
            "src_ip": target.get("src_ip"),
            "src_mac": target.get("src_mac"),
            "rate_pps": rate_pps,
            "ttl": ttl,
        })
        return result

    def remover_rate_limit(self, data):
        self._purgar_rate_limits_expirados()
        device_id = data.get("device") or data.get("device_id")
        port = data.get("port") or data.get("in_port")
        event = data.get("event") or "port_traffic_stress"
        if not device_id or port is None:
            return {"ok": False, "error": "se requiere device y port"}
        try:
            key = self._rate_limit_key(device_id, int(port), event)
        except (TypeError, ValueError):
            return {"ok": False, "error": "port debe ser numerico"}
        with self._lock:
            item = self.rate_limits.pop(key, None)
        if not item:
            return {"ok": False, "error": "rate-limit no encontrado", "key": key}
        flow_ok = self.onos.eliminar_flow(item.get("device"), item.get("flow_id"))
        meter_ok = self.onos.eliminar_meter(item.get("device"), item.get("meter_id"))
        item.update({
            "ok": bool(flow_ok and meter_ok),
            "status": "REMOVED" if flow_ok and meter_ok else "REMOVE_FAILED",
            "removed_at": datetime.now(timezone.utc).isoformat(),
        })
        return item

    def listar_rate_limits(self, active_only=False):
        self._purgar_rate_limits_expirados()
        now = datetime.now(timezone.utc)
        with self._lock:
            items = [dict(item) for item in self.rate_limits.values()]
        for item in items:
            expires_at = self._parse_iso_datetime(item.get("expires_at"))
            remaining = None
            if expires_at:
                remaining = max(0, int((expires_at - now).total_seconds()))
            item["remaining_seconds"] = remaining
            item["active"] = remaining is None or remaining > 0
        if active_only:
            items = [item for item in items if item.get("active")]
        return items

    def _resolver_contexto_mitigacion(self, alerta):
        src_ip = alerta.get("src_ip") or alerta.get("ip_atacante")
        if not src_ip:
            return None

        if alerta.get("simulated_session"):
            src_mac = alerta.get("src_mac") or alerta.get("mac_atacante")
            switch_dpid = alerta.get("switch_dpid")
            in_port = alerta.get("in_port")
            if src_mac and switch_dpid and in_port is not None:
                return {
                    "ip_asignada": src_ip,
                    "mac_address": src_mac,
                    "switch_dpid": switch_dpid,
                    "in_port": int(in_port),
                    "codigo_pucp": alerta.get("codigo_pucp", "SIMULATED"),
                }

        session = self._buscar_sesion_db_por_ip(src_ip)
        if session:
            return session
        return None

    def _normalizar_politica_mitigacion(self, alerta):
        sid = alerta.get("sid") or alerta.get("signature_id")
        try:
            sid = int(sid) if sid is not None else None
        except (TypeError, ValueError):
            sid = None
        policy = Config.SECURITY_MITIGATION_POLICIES.get(sid)
        explicit_action = alerta.get("mitigation_action")
        if not policy and not explicit_action:
            return sid, None, None, None
        policy = dict(policy or {})
        action = str(explicit_action or policy["action"])
        ttl = int(alerta.get("ttl_segundos") or policy.get("ttl", 600))
        dst_port = alerta.get("dst_port") or policy.get("dst_port")
        return sid, action, ttl, dst_port

    def procesar_alerta_seguridad(self, alerta):
        """
        Recibe una alerta normalizada de M4/Suricata, resuelve la sesión activa
        por IP origen y aplica un DROP T0 solo en el switch de borde usuario.
        """
        incident_id = alerta.get("incident_id") or str(uuid4())
        src_ip = alerta.get("src_ip") or alerta.get("ip_atacante")
        if not src_ip:
            return {"ok": False, "error": "falta src_ip"}

        session = self._resolver_contexto_mitigacion(alerta)
        if not session:
            return {
                "ok": False,
                "error": "sesion activa no encontrada para src_ip",
                "src_ip": src_ip,
            }

        sid, action, ttl, dst_port = self._normalizar_politica_mitigacion(alerta)
        if not action:
            return {
                "ok": False,
                "error": "sid no soportado para mitigacion",
                "sid": sid,
            }

        dst_ip = alerta.get("dst_ip")
        proto = str(alerta.get("proto") or alerta.get("protocol") or "").upper()
        if action == "block_icmp":
            proto, dst_ip, dst_port = "ICMP", None, None
        elif action == "block_tcp_port":
            proto, dst_ip = "TCP", None
        elif action == "block_tcp_to_dest":
            proto, dst_port = "TCP", None
        elif action == "block_tcp_to_dest_port":
            proto = "TCP"
        elif action == "block_all_ip":
            proto, dst_ip, dst_port = None, None, None

        switch_dpid = session.get("switch_dpid")
        in_port = session.get("in_port")
        mac = session.get("mac_address")
        if not switch_dpid or in_port is None or not mac:
            return {
                "ok": False,
                "error": "sesion activa incompleta para mitigacion",
                "src_ip": src_ip,
            }

        flow = self.builder.t0_bloqueo_ataque(
            switch_dpid,
            ip_atacante=src_ip,
            mac_atacante=mac,
            in_port=int(in_port),
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            ttl=ttl,
            prio=int(alerta.get("prioridad") or Config.PRIO_T0_ATAQUE),
        )
        flow_id = self.onos.instalar_flow(switch_dpid, flow)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        status = (
            "EXECUTED"
            if Config.NETWORK_ACTIONS_ENABLED and Config.ONOS_WRITES_ENABLED
            else "SIMULATED"
        )
        result = {
            "ok": bool(flow_id),
            "incident_id": incident_id,
            "action_id": str(uuid4()),
            "status": status,
            "sid": sid,
            "mitigation_action": action,
            "flow_ids": [flow_id] if flow_id else [],
            "devices": [switch_dpid] if flow_id else [],
            "flows": [flow] if flow_id else [],
            "src_ip": src_ip,
            "src_mac": mac,
            "switch_dpid": switch_dpid,
            "in_port": int(in_port),
            "expires_at": expires_at.isoformat(),
        }
        with self._lock:
            self.mitigaciones[incident_id] = {**result, "active": True}
        self.logger.log({
            "modulo": "M6",
            "evento": "security_mitigation_applied",
            "incident_id": incident_id,
            "sid": sid,
            "action": action,
            "src_ip": src_ip,
            "mac": mac,
            "switch_dpid": switch_dpid,
            "in_port": int(in_port),
            "ttl": ttl,
            "status": status,
        })
        return result

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
        threading.Thread(
            target=self._marcar_incidente_m4_expirado,
            args=(incident_id,),
            daemon=True,
        ).start()
        return {
            "ok": success,
            "incident_id": incident_id,
            "status": mitigation["unblock_status"],
        }

    @staticmethod
    def _parse_iso_datetime(value):
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def listar_mitigaciones(self, active_only=False):
        now = datetime.now(timezone.utc)
        with self._lock:
            mitigations = [dict(item) for item in self.mitigaciones.values()]
        enriched = []
        for item in mitigations:
            expires_at = self._parse_iso_datetime(item.get("expires_at"))
            active = bool(item.get("active"))
            remaining = None
            if expires_at:
                remaining = max(0, int((expires_at - now).total_seconds()))
                if remaining == 0:
                    active = False
            item["active"] = active
            item["state"] = "ACTIVE" if active else "EXPIRED"
            item["remaining_seconds"] = remaining
            if remaining is None:
                item["remaining_human"] = "-"
            else:
                minutes, seconds = divmod(remaining, 60)
                item["remaining_human"] = f"{minutes:02d}:{seconds:02d}"
            enriched.append(item)
        if active_only:
            enriched = [item for item in enriched if item.get("active")]
        return enriched

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

    @staticmethod
    def _short_flow(flow):
        device_id = flow.get("deviceId")
        return {
            "id": flow.get("id"),
            "state": flow.get("state"),
            "deviceId": device_id,
            "deviceName": Config.SWITCH_NOMBRES.get(device_id, device_id),
            "tableId": flow.get("tableId"),
            "priority": flow.get("priority"),
            "isPermanent": flow.get("isPermanent"),
            "timeout": flow.get("timeout"),
            "life": flow.get("life"),
            "packets": flow.get("packets"),
            "bytes": flow.get("bytes"),
            "selector": flow.get("selector", {}).get("criteria", []),
            "treatment": flow.get("treatment", {}),
        }

    def dashboard_summary(self):
        devices = self.onos.get_devices()
        mitigations = self.listar_mitigaciones(active_only=False)
        rate_limits = self.listar_rate_limits(active_only=False)
        active_mitigations = [m for m in mitigations if m.get("active")]
        active_rate_limits = [r for r in rate_limits if r.get("active")]
        with self._lock:
            sessions = dict(self.flows_por_sesion)
            portals = dict(self.flows_portal)
            session_gates = dict(self.session_gates)
            shared = dict(self.flows_t0_shared)
        return {
            "ok": True,
            "status": "ok",
            "onos_url": Config.ONOS_URL,
            "devices_count": len(devices),
            "devices": devices,
            "sessions_count": len(sessions),
            "session_gate_count": len(session_gates),
            "portal_hosts_count": len(portals),
            "mitigations_count": len(mitigations),
            "active_mitigations_count": len(active_mitigations),
            "rate_limits_count": len(rate_limits),
            "active_rate_limits_count": len(active_rate_limits),
            "portal_sync_interval": Config.PORTAL_SYNC_INTERVAL,
            "portal_forward_permanent": Config.PORTAL_FORWARD_PERMANENT,
            "portal_return_timeout": Config.PORTAL_RETURN_TIMEOUT,
            "session_idle_timeout": Config.SESSION_IDLE_TIMEOUT,
            "data_flow_timeout": Config.DATA_FLOW_TIMEOUT,
            "network_actions_enabled": Config.NETWORK_ACTIONS_ENABLED,
            "onos_reads_enabled": Config.ONOS_READS_ENABLED,
            "onos_writes_enabled": Config.ONOS_WRITES_ENABLED,
            "reactive_data_flows_enabled": Config.REACTIVE_DATA_FLOWS_ENABLED,
            "t0_shared_flows_count": len(shared),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def dashboard_portal(self):
        portal_ip = Config.PORTAL_IP
        portal_forward = []
        portal_return = []
        all_flows = []
        for device_id in self.onos.get_devices():
            for flow in self.onos.get_flows(device_id):
                if str(flow.get("tableId")) != "1":
                    continue
                criteria = flow.get("selector", {}).get("criteria", [])
                serialized = str(criteria)
                if portal_ip not in serialized or "8282" not in serialized:
                    continue
                item = self._short_flow(flow)
                item["deviceId"] = device_id
                all_flows.append(item)
                if "IPV4_DST" in serialized and "TCP_DST" in serialized:
                    portal_forward.append(item)
                elif "IPV4_SRC" in serialized and "TCP_SRC" in serialized:
                    portal_return.append(item)

        hosts_by_ip = {}
        for h in self.onos.get_hosts():
            locs = h.get("locations") or []
            if not locs:
                continue
            for ip_addr in h.get("ipAddresses", []):
                if ip_addr.startswith("192.168.100.") and ip_addr != portal_ip:
                    hosts_by_ip[ip_addr] = {
                        "ip": ip_addr,
                        "mac": h.get("mac"),
                        "switch_dpid": locs[0].get("elementId"),
                        "in_port": locs[0].get("port"),
                    }
        with self._lock:
            portal_ips = dict(self.portal_ips)
            cached = {mac: list(flows) for mac, flows in self.flows_portal.items()}
        portal_hosts = []
        for mac, ip_addr in sorted(portal_ips.items(), key=lambda item: item[1]):
            portal_hosts.append({
                **hosts_by_ip.get(ip_addr, {"ip": ip_addr, "mac": mac}),
                "mac": mac,
                "cached_flows": len(cached.get(mac, [])),
                "return_flow_present": any(
                    ip_addr in str(f.get("selector", {})) for f in portal_return
                ),
            })
        return {
            "ok": True,
            "portal_ip": portal_ip,
            "portal_forward": portal_forward,
            "portal_return": portal_return,
            "portal_hosts": portal_hosts,
            "flows": all_flows,
            "sync_interval": Config.PORTAL_SYNC_INTERVAL,
            "return_timeout": Config.PORTAL_RETURN_TIMEOUT,
        }

    def dashboard_sessions(self):
        with self._lock:
            flows = {mac: list(items) for mac, items in self.flows_por_sesion.items()}
            gates = dict(self.session_gates)
            portal_ips = dict(self.portal_ips)
        hosts = {}
        for h in self.onos.get_hosts():
            locs = h.get("locations") or []
            if not locs:
                continue
            mac = str(h.get("mac", "")).lower()
            hosts[mac] = {
                "mac": mac,
                "ips": h.get("ipAddresses", []),
                "switch_dpid": locs[0].get("elementId"),
                "in_port": locs[0].get("port"),
                "vlan": h.get("vlan"),
            }
        sessions = []
        for mac in sorted(set(flows) | set(gates) | set(portal_ips)):
            gate = gates.get(mac)
            sessions.append({
                **hosts.get(mac, {
                    "mac": mac,
                    "ips": [portal_ips.get(mac)] if portal_ips.get(mac) else [],
                }),
                "session_flows": len(flows.get(mac, [])),
                "session_gate_present": bool(gate),
                "session_gate_flow": gate[1] if gate else None,
                "session_gate_expires_at": gate[2] if gate else None,
                "portal_ip": portal_ips.get(mac),
            })
        return {"ok": True, "sessions": sessions}

    def dashboard_flows(self, device_id=None, table_id=None, limit=200):
        devices = [device_id] if device_id else self.onos.get_devices()
        result = []
        for dev in devices:
            for flow in self.onos.get_flows(dev):
                if table_id is not None and str(flow.get("tableId")) != str(table_id):
                    continue
                item = self._short_flow(flow)
                item["deviceId"] = dev
                result.append(item)
                if len(result) >= limit:
                    return {"ok": True, "flows": result, "truncated": True}
        return {"ok": True, "flows": result, "truncated": False}

    def dashboard_events(self, limit=120, contains=None):
        limit = max(1, min(int(limit), 300))
        try:
            with open(Config.M6_LOG_FILE, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except FileNotFoundError:
            return {"ok": True, "log_file": Config.M6_LOG_FILE, "events": []}
        if contains:
            needle = str(contains).lower()
            lines = [line for line in lines if needle in line.lower()]
        events = [line.rstrip("\n") for line in lines[-limit:]]
        return {"ok": True, "log_file": Config.M6_LOG_FILE, "events": events}


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
    
    obs.update_context(
        context_id=str(uuid4()),
        host_ip=token.get("ip_asignada"),
        user_code=token.get("codigo_pucp"),
        user_role=token.get("nombre_rol"))

    resultado = m6.procesar_token_rol(token)
    if resultado:
        return jsonify(resultado), 200
    return jsonify({"error": "no se pudo procesar (ver logs de M6)"}), 500


@app.route("/m6/cerrar_sesion", methods=["POST"])
def endpoint_cerrar_sesion():
    """M1 llama aquí al cerrar sesión del usuario."""
    obs.update_context(context_id=str(uuid4()))
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


@app.route("/m6/sessions/cleanup-stale", methods=["POST"])
def endpoint_cleanup_stale_sessions():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    dry_run = str(request.args.get("dry_run", "")).lower() in {"1", "true", "yes"}
    resultado = m6.cleanup_session_gates_huerfanos(dry_run=dry_run)
    return jsonify(resultado), 200 if resultado.get("ok") else 500


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


@app.route("/m6/security/mitigate", methods=["POST"])
def endpoint_security_mitigate():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    alerta = request.json or {}
    result = m6.procesar_alerta_seguridad(alerta)
    if result.get("ok"):
        return jsonify(result), 200
    status_code = 404 if "sesion activa" in result.get("error", "") else 400
    return jsonify(result), status_code


@app.route("/m6/security/unmitigate", methods=["POST"])
def endpoint_security_unmitigate():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    incident_id = (request.json or {}).get("incident_id")
    if not incident_id:
        return jsonify({"error": "falta incident_id"}), 400
    result = m6.deshacer_mitigacion(incident_id)
    return jsonify(result), 200 if result.get("ok") else 404


@app.route("/m6/security/mitigations", methods=["GET"])
def endpoint_security_mitigations():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    active_only = str(request.args.get("active", "")).lower() in {"1", "true", "yes"}
    mitigations = m6.listar_mitigaciones(active_only=active_only)
    return jsonify({"ok": True, "mitigations": mitigations}), 200


@app.route("/m6/security/rate-limit", methods=["POST"])
def endpoint_security_rate_limit():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    result = m6.procesar_rate_limit_event(request.json or {})
    if result.get("ok"):
        return jsonify(result), 200
    return jsonify(result), 400


@app.route("/m6/security/rate-limit/remove", methods=["POST"])
def endpoint_security_rate_limit_remove():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    result = m6.remover_rate_limit(request.json or {})
    return jsonify(result), 200 if result.get("ok") else 404


@app.route("/m6/security/rate-limits", methods=["GET"])
def endpoint_security_rate_limits():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    active_only = str(request.args.get("active", "")).lower() in {"1", "true", "yes"}
    return jsonify({
        "ok": True,
        "rate_limits": m6.listar_rate_limits(active_only=active_only),
    }), 200


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


@app.route("/m6/dashboard/summary", methods=["GET"])
def endpoint_dashboard_summary():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    return jsonify(m6.dashboard_summary()), 200


@app.route("/m6/dashboard/portal", methods=["GET"])
def endpoint_dashboard_portal():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    return jsonify(m6.dashboard_portal()), 200


@app.route("/m6/dashboard/sessions", methods=["GET"])
def endpoint_dashboard_sessions():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    return jsonify(m6.dashboard_sessions()), 200


@app.route("/m6/dashboard/flows", methods=["GET"])
def endpoint_dashboard_flows():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    device_id = request.args.get("device")
    table_id = request.args.get("table")
    limit = int(request.args.get("limit", "200"))
    return jsonify(m6.dashboard_flows(device_id=device_id,
                                      table_id=table_id,
                                      limit=limit)), 200


@app.route("/m6/dashboard/events", methods=["GET"])
def endpoint_dashboard_events():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    limit = int(request.args.get("limit", "120"))
    contains = request.args.get("contains")
    return jsonify(m6.dashboard_events(limit=limit, contains=contains)), 200


@app.route("/m6/dashboard", methods=["GET"])
def endpoint_m6_dashboard():
    html = r"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>M6 Observabilidad</title>
  <style>
    :root { font-family: Inter, system-ui, Arial, sans-serif; color: #172033; background: #f4f6fa; }
    body { margin: 0; }
    header { background: #fff; border-bottom: 1px solid #dbe2ec; padding: 14px 20px; display: flex; gap: 12px; align-items: center; justify-content: space-between; flex-wrap: wrap; }
    h1 { margin: 0; font-size: 20px; }
    main { padding: 16px 20px 28px; }
    .controls, .tabs, .filters { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    input, select, button { height: 34px; border: 1px solid #aeb9c8; border-radius: 6px; padding: 0 10px; background: #fff; color: #172033; }
    button { cursor: pointer; }
    button.primary { background: #2458d3; color: #fff; border-color: #2458d3; }
    button.danger { color: #aa2626; border-color: #c94444; }
    .tabs { margin: 0 0 14px; }
    .tab { background: #fff; }
    .tab.active { background: #172033; color: #fff; border-color: #172033; }
    .grid { display: grid; grid-template-columns: repeat(5, minmax(130px, 1fr)); gap: 10px; margin-bottom: 14px; }
    .metric, .panel { background: #fff; border: 1px solid #dbe2ec; border-radius: 8px; padding: 12px; }
    .metric strong { display: block; font-size: 22px; }
    .metric span, .muted { color: #637086; font-size: 12px; }
    .status { min-height: 20px; margin: 10px 0; color: #637086; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; min-width: 980px; }
    .table-wrap { overflow: auto; background: #fff; border: 1px solid #dbe2ec; border-radius: 8px; }
    th, td { padding: 9px 10px; border-bottom: 1px solid #edf1f6; text-align: left; font-size: 13px; vertical-align: top; }
    th { background: #f8fafd; position: sticky; top: 0; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    pre { white-space: pre-wrap; margin: 0; max-height: 520px; overflow: auto; }
    .badge { display: inline-block; border-radius: 999px; padding: 3px 8px; font-weight: 700; font-size: 12px; }
    .chip { display: inline-block; border-radius: 5px; padding: 3px 6px; margin: 2px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; border: 1px solid #d3dbe8; background: #f7f9fc; }
    .chip.src { background: #e8f2ff; border-color: #9ec7ff; color: #174f91; }
    .chip.dst { background: #fff0dc; border-color: #ffc578; color: #7b4700; }
    .chip.port { background: #edf7e8; border-color: #a8d99b; color: #246b1c; }
    .chip.vlan { background: #f1eaff; border-color: #c7aef7; color: #57309a; }
    .chip.action { background: #e9f7f6; border-color: #94d5cd; color: #1f665f; font-weight: 700; }
    .chip.drop { background: #ffe8e8; border-color: #ffaaaa; color: #9b2222; font-weight: 700; }
    .hint { display: block; color: #637086; font-size: 12px; margin-top: 3px; }
    .ok { background: #e6f7ed; color: #176b3a; }
    .warn { background: #fff4d6; color: #8a5a00; }
    .bad { background: #ffe5e5; color: #a02727; }
    .view { display: none; }
    .view.active { display: block; }
    @media (max-width: 900px) { .grid { grid-template-columns: repeat(2, minmax(130px, 1fr)); } }
  </style>
</head>
<body>
  <header>
    <h1>M6 Observabilidad</h1>
    <div class="controls">
      <input id="token" type="password" placeholder="X-Security-Token">
      <select id="refreshRate"><option value="5000">5s</option><option value="10000">10s</option><option value="0">Pausado</option></select>
      <button id="refresh" class="primary">Actualizar</button>
    </div>
  </header>
  <main>
    <div class="tabs">
      <button class="tab active" data-view="summary">Resumen</button>
      <button class="tab" data-view="portal">Portal</button>
      <button class="tab" data-view="sessions">Sesiones</button>
      <button class="tab" data-view="mitigations">Mitigaciones</button>
      <button class="tab" data-view="failover">Failover</button>
      <button class="tab" data-view="flows">Flows</button>
      <button class="tab" data-view="events">Eventos</button>
    </div>
    <div id="status" class="status">Ingresa token y actualiza.</div>

    <section id="summary" class="view active">
      <div class="grid" id="summaryGrid"></div>
      <div class="panel"><pre id="summaryRaw"></pre></div>
    </section>

    <section id="portal" class="view">
      <div class="filters"><button id="ensurePortal" class="primary">Reasegurar Portal</button></div>
      <div class="grid" id="portalGrid"></div>
      <div class="table-wrap"><table><thead><tr><th>Tipo</th><th>Device</th><th>Match</th><th>Accion</th><th>Perm</th><th>Timeout</th><th>Pkts</th></tr></thead><tbody id="portalRows"></tbody></table></div>
    </section>

    <section id="sessions" class="view">
      <div class="table-wrap"><table><thead><tr><th>MAC</th><th>IPs</th><th>SW/Puerto</th><th>VLAN</th><th>T1</th><th>Flows sesión</th><th>Portal IP</th></tr></thead><tbody id="sessionRows"></tbody></table></div>
    </section>

    <section id="mitigations" class="view">
      <div class="filters"><input id="mitigationFilter" placeholder="Filtrar IP, SID o acción"></div>
      <div class="table-wrap"><table><thead><tr><th>Estado</th><th>IP/MAC</th><th>SID</th><th>Acción</th><th>Destino</th><th>Tiempo</th><th>Flow IDs</th><th>Levantar</th></tr></thead><tbody id="mitigationRows"></tbody></table></div>
    </section>

    <section id="failover" class="view">
      <div class="filters">
        <select id="failoverDevice">
          <option value="of:0000e2ecb0ea0445">Simular caída SW2</option>
          <option value="of:0000eadb63449748">Simular caída SW3</option>
          <option value="of:00007e3892af7141">Simular caída SW1</option>
          <option value="of:00006a0757adfc4e">Simular caída SW4</option>
          <option value="of:0000ca126249d546">Simular caída SW5</option>
        </select>
        <button id="runFailover" class="primary">Analizar</button>
        <button id="planFailoverRecovery">Plan recovery</button>
      </div>
      <div class="grid" id="failoverGrid"></div>
      <div class="table-wrap"><table><thead><tr><th>Sesión</th><th>Host</th><th>Estado</th><th>Permisos afectados</th><th>Ruta alternativa</th></tr></thead><tbody id="failoverRows"></tbody></table></div>
      <div class="panel" style="margin-top:12px"><pre id="failoverRaw"></pre></div>
    </section>

    <section id="flows" class="view">
      <div class="filters">
        <select id="flowDevice"><option value="">Todos los switches</option></select>
        <select id="flowTable"><option value="">Todas las tablas</option><option>0</option><option>1</option><option>2</option><option>3</option><option>4</option></select>
        <select id="flowKind">
          <option value="">Todos los tipos</option>
          <option value="portal_ida">Portal ida</option>
          <option value="portal_vuelta">Portal vuelta</option>
          <option value="sesion_usuario">Sesion usuario</option>
          <option value="academico_ida">Academico ida</option>
          <option value="academico_vuelta">Academico vuelta</option>
          <option value="mitigacion_drop">Mitigacion/drop</option>
          <option value="miss_goto">Miss/goto</option>
          <option value="control">Control</option>
        </select>
        <select id="flowSort">
          <option value="priority_desc">Prioridad mayor</option>
          <option value="priority_asc">Prioridad menor</option>
          <option value="table_asc">Tabla</option>
          <option value="packets_desc">Mas paquetes</option>
          <option value="life_desc">Mas reciente/vida</option>
        </select>
        <input id="flowMinPriority" type="number" placeholder="Prioridad min">
        <input id="flowFilter" placeholder="Filtrar texto">
      </div>
      <div class="table-wrap"><table><thead><tr><th>Device</th><th>T</th><th>Prio</th><th>Sentido</th><th>Estado</th><th>Match</th><th>Tratamiento</th><th>Pkts</th><th>Timeout</th></tr></thead><tbody id="flowRows"></tbody></table></div>
    </section>

    <section id="events" class="view">
      <div class="filters"><input id="eventFilter" placeholder="Filtrar logs: PORTAL, security, token..."><button id="loadEvents">Cargar eventos</button></div>
      <div class="panel"><pre id="eventLog"></pre></div>
    </section>
  </main>
<script>
const state = {view: 'summary', timer: null, data: {}};
const tokenInput = document.getElementById('token');
tokenInput.value = sessionStorage.getItem('m6Token') || '';
function h() { return {'X-Security-Token': tokenInput.value.trim()}; }
function esc(v) { return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function j(v) { return esc(JSON.stringify(v ?? {}, null, 0)); }
function setStatus(msg) { document.getElementById('status').textContent = msg; }
function metric(label, value, klass='') { return `<div class="metric"><strong class="${klass}">${esc(value)}</strong><span>${esc(label)}</span></div>`; }
const swNames = {
  'of:00007e3892af7141': 'SW1',
  'of:0000e2ecb0ea0445': 'SW2',
  'of:0000eadb63449748': 'SW3',
  'of:00006a0757adfc4e': 'SW4',
  'of:0000ca126249d546': 'SW5'
};
const academicServers = ['192.168.100.101', '192.168.100.102'];
function swLabel(id) { return swNames[id] || id || '-'; }
function criterionValue(c) { return c.ip || c.mac || c.port || c.tcpPort || c.protocol || c.vlanId || c.ethType || ''; }
function criterionClass(c) {
  if (c.type === 'IPV4_SRC' || c.type === 'ETH_SRC') return 'src';
  if (c.type === 'IPV4_DST' || c.type === 'ETH_DST') return 'dst';
  if ((c.type || '').includes('PORT') || c.type === 'IN_PORT') return 'port';
  if (c.type === 'VLAN_VID') return 'vlan';
  return '';
}
function flowMatchHtml(f) {
  return (f.selector || []).map(c => `<span class="chip ${criterionClass(c)}">${esc(c.type)}=${esc(criterionValue(c))}</span>`).join('');
}
function flowActionHtml(f) {
  const treatment = f.treatment || {};
  const instructions = [
    ...(treatment.instructions || []),
    ...(treatment.immediate || []),
    ...(treatment.deferred || [])
  ];
  const hasController = instructions.some(i =>
    i.type === 'OUTPUT' && String(i.port).toUpperCase() === 'CONTROLLER'
  );
  if (hasController) {
    return '<span class="chip action">CONTROLLER</span><span class="hint">Packet-in hacia ONOS</span>';
  }
  if (instructions.length === 0) {
    return '<span class="chip drop">DROP</span>';
  }
  return instructions.map(i => {
    if (i.type === 'OUTPUT') {
      const port = String(i.port).toUpperCase();
      if (port === 'CONTROLLER') return '<span class="chip action">CONTROLLER</span>';
      return `<span class="chip action">OUTPUT:${esc(i.port)}</span>`;
    }
    if (i.type === 'TABLE') return `<span class="chip action">GOTO:T${esc(i.tableId)}</span>`;
    if (i.type === 'L2MODIFICATION') return `<span class="chip action">${esc(i.subtype)}${i.vlanId ? ':' + esc(i.vlanId) : ''}</span>`;
    return `<span class="chip action">${esc(i.type)}</span>`;
  }).join('');
}
function criteriaMap(f) {
  const m = {};
  (f.selector || []).forEach(c => { m[c.type] = c; });
  return m;
}
function hasAction(f, type) {
  return ((f.treatment || {}).instructions || []).some(i => i.type === type);
}
function actionTable(f) {
  const item = ((f.treatment || {}).instructions || []).find(i => i.type === 'TABLE');
  return item ? String(item.tableId) : '';
}
function flowKind(f) {
  const c = criteriaMap(f);
  const table = String(f.tableId);
  const prio = Number(f.priority || 0);
  const src = (c.IPV4_SRC || {}).ip || '';
  const dst = (c.IPV4_DST || {}).ip || '';
  const tcpSrc = (c.TCP_SRC || {}).tcpPort;
  const tcpDst = (c.TCP_DST || {}).tcpPort;
  const treatment = f.treatment || {};
  const instructions = [
    ...(treatment.instructions || []),
    ...(treatment.immediate || []),
    ...(treatment.deferred || [])
  ];
  const hasController = instructions.some(i =>
    i.type === 'OUTPUT' && String(i.port).toUpperCase() === 'CONTROLLER'
  );
  if (hasController) return {kind: 'control', label: 'Controller', detail: 'Packet-in hacia ONOS'};
  if (instructions.length === 0 && prio >= 1000) {
    return {kind: 'mitigacion_drop', label: 'Mitigacion/drop', detail: 'Bloquea trafico antes de que avance'};
  }
  if (table === '0' && prio >= 40000) return {kind: 'control', label: 'Control', detail: 'ARP/DHCP/LLDP/BDDP hacia ONOS'};
  if (hasAction(f, 'TABLE') && prio === 0) return {kind: 'miss_goto', label: 'Miss/goto', detail: 'Fallback hacia T' + actionTable(f)};
  if (dst.includes('192.168.100.110') && String(tcpDst) === '8282') return {kind: 'portal_ida', label: 'Portal ida', detail: 'Host hacia portal cautivo'};
  if (src.includes('192.168.100.110') && String(tcpSrc) === '8282') return {kind: 'portal_vuelta', label: 'Portal vuelta', detail: 'Portal responde al host'};
  if (table === '1' && prio === 39900 && hasAction(f, 'TABLE')) return {kind: 'sesion_usuario', label: 'Sesion usuario', detail: 'Marca VLAN logica y pasa a T2'};
  const srcIsAcademicServer = academicServers.some(ip => src.includes(ip));
  const dstIsAcademicServer = academicServers.some(ip => dst.includes(ip));
  if ((table === '2' || table === '3') && srcIsAcademicServer) return {kind: 'academico_vuelta', label: 'Academico vuelta', detail: 'Servidor responde al host'};
  if ((table === '2' || table === '3') && dstIsAcademicServer) return {kind: 'academico_ida', label: 'Academico ida', detail: 'Host hacia curso/notas'};
  if (table === '0' && srcIsAcademicServer) return {kind: 'academico_vuelta', label: 'Troncal vuelta', detail: 'Transporte agregado servidor -> usuarios'};
  if (table === '0' && dstIsAcademicServer) return {kind: 'academico_ida', label: 'Troncal ida', detail: 'Transporte agregado usuarios -> servidor'};
  return {kind: 'otro', label: 'Otro', detail: 'Flow auxiliar o compartida'};
}
function flowKindHtml(f) {
  const info = flowKind(f);
  const klass = info.kind.includes('vuelta') ? 'src' : info.kind.includes('ida') ? 'dst' : info.kind.includes('drop') ? 'drop' : 'action';
  return `<span class="chip ${klass}">${esc(info.label)}</span><span class="hint">${esc(info.detail)}</span>`;
}
function sortFlows(items) {
  const mode = document.getElementById('flowSort').value;
  const n = x => Number(x || 0);
  const cmp = {
    priority_desc: (a,b) => n(b.priority) - n(a.priority),
    priority_asc: (a,b) => n(a.priority) - n(b.priority),
    table_asc: (a,b) => n(a.tableId) - n(b.tableId) || n(b.priority) - n(a.priority),
    packets_desc: (a,b) => n(b.packets) - n(a.packets),
    life_desc: (a,b) => n(b.life) - n(a.life)
  }[mode] || ((a,b) => n(b.priority) - n(a.priority));
  return [...items].sort(cmp);
}
async function api(path, opts={}) {
  const token = tokenInput.value.trim();
  if (!token) throw new Error('falta token');
  sessionStorage.setItem('m6Token', token);
  const res = await fetch(path, {...opts, headers: {...(opts.headers || {}), ...h()}});
  if (!res.ok) throw new Error(path + ' HTTP ' + res.status);
  return res.json();
}
function activate(view) {
  state.view = view;
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === view));
  load();
}
document.querySelectorAll('.tab').forEach(b => b.onclick = () => activate(b.dataset.view));
document.getElementById('refresh').onclick = () => load(true);
document.getElementById('refreshRate').onchange = schedule;
document.getElementById('mitigationFilter').oninput = renderMitigations;
document.getElementById('flowFilter').oninput = renderFlows;
document.getElementById('flowKind').onchange = renderFlows;
document.getElementById('flowSort').onchange = renderFlows;
document.getElementById('flowMinPriority').oninput = renderFlows;
document.getElementById('flowDevice').onchange = () => load(true);
document.getElementById('flowTable').onchange = () => load(true);
document.getElementById('loadEvents').onclick = () => load(true);
document.getElementById('runFailover').onclick = () => runFailover();
document.getElementById('planFailoverRecovery').onclick = () => planFailoverRecovery();
document.getElementById('ensurePortal').onclick = async () => {
  try { await api('/m6/portal/sync?force=1', {method: 'POST'}); setStatus('Portal reasegurado.'); await load(true); }
  catch (e) { setStatus('Error: ' + e.message); }
};
async function load(force=false) {
  try {
    if (state.view === 'summary') {
      const data = await api('/m6/dashboard/summary'); state.data.summary = data; renderSummary(data);
      const sel = document.getElementById('flowDevice');
      if (sel.options.length === 1) data.devices.forEach(d => sel.insertAdjacentHTML('beforeend', `<option value="${esc(d)}">${esc(swLabel(d))} (${esc(d.slice(-4))})</option>`));
    } else if (state.view === 'portal') {
      const data = await api('/m6/dashboard/portal'); state.data.portal = data; renderPortal(data);
    } else if (state.view === 'sessions') {
      const data = await api('/m6/dashboard/sessions'); state.data.sessions = data; renderSessions(data);
    } else if (state.view === 'mitigations') {
      const data = await api('/m6/security/mitigations?active=0'); state.data.mitigations = data.mitigations || []; renderMitigations();
    } else if (state.view === 'failover') {
      const topo = await api('/m6/failover/topology'); state.data.failoverTopology = topo; renderFailoverTopology(topo);
    } else if (state.view === 'flows') {
      const dev = document.getElementById('flowDevice').value;
      const table = document.getElementById('flowTable').value;
      const qs = new URLSearchParams({limit: '250'}); if (dev) qs.set('device', dev); if (table) qs.set('table', table);
      const data = await api('/m6/dashboard/flows?' + qs); state.data.flows = data.flows || []; renderFlows();
    } else if (state.view === 'events') {
      const q = document.getElementById('eventFilter').value.trim();
      const qs = new URLSearchParams({limit: '160'}); if (q) qs.set('contains', q);
      const data = await api('/m6/dashboard/events?' + qs); document.getElementById('eventLog').textContent = (data.events || []).join('\n');
    }
    setStatus('OK ' + new Date().toLocaleTimeString());
  } catch (e) { setStatus('Error: ' + e.message); }
}
function renderSummary(d) {
  document.getElementById('summaryGrid').innerHTML = [
    metric('M6', d.status, 'ok'), metric('Switches ONOS', d.devices_count),
    metric('Sesiones', d.sessions_count), metric('Portal hosts', d.portal_hosts_count),
    metric('Mitigaciones activas', d.active_mitigations_count, d.active_mitigations_count ? 'bad' : 'ok'),
    metric('Portal sync', d.portal_sync_interval + 's'), metric('Vuelta portal', d.portal_return_timeout + 's'),
    metric('T1 sesión', d.session_idle_timeout + 's'), metric('T2/T3 datos', d.data_flow_timeout + 's'),
    metric('ONOS writes', d.onos_writes_enabled ? 'ON' : 'OFF', d.onos_writes_enabled ? 'ok' : 'warn')
  ].join('');
  document.getElementById('summaryRaw').textContent = JSON.stringify(d, null, 2);
}
function renderPortal(d) {
  document.getElementById('portalGrid').innerHTML = [
    metric('IP portal', d.portal_ip), metric('Ida permanente', (d.portal_forward || []).some(f => f.isPermanent) ? 'SI' : 'NO'),
    metric('Flows ida', (d.portal_forward || []).length), metric('Flows vuelta', (d.portal_return || []).length),
    metric('Hosts portal', (d.portal_hosts || []).length), metric('Sync', d.sync_interval + 's')
  ].join('');
  const rows = [...(d.portal_forward || []).map(f => ['ida', f]), ...(d.portal_return || []).map(f => ['vuelta', f])];
  document.getElementById('portalRows').innerHTML = rows.map(([type, f]) => `<tr><td>${type}</td><td><strong>${esc(swLabel(f.deviceId))}</strong><br><code>${esc(f.deviceId)}</code></td><td>${flowMatchHtml(f)}</td><td>${flowActionHtml(f)}</td><td>${f.isPermanent}</td><td>${f.timeout}</td><td>${f.packets || 0}</td></tr>`).join('');
}
function renderSessions(d) {
  document.getElementById('sessionRows').innerHTML = (d.sessions || []).map(s => `<tr><td><code>${esc(s.mac)}</code></td><td><code>${esc((s.ips || []).join(', '))}</code></td><td><strong>${esc(swLabel(s.switch_dpid))}</strong><br>port ${esc(s.in_port || '-')}</td><td>${esc(s.vlan || '-')}</td><td>${s.session_gate_present ? '<span class="badge ok">OK</span>' : '<span class="badge warn">NO</span>'}</td><td>${s.session_flows}</td><td><code>${esc(s.portal_ip || '-')}</code></td></tr>`).join('');
}
function renderMitigations() {
  const q = document.getElementById('mitigationFilter').value.toLowerCase();
  const items = (state.data.mitigations || []).filter(x => JSON.stringify(x).toLowerCase().includes(q));
  document.getElementById('mitigationRows').innerHTML = items.map(m => `<tr><td>${m.active ? '<span class="badge bad">ACTIVE</span>' : '<span class="badge">EXPIRED</span>'}</td><td><code>${esc(m.src_ip || '-')}</code><br><code>${esc(m.src_mac || '-')}</code></td><td>${esc(m.sid || '-')}</td><td>${esc(m.mitigation_action || '-')}</td><td><code>${esc((m.dst_ip || '') + (m.dst_port ? ':' + m.dst_port : ''))}</code></td><td>${esc(m.remaining_human || '-')}</td><td><code>${esc((m.flow_ids || []).join(', '))}</code></td><td><button class="danger" ${m.active ? '' : 'disabled'} onclick="unmitigate('${esc(m.incident_id)}')">Levantar</button></td></tr>`).join('');
}
async function unmitigate(id) { if (!id || !confirm('Levantar mitigacion?')) return; await api('/m6/security/unmitigate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({incident_id:id})}); await load(true); }
window.unmitigate = unmitigate;
async function runFailover() {
  const device = document.getElementById('failoverDevice').value;
  try {
    const data = await api('/m6/failover/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({failed_devices: [device]})
    });
    state.data.failover = data;
    renderFailover(data);
    setStatus('Failover dry-run OK para ' + swLabel(device));
  } catch (e) {
    setStatus('Error failover: ' + e.message);
  }
}
async function planFailoverRecovery() {
  try {
    const data = await api('/m6/failover/recover', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({apply: false})
    });
    state.data.failover = data;
    renderFailoverRecovery(data);
    setStatus('Plan de recovery generado sin instalar ni borrar flows.');
  } catch (e) {
    setStatus('Error recovery: ' + e.message);
  }
}
function renderFailoverTopology(d) {
  document.getElementById('failoverGrid').innerHTML = [
    metric('Switches disponibles', (d.available_devices || []).length),
    metric('Switches caidos', (d.unavailable_devices || []).length, (d.unavailable_devices || []).length ? 'bad' : 'ok'),
    metric('Links ONOS', d.links_count || 0),
    metric('Hosts ONOS', d.hosts_count || 0),
    metric('Auto reinstall', d.failover_auto_reinstall_enabled ? 'ON' : 'OFF', d.failover_auto_reinstall_enabled ? 'warn' : 'ok')
  ].join('');
  document.getElementById('failoverRows').innerHTML = '<tr><td colspan="5" class="muted">Elige un switch y presiona Analizar. No se instalaran ni borraran flows.</td></tr>';
  document.getElementById('failoverRaw').textContent = JSON.stringify(d, null, 2);
}
function renderFailoverRecovery(d) {
  const planned = d.planned || [];
  const permissions = planned.reduce((sum, item) => sum + ((item.permissions || []).length), 0);
  document.getElementById('failoverGrid').innerHTML = [
    metric('Sesiones planificadas', planned.length),
    metric('Permisos a reinstalar', permissions),
    metric('Modo', d.dry_run ? 'DRY-RUN' : 'APPLY', d.dry_run ? 'ok' : 'warn'),
    metric('Auto reinstall', d.auto_reinstall_enabled ? 'ON' : 'OFF', d.auto_reinstall_enabled ? 'warn' : 'ok')
  ].join('');
  document.getElementById('failoverRows').innerHTML = planned.length ? planned.map(item => {
    const perms = item.permissions || [];
    return `<tr>
      <td><code>${esc(item.session_id || '-')}</code><br>${esc(item.codigo_pucp || '')}</td>
      <td><code>${esc(item.ip || '-')}</code><br><code>${esc(item.mac || '-')}</code><br>${esc(swLabel(item.switch_dpid))} port ${esc(item.in_port || '-')}</td>
      <td>${item.ok ? '<span class="badge ok">PLAN</span>' : '<span class="badge bad">INVALID</span>'}</td>
      <td>${perms.map(p => `<span class="chip action">${esc(p.table)} ${esc(p.dst_ip)}:${esc(p.tcp_port || '-')}</span>`).join('') || '<span class="muted">Sin permisos a reinstalar</span>'}</td>
      <td><span class="hint">Este plan no borra ni instala flows. Aplicar requiere curl con apply=true y flag activo.</span></td>
    </tr>`;
  }).join('') : '<tr><td colspan="5"><span class="muted">No hay sesiones activas para recovery</span></td></tr>';
  document.getElementById('failoverRaw').textContent = JSON.stringify(d, null, 2);
}
function compactPath(path) {
  return (path || []).map(p => `${swLabel(p.device_id)}:${p.in_port}->${p.out_port}`).join(' | ') || '-';
}
function renderFailover(d) {
  const s = d.summary || {};
  document.getElementById('failoverGrid').innerHTML = [
    metric('Sesiones totales', d.sessions_total ?? 0),
    metric('Afectadas', s.impacted_sessions ?? 0, (s.impacted_sessions || 0) ? 'warn' : 'ok'),
    metric('Recuperables', s.recoverable_sessions ?? 0, (s.recoverable_sessions || 0) ? 'ok' : ''),
    metric('Sin ruta', s.unavailable_sessions ?? 0, (s.unavailable_sessions || 0) ? 'bad' : 'ok'),
    metric('Auto reinstall', d.auto_reinstall_enabled ? 'ON' : 'OFF', d.auto_reinstall_enabled ? 'warn' : 'ok')
  ].join('');
  const rows = d.impacted || [];
  document.getElementById('failoverRows').innerHTML = rows.length ? rows.map(item => {
    const perms = (item.permissions || []).filter(p => p.status !== 'unaffected');
    return `<tr>
      <td><code>${esc(item.session_id || '-')}</code><br>${esc(item.codigo_pucp || '')}</td>
      <td><code>${esc(item.ip || '-')}</code><br><code>${esc(item.mac || '-')}</code><br>${esc(swLabel(item.switch_dpid))} port ${esc(item.in_port || '-')}</td>
      <td>${item.recoverable ? '<span class="badge ok">RECOVERABLE</span>' : '<span class="badge bad">UNAVAILABLE</span>'}</td>
      <td>${perms.map(p => `<span class="chip ${p.recoverable ? 'action' : 'drop'}">${esc(p.dst_ip)}:${esc(p.tcp_port || '-')} ${esc(p.status)}</span>`).join('') || '<span class="muted">Sin permisos afectados</span>'}</td>
      <td>${perms.map(p => `<div><strong>${esc(p.dst_ip)}:${esc(p.tcp_port || '-')}</strong><br><span class="hint">ida: ${esc(compactPath(p.alternative_ida))}</span><span class="hint">vuelta: ${esc(compactPath(p.alternative_retorno))}</span></div>`).join('')}</td>
    </tr>`;
  }).join('') : '<tr><td colspan="5"><span class="badge ok">Sin sesiones afectadas</span></td></tr>';
  document.getElementById('failoverRaw').textContent = JSON.stringify(d, null, 2);
}
window.runFailover = runFailover;
function renderFlows() {
  const q = document.getElementById('flowFilter').value.toLowerCase();
  const kind = document.getElementById('flowKind').value;
  const minPrioRaw = document.getElementById('flowMinPriority').value;
  const minPrio = minPrioRaw === '' ? null : Number(minPrioRaw);
  let items = (state.data.flows || []).filter(f => {
    const info = flowKind(f);
    if (kind && info.kind !== kind) return false;
    if (minPrio !== null && Number(f.priority || 0) < minPrio) return false;
    return JSON.stringify(f).toLowerCase().includes(q)
      || info.label.toLowerCase().includes(q)
      || info.detail.toLowerCase().includes(q)
      || swLabel(f.deviceId).toLowerCase().includes(q);
  });
  items = sortFlows(items);
  document.getElementById('flowRows').innerHTML = items.map(f => `<tr><td><strong>${esc(swLabel(f.deviceId))}</strong><br><code>${esc(f.deviceId)}</code></td><td>T${esc(f.tableId)}</td><td>${esc(f.priority)}</td><td>${flowKindHtml(f)}</td><td>${esc(f.state || '-')}</td><td>${flowMatchHtml(f)}</td><td>${flowActionHtml(f)}</td><td>${esc(f.packets || 0)}</td><td>${f.isPermanent ? 'perm' : esc(f.timeout || '-')}</td></tr>`).join('');
}
function schedule() {
  if (state.timer) clearInterval(state.timer);
  const ms = Number(document.getElementById('refreshRate').value);
  if (ms > 0) state.timer = setInterval(() => load(), ms);
}
schedule(); load();
</script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@app.route("/m6/security/dashboard", methods=["GET"])
def endpoint_security_dashboard():
    html = r"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>M6 Mitigaciones</title>
  <style>
    :root { color-scheme: light; font-family: Inter, system-ui, Arial, sans-serif; }
    body { margin: 0; background: #f5f7fb; color: #172033; }
    header { background: #ffffff; border-bottom: 1px solid #dde3ee; padding: 16px 22px; display: flex; gap: 16px; align-items: center; justify-content: space-between; flex-wrap: wrap; }
    h1 { font-size: 20px; margin: 0; letter-spacing: 0; }
    main { padding: 18px 22px 28px; }
    .controls { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    input { height: 34px; border: 1px solid #b9c3d3; border-radius: 6px; padding: 0 10px; min-width: 230px; }
    button { height: 34px; border: 1px solid #9aa8ba; border-radius: 6px; background: #ffffff; color: #172033; cursor: pointer; padding: 0 12px; }
    button.primary { background: #2458d3; border-color: #2458d3; color: white; }
    button.danger { border-color: #c94444; color: #b32626; }
    button:disabled { opacity: .5; cursor: not-allowed; }
    .summary { display: grid; grid-template-columns: repeat(4, minmax(130px, 1fr)); gap: 10px; margin: 14px 0; }
    .metric { background: #ffffff; border: 1px solid #dde3ee; border-radius: 8px; padding: 12px; }
    .metric strong { display: block; font-size: 22px; }
    .metric span { color: #5b6678; font-size: 12px; }
    .status { font-size: 13px; color: #5b6678; margin: 8px 0 14px; min-height: 18px; }
    .table-wrap { background: #ffffff; border: 1px solid #dde3ee; border-radius: 8px; overflow: auto; }
    table { width: 100%; border-collapse: collapse; min-width: 1100px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #edf1f6; text-align: left; font-size: 13px; vertical-align: top; }
    th { background: #f9fbfe; color: #455168; font-weight: 700; position: sticky; top: 0; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    .badge { display: inline-block; border-radius: 999px; padding: 3px 8px; font-weight: 700; font-size: 12px; }
    .active { background: #e6f7ed; color: #176b3a; }
    .expired { background: #eef1f5; color: #5b6678; }
    .empty { padding: 28px; text-align: center; color: #5b6678; }
    @media (max-width: 760px) {
      header { align-items: stretch; }
      .controls { width: 100%; }
      input { flex: 1; min-width: 170px; }
      .summary { grid-template-columns: repeat(2, minmax(130px, 1fr)); }
      main { padding: 14px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>M6 Mitigaciones</h1>
    <div class="controls">
      <input id="token" type="password" placeholder="X-Security-Token">
      <button id="refresh" class="primary">Actualizar</button>
      <button id="toggle">Pausar</button>
    </div>
  </header>
  <main>
    <div class="summary">
      <div class="metric"><strong id="total">0</strong><span>Total</span></div>
      <div class="metric"><strong id="active">0</strong><span>Activas</span></div>
      <div class="metric"><strong id="expired">0</strong><span>Expiradas/levantadas</span></div>
      <div class="metric"><strong id="last">-</strong><span>Ultima lectura</span></div>
    </div>
    <div id="status" class="status">Ingresa el token y presiona Actualizar.</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Estado</th><th>IP/MAC</th><th>SID</th><th>Castigo</th>
            <th>Destino</th><th>Switch/Puerto</th><th>Tiempo</th>
            <th>Flows</th><th>Incident</th><th>Accion</th>
          </tr>
        </thead>
        <tbody id="rows"><tr><td colspan="10" class="empty">Sin datos cargados</td></tr></tbody>
      </table>
    </div>
  </main>
  <script>
    const tokenInput = document.getElementById('token');
    const rows = document.getElementById('rows');
    const statusEl = document.getElementById('status');
    const refreshBtn = document.getElementById('refresh');
    const toggleBtn = document.getElementById('toggle');
    let paused = false;
    let loading = false;
    tokenInput.value = sessionStorage.getItem('m6Token') || '';

    function esc(value) {
      return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[ch]));
    }
    function shortId(value) {
      value = String(value || '');
      return value.length > 12 ? value.slice(0, 8) + '...' : value;
    }
    function setMetric(id, value) { document.getElementById(id).textContent = value; }
    function headers() { return {'X-Security-Token': tokenInput.value.trim()}; }

    async function load() {
      if (loading || paused) return;
      const token = tokenInput.value.trim();
      if (!token) {
        statusEl.textContent = 'Ingresa el token para consultar M6.';
        return;
      }
      sessionStorage.setItem('m6Token', token);
      loading = true;
      refreshBtn.disabled = true;
      try {
        const resp = await fetch('/m6/security/mitigations?active=0', {headers: headers()});
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const data = await resp.json();
        render(data.mitigations || []);
        statusEl.textContent = 'OK - mitigaciones actualizadas.';
      } catch (err) {
        statusEl.textContent = 'Error consultando M6: ' + err.message;
      } finally {
        loading = false;
        refreshBtn.disabled = false;
      }
    }

    function render(items) {
      const active = items.filter(x => x.active).length;
      setMetric('total', items.length);
      setMetric('active', active);
      setMetric('expired', items.length - active);
      setMetric('last', new Date().toLocaleTimeString());
      if (!items.length) {
        rows.innerHTML = '<tr><td colspan="10" class="empty">No hay mitigaciones registradas</td></tr>';
        return;
      }
      rows.innerHTML = items.map(item => {
        const badge = item.active
          ? '<span class="badge active">ACTIVE</span>'
          : '<span class="badge expired">' + esc(item.state || 'EXPIRED') + '</span>';
        const dst = [item.dst_ip || '', item.dst_port ? ':' + item.dst_port : ''].join('');
        const flows = (item.flow_ids || []).map(shortId).join('<br>') || '-';
        const disabled = item.active ? '' : 'disabled';
        return `<tr>
          <td>${badge}</td>
          <td><code>${esc(item.src_ip || item.ip_atacante || '-')}</code><br><code>${esc(item.src_mac || item.mac_atacante || '-')}</code></td>
          <td><code>${esc(item.sid || '-')}</code></td>
          <td>${esc(item.mitigation_action || item.accion || item.action || '-')}</td>
          <td><code>${esc(dst || '-')}</code></td>
          <td><code>${esc(item.switch_dpid || (item.devices || [])[0] || '-')}</code><br>port ${esc(item.in_port ?? '-')}</td>
          <td>${esc(item.remaining_human || '-')}<br><code>${esc(item.expires_at || '-')}</code></td>
          <td><code>${flows}</code></td>
          <td><code title="${esc(item.incident_id)}">${esc(shortId(item.incident_id))}</code></td>
          <td><button class="danger" ${disabled} onclick="unmitigate('${esc(item.incident_id)}')">Levantar</button></td>
        </tr>`;
      }).join('');
    }

    async function unmitigate(incidentId) {
      if (!incidentId || !confirm('Levantar mitigacion ' + incidentId + '?')) return;
      try {
        const resp = await fetch('/m6/security/unmitigate', {
          method: 'POST',
          headers: {...headers(), 'Content-Type': 'application/json'},
          body: JSON.stringify({incident_id: incidentId})
        });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        await load();
      } catch (err) {
        statusEl.textContent = 'Error levantando mitigacion: ' + err.message;
      }
    }
    window.unmitigate = unmitigate;
    refreshBtn.addEventListener('click', load);
    toggleBtn.addEventListener('click', () => {
      paused = !paused;
      toggleBtn.textContent = paused ? 'Reanudar' : 'Pausar';
      if (!paused) load();
    });
    setInterval(load, 2000);
  </script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@app.route("/m6/monitoring/ensure-gre", methods=["POST"])
def endpoint_monitoring_ensure_gre():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    result = m6.asegurar_monitoring_gre()
    return jsonify(result), 200 if result.get("ok") else 500


@app.route("/m6/monitoring/gre-status", methods=["GET"])
def endpoint_monitoring_gre_status():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    result = m6.estado_monitoring_gre()
    return jsonify(result), 200 if result.get("ok") else 500


@app.route("/m6/failover/topology", methods=["GET"])
def endpoint_failover_topology():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    result = m6.estado_failover_topologia()
    return jsonify(result), 200 if result.get("ok") else 500


@app.route("/m6/failover/analyze", methods=["POST"])
def endpoint_failover_analyze():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    data = request.json or {}
    result = m6.analizar_failover(data)
    return jsonify(result), 200 if result.get("ok") else 500


@app.route("/m6/failover/recover", methods=["POST"])
def endpoint_failover_recover():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    data = request.json or {}
    result = m6.recuperar_failover(data)
    status = 200 if result.get("ok") else 409
    return jsonify(result), status


@app.route("/m6/failover/event", methods=["POST"])
def endpoint_failover_event():
    if not _security_token_valido():
        return jsonify({"error": "security token inválido"}), 401
    data = request.json or {}
    result = m6.procesar_failover_event(data)
    return jsonify(result), 200 if result.get("ok") else 500


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
    m6._purgar_rate_limits_expirados()
    devices = m6.onos.get_devices()
    with m6._lock:
        sesiones = {mac: len(flows)
                    for mac, flows in m6.flows_por_sesion.items()}
        portal_flows = {mac: len(flows)
                        for mac, flows in m6.flows_portal.items()}
        portal_ips = dict(m6.portal_ips)
        path_records = sum(len(items) for items in m6.path_records.values())
        rate_limits_active = len(m6.rate_limits)
        now = time.time()
        t0_shared_flows = sum(
            1 for _, _, expires_at in m6.flows_t0_shared.values()
            if expires_at is None or expires_at > now
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
        "path_records":     path_records,
        "t0_shared_flows":  t0_shared_flows,
        "rate_limits_active": rate_limits_active,
        "rate_limit_default_pps": Config.RATE_LIMIT_DEFAULT_PPS,
        "rate_limit_default_ttl": Config.RATE_LIMIT_DEFAULT_TTL,
        "network_actions_enabled": Config.NETWORK_ACTIONS_ENABLED,
        "onos_writes_enabled": Config.ONOS_WRITES_ENABLED,
        "onos_reads_enabled": Config.ONOS_READS_ENABLED,
        "failover_analysis_enabled": Config.FAILOVER_ANALYSIS_ENABLED,
        "failover_auto_reinstall_enabled": Config.FAILOVER_AUTO_REINSTALL_ENABLED,
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
    if Config.MONITORING_GRE_INSTALL_ON_STARTUP:
        print("[M6] Asegurando flows GRE de monitoreo al arranque")
        print(f"[M6] monitoring_gre={m6.asegurar_monitoring_gre()}")
    if Config.SESSION_CLEANUP_ON_STARTUP:
        print("[M6] Limpiando session gates T1 huérfanos al arranque")
        print(f"[M6] session_cleanup={m6.cleanup_session_gates_huerfanos()}")

    m6.iniciar_sincronizador_portal()

    print(f"[M6] API escuchando en {Config.M6_HOST}:{Config.M6_PORT}\n")
    app.run(host=Config.M6_HOST, port=Config.M6_PORT,
            debug=False, threaded=True)
