#!/usr/bin/env python3
"""
m6_traductor.py â€” MÃ³dulo Traductor SDN PUCP | Grupo 2 TEL354
Mark V

Ãšnica interfaz entre la lÃ³gica de negocio y ONOS Controller.
M1, M2 y M4 NUNCA tocan ONOS directamente â€” todo pasa por M6.

Pipeline OpenFlow implementado:
  T0 (tabla 0): Rutas directas portal + enforcement por MAC + bloqueo atacantes
  T1 (tabla 1): Cuarentena VLAN 90 + SET_FIELD post-auth
  T2 (tabla 2): ALLOW proactivo por VLAN â†’ servidor (instalado al arrancar)
  T3 (tabla 3): DENY por sesiÃ³n MAC+IP con hard_timeout

NOTA ONOS: DROP = {"clearDeferred": true, "instructions": []}
           ({"type": "DROP"} da error HTTP 400)

NOTA VNRT: el trÃ¡fico IP normal de los hosts no llega a tabla-1 automÃ¡ticamente
           en este slice. Las rutas tabla-0 para portal son las que funcionan
           (verificado con SSH desde H1 a 192.168.100.1).
"""

import time
import threading
import requests
import json
import os
from collections import deque
from urllib.parse import quote
from flask import Flask, request, jsonify

try:
    import mysql.connector
    MYSQL_OK = True
except ImportError:
    try:
        import pymysql

        class _PyMySQLConnection:
            def __init__(self, conn):
                self._conn = conn

            def cursor(self, dictionary=False):
                return self._conn.cursor()

            def commit(self):
                return self._conn.commit()

            def rollback(self):
                return self._conn.rollback()

            def close(self):
                self._conn.close()

        class _PyMySQLCompat:
            @staticmethod
            def connect(host, user, password, database, connection_timeout=3, **kwargs):
                conn = pymysql.connect(
                    host=host,
                    user=user,
                    password=password,
                    database=database,
                    connect_timeout=connection_timeout,
                    cursorclass=pymysql.cursors.DictCursor,
                )
                return _PyMySQLConnection(conn)

        class _MySQLCompat:
            connector = _PyMySQLCompat()

        mysql = _MySQLCompat()
        MYSQL_OK = True
    except ImportError:
        MYSQL_OK = False


# â”€â”€â”€ ConfiguraciÃ³n â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class Config:
    # ONOS (puerto 8181)
    ONOS_URL  = os.getenv("ONOS_URL", "http://127.0.0.1:8181")
    ONOS_AUTH = ("onos", "rocks")

    # OPA â€” puerto 8182 (distinto de ONOS que usa 8181)
    # Endpoint real de M2: package policy â†’ /v1/data/policy/result
    OPA_URL = os.getenv("OPA_URL", "http://127.0.0.1:8182/v1/data/policy/result")

    # Mapeo IPs diseÃ±o M2 (10.0.0.x) â†’ IPs reales VNRT (192.168.100.x)
    # M2's init.sql usa IPs del diseÃ±o original; VNRT tiene 2 servidores reales.
    IP_MAPPING_M2 = {
        "10.0.0.21": "192.168.100.200",  # cursos_telecom â†’ H3
        "10.0.0.22": "192.168.100.201",  # cursos_info    â†’ H4 (VLAN 220)
        "10.0.0.23": "192.168.100.200",  # cursos_electro â†’ H3
        "10.0.0.30": "192.168.100.201",  # servidor_notas â†’ H4
        "10.0.0.40": "192.168.100.201",  # panel_admin    â†’ H4
        "10.0.0.50": "192.168.100.200",  # server_compartido â†’ H3
        "10.0.0.10": "192.168.100.1",    # portal_cautivo â†’ controller
    }
    GATEWAY_INTERNET = os.getenv("GATEWAY_INTERNET", "192.168.201.1")

    # M5 auditorÃ­a
    M5_URL = "http://127.0.0.1:5002/m5/log"

    # M6 propio
    M6_HOST = "0.0.0.0"
    M6_PORT = 8080

    # MySQL (fallback cuando OPA no disponible)
    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_USER = os.getenv("MYSQL_USER", "radius")
    MYSQL_PASS = os.getenv("MYSQL_PASS", "radius_pass")
    MYSQL_DB   = os.getenv("MYSQL_DB", "radius_db")

    # Resiliencia
    MAX_REINTENTOS = 3
    BACKOFF_BASE   = 1        # segundos, backoff exponencial: 1â†’2â†’4
    MAX_COLA_LOGS  = 10000
    SESSION_IDLE_TIMEOUT = 900
    SESSION_REAPER_INTERVAL = 30

    # Cargar IPs estÃ¡ticas dinÃ¡micamente si el archivo existe
    import json
    import os
    CONFIG_IPS_PATH = os.path.join(os.path.dirname(__file__), "config_ips.json")
    
    if os.path.exists(CONFIG_IPS_PATH):
        try:
            with open(CONFIG_IPS_PATH, "r") as f:
                DYNAMIC_IPS = json.load(f)
            PORTAL_IP = DYNAMIC_IPS.get("PORTAL_IP", "192.168.100.1")
            SERVER_CURSOS = DYNAMIC_IPS.get("SERVER_CURSOS", "192.168.100.200")
            SERVER_NOTAS = DYNAMIC_IPS.get("SERVER_NOTAS", "192.168.100.201")
        except Exception as e:
            print(f"Error cargando config_ips.json: {e}")
            PORTAL_IP     = "192.168.100.1"    
            SERVER_CURSOS = "192.168.100.200"  
            SERVER_NOTAS  = "192.168.100.201"  
    else:
        # IPs del plano de datos por defecto (verificadas en el slice VNRT)
        PORTAL_IP     = "192.168.100.1"    
        SERVER_CURSOS = "192.168.100.200"  
        SERVER_NOTAS  = "192.168.100.201"

    CONFIG_IP_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "config_ip_mapping.json")
    if os.path.exists(CONFIG_IP_MAPPING_PATH):
        try:
            with open(CONFIG_IP_MAPPING_PATH, "r") as f:
                IP_MAPPING_M2.update(json.load(f))
        except Exception as e:
            print(f"Error cargando config_ip_mapping.json: {e}")

    # Cargar roles y configuraciÃ³n de switches de forma dinÃ¡mica
    # Si existe el archivo config_switches.json (generado por Ansible), lo usa.
    # Si no, usa valores por defecto para evitar que se rompa en local.
    import json
    import os
    CONFIG_SWITCHES_PATH = os.path.join(os.path.dirname(__file__), "config_switches.json")
    
    if os.path.exists(CONFIG_SWITCHES_PATH):
        try:
            with open(CONFIG_SWITCHES_PATH, "r") as f:
                DYNAMIC_SWITCHES = json.load(f)
        except Exception as e:
            print(f"Error cargando config_switches.json: {e}")
            DYNAMIC_SWITCHES = {}
    else:
        # Fallback local
        DYNAMIC_SWITCHES = {
            "of:00005ec76ec6114c": {"name": "SW1", "role": "troncal"},
            "of:000072e0807e854c": {"name": "SW2", "role": "acceso_hosts"},
            "of:0000f220f9454c4e": {"name": "SW3", "role": "acceso_servidores"},
        }
    
    # DPIDs derivados desde roles generados por Ansible; si no existen,
    # caen a los DPIDs VNRT de desarrollo.
    SW1 = "of:00005ec76ec6114c"
    SW2 = "of:000072e0807e854c"
    SW3 = "of:0000f220f9454c4e"
    for _dpid, _data in DYNAMIC_SWITCHES.items():
        if _data.get("role") == "troncal":
            SW1 = _dpid
        elif _data.get("role") == "acceso_hosts":
            SW2 = _dpid
        elif _data.get("role") == "acceso_servidores":
            SW3 = _dpid

    SWITCH_NOMBRES = {dpid: data.get("name") for dpid, data in DYNAMIC_SWITCHES.items()}

    # Cargar HOSTS_VNRT dinÃ¡micamente si existe el archivo (generado por Ansible)
    CONFIG_HOSTS_PATH = os.path.join(os.path.dirname(__file__), "config_hosts.json")
    if os.path.exists(CONFIG_HOSTS_PATH):
        try:
            with open(CONFIG_HOSTS_PATH, "r") as f:
                HOSTS_VNRT = json.load(f)
        except Exception as e:
            print(f"Error cargando config_hosts.json: {e}")
            HOSTS_VNRT = {}
    else:
        # Fallback estÃ¡tico legacy
        HOSTS_VNRT = {
            "192.168.100.41": {
                "mac":         "FA:16:3E:53:F8:E8",
                "switch_dpid": "of:000072e0807e854c",
                "in_port":     2
            }
        }

    # Prioridades OpenFlow (acordadas en diseÃ±o de arquitectura)
    PRIO_VLAN_PUSH  = 10      # T1: sin tag â†’ PUSH VLAN 90
    PRIO_DHCP       = 500     # T1: DHCP â†’ CONTROLLER
    PRIO_PORTAL_T1  = 100     # T1: portal en cuarentena (tabla 1)
    PRIO_DROP_T1    = 5       # T1: DROP default cuarentena
    PRIO_SESION_T1  = 40000   # T1: SET_FIELD post-auth
    PRIO_T2_ALLOW   = 100     # T2: ALLOW proactivo por VLAN
    PRIO_T3_ALLOW   = 150     # T3: ALLOW personal por MAC/IP/puerto
    PRIO_T3_DENY    = 200     # T3: DROP por sesiÃ³n
    PRIO_T0_PORTAL  = 200     # T0: ruta directa portal (VERIFICADA en VNRT)
    PRIO_T0_USUARIO = 35000   # T0: enforcement por MAC post-auth
    PRIO_T0_ATAQUE  = 5000    # T0: bloqueo atacante (instalado por M4)
    PRIO_TABLE_MISS = 0       # pipeline clean: goto siguiente tabla / controller

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


# â”€â”€â”€ Constructor de flow entries â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class FlowBuilder:
    """Construye los JSON de flow entries para cada caso del pipeline."""

    # â”€â”€ T1: Cuarentena (tabla 1) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def vlan_push_cuarentena(self, device_id, in_port):
        """T1 prio10 â€” IP sin tag en in_port â†’ PUSH VLAN 90 + OUTPUT NORMAL."""
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
        """T1 prio500 â€” VLAN 90 + UDP dst=67 â†’ CONTROLLER."""
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
        """T1 prio100 â€” VLAN 90 + TCP + dst=portal â†’ OUTPUT NORMAL."""
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

    def internet_cuarentena_t1(self, device_id, ip_gateway=None):
        """T1 prio80 â€” VLAN 90 + gateway controlado â†’ OUTPUT NORMAL."""
        if ip_gateway is None:
            ip_gateway = Config.GATEWAY_INTERNET
        return {
            "priority":    80,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "VLAN_VID", "vlanId": Config.VLAN_CUARENTENA},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{ip_gateway}/32"}
            ]},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": "NORMAL"}
            ]}
        }

    def bloqueo_interno_cuarentena_t1(self, device_id, ip_destino):
        """T1 prio70 â€” VLAN 90 + destino interno PUCP â†’ DROP explÃ­cito."""
        return {
            "priority":    70,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "VLAN_VID", "vlanId": Config.VLAN_CUARENTENA},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IPV4_DST", "ip": f"{ip_destino}/32"}
            ]},
            "treatment": {"clearDeferred": True, "instructions": []}
        }

    def drop_default_cuarentena(self, device_id):
        """T1 prio5 â€” VLAN 90 + cualquier cosa â†’ DROP."""
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

    # â”€â”€ T1: SET_FIELD post-auth (tabla 1) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def set_vlan_post_auth(self, device_id, mac, in_port, vlan_nuevo,
                            idle_timeout=Config.SESSION_IDLE_TIMEOUT):
        """T1 prio40000 - MAC+IN_PORT autenticados -> SET_FIELD vlan_nuevo + goto T2."""
        return {
            "priority":    Config.PRIO_SESION_T1,
            "isPermanent": False,
            "timeout":     idle_timeout,
            "deviceId":    device_id,
            "tableId":     1,
            "selector": {"criteria": [
                {"type": "IN_PORT",  "port": in_port},
                {"type": "ETH_SRC",  "mac":  mac},
                {"type": "ETH_TYPE", "ethType": "0x0800"}
            ]},
            "treatment": {"instructions": [
                {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
                {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                 "vlanId": vlan_nuevo},
                {"type": "TABLE", "tableId": 2}
            ]}
        }

    # â”€â”€ T2: ALLOW reactivo por VLAN (tabla 2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def t2_allow_vlan(self, device_id, vlan_id, ip_dst, tcp_port,
                      idle_timeout=300, out_port="NORMAL", pop_vlan=False):
        """T2 prio100 â€” VLAN_VID + IP_DST + TCP_PORT â†’ OUTPUT NORMAL."""
        criteria = [
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IP_PROTO", "protocol": 6},
            {"type": "IPV4_DST", "ip": f"{ip_dst}/32"},
            {"type": "TCP_DST",  "tcpPort": tcp_port}
        ]
        if vlan_id is not None:
            criteria.insert(0, {"type": "VLAN_VID", "vlanId": vlan_id})

        instructions = []
        if pop_vlan:
            instructions.append({"type": "L2MODIFICATION", "subtype": "VLAN_POP"})
        instructions.append({"type": "OUTPUT", "port": out_port})
        return {
            "priority":    Config.PRIO_T2_ALLOW,
            "isPermanent": False,
            "timeout":     idle_timeout,
            "deviceId":    device_id,
            "tableId":     2,
            "selector": {"criteria": criteria},
            "treatment": {"instructions": instructions}
        }

    def t2_allow_reverse(self, device_id, ip_src, tcp_src, ip_dst, out_port,
                         vlan_id=None, idle_timeout=300, push_vlan=False,
                         pop_vlan=False):
        """T2 retorno: servidor:puerto -> cliente, con push/pop VLAN segun salto."""
        criteria = [
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IP_PROTO", "protocol": 6},
            {"type": "IPV4_SRC", "ip": f"{ip_src}/32"},
            {"type": "IPV4_DST", "ip": f"{ip_dst}/32"},
            {"type": "TCP_SRC",  "tcpPort": int(tcp_src)}
        ]
        if vlan_id is not None and not push_vlan:
            criteria.insert(0, {"type": "VLAN_VID", "vlanId": int(vlan_id)})

        instructions = []
        if push_vlan:
            instructions.extend([
                {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
                {"type": "L2MODIFICATION", "subtype": "VLAN_ID", "vlanId": int(vlan_id)}
            ])
        if pop_vlan:
            instructions.append({"type": "L2MODIFICATION", "subtype": "VLAN_POP"})
        instructions.append({"type": "OUTPUT", "port": out_port})

        return {
            "priority":    Config.PRIO_T2_ALLOW,
            "isPermanent": False,
            "timeout":     idle_timeout,
            "deviceId":    device_id,
            "tableId":     2,
            "selector":    {"criteria": criteria},
            "treatment":   {"instructions": instructions}
        }

    def goto_table_miss(self, device_id, table_id, next_table_id):
        """Table-miss generico: si no hay match, avanza a la siguiente tabla."""
        return {
            "priority":    Config.PRIO_TABLE_MISS,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     table_id,
            "selector":    {"criteria": []},
            "treatment": {"instructions": [
                {"type": "TABLE", "tableId": next_table_id}
            ]}
        }

    def t4_table_miss_controller(self, device_id):
        """T4 prio0 â€” decision reactiva final hacia ONOS/M6."""
        return {
            "priority":    Config.PRIO_TABLE_MISS,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     4,
            "selector":    {"criteria": []},
            "treatment": {"instructions": [
                {"type": "OUTPUT", "port": "CONTROLLER"}
            ]}
        }

    # â”€â”€ T3: DENY por sesiÃ³n (tabla 3) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def t3_allow_sesion(self, device_id, mac, ip_dst, tcp_port, out_port,
                        session_timeout=300, pop_vlan=False):
        """T3 prio200 â€” excepcion personal ALLOW por MAC+IP_DST+TCP_DST."""
        instructions = []
        if pop_vlan:
            instructions.append({"type": "L2MODIFICATION", "subtype": "VLAN_POP"})
        instructions.append({"type": "OUTPUT", "port": out_port})
        return {
            "priority":    Config.PRIO_T3_ALLOW,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     3,
            "selector": {"criteria": [
                {"type": "ETH_SRC",  "mac":  mac},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{ip_dst}/32"},
                {"type": "TCP_DST",  "tcpPort": int(tcp_port)}
            ]},
            "treatment": {"instructions": instructions}
        }

    def t3_allow_sesion_t2_fallback(self, device_id, mac, ip_dst, tcp_port,
                                    out_port, session_timeout=300,
                                    pop_vlan=False):
        """Fallback de laboratorio: misma excepcion personal en T2 si T3 no persiste."""
        instructions = []
        if pop_vlan:
            instructions.append({"type": "L2MODIFICATION", "subtype": "VLAN_POP"})
        instructions.append({"type": "OUTPUT", "port": out_port})
        return {
            "priority":    Config.PRIO_T3_ALLOW,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     2,
            "selector": {"criteria": [
                {"type": "ETH_SRC",  "mac":  mac},
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IP_PROTO", "protocol": 6},
                {"type": "IPV4_DST", "ip": f"{ip_dst}/32"},
                {"type": "TCP_DST",  "tcpPort": int(tcp_port)}
            ]},
            "treatment": {"instructions": instructions}
        }

    def t3_deny_sesion(self, device_id, mac, ip_src, ip_dst, tcp_port=None,
                        session_timeout=28800):
        """T3 prio200 â€” MAC+IP_SRC+IP_DST+TCP_DST opcional â†’ DROP."""
        criteria = [
            {"type": "ETH_SRC",  "mac":  mac},
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IP_PROTO", "protocol": 6},
            {"type": "IPV4_SRC", "ip": f"{ip_src}/32"},
            {"type": "IPV4_DST", "ip": f"{ip_dst}/32"}
        ]
        if tcp_port:
            criteria.append({"type": "TCP_DST", "tcpPort": int(tcp_port)})
        return {
            "priority":    Config.PRIO_T3_DENY,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     3,
            "selector": {"criteria": criteria},
            "treatment": {"clearDeferred": True, "instructions": []}
        }

    def t0_allow_arp(self, device_id):
        """T0 prio500 â€” ARP broadcast/unicast â†’ OUTPUT NORMAL (resoluciÃ³n MAC)."""
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

    # â”€â”€ T0: Bloqueo atacante (tabla 0) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def t0_bloqueo_ataque(self, device_id, ip_atacante, ttl=600, prio=None):
        """T0 prio5000+ â€” IP_SRC/32 atacante â†’ DROP con timeout."""
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

    def t0_table_miss_goto_t1(self, device_id):
        """T0 prio0 â€” si no hay castigo/ruta base, avanzar a T1."""
        return self.goto_table_miss(device_id, 0, 1)

    def t0_ipv4_goto_t1(self, device_id):
        """T0 prio10 - IPv4 normal avanza a T1 antes que apps legacy."""
        return {
            "priority":    10,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     0,
            "selector": {"criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"}
            ]},
            "treatment": {"instructions": [
                {"type": "TABLE", "tableId": 1}
            ]}
        }

    def t1_table_miss_goto_t2(self, device_id):
        """T1 prio0 â€” si no es cuarentena/portal, avanzar a T2."""
        return self.goto_table_miss(device_id, 1, 2)

    def t2_table_miss_goto_t3(self, device_id):
        """T2 prio0 â€” si RBAC general no decide, avanzar a T3."""
        return self.goto_table_miss(device_id, 2, 3)

    def t3_table_miss_goto_t4(self, device_id):
        """T3 prio0 â€” si no hay excepcion personal, avanzar a T4."""
        return self.goto_table_miss(device_id, 3, 4)


# â”€â”€â”€ Log asÃ­ncrono hacia M5 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class M5Logger:

    def __init__(self):
        self.cola = deque(maxlen=Config.MAX_COLA_LOGS)

    def log(self, evento):
        """EnvÃ­a a M5 en thread daemon para no bloquear la respuesta a M1."""
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
        """ReenvÃ­a todos los logs encolados cuando M5 se recupera."""
        while self.cola:
            self._enviar(self.cola.popleft())


# â”€â”€â”€ Motor de polÃ­ticas: OPA â†’ MySQL â†’ hardcoded â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class PolicyEngine:
    """
    Obtiene {permisos, denegaciones} para un usuario autenticado.
    Cadena de fallback: OPA (M2) â†’ MySQL (radius_db) â†’ tabla hardcoded por VLAN.
    """

    def get_policies(self, payload_opa):
        """
        payload_opa: {"input": {codigo_pucp, rol, vlan_id, ip_asignada, ...}}
        Retorna: {"permisos": [...], "denegaciones": [...]}

        Cadena de fallback: OPA M2 â†’ MySQL â†’ hardcoded por VLAN
        """
        input_data  = payload_opa.get("input", {})
        codigo_pucp = input_data.get("codigo_pucp", "")
        nombre_rol  = input_data.get("rol", "")
        vlan_id     = int(input_data.get("vlan_id", 0))

        # 1. OPA (M2) â€” usa polÃ­ticas RBAC completas con excepciones temporales
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
                if any(k in resultado for k in (
                    "permisos_generales", "excepciones_allow", "excepciones_deny"
                )):
                    print("  [PolicyEngine] Politicas separadas desde OPA M2")
                    return self._convertir_resultado_m2(resultado, vlan_id)
                if m2_permisos is not None:
                    print(f"  [PolicyEngine] PolÃ­ticas desde OPA M2 "
                          f"({len(m2_permisos)} permisos)")
                    return self._convertir_permisos_m2(m2_permisos, vlan_id)
        except Exception as e:
            print(f"  [PolicyEngine] OPA no disponible: {e}")

        # 2. MySQL â€” fallback si OPA no estÃ¡ corriendo
        pol_mysql = self._desde_mysql(nombre_rol)
        if pol_mysql is not None:
            return pol_mysql

        # 3. Hardcoded por VLAN â€” siempre disponible
        print(f"  [PolicyEngine] PolÃ­ticas hardcoded para VLAN {vlan_id}")
        return self._hardcoded(vlan_id)

    def _normalizar_ip(self, ip_raw):
        """Traduce IPs del diseÃ±o M2 (10.0.0.x) a IPs reales VNRT."""
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

        # Denegaciones: servidores VNRT conocidos que NO estÃ¡n en permisos
        all_vnrt  = {Config.SERVER_CURSOS, Config.SERVER_NOTAS}
        denied_ips = all_vnrt - set(allow_map.keys())
        denegaciones = [{"ip_dst": ip, "puertos": [80, 443]}
                        for ip in sorted(denied_ips)]

        return {"permisos": permisos, "denegaciones": denegaciones}

    def _agrupar_permisos_m2(self, items):
        allow_map = {}
        for p in items or []:
            recurso = p.get("recurso", {})
            ip_raw = recurso.get("ip_dst", "")
            puerto = recurso.get("puerto")
            if not ip_raw or puerto is None:
                continue
            ip_dst = self._normalizar_ip(ip_raw)
            allow_map.setdefault(ip_dst, set()).add(int(puerto))
        return [
            {"ip_dst": ip, "puertos": sorted(ports)}
            for ip, ports in allow_map.items()
        ]

    def _fusionar_listas_puertos(self, *listas):
        merged = {}
        for lista in listas:
            for item in lista:
                merged.setdefault(item["ip_dst"], set()).update(
                    item.get("puertos", [])
                )
        return [
            {"ip_dst": ip, "puertos": sorted(ports)}
            for ip, ports in merged.items()
        ]

    def _convertir_resultado_m2(self, resultado, vlan_id):
        permisos_generales = self._agrupar_permisos_m2(
            resultado.get("permisos_generales", [])
        )
        excepciones_allow = self._agrupar_permisos_m2(
            resultado.get("excepciones_allow", [])
        )
        excepciones_deny = self._agrupar_permisos_m2(
            resultado.get("excepciones_deny", [])
        )
        permisos = self._agrupar_permisos_m2(resultado.get("permisos", []))
        if not permisos:
            permisos = self._fusionar_listas_puertos(
                permisos_generales, excepciones_allow
            )
        return {
            "permisos": permisos,
            "denegaciones": excepciones_deny,
            "permisos_generales": permisos_generales,
            "excepciones_allow": excepciones_allow,
            "excepciones_deny": excepciones_deny,
        }

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

            # Si varios recursos viven en la misma IP real, se decide por puerto.
            # ALLOW prevalece solo sobre el mismo puerto, no sobre toda la IP.
            for ip in list(deny_map.keys()):
                allowed_ports = set(allow_map.get(ip, []))
                deny_ports = [p for p in deny_map[ip] if p not in allowed_ports]
                if deny_ports:
                    deny_map[ip] = deny_ports
                else:
                    del deny_map[ip]

            print(f"  [PolicyEngine] MySQL â€” {nombre_rol}: "
                  f"{len(allow_map)} destinos ALLOW, {len(deny_map)} DENY")
            permisos = [{"ip_dst": ip, "puertos": sorted(set(ps))}
                        for ip, ps in allow_map.items()]
            denegaciones = [{"ip_dst": ip, "puertos": sorted(set(ps))}
                            for ip, ps in deny_map.items()]
            return {
                "permisos": permisos,
                "denegaciones": denegaciones,
                "permisos_generales": permisos,
                "excepciones_allow": [],
                "excepciones_deny": denegaciones,
            }
        except Exception as e:
            print(f"  [PolicyEngine] MySQL error: {e}")
            return None

    def _hardcoded(self, vlan_id):
        """PolÃ­ticas por defecto â€” espejo de la arquitectura de acceso PUCP."""
        cursos, notas = Config.SERVER_CURSOS, Config.SERVER_NOTAS
        if vlan_id in (210, 220, 230):    # Estudiantes â€” solo cursos
            permisos = [{"ip_dst": cursos, "puertos": [80, 443]}]
            denegaciones = [{"ip_dst": notas,  "puertos": [80, 443]}]
        elif vlan_id in (300, 400):        # Docentes y Admin â€” cursos + notas
            permisos = [
                {"ip_dst": cursos, "puertos": [80, 443]},
                {"ip_dst": notas,  "puertos": [80, 443]}
            ]
            denegaciones = []
        else:                              # Visitante
            permisos = [{"ip_dst": cursos, "puertos": [80]}]
            denegaciones = []
        return {
            "permisos": permisos,
            "denegaciones": denegaciones,
            "permisos_generales": permisos,
            "excepciones_allow": [],
            "excepciones_deny": denegaciones,
        }

    def obtener_rol_por_vlan(self, vlan_id):
        """Traduce VLAN a Rol consultando radius_db.roles_facultad."""
        if not MYSQL_OK:
            # Fallback simple
            mapping = {210: "Estudiante_Telecom", 220: "Estudiante_Informatica",
                       230: "Estudiante_Electronica", 300: "Docente", 400: "Admin_TI"}
            return mapping.get(vlan_id)
            
        try:
            conn = mysql.connector.connect(
                host=Config.MYSQL_HOST, user=Config.MYSQL_USER,
                password=Config.MYSQL_PASS, database=Config.MYSQL_DB,
                connection_timeout=3
            )
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT nombre_rol FROM roles_facultad WHERE vlan_id = %s", (vlan_id,))
            row = cur.fetchone()
            conn.close()
            return row["nombre_rol"] if row else None
        except Exception as e:
            print(f"  [PolicyEngine] MySQL error obtener_rol: {e}")
            return None

    def obtener_roles_por_usuario(self, codigo_pucp):
        """Retorna todos los roles activos asociados al usuario."""
        if not MYSQL_OK or not codigo_pucp:
            return []
        try:
            conn = mysql.connector.connect(
                host=Config.MYSQL_HOST, user=Config.MYSQL_USER,
                password=Config.MYSQL_PASS, database=Config.MYSQL_DB,
                connection_timeout=3
            )
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT rf.nombre_rol
                FROM usuarios u
                JOIN usuarios_roles ur ON ur.id_usuario = u.id_usuario
                JOIN roles_facultad rf ON rf.id_rol = ur.id_rol
                WHERE u.codigo_pucp = %s
                  AND ur.activo = 1
                ORDER BY ur.id_rol ASC
            """, (codigo_pucp,))
            rows = cur.fetchall() or []
            conn.close()
            return [row["nombre_rol"] for row in rows if row.get("nombre_rol")]
        except Exception as e:
            print(f"  [PolicyEngine] MySQL error roles_usuario: {e}")
            return []

    def obtener_vlan_por_rol(self, nombre_rol):
        """Retorna la VLAN asociada a un rol."""
        if not MYSQL_OK or not nombre_rol:
            return None
        try:
            conn = mysql.connector.connect(
                host=Config.MYSQL_HOST, user=Config.MYSQL_USER,
                password=Config.MYSQL_PASS, database=Config.MYSQL_DB,
                connection_timeout=3
            )
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT vlan_id FROM roles_facultad WHERE nombre_rol = %s",
                (nombre_rol,)
            )
            row = cur.fetchone()
            conn.close()
            return int(row["vlan_id"]) if row and row.get("vlan_id") is not None else None
        except Exception as e:
            print(f"  [PolicyEngine] MySQL error vlan_rol: {e}")
            return None


# â”€â”€â”€ Cliente ONOS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class ONOSClient:
    """Toda la comunicaciÃ³n con ONOS REST API pasa por aquÃ­."""

    def __init__(self):
        self.url  = Config.ONOS_URL
        self.auth = Config.ONOS_AUTH

    def _post_flow(self, device_id, flow_entry, reintentos=0):
        """
        POST /onos/v1/flows/{deviceId}
        El flow se envÃ­a DIRECTAMENTE como body (sin wrapper {"flows": [...]}).
        El wrapper es exclusivo del endpoint batch POST /onos/v1/flows.
        Retorna el flowId asignado por ONOS, o None si fallÃ³.
        """
        endpoint = f"{self.url}/onos/v1/flows/{device_id}"
        try:
            resp = requests.post(
                endpoint, json=flow_entry,
                auth=self.auth, timeout=5
            )
            if resp.status_code in (200, 201):
                # ONOS 2.7.0 devuelve HTTP 201 con body VACï¿½?O.
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
                print(f"    [ONOS] âœ“ {nombre} T{flow_entry.get('tableId','?')} "
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
            print(f"    [ONOS] âœ— Fallo definitivo: {e}")
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

    def _list_flows(self, device_id):
        endpoint = f"{self.url}/onos/v1/flows/{device_id}"
        try:
            resp = requests.get(endpoint, auth=self.auth, timeout=5)
            if resp.status_code == 200:
                data = resp.json() or {}
                return data.get("flows", []) or []
            print(f"  [ONOS] Error al listar flows de {device_id}: "
                  f"HTTP {resp.status_code}")
            return []
        except Exception as e:
            print(f"  [ONOS] Error al listar flows de {device_id}: {e}")
            return []

    def flow_existe(self, device_id, flow_id):
        for flow in self._list_flows(device_id):
            if str(flow.get("id")) == str(flow_id):
                return True
        return False

    def get_host_by_ip(self, ip_asignada):
        """
        Busca host en ONOS por IP â†’ {mac, switch_dpid, in_port}.
        Si ONOS no lo tiene (IP asignada fuera de ONOS DHCP), usa HOSTS_VNRT.
        """
        # Para el lab/demo, Ansible descubre los puertos reales de acceso.
        # Preferimos ese mapa porque ONOS puede aprender el host por un trunk
        # durante ARP/LLDP y entregar un puerto incorrecto para access.
        if ip_asignada in Config.HOSTS_VNRT:
            h = Config.HOSTS_VNRT[ip_asignada]
            print(f"  [ONOS] Host estatico {ip_asignada}: sw={h['switch_dpid']} p{h['in_port']}")
            return dict(h)

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

        print(f"  [ONOS] Host {ip_asignada} no encontrado")
        return None

    def get_path_to_ip(self, src_device_id, dst_ip):
        """
        Devuelve saltos {device_id, out_port} desde src_device_id hasta dst_ip.
        El ultimo salto sale hacia el puerto donde ONOS ubica al host destino.
        """
        dst_host = self.get_host_by_ip(dst_ip)
        if not dst_host:
            print(f"  [ONOS] No se pudo resolver destino {dst_ip}; usando NORMAL")
            return []

        dst_device_id = dst_host["switch_dpid"]
        dst_host_port = dst_host["in_port"]

        if src_device_id == dst_device_id:
            return [{
                "device_id": src_device_id,
                "out_port": dst_host_port,
                "kind": "host",
            }]

        try:
            src_path_id = quote(src_device_id, safe="")
            dst_path_id = quote(dst_device_id, safe="")
            resp = requests.get(
                f"{self.url}/onos/v1/paths/{src_path_id}/{dst_path_id}",
                auth=self.auth, timeout=5
            )
            if resp.status_code != 200:
                print(f"  [ONOS] Error GET /paths: HTTP {resp.status_code} {resp.text[:200]}")
                return []

            paths = resp.json().get("paths", [])
            if not paths:
                print(f"  [ONOS] Sin camino {src_device_id} -> {dst_device_id}")
                return []

            hops = []
            for link in paths[0].get("links", []):
                src = link.get("src", {})
                device = src.get("device")
                port = src.get("port")
                if device and port:
                    hops.append({
                        "device_id": device,
                        "out_port": int(port) if str(port).isdigit() else port,
                        "kind": "link",
                    })

            hops.append({
                "device_id": dst_device_id,
                "out_port": dst_host_port,
                "kind": "host",
            })

            resumen = " -> ".join(
                f"{Config.SWITCH_NOMBRES.get(h['device_id'], h['device_id'])}:p{h['out_port']}"
                for h in hops
            )
            print(f"  [ONOS] Path {src_device_id} -> {dst_ip}: {resumen}")
            return hops

        except Exception as e:
            print(f"  [ONOS] Error calculando path hacia {dst_ip}: {e}")
            return []

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
        print(f"  [ONOS] {nombre} â€” acceso={access_ports} trunk={sorted(trunk_ports)}")
        return access_ports

    def instalar_flow(self, device_id, flow_entry):
        return self._post_flow(device_id, flow_entry)

    def eliminar_flow(self, device_id, flow_id):
        return self._delete_flow(device_id, flow_id)


# â”€â”€â”€ LÃ³gica principal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class M6Translator:

    def __init__(self):
        self.onos     = ONOSClient()
        self.builder  = FlowBuilder()
        self.logger   = M5Logger()
        self.policies = PolicyEngine()
        # Cache flows por sesiÃ³n: {mac: [(device_id, flow_id), ...]}
        # Protegido por lock para acceso concurrente (Flask threaded)
        self._lock = threading.Lock()
        self.flows_por_sesion = {}
        self.sesiones_por_mac = {}
        self.t1_flow_por_mac = {}
        self._stop_reaper = threading.Event()
        self._reaper_thread = threading.Thread(
            target=self._reaper_sesiones,
            name="m6-session-reaper",
            daemon=True,
        )
        self._reaper_thread.start()

    def autenticar_cli(self, codigo_pucp, password, ip_asignada):
        """Valida credenciales en MySQL y activa la sesion via token M6."""
        if not MYSQL_OK:
            return None, "mysql_no_disponible"

        conn = None
        try:
            conn = mysql.connector.connect(
                host=Config.MYSQL_HOST,
                user=Config.MYSQL_USER,
                password=Config.MYSQL_PASS,
                database=Config.MYSQL_DB,
                connection_timeout=3,
            )
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT u.id_usuario, u.estado_cuenta,
                       rf.nombre_rol, rf.vlan_id
                FROM usuarios u
                JOIN usuarios_roles ur ON ur.id_usuario = u.id_usuario
                JOIN roles_facultad rf ON rf.id_rol = ur.id_rol
                WHERE u.codigo_pucp = %s
                  AND u.password_hash = SHA2(%s, 256)
                  AND ur.activo = 1
                ORDER BY rf.vlan_id ASC, rf.nombre_rol ASC
                LIMIT 1
            """, (codigo_pucp, password))
            row = cur.fetchone()
            if not row:
                return None, "credenciales_invalidas"
            if row.get("estado_cuenta") != "ACTIVO":
                return None, "cuenta_no_activa"

            token = {
                "id_usuario": row["id_usuario"],
                "codigo_pucp": codigo_pucp,
                "nombre_rol": row["nombre_rol"],
                "vlan_id": int(row["vlan_id"]),
                "ip_asignada": ip_asignada,
            }
            resultado = self.procesar_token_rol(token)
            if not resultado:
                return None, "m6_no_pudo_activar_sesion"
            resultado.update({
                "codigo_pucp": codigo_pucp,
                "nombre_rol": row["nombre_rol"],
                "vlan_id": int(row["vlan_id"]),
                "ip_asignada": ip_asignada,
            })
            return resultado, None
        except Exception as e:
            print(f"  [CLI Login] Error autenticando {codigo_pucp}: {e}")
            return None, "error_interno"
        finally:
            if conn:
                conn.close()

    def _instalar_y_cachear(self, device_id, flow_entry, mac=None):
        """Instala un flow y lo registra en el cache de sesiÃ³n si se provee mac."""
        fid = self.onos.instalar_flow(device_id, flow_entry)
        if fid and mac is not None:
            with self._lock:
                self.flows_por_sesion.setdefault(mac, [])
                self.flows_por_sesion[mac].append((device_id, fid))
        return fid

    def _mysql_conn(self):
        if not MYSQL_OK:
            return None
        try:
            return mysql.connector.connect(
                host=Config.MYSQL_HOST,
                user=Config.MYSQL_USER,
                password=Config.MYSQL_PASS,
                database=Config.MYSQL_DB,
                connection_timeout=3,
            )
        except Exception as e:
            print(f"  [M6][MySQL] No se pudo conectar: {e}")
            return None

    def _obtener_id_usuario_por_codigo(self, codigo_pucp):
        conn = self._mysql_conn()
        if not conn:
            return None
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id_usuario FROM usuarios WHERE codigo_pucp = %s",
                (codigo_pucp,)
            )
            row = cur.fetchone()
            return row["id_usuario"] if row else None
        except Exception as e:
            print(f"  [M6][MySQL] Error buscando usuario {codigo_pucp}: {e}")
            return None
        finally:
            conn.close()

    def _cargar_sesion_mysql(self, mac):
        conn = self._mysql_conn()
        if not conn:
            return None
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT s.id_sesion, s.id_usuario, u.codigo_pucp, s.mac_address,
                       s.ip_asignada, s.vlan_id, s.nombre_rol, s.switch_dpid,
                       s.in_port, s.login_timestamp, s.estado
                FROM sesiones_activas s
                LEFT JOIN usuarios u ON u.id_usuario = s.id_usuario
                WHERE s.mac_address = %s
                LIMIT 1
            """, (mac,))
            return cur.fetchone()
        except Exception as e:
            print(f"  [M6][MySQL] Error cargando sesion {mac}: {e}")
            return None
        finally:
            conn.close()

    def _registrar_sesion_mysql(self, id_usuario, codigo_pucp, mac, ip_asignada,
                                vlan_id, nombre_rol, switch_dpid, in_port):
        conn = self._mysql_conn()
        if not conn:
            return None
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO sesiones_activas
                    (id_usuario, mac_address, ip_asignada, vlan_id,
                     nombre_rol, switch_dpid, in_port)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    id_usuario      = VALUES(id_usuario),
                    ip_asignada     = VALUES(ip_asignada),
                    vlan_id         = VALUES(vlan_id),
                    nombre_rol      = VALUES(nombre_rol),
                    switch_dpid     = VALUES(switch_dpid),
                    in_port         = VALUES(in_port),
                    login_timestamp = NOW(),
                    estado          = 'ACTIVA',
                    id_sesion       = LAST_INSERT_ID(id_sesion)
            """, (id_usuario, mac, ip_asignada, vlan_id, nombre_rol, switch_dpid, in_port))
            id_sesion = cur.lastrowid
            if not id_sesion:
                cur.execute(
                    "SELECT id_sesion FROM sesiones_activas WHERE mac_address = %s",
                    (mac,)
                )
                row = cur.fetchone()
                id_sesion = row[0] if row else None
            if not id_sesion:
                raise RuntimeError("No se pudo obtener id_sesion")

            cur.execute("""
                INSERT INTO ip_mac_binding
                    (ip_asignada, mac_address, id_sesion)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    id_sesion = VALUES(id_sesion)
            """, (ip_asignada, mac, id_sesion))

            conn.commit()
            print(f"  [M6][MySQL] sesion activa registrada: {codigo_pucp} "
                  f"mac={mac} id_sesion={id_sesion}")
            return id_sesion
        except Exception as e:
            conn.rollback()
            print(f"  [M6][MySQL] Error registrando sesion {codigo_pucp}: {e}")
            return None
        finally:
            conn.close()

    def _archivar_y_borrar_sesion_mysql(self, mac, motivo_cierre):
        conn = self._mysql_conn()
        if not conn:
            return False
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT s.id_sesion, s.id_usuario, s.mac_address, s.ip_asignada,
                       s.vlan_id, s.nombre_rol, s.switch_dpid, s.in_port,
                       s.login_timestamp
                FROM sesiones_activas s
                WHERE s.mac_address = %s
                LIMIT 1
            """, (mac,))
            sesion = cur.fetchone()
            if not sesion:
                return False

            cur.execute("""
                INSERT INTO historial_sesiones
                    (id_usuario, mac_address, ip_asignada, vlan_id, nombre_rol,
                     switch_dpid, in_port, login_timestamp, logout_timestamp,
                     motivo_cierre)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
            """, (
                sesion["id_usuario"], sesion["mac_address"], sesion["ip_asignada"],
                sesion["vlan_id"], sesion["nombre_rol"], sesion["switch_dpid"],
                sesion["in_port"], sesion["login_timestamp"], motivo_cierre
            ))
            cur.execute(
                "DELETE FROM ip_mac_binding WHERE mac_address = %s",
                (mac,)
            )
            cur.execute(
                "DELETE FROM sesiones_activas WHERE id_sesion = %s",
                (sesion["id_sesion"],)
            )
            conn.commit()
            print(f"  [M6][MySQL] sesion archivada y borrada: mac={mac} motivo={motivo_cierre}")
            return True
        except Exception as e:
            conn.rollback()
            print(f"  [M6][MySQL] Error archivando sesion {mac}: {e}")
            return False
        finally:
            conn.close()

    def _limpiar_sesion_completa(self, mac, motivo_cierre="LOGOUT"):
        mac_norm = (mac or "").upper()
        mac_alt = (mac or "").lower()
        if not mac_norm:
            return 0

        with self._lock:
            flows = self.flows_por_sesion.pop(mac_norm, [])
            if not flows and mac_alt:
                flows = self.flows_por_sesion.pop(mac_alt, [])
            self.sesiones_por_mac.pop(mac_norm, None)
            if mac_alt:
                self.sesiones_por_mac.pop(mac_alt, None)
            self.t1_flow_por_mac.pop(mac_norm, None)
            if mac_alt:
                self.t1_flow_por_mac.pop(mac_alt, None)

        print(f"\n[M6] Cerrando sesion MAC={mac_norm} motivo={motivo_cierre} "
              f"— {len(flows)} flows")
        for device_id, flow_id in flows:
            self.onos.eliminar_flow(device_id, flow_id)

        if MYSQL_OK:
            self._archivar_y_borrar_sesion_mysql(mac_norm, motivo_cierre)

        self.logger.log({
            "modulo":           "M6",
            "evento":           "sesion_cerrada",
            "motivo":           motivo_cierre,
            "mac":              mac_norm,
            "flows_eliminados": len(flows)
        })
        return len(flows)

    def _reaper_sesiones(self):
        while not self._stop_reaper.is_set():
            try:
                time.sleep(Config.SESSION_REAPER_INTERVAL)
                ahora = time.time()
                with self._lock:
                    sesiones = list(self.sesiones_por_mac.items())

                for mac, meta in sesiones:
                    last_activity = float(meta.get("last_activity", meta.get("login_at", ahora)))
                    if ahora - last_activity < Config.SESSION_IDLE_TIMEOUT:
                        continue
                    self._limpiar_sesion_completa(mac, motivo_cierre="TIMEOUT")
            except Exception as e:
                print(f"  [M6][Reaper] error: {e}")


    # â”€â”€ Arranque â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _path_hacia_destino(self, src_device_id, ip_dst):
        """
        Pide a ONOS el camino hasta ip_dst. Si ONOS no puede resolverlo,
        devuelve una lista vacia y el llamador decide si usa fallback NORMAL.
        """
        return self.onos.get_path_to_ip(src_device_id, ip_dst)

    def _instalar_t2_allow_por_path(self, src_device_id, vlan_id, ip_dst,
                                    tcp_port, cache_mac=None, src_ip=None):
        """Instala T2 ALLOW por VLAN en todos los switches del path calculado."""
        hops = self._path_hacia_destino(src_device_id, ip_dst)
        if not hops:
            print(f"  [T2] Sin path dinamico hacia {ip_dst}; fallback OUTPUT NORMAL")
            fid = self._instalar_y_cachear(
                src_device_id,
                self.builder.t2_allow_vlan(
                    src_device_id, vlan_id, ip_dst, tcp_port, idle_timeout=300
                ),
                cache_mac,
            )
            return 1 if fid else 0

        instalados = 0
        for i, hop in enumerate(hops):
            es_salida_host = hop.get("kind") == "host"
            es_primer_trunk = i == 0 and hop.get("kind") == "link"
            fid = self._instalar_y_cachear(
                hop["device_id"],
                self.builder.t2_allow_vlan(
                    hop["device_id"], vlan_id, ip_dst, tcp_port,
                    idle_timeout=300, out_port=hop["out_port"],
                    pop_vlan=es_salida_host or es_primer_trunk
                ),
                cache_mac,
            )
            if fid:
                instalados += 1

            # En algunos slices OVS/ONOS el tag no se preserva o se filtra
            # entre bridges virtuales. Despues del borde instalamos match sin VLAN.
            if i > 0:
                fid = self._instalar_y_cachear(
                    hop["device_id"],
                    self.builder.t2_allow_vlan(
                        hop["device_id"], None, ip_dst, tcp_port,
                        idle_timeout=300, out_port=hop["out_port"],
                        pop_vlan=False
                    ),
                    cache_mac,
                )
                if fid:
                    instalados += 1

        if src_ip:
            instalados += self._instalar_t2_retorno_por_path(
                ip_servidor=ip_dst,
                tcp_src=tcp_port,
                ip_cliente=src_ip,
                vlan_id=vlan_id,
                cache_mac=cache_mac,
            )
        return instalados

    def _instalar_t2_retorno_por_path(self, ip_servidor, tcp_src, ip_cliente,
                                      vlan_id, cache_mac=None):
        """Instala retorno TCP desde servidor:puerto hacia cliente."""
        servidor = self.onos.get_host_by_ip(ip_servidor)
        if not servidor:
            print(f"  [T2] Sin host servidor {ip_servidor}; no instalo retorno")
            return 0

        hops = self._path_hacia_destino(servidor["switch_dpid"], ip_cliente)
        if not hops:
            print(f"  [T2] Sin path retorno {ip_servidor} -> {ip_cliente}")
            return 0

        instalados = 0
        for i, hop in enumerate(hops):
            fid = self._instalar_y_cachear(
                hop["device_id"],
                self.builder.t2_allow_reverse(
                    hop["device_id"],
                    ip_src=ip_servidor,
                    tcp_src=tcp_src,
                    ip_dst=ip_cliente,
                    out_port=hop["out_port"],
                    vlan_id=None,
                    idle_timeout=300,
                    push_vlan=False,
                    pop_vlan=False,
                ),
                cache_mac,
            )
            if fid:
                instalados += 1
        return instalados

    def _instalar_t3_allow_por_path(self, src_device_id, mac, ip_cliente, ip_dst,
                                    tcp_port, cache_mac=None):
        """Instala T3 ALLOW personal por MAC sobre el path calculado."""
        hops = self._path_hacia_destino(src_device_id, ip_dst)
        if not hops:
            print(f"  [T3] Sin path dinamico hacia {ip_dst}; fallback OUTPUT NORMAL")
            fid = self._instalar_y_cachear(
                src_device_id,
                self.builder.t3_allow_sesion(
                    src_device_id, mac, ip_dst, tcp_port, out_port="NORMAL"
                ),
                cache_mac,
            )
            fid_fallback = self._instalar_y_cachear(
                src_device_id,
                self.builder.t3_allow_sesion_t2_fallback(
                    src_device_id, mac, ip_dst, tcp_port, out_port="NORMAL"
                ),
                cache_mac,
            )
            return (1 if fid else 0) + (1 if fid_fallback else 0)

        instalados = 0
        total_hops = len(hops)
        for i, hop in enumerate(hops):
            es_salida_host = hop.get("kind") == "host"
            es_ultimo_salto = i == total_hops - 1
            fid = self._instalar_y_cachear(
                hop["device_id"],
                self.builder.t3_allow_sesion(
                    hop["device_id"], mac, ip_dst, tcp_port,
                    out_port=hop["out_port"],
                    session_timeout=300,
                    pop_vlan=es_salida_host or es_ultimo_salto,
                ),
                cache_mac,
            )
            if fid:
                instalados += 1
            fid_fallback = self._instalar_y_cachear(
                hop["device_id"],
                self.builder.t3_allow_sesion_t2_fallback(
                    hop["device_id"], mac, ip_dst, tcp_port,
                    out_port=hop["out_port"],
                    session_timeout=300,
                    pop_vlan=es_salida_host or es_ultimo_salto,
                ),
                cache_mac,
            )
            if fid_fallback:
                instalados += 1
        instalados += self._instalar_t2_retorno_por_path(
            ip_servidor=ip_dst,
            tcp_src=tcp_port,
            ip_cliente=ip_cliente,
            vlan_id=None,
            cache_mac=cache_mac,
        )
        return instalados

    def _rol_autoriza_destino(self, codigo_pucp, nombre_rol, ip_dst, tcp_port):
        """Pregunta a M2/OPA si un rol dado permite un destino puntual."""
        vlan_rol = self.policies.obtener_vlan_por_rol(nombre_rol) or 0
        payload = {
            "input": {
                "codigo_pucp": codigo_pucp,
                "rol": nombre_rol,
                "vlan_id": vlan_rol,
                "mac_address": "",
                "ip_asignada": "",
                "switch_dpid": "",
                "in_port": None,
            }
        }
        politicas = self.policies.get_policies(payload)
        lista = politicas.get("permisos_generales", politicas.get("permisos", []))
        for item in lista:
            if item["ip_dst"] == ip_dst:
                puertos = item.get("puertos", [])
                if not puertos or tcp_port in puertos:
                    return True
        for item in politicas.get("excepciones_allow", []):
            if item["ip_dst"] == ip_dst:
                puertos = item.get("puertos", [])
                if not puertos or tcp_port in puertos:
                    return True
        for item in politicas.get("excepciones_deny", []):
            if item["ip_dst"] == ip_dst:
                puertos = item.get("puertos", [])
                if not puertos or tcp_port in puertos:
                    return False
        return False

    def _intentar_roles_alternos(self, codigo_pucp, roles, ip_dst, tcp_port):
        """Busca un rol alterno que autorice el destino."""
        for rol in roles:
            if self._rol_autoriza_destino(codigo_pucp, rol, ip_dst, tcp_port):
                return rol
        return None

    def instalar_cuarentena_arranque(self):
        """
        Instala al arrancar:
          1. T1 cuarentena en todos los switches (VLAN 90)
          2. T0 rutas directas portal en SW1 y SW2 (funcionan en VNRT)
          3. T2 ALLOW proactivo por VLAN â†’ servidor en SW2
        """
        devices     = self.onos.get_devices()
        devices_set = set(devices)
        SEP = "â”€" * 47

        print(f"\n[M6] {SEP}")
        print(f"[M6]  Cuarentena arranque â€” {len(devices)} switch(es)")
        print(f"[M6] {SEP}")

        # T1: Cuarentena VLAN 90 en todos los switches
        # VLAN push solo en SW2 (host access); puertos descubiertos dinÃ¡micamente
        sw2_access_ports = (self.onos.get_access_ports(Config.SW2)
                            if Config.SW2 in devices_set else [])

        for device_id in devices:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id)
            print(f"\n  â†’ {nombre}")

            self.onos.instalar_flow(device_id,
                self.builder.dhcp_al_controller(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.portal_cuarentena_t1(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.internet_cuarentena_t1(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.bloqueo_interno_cuarentena_t1(
                    device_id, Config.SERVER_CURSOS))
            self.onos.instalar_flow(device_id,
                self.builder.bloqueo_interno_cuarentena_t1(
                    device_id, Config.SERVER_NOTAS))
            self.onos.instalar_flow(device_id,
                self.builder.drop_default_cuarentena(device_id))
            if device_id == Config.SW2:
                for puerto in sw2_access_ports:
                    self.onos.instalar_flow(device_id,
                        self.builder.vlan_push_cuarentena(device_id, puerto))
                print(f"    T1 VLAN push cuarentena â†’ puertos acceso: {sw2_access_ports}")

        print(f"\n  [T0] Pipeline limpio: portal se maneja en T1, no en T0")

        # T0: ARP pass-through en todos los switches (necesario para resoluciÃ³n MAC)
        print(f"\n  [T0] ARP pass-through (0x0806 â†’ NORMAL):")
        for device_id in devices:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id)
            self.onos.instalar_flow(device_id, self.builder.t0_allow_arp(device_id))
            print(f"    âœ“ {nombre}")

        print(f"\n  [PIPELINE] T0->T1->T2, T2->T3, T3->T4, T4->CONTROLLER")
        for device_id in devices:
            nombre = Config.SWITCH_NOMBRES.get(device_id, device_id)
            self.onos.instalar_flow(device_id,
                self.builder.t0_table_miss_goto_t1(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.t0_ipv4_goto_t1(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.t1_table_miss_goto_t2(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.t2_table_miss_goto_t3(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.t3_table_miss_goto_t4(device_id))
            self.onos.instalar_flow(device_id,
                self.builder.t4_table_miss_controller(device_id))
            print(f"    âœ“ pipeline limpio instalado en {nombre}")

        print(f"\n[M6] {SEP}")
        print("[M6]  Arranque completado")
        print(f"[M6] {SEP}\n")

    # â”€â”€ Procesamiento de token de M1 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def procesar_token_rol(self, token):
        """
        Punto de entrada desde M1 tras autenticaciÃ³n exitosa.
        token = {codigo_pucp, nombre_rol, vlan_id, ip_asignada}
        Retorna {mac, switch_dpid, in_port} para que M1 registre la sesiÃ³n.
        """
        codigo_pucp = token["codigo_pucp"]
        nombre_rol  = token["nombre_rol"]
        vlan_id     = int(token["vlan_id"])
        ip_asignada = token["ip_asignada"]

        print(f"\n[M6] â”€â”€ Token de M1 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
        print(f"  usuario={codigo_pucp}  rol={nombre_rol}  "
              f"vlan={vlan_id}  ip={ip_asignada}")

        # 1. Resolver host: ONOS GET /hosts â†’ fallback VNRT
        host = self.onos.get_host_by_ip(ip_asignada)
        if not host:
            self.logger.log({
                "modulo": "M6", "evento": "error_host_no_encontrado",
                "ip": ip_asignada, "usuario": codigo_pucp
            })
            return None

        mac         = host["mac"]
        switch_dpid = host["switch_dpid"]
        in_port     = host["in_port"]
        nombre_sw   = Config.SWITCH_NOMBRES.get(switch_dpid, switch_dpid)
        print(f"  host: mac={mac}  switch={nombre_sw}  puerto={in_port}")
        id_usuario = token.get("id_usuario") or self._obtener_id_usuario_por_codigo(codigo_pucp)
        if id_usuario is None:
            print(f"  [M6] No se pudo resolver id_usuario para {codigo_pucp}")
            return None

        login_at = time.time()
        with self._lock:
            self.sesiones_por_mac[mac.upper()] = {
                "id_usuario": id_usuario,
                "codigo_pucp": codigo_pucp,
                "nombre_rol": nombre_rol,
                "vlan_id": vlan_id,
                "ip_asignada": ip_asignada,
                "switch_dpid": switch_dpid,
                "in_port": in_port,
                "login_at": login_at,
                "last_activity": login_at,
                "session_timeout": Config.SESSION_IDLE_TIMEOUT,
            }

        if MYSQL_OK:
            if not self._registrar_sesion_mysql(
                id_usuario, codigo_pucp, mac, ip_asignada, vlan_id,
                nombre_rol, switch_dpid, in_port
            ):
                return None

        # 2. T1 SET_FIELD: VLAN 90 â†’ vlan_id del rol (tabla 1, per-sesiÃ³n)
        print(f"  [T1] SET_FIELD VLAN {Config.VLAN_CUARENTENA}â†’{vlan_id}...")
        fid_t1 = self._instalar_y_cachear(
            switch_dpid,
            self.builder.set_vlan_post_auth(
                switch_dpid, mac, in_port, vlan_id,
                idle_timeout=Config.SESSION_IDLE_TIMEOUT
            ),
            mac
        )
        with self._lock:
            self.t1_flow_por_mac[mac.upper()] = (switch_dpid, fid_t1) if fid_t1 else None

        # 3. Obtener polÃ­ticas (OPA â†’ MySQL â†’ hardcoded)
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

        # 4. Instalar flows de polÃ­tica
        n_allow, n_deny = 0, 0
        print(f"  Instalando enforcement...")

        permisos_generales = politicas.get("permisos_generales") or politicas.get("permisos", [])
        excepciones_allow = politicas.get("excepciones_allow", [])
        excepciones_deny = politicas.get("excepciones_deny") or politicas.get("denegaciones", [])

        for permiso in permisos_generales:
            ip_dst = permiso["ip_dst"]
            puertos = permiso.get("puertos", [80, 443]) or [0]
            for tcp_port in puertos:
                self._instalar_t2_allow_por_path(
                    switch_dpid, vlan_id, ip_dst, tcp_port,
                    cache_mac=mac, src_ip=ip_asignada
                )
            n_allow += 1

        for permiso in excepciones_allow:
            ip_dst = permiso["ip_dst"]
            puertos = permiso.get("puertos", [80, 443]) or [0]
            for tcp_port in puertos:
                self._instalar_t3_allow_por_path(
                    switch_dpid, mac, ip_dst, tcp_port, cache_mac=mac
                )
            n_allow += 1

        for denegacion in excepciones_deny:
            ip_dst = denegacion["ip_dst"]
            puertos = denegacion.get("puertos", [80, 443]) or [0]
            for tcp_port in puertos:
                self._instalar_y_cachear(
                    switch_dpid,
                    self.builder.t3_deny_sesion(
                        switch_dpid, mac, ip_asignada, ip_dst, tcp_port=tcp_port
                    ),
                    mac
                )
            n_deny += 1
        n_total = len(self.flows_por_sesion.get(mac.upper(), self.flows_por_sesion.get(mac.lower(), [])))
        print(f"  âœ“ SesiÃ³n activada â€” {n_total} flows  "
              f"(pipeline=clean allow={n_allow} deny={n_deny})")

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

        return {
            "mac":         mac,
            "switch_dpid": switch_dpid,
            "in_port":     in_port
        }

    # â”€â”€ Cierre de sesiÃ³n â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def cerrar_sesion(self, mac):
        """
        Elimina todos los flows de la sesiÃ³n (T1, T3, T0 ALLOW/DENY por MAC).
        Llamado por M1 al hacer logout.
        """
        self._limpiar_sesion_completa(mac, motivo_cierre="LOGOUT")

    # â”€â”€ MitigaciÃ³n de ataques (M4) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€â”€ Flask API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app = Flask(__name__)
m6  = M6Translator()


@app.route("/m6/token_rol", methods=["POST"])
def endpoint_token_rol():
    """M1 llama aquÃ­ despuÃ©s de autenticar exitosamente al usuario."""
    token = request.json
    if not token:
        return jsonify({"error": "body vacÃ­o"}), 400
    for campo in ("codigo_pucp", "nombre_rol", "vlan_id", "ip_asignada"):
        if campo not in token:
            return jsonify({"error": f"falta campo: {campo}"}), 400
    resultado = m6.procesar_token_rol(token)
    if resultado:
        return jsonify(resultado), 200
    return jsonify({"error": "no se pudo procesar (ver logs de M6)"}), 500


@app.route("/m6/cli_login", methods=["POST"])
def endpoint_cli_login():
    """Login CLI desde hosts: valida usuario/password y activa sesion."""
    data = request.json or {}
    for campo in ("codigo_pucp", "password", "ip_asignada"):
        if campo not in data:
            return jsonify({"ok": False, "error": f"falta campo: {campo}"}), 400

    resultado, error = m6.autenticar_cli(
        data["codigo_pucp"],
        data["password"],
        data["ip_asignada"],
    )
    if error:
        return jsonify({"ok": False, "error": error}), 401
    return jsonify({"ok": True, "sesion": resultado}), 200


@app.route("/m6/cerrar_sesion", methods=["POST"])
def endpoint_cerrar_sesion():
    """M1 llama aquÃ­ al cerrar sesiÃ³n del usuario."""
    data = request.json or {}
    mac  = data.get("mac")
    if not mac:
        return jsonify({"error": "falta campo: mac"}), 400
    m6.cerrar_sesion(mac)
    return jsonify({"ok": True}), 200


@app.route("/m6/mitigacion", methods=["POST"])
def endpoint_mitigacion():
    """M4 llama aquÃ­ al detectar un atacante."""
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


@app.route("/m6/packet_in", methods=["POST"])
def endpoint_packet_in():
    """
    Recibe Packet-Ins de la app Java de ONOS.
    Body esperado: {src_mac, src_ip, vlan_id, ip_dst, tcp_port, device_id, in_port}
    """
    data = request.json
    if not data:
        return jsonify({"error": "body vacio"}), 400

    vlan_id = int(data.get("vlan_id", 0))
    ip_dst = data.get("ip_dst")
    tcp_port = int(data.get("tcp_port", 0))
    device_id = data.get("device_id", Config.SW2)
    in_port = data.get("in_port")
    src_mac = (data.get("src_mac") or "").upper()
    src_ip = data.get("src_ip")
    ip_dst = m6.policies._normalizar_ip(ip_dst) if ip_dst else ip_dst

    if not ip_dst or tcp_port <= 0:
        return jsonify({
            "status": "ignored",
            "reason": "packet_in requiere ip_dst y tcp_port"
        }), 200

    with m6._lock:
        sesion = m6.sesiones_por_mac.get(src_mac) if src_mac else None
        if sesion is not None:
            sesion["last_activity"] = time.time()

    if not src_ip and sesion:
        src_ip = sesion.get("ip_asignada")

    nombre_rol = sesion.get("nombre_rol") if sesion else None
    codigo_pucp = sesion.get("codigo_pucp") if sesion else f"vlan_{vlan_id}"
    if sesion:
        vlan_id = int(sesion.get("vlan_id", vlan_id))
    if not nombre_rol:
        nombre_rol = m6.policies.obtener_rol_por_vlan(vlan_id)
    if not nombre_rol:
        return jsonify({
            "status": "ignored",
            "reason": f"vlan {vlan_id} no mapeada a ningun rol"
        }), 200

    def _match_destino(politicas):
        if not politicas:
            return {"allow": False, "deny": False}

        def _contiene(lista):
            for item in lista or []:
                if item["ip_dst"] == ip_dst:
                    puertos = item.get("puertos", [])
                    if not puertos or tcp_port in puertos:
                        return True
            return False

        return {
            "allow": _contiene(politicas.get("permisos_generales", politicas.get("permisos", [])))
                     or _contiene(politicas.get("excepciones_allow", [])),
            "deny":  _contiene(politicas.get("excepciones_deny") or politicas.get("denegaciones", [])),
        }

    roles_candidatos = [nombre_rol]
    for rol_alt in m6.policies.obtener_roles_por_usuario(codigo_pucp):
        if rol_alt not in roles_candidatos:
            roles_candidatos.append(rol_alt)

    evaluaciones = []
    allow_base = None
    allow_alt = None
    deny_roles = []

    for rol in roles_candidatos:
        vlan_rol = m6.policies.obtener_vlan_por_rol(rol) or vlan_id
        payload_opa = {
            "input": {
                "codigo_pucp": codigo_pucp,
                "rol": rol,
                "vlan_id": vlan_rol,
                "mac_address": src_mac,
                "ip_asignada": src_ip,
                "switch_dpid": device_id,
                "in_port": in_port,
            }
        }
        politicas = m6.policies.get_policies(payload_opa)
        match = _match_destino(politicas)
        evaluaciones.append((rol, vlan_rol, politicas, match))

        if match["allow"]:
            if rol == nombre_rol and allow_base is None:
                allow_base = (rol, vlan_rol)
            elif allow_alt is None:
                allow_alt = (rol, vlan_rol)

        if match["deny"]:
            deny_roles.append(rol)

    if allow_base is not None:
        rol, vlan_rol = allow_base
        instalados = m6._instalar_t2_allow_por_path(
            device_id, vlan_rol, ip_dst, tcp_port, src_ip=src_ip
        )
        print(f"  [Packet-In] VLAN {vlan_rol} ({rol}) -> {ip_dst}:{tcp_port} ALLOW T2")
        return jsonify({"status": "installed", "table": "T2", "flows_installed": instalados, "role": rol}), 201

    if allow_alt is not None:
        rol, vlan_rol = allow_alt
        instalados = m6._instalar_t3_allow_por_path(
            device_id, src_mac, src_ip, ip_dst, tcp_port, cache_mac=src_mac
        )
        print(f"  [Packet-In] {codigo_pucp} rol alterno={rol} -> {ip_dst}:{tcp_port} ALLOW T3")
        return jsonify({"status": "installed", "table": "T3", "flows_installed": instalados, "role": rol}), 201

    if deny_roles:
        print(f"  [Packet-In] {codigo_pucp} -> {ip_dst}:{tcp_port} DENEGADO por roles {deny_roles}")
        return jsonify({"status": "denied", "table": "T3", "evaluated_roles": [r for r, _, _, _ in evaluaciones]}), 200

    print(f"  [Packet-In] VLAN {vlan_id} ({nombre_rol}) -> {ip_dst}:{tcp_port} DENEGADO")
    return jsonify({"status": "denied", "evaluated_roles": [r for r, _, _, _ in evaluaciones]}), 200

@app.route("/m6/status", methods=["GET"])
def endpoint_status():
    """Healthcheck â€” estado de ONOS y sesiones activas."""
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


# â”€â”€â”€ Main (modo desarrollo â€” para producciÃ³n usa run_m6.sh con gunicorn) â”€â”€â”€â”€â”€â”€
if __name__ == "__main__":
    SEP = "=" * 55
    print(f"\n{SEP}")
    print("  M6 â€” MÃ³dulo Traductor SDN PUCP")
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
    # threaded=True: permite requests simultÃ¡neos de M1, M4, M5 sin cola
    app.run(host=Config.M6_HOST, port=Config.M6_PORT,
            debug=False, threaded=True)
