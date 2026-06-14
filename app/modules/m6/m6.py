#!/usr/bin/env python3
"""
m6.py — Módulo Traductor — SDN PUCP
Módulo M6 | Grupo 2 - TEL354
Única interfaz entre la lógica de negocio y ONOS Controller
"""

import json
import time
import threading
import requests
from collections import deque
from flask import Flask, request, jsonify

# ─── Configuración ────────────────────────────────────────────────────────────
class Config:
    # ONOS
    ONOS_URL  = "http://127.0.0.1:8181"
    ONOS_AUTH = ("onos", "rocks")

    # OPA (M2)
    OPA_URL = "http://127.0.0.1:8181/v1/data/rbac/allow"

    # M1 (portal cautivo) — para revocar sesiones
    M1_URL = "http://127.0.0.1:5001"

    # M5 (auditoría) — log asíncrono
    M5_URL = "http://127.0.0.1:5002/m5/log"

    # M6 propio
    M6_HOST = "0.0.0.0"
    M6_PORT = 8080

    # Resiliencia
    MAX_REINTENTOS   = 3
    BACKOFF_BASE     = 1   # segundos
    MAX_COLA_LOGS    = 10000

    # Prioridades OpenFlow
    PRIO_VLAN_BASE   = 10    # sin tag → PUSH VLAN 90
    PRIO_DHCP        = 500   # DHCP hacia controller
    PRIO_PORTAL      = 100   # tráfico hacia portal cautivo
    PRIO_DROP        = 5     # DROP default VLAN 90
    PRIO_SESION      = 40000 # SET_FIELD post-auth en T1
    PRIO_T2_ALLOW    = 100   # permisos proactivos T2
    PRIO_T3_DENY     = 200   # denegaciones T3
    PRIO_T0_ATAQUE   = 5000  # bloqueo de atacante T0

    # VLANs
    VLAN_CUARENTENA  = 90

    # Switches del slice (deviceId → puerto hacia core)
    SWITCHES = {
        "of:00005ec76ec6114c": {"nombre": "SW1", "ip": "192.168.200.201"},
        "of:000072e0807e854c": {"nombre": "SW2", "ip": "192.168.200.202"},
        "of:0000f220f9454c4e": {"nombre": "SW3", "ip": "192.168.200.203"},
    }


# ─── Cliente ONOS ─────────────────────────────────────────────────────────────
class ONOSClient:
    """Toda la comunicación con ONOS REST API pasa por aquí."""

    def __init__(self):
        self.url  = Config.ONOS_URL
        self.auth = Config.ONOS_AUTH
        # Cache local: {switch_dpid: {tabla: [flow_id]}}
        self.cache_flows = {}

    def _post_flow(self, device_id, flow_entry, reintentos=0):
        """Instala un flow entry en ONOS con backoff exponencial."""
        endpoint = f"{self.url}/onos/v1/flows/{device_id}"
        try:
            resp = requests.post(
                endpoint,
                json={"flows": [flow_entry]},
                auth=self.auth,
                timeout=5
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                flow_id = None
                if "flows" in data and data["flows"]:
                    flow_id = data["flows"][0].get("flowId")
                print(f"  [ONOS] Flow instalado en {device_id} — flowId: {flow_id}")
                return flow_id
            else:
                raise Exception(f"HTTP {resp.status_code}: {resp.text}")

        except Exception as e:
            if reintentos < Config.MAX_REINTENTOS:
                espera = Config.BACKOFF_BASE * (2 ** reintentos)
                print(f"  [ONOS] Error, reintentando en {espera}s: {e}")
                time.sleep(espera)
                return self._post_flow(device_id, flow_entry, reintentos + 1)
            else:
                print(f"  [ONOS] Fallo definitivo tras {Config.MAX_REINTENTOS} intentos: {e}")
                return None

    def _delete_flow(self, device_id, flow_id):
        """Elimina un flow entry de ONOS."""
        endpoint = f"{self.url}/onos/v1/flows/{device_id}/{flow_id}"
        try:
            resp = requests.delete(endpoint, auth=self.auth, timeout=5)
            if resp.status_code in (200, 204):
                print(f"  [ONOS] Flow eliminado: {flow_id}")
                return True
            else:
                print(f"  [ONOS] Error al eliminar {flow_id}: HTTP {resp.status_code}")
                return False
        except Exception as e:
            print(f"  [ONOS] Error al eliminar flow: {e}")
            return False

    def get_host_by_ip(self, ip_asignada):
        """
        Consulta ONOS para obtener mac, switch_dpid e in_port
        del host con la IP dada.
        Retorna dict o None.
        """
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/hosts",
                auth=self.auth,
                timeout=5
            )
            if resp.status_code != 200:
                return None

            hosts = resp.json().get("hosts", [])
            for host in hosts:
                if ip_asignada in host.get("ipAddresses", []):
                    # Tomar la primera ubicación
                    locs = host.get("locations", [])
                    if not locs:
                        continue
                    return {
                        "mac":         host["mac"],
                        "switch_dpid": locs[0]["elementId"],
                        "in_port":     int(locs[0]["port"])
                    }
            return None

        except Exception as e:
            print(f"  [ONOS] Error consultando hosts: {e}")
            return None

    def get_devices(self):
        """Retorna lista de deviceIds disponibles."""
        try:
            resp = requests.get(
                f"{self.url}/onos/v1/devices",
                auth=self.auth,
                timeout=5
            )
            if resp.status_code == 200:
                return [d["id"] for d in resp.json().get("devices", [])]
            return []
        except Exception as e:
            print(f"  [ONOS] Error obteniendo devices: {e}")
            return []

    def instalar_flow(self, device_id, flow_entry):
        """Instala un flow y guarda el flow_id en cache."""
        flow_id = self._post_flow(device_id, flow_entry)
        if flow_id:
            tabla = flow_entry.get("tableId", 0)
            if device_id not in self.cache_flows:
                self.cache_flows[device_id] = {}
            if tabla not in self.cache_flows[device_id]:
                self.cache_flows[device_id][tabla] = []
            self.cache_flows[device_id][tabla].append(flow_id)
        return flow_id

    def eliminar_flow(self, device_id, flow_id):
        """Elimina un flow y lo saca del cache."""
        result = self._delete_flow(device_id, flow_id)
        if result:
            for tabla in self.cache_flows.get(device_id, {}).values():
                if flow_id in tabla:
                    tabla.remove(flow_id)
        return result


# ─── Constructor de flow entries ──────────────────────────────────────────────
class FlowBuilder:
    """Construye los JSON de flow entries para cada caso."""

    def vlan_push_cuarentena(self, device_id, in_port):
        """T1 — sin VLAN tag → PUSH VLAN 90."""
        return {
            "priority":    Config.PRIO_VLAN_BASE,
            "isPermanent": True,
            "deviceId":    device_id,
            "treatment": {
                "instructions": [
                    {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH"},
                    {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                     "vlanId": Config.VLAN_CUARENTENA},
                    {"type": "OUTPUT", "port": "NORMAL"}
                ]
            },
            "selector": {
                "criteria": [
                    {"type": "IN_PORT",   "port": in_port},
                    {"type": "ETH_TYPE",  "ethType": "0x0800"}
                ]
            }
        }

    def dhcp_al_controller(self, device_id):
        """T1 — VLAN 90 + UDP 67 → OUTPUT CONTROLLER."""
        return {
            "priority":    Config.PRIO_DHCP,
            "isPermanent": True,
            "deviceId":    device_id,
            "treatment": {
                "instructions": [
                    {"type": "OUTPUT", "port": "CONTROLLER"}
                ]
            },
            "selector": {
                "criteria": [
                    {"type": "VLAN_VID",  "vlanId": Config.VLAN_CUARENTENA},
                    {"type": "IP_PROTO",  "protocol": 17},
                    {"type": "UDP_DST",   "udpPort": 67}
                ]
            }
        }

    def portal_cautivo(self, device_id, puerto_portal, ip_portal="10.0.0.10"):
        """T1 — VLAN 90 + TCP + ip_portal → OUTPUT puerto_portal."""
        return {
            "priority":    Config.PRIO_PORTAL,
            "isPermanent": True,
            "deviceId":    device_id,
            "treatment": {
                "instructions": [
                    {"type": "OUTPUT", "port": str(puerto_portal)}
                ]
            },
            "selector": {
                "criteria": [
                    {"type": "VLAN_VID",  "vlanId": Config.VLAN_CUARENTENA},
                    {"type": "ETH_TYPE",  "ethType": "0x0800"},
                    {"type": "IPV4_DST",  "ip": f"{ip_portal}/32"},
                    {"type": "IP_PROTO",  "protocol": 6}
                ]
            }
        }

    def drop_default_cuarentena(self, device_id):
        """T1 — VLAN 90 + otro → DROP (treatment vacío)."""
        return {
            "priority":    Config.PRIO_DROP,
            "isPermanent": True,
            "deviceId":    device_id,
            "treatment": {
                "clearDeferred": True,
                "instructions":  []
            },
            "selector": {
                "criteria": [
                    {"type": "VLAN_VID", "vlanId": Config.VLAN_CUARENTENA}
                ]
            }
        }

    def set_vlan_post_auth(self, device_id, mac, in_port, vlan_actual, vlan_nuevo, session_timeout=28800):
        """T1 — ETH_SRC + VLAN_actual + IN_PORT → SET_FIELD vlan_nuevo + goto T2."""
        return {
            "priority":    Config.PRIO_SESION,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     1,
            "treatment": {
                "instructions": [
                    {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                     "vlanId": vlan_nuevo},
                    {"type": "TABLE", "tableId": 2}
                ]
            },
            "selector": {
                "criteria": [
                    {"type": "IN_PORT",  "port": str(in_port)},
                    {"type": "ETH_SRC",  "mac":  mac},
                    {"type": "VLAN_VID", "vlanId": vlan_actual}
                ]
            }
        }

    def t2_allow(self, device_id, vlan_id, ip_dst, puerto_dst, puerto_salida):
        """T2 — VLAN_VID=rol + ip_dst → OUTPUT puerto servidor."""
        return {
            "priority":    Config.PRIO_T2_ALLOW,
            "isPermanent": True,
            "deviceId":    device_id,
            "tableId":     2,
            "treatment": {
                "instructions": [
                    {"type": "OUTPUT", "port": str(puerto_salida)}
                ]
            },
            "selector": {
                "criteria": [
                    {"type": "VLAN_VID", "vlanId": vlan_id},
                    {"type": "ETH_TYPE", "ethType": "0x0800"},
                    {"type": "IPV4_DST", "ip": f"{ip_dst}/32"},
                    {"type": "IP_PROTO", "protocol": 6},
                    {"type": "TCP_DST",  "tcpPort": puerto_dst}
                ]
            }
        }

    def t3_deny(self, device_id, mac, ip_src, ip_dst, session_timeout=28800):
        """T3 — MAC + IP_SRC/32 + IP_DST/32 → DROP con hard_timeout."""
        return {
            "priority":    Config.PRIO_T3_DENY,
            "isPermanent": False,
            "timeout":     session_timeout,
            "deviceId":    device_id,
            "tableId":     3,
            "treatment": {
                "clearDeferred": True,
                "instructions":  []
            },
            "selector": {
                "criteria": [
                    {"type": "ETH_SRC",  "mac":  mac},
                    {"type": "ETH_TYPE", "ethType": "0x0800"},
                    {"type": "IPV4_SRC", "ip": f"{ip_src}/32"},
                    {"type": "IPV4_DST", "ip": f"{ip_dst}/32"},
                    {"type": "IP_PROTO", "protocol": 6}
                ]
            }
        }

    def t0_bloqueo_ataque(self, device_id, ip_atacante, ttl=600):
        """T0 — IP_SRC/32 atacante → DROP, prio 5000+."""
        return {
            "priority":    Config.PRIO_T0_ATAQUE,
            "isPermanent": False,
            "timeout":     ttl,
            "deviceId":    device_id,
            "tableId":     0,
            "treatment": {
                "clearDeferred": True,
                "instructions":  []
            },
            "selector": {
                "criteria": [
                    {"type": "ETH_TYPE", "ethType": "0x0800"},
                    {"type": "IPV4_SRC", "ip": f"{ip_atacante}/32"}
                ]
            }
        }


# ─── Log asíncrono hacia M5 ───────────────────────────────────────────────────
class M5Logger:
    def __init__(self):
        self.cola = deque(maxlen=Config.MAX_COLA_LOGS)

    def log(self, evento):
        """Envía log a M5 de forma asíncrona."""
        threading.Thread(
            target=self._enviar, args=(evento,), daemon=True
        ).start()

    def _enviar(self, evento):
        try:
            resp = requests.post(
                Config.M5_URL, json=evento, timeout=3
            )
            if resp.status_code not in (200, 201):
                self.cola.append(evento)
        except Exception:
            self.cola.append(evento)

    def flush(self):
        """Envía todos los logs encolados cuando M5 se recupera."""
        while self.cola:
            self._enviar(self.cola.popleft())


# ─── Lógica principal de M6 ───────────────────────────────────────────────────
class M6Translator:

    def __init__(self):
        self.onos    = ONOSClient()
        self.builder = FlowBuilder()
        self.logger  = M5Logger()
        # Cache de flow_ids por sesión: {mac: [flow_id, ...]}
        self.flows_por_sesion = {}

    def instalar_cuarentena_arranque(self):
        """
        Instala las reglas T1 de cuarentena en todos los switches al arrancar.
        Llamar esto una vez cuando M6 inicia.
        """
        devices = self.onos.get_devices()
        print(f"\n[M6] Instalando cuarentena en {len(devices)} switches...")

        for device_id in devices:
            print(f"  → {device_id}")

            # Regla DHCP
            flow = self.builder.dhcp_al_controller(device_id)
            self.onos.instalar_flow(device_id, flow)

            # Regla DROP default
            flow = self.builder.drop_default_cuarentena(device_id)
            self.onos.instalar_flow(device_id, flow)

            # Regla PUSH VLAN 90 para puertos de acceso (2 y 3)
            for puerto in [2, 3]:
                flow = self.builder.vlan_push_cuarentena(device_id, puerto)
                self.onos.instalar_flow(device_id, flow)

        print("[M6] Cuarentena instalada en todos los switches.\n")

    def procesar_token_rol(self, token):
        """
        Punto de entrada principal desde M1.
        token = {codigo_pucp, nombre_rol, vlan_id, ip_asignada}
        Retorna {mac, switch_dpid, in_port} o None si falla.
        """
        codigo_pucp = token["codigo_pucp"]
        nombre_rol  = token["nombre_rol"]
        vlan_id     = token["vlan_id"]
        ip_asignada = token["ip_asignada"]

        print(f"\n[M6] Token recibido de M1:")
        print(f"  usuario={codigo_pucp}, rol={nombre_rol}, "
              f"vlan={vlan_id}, ip={ip_asignada}")

        # 1. Consultar ONOS para obtener mac/switch/puerto del host
        host_info = self.onos.get_host_by_ip(ip_asignada)
        if not host_info:
            print(f"  [M6] Host con IP {ip_asignada} no encontrado en ONOS")
            return None

        mac         = host_info["mac"]
        switch_dpid = host_info["switch_dpid"]
        in_port     = host_info["in_port"]

        print(f"  [M6] Host encontrado: mac={mac}, "
              f"switch={switch_dpid}, puerto={in_port}")

        # 2. Instalar SET_FIELD vlan_vid en T1 (cambio VLAN 90 → vlan_id)
        flow_sesion = self.builder.set_vlan_post_auth(
            device_id   = switch_dpid,
            mac         = mac,
            in_port     = in_port,
            vlan_actual = Config.VLAN_CUARENTENA,
            vlan_nuevo  = vlan_id
        )
        flow_id_sesion = self.onos.instalar_flow(switch_dpid, flow_sesion)

        # Guardar flow_id para eliminar al cerrar sesión
        if mac not in self.flows_por_sesion:
            self.flows_por_sesion[mac] = []
        if flow_id_sesion:
            self.flows_por_sesion[mac].append(
                (switch_dpid, flow_id_sesion)
            )

        # 3. Consultar OPA (M2) para obtener permisos y denegaciones
        flows_t2_t3 = self._consultar_opa_e_instalar(
            token, mac, switch_dpid, ip_asignada
        )

        # 4. Log a M5
        self.logger.log({
            "modulo":    "M6",
            "evento":    "token_rol_procesado",
            "usuario":   codigo_pucp,
            "rol":       nombre_rol,
            "vlan":      vlan_id,
            "mac":       mac,
            "switch":    switch_dpid,
            "puerto":    in_port,
            "flow_id":   flow_id_sesion,
            "flows_t2t3": flows_t2_t3
        })

        print(f"  [M6] Token procesado correctamente para {codigo_pucp}")
        return {
            "mac":         mac,
            "switch_dpid": switch_dpid,
            "in_port":     in_port
        }

    def _consultar_opa_e_instalar(self, token, mac, switch_dpid, ip_asignada):
        """
        Consulta OPA con el token y traduce la respuesta
        a flow entries T2 (ALLOW) y T3 (DENY).
        """
        payload = {
            "input": {
                "codigo_pucp": token["codigo_pucp"],
                "rol":         token["nombre_rol"],
                "ip_asignada": ip_asignada,
                "vlan_id":     token["vlan_id"],
                "mac_address": mac,
                "switch_dpid": switch_dpid,
            }
        }

        try:
            resp = requests.post(
                Config.OPA_URL, json=payload, timeout=5
            )
            if resp.status_code != 200:
                print(f"  [OPA] Error HTTP {resp.status_code}")
                return []

            resultado = resp.json().get("result", {})
            flows_instalados = []

            # Instalar permisos T2
            for permiso in resultado.get("permisos", []):
                flow = self.builder.t2_allow(
                    device_id    = switch_dpid,
                    vlan_id      = token["vlan_id"],
                    ip_dst       = permiso["ip_dst"],
                    puerto_dst   = permiso["puertos"][0],
                    puerto_salida = 1  # puerto hacia SW1/core
                )
                fid = self.onos.instalar_flow(switch_dpid, flow)
                if fid:
                    flows_instalados.append(fid)
                    self.flows_por_sesion[mac].append((switch_dpid, fid))

            # Instalar denegaciones T3
            for denegacion in resultado.get("denegaciones", []):
                flow = self.builder.t3_deny(
                    device_id = switch_dpid,
                    mac       = mac,
                    ip_src    = ip_asignada,
                    ip_dst    = denegacion["ip_dst"]
                )
                fid = self.onos.instalar_flow(switch_dpid, flow)
                if fid:
                    flows_instalados.append(fid)
                    self.flows_por_sesion[mac].append((switch_dpid, fid))

            print(f"  [OPA] {len(flows_instalados)} flows instalados "
                  f"desde políticas OPA")
            return flows_instalados

        except Exception as e:
            print(f"  [OPA] No disponible, saltando políticas: {e}")
            return []

    def cerrar_sesion(self, mac):
        """
        Elimina todos los flows asociados a una sesión (T1, T2, T3).
        Llamado por M1 al cerrar sesión.
        """
        flows = self.flows_por_sesion.pop(mac, [])
        print(f"\n[M6] Cerrando sesión MAC={mac}, "
              f"eliminando {len(flows)} flows...")

        for switch_dpid, flow_id in flows:
            self.onos.eliminar_flow(switch_dpid, flow_id)

        self.logger.log({
            "modulo":  "M6",
            "evento":  "sesion_cerrada",
            "mac":     mac,
            "flows_eliminados": len(flows)
        })

    def procesar_mitigacion(self, directiva):
        """
        Recibe DirectivaMitigacion de M4 y bloquea al atacante.
        directiva = {ip_atacante, tipo, switch_dpid, prioridad, ttl_segundos}
        """
        ip_atacante = directiva["ip_atacante"]
        switch_dpid = directiva.get("switch_dpid")
        ttl         = directiva.get("ttl_segundos", 600)

        print(f"\n[M6] DirectivaMitigacion recibida: ip={ip_atacante}")

        # Instalar T0 DROP en el switch del atacante
        if switch_dpid:
            devices = [switch_dpid]
        else:
            devices = self.onos.get_devices()

        for device_id in devices:
            flow = self.builder.t0_bloqueo_ataque(device_id, ip_atacante, ttl)
            self.onos.instalar_flow(device_id, flow)

        # Notificar a M1 para revocar sesión
        try:
            resp = requests.post(
                f"{Config.M1_URL}/m1/revocar_sesion",
                json={"ip_atacante": ip_atacante},
                timeout=3
            )
            print(f"  [M6→M1] Revocación notificada: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [M6→M1] M1 no disponible para revocar: {e}")

        self.logger.log({
            "modulo":      "M6",
            "evento":      "mitigacion_aplicada",
            "ip_atacante": ip_atacante,
            "ttl":         ttl
        })


# ─── Flask API ────────────────────────────────────────────────────────────────
app = Flask(__name__)
m6  = M6Translator()


@app.route("/m6/token_rol", methods=["POST"])
def endpoint_token_rol():
    """M1 llama aquí después de autenticar al usuario."""
    token = request.json
    if not token:
        return jsonify({"error": "token vacío"}), 400

    campos = ["codigo_pucp", "nombre_rol", "vlan_id", "ip_asignada"]
    for c in campos:
        if c not in token:
            return jsonify({"error": f"falta campo {c}"}), 400

    resultado = m6.procesar_token_rol(token)
    if resultado:
        return jsonify(resultado), 200
    else:
        return jsonify({"error": "no se pudo procesar token"}), 500


@app.route("/m6/cerrar_sesion", methods=["POST"])
def endpoint_cerrar_sesion():
    """M1 llama aquí al cerrar sesión."""
    data = request.json
    mac  = data.get("mac")
    if not mac:
        return jsonify({"error": "falta mac"}), 400
    m6.cerrar_sesion(mac)
    return jsonify({"ok": True}), 200


@app.route("/m6/mitigacion", methods=["POST"])
def endpoint_mitigacion():
    """M4 llama aquí al detectar un ataque."""
    directiva = request.json
    if not directiva or "ip_atacante" not in directiva:
        return jsonify({"error": "falta ip_atacante"}), 400
    m6.procesar_mitigacion(directiva)
    return jsonify({"ok": True}), 200


@app.route("/m6/arranque", methods=["POST"])
def endpoint_arranque():
    """Instala reglas de cuarentena en todos los switches."""
    m6.instalar_cuarentena_arranque()
    return jsonify({"ok": True}), 200


@app.route("/m6/status", methods=["GET"])
def endpoint_status():
    """Healthcheck."""
    devices = m6.onos.get_devices()
    return jsonify({
        "status":   "ok",
        "devices":  devices,
        "sesiones": list(m6.flows_por_sesion.keys())
    }), 200


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "═" * 55)
    print("  M6 — Módulo Traductor SDN PUCP")
    print("═" * 55)

    # Instalar cuarentena al arrancar
    m6.instalar_cuarentena_arranque()

    # Levantar servidor Flask
    print(f"\n[M6] Servidor escuchando en "
          f"{Config.M6_HOST}:{Config.M6_PORT}\n")
    app.run(
        host  = Config.M6_HOST,
        port  = Config.M6_PORT,
        debug = False
    )