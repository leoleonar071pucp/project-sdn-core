#!/usr/bin/env python3
"""
dhcp_manager.py
Módulo DHCP Manager para SDN PUCP
Controla dnsmasq dinámicamente para asignar IPs por rol tras autenticación.

Uso:
  - Como módulo importado por portal_cautivo.py
  - Como servicio Flask independiente (puerto 5001)
"""

import os
import signal
import subprocess
import ipaddress
import logging
from pathlib import Path
from datetime import datetime
from threading import Lock
from typing import Optional

# Flask para API REST (por si M1 lo llama por HTTP)
from flask import Flask, request, jsonify

# MySQL para actualizar sesiones_activas
import mysql.connector

# ── CONFIGURACIÓN ─────────────────────────────────────────────────────────────

RESERVATIONS_FILE = "/etc/dnsmasq.d/reservations.conf"

DB_CONFIG = {
    "host": "localhost",
    "user": "radius",
    "password": "radius_pass",
    "database": "radius_db"
}

# Mapa de rol → tag dnsmasq y bloque IP disponible
ROL_CONFIG = {
    "Visitante":              {"tag": "visitante",   "pool": "10.1.0.0/24",       "lease": "8h"},
    "Estudiante_Telecom":     {"tag": "telecom",     "pool": "10.2.1.0/24",       "lease": "8h"},
    "Estudiante_Informatica": {"tag": "informatica", "pool": "10.2.2.0/24",       "lease": "8h"},
    "Estudiante_Electronica": {"tag": "electronica", "pool": "10.2.3.0/24",       "lease": "8h"},
    "Docente":                {"tag": "docente",     "pool": "10.3.0.0/24",       "lease": "10h"},
    "Admin_TI":               {"tag": "admin",       "pool": "10.4.0.0/24",       "lease": "12h"},
    "Cuarentena":             {"tag": "cuarentena",  "pool": "192.168.100.0/24",  "lease": "5m"},
}

# Rango usable dentro de cada /24 (evitar .1 gateway y .255 broadcast)
POOL_START_OFFSET = 100  # empieza en .100
POOL_END_OFFSET   = 200  # termina en .200

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DHCP] %(levelname)s %(message)s"
)
log = logging.getLogger("dhcp_manager")

_lock = Lock()  # para escritura thread-safe en el archivo de reservas


# ── FUNCIONES CORE ────────────────────────────────────────────────────────────

def _get_db():
    """Retorna conexión a MySQL."""
    return mysql.connector.connect(**DB_CONFIG)


def _reload_dnsmasq():
    """
    Envía SIGHUP a dnsmasq para que recargue la configuración sin reiniciar.
    No interrumpe leases activos.
    """
    try:
        result = subprocess.run(
            ["pidof", "dnsmasq"],
            capture_output=True, text=True
        )
        pid = int(result.stdout.strip())
        os.kill(pid, signal.SIGHUP)
        log.info(f"dnsmasq recargado (PID {pid})")
        return True
    except Exception as e:
        log.error(f"Error recargando dnsmasq: {e}")
        return False


def _get_ips_en_uso() -> set:
    """
    Lee el archivo de reservas actual y retorna el conjunto de IPs ya asignadas.
    """
    ips_en_uso = set()
    path = Path(RESERVATIONS_FILE)
    if not path.exists():
        return ips_en_uso
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("dhcp-host=") and not line.startswith("#"):
            # formato: dhcp-host=MAC,set:tag,IP,nombre,lease
            partes = line.split(",")
            if len(partes) >= 3:
                ip_candidata = partes[2]
                try:
                    ipaddress.IPv4Address(ip_candidata)
                    ips_en_uso.add(ip_candidata)
                except ValueError:
                    pass
    return ips_en_uso


def _elegir_ip_libre(pool_cidr: str, ips_en_uso: set) -> Optional[str]:
    """
    Elige la primera IP libre en el rango pool_cidr entre offset 100 y 200.
    """
    red = ipaddress.IPv4Network(pool_cidr, strict=False)
    hosts = list(red.hosts())
    for host in hosts[POOL_START_OFFSET - 1 : POOL_END_OFFSET]:
        ip_str = str(host)
        if ip_str not in ips_en_uso:
            return ip_str
    return None


def _leer_reservas() -> dict:
    """
    Lee el archivo de reservas y retorna dict {mac: linea_completa}.
    """
    reservas = {}
    path = Path(RESERVATIONS_FILE)
    if not path.exists():
        return reservas
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("dhcp-host=") and not line.startswith("#"):
            mac = line.split("=")[1].split(",")[0]
            reservas[mac.lower()] = line
    return reservas


def _escribir_reservas(reservas: dict):
    """
    Escribe el archivo de reservas completo desde el dict {mac: linea}.
    """
    path = Path(RESERVATIONS_FILE)
    header = (
        "# Reservas dinámicas SDN PUCP\n"
        f"# Generado automáticamente por dhcp_manager.py\n"
        f"# Última actualización: {datetime.now().isoformat()}\n"
        "# NO editar manualmente\n\n"
    )
    contenido = header + "\n".join(reservas.values()) + "\n"
    path.write_text(contenido)


# ── FUNCIÓN PRINCIPAL: asignar IP por rol ─────────────────────────────────────

def asignar_ip_rol(mac: str, rol: str, codigo_pucp: str,
                   switch_dpid: str, in_port: int) -> dict:
    """
    Asigna una IP del pool del rol a la MAC indicada.
    Actualiza dnsmasq y la tabla sesiones_activas en MySQL.

    Retorna:
        {
          "exito": True/False,
          "ip_asignada": "10.2.1.105",
          "cidr_rol": "10.2.1.0/24",
          "mensaje": "..."
        }
    """
    mac = mac.lower().strip()

    if rol not in ROL_CONFIG:
        return {"exito": False, "mensaje": f"Rol desconocido: {rol}"}

    cfg = ROL_CONFIG[rol]
    pool_cidr = cfg["pool"]
    tag = cfg["tag"]
    lease = cfg["lease"]

    with _lock:
        reservas_actuales = _leer_reservas()
        ips_en_uso = _get_ips_en_uso()

        # Si ya tiene reserva, reutilizar esa IP
        if mac in reservas_actuales:
            # extraer IP de la línea existente
            partes = reservas_actuales[mac].split(",")
            ip_asignada = partes[2]
            log.info(f"MAC {mac} ya tiene reserva: {ip_asignada}")
        else:
            ip_asignada = _elegir_ip_libre(pool_cidr, ips_en_uso)
            if not ip_asignada:
                return {
                    "exito": False,
                    "mensaje": f"Pool agotado para rol {rol} ({pool_cidr})"
                }

            # Escribir nueva reserva
            # formato dnsmasq: dhcp-host=MAC,set:tag,IP,nombre,lease
            nombre = f"{rol}_{mac.replace(':','')[-4:]}"
            linea = f"dhcp-host={mac},set:{tag},{ip_asignada},{nombre},{lease}"
            reservas_actuales[mac] = linea
            _escribir_reservas(reservas_actuales)
            log.info(f"Nueva reserva: {mac} → {ip_asignada} ({rol})")

        # Recargar dnsmasq
        _reload_dnsmasq()

        # Actualizar sesiones_activas en MySQL
        _actualizar_sesion_db(mac, ip_asignada, pool_cidr, rol,
                              codigo_pucp, switch_dpid, in_port)

    return {
        "exito": True,
        "ip_asignada": ip_asignada,
        "cidr_rol": pool_cidr,
        "tag": tag,
        "mensaje": f"IP {ip_asignada} asignada a {mac} para rol {rol}"
    }


def liberar_ip(mac: str) -> dict:
    """
    Elimina la reserva de una MAC (logout o revocación por M4).
    """
    mac = mac.lower().strip()

    with _lock:
        reservas = _leer_reservas()
        if mac not in reservas:
            return {"exito": False, "mensaje": f"No hay reserva para {mac}"}

        ip_liberada = reservas[mac].split(",")[2]
        del reservas[mac]
        _escribir_reservas(reservas)
        _reload_dnsmasq()
        log.info(f"IP liberada: {mac} ({ip_liberada})")

    return {"exito": True, "ip_liberada": ip_liberada}


# ── BASE DE DATOS ─────────────────────────────────────────────────────────────

def _actualizar_sesion_db(mac: str, ip_asignada: str, cidr_rol: str,
                          nombre_rol: str, codigo_pucp: str,
                          switch_dpid: str, in_port: int):
    """
    Actualiza o crea la entrada en sesiones_activas con la IP definitiva.
    """
    try:
        conn = _get_db()
        cursor = conn.cursor()

        # Obtener id_usuario
        cursor.execute(
            "SELECT id_usuario FROM usuarios WHERE codigo_pucp = %s",
            (codigo_pucp,)
        )
        row = cursor.fetchone()
        if not row:
            log.warning(f"Usuario no encontrado: {codigo_pucp}")
            return
        id_usuario = row[0]

        # Upsert en sesiones_activas
        cursor.execute("""
            INSERT INTO sesiones_activas
                (id_usuario, mac_address, ip_asignada, cidr_rol,
                 nombre_rol, switch_dpid, in_port, estado)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'ACTIVA')
            ON DUPLICATE KEY UPDATE
                ip_asignada  = VALUES(ip_asignada),
                cidr_rol     = VALUES(cidr_rol),
                nombre_rol   = VALUES(nombre_rol),
                switch_dpid  = VALUES(switch_dpid),
                in_port      = VALUES(in_port),
                estado       = 'ACTIVA',
                login_timestamp = CURRENT_TIMESTAMP
        """, (id_usuario, mac, ip_asignada, cidr_rol,
              nombre_rol, switch_dpid, in_port))

        conn.commit()
        log.info(f"sesiones_activas actualizada: {codigo_pucp} → {ip_asignada}")

    except Exception as e:
        log.error(f"Error actualizando DB: {e}")
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass


# ── API FLASK (por si se llama por HTTP desde otro proceso) ──────────────────

app = Flask(__name__)


@app.route("/dhcp/assign", methods=["POST"])
def api_asignar():
    """
    POST /dhcp/assign
    Body JSON: {mac, rol, codigo_pucp, switch_dpid, in_port}
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Body JSON requerido"}), 400

    campos = ["mac", "rol", "codigo_pucp", "switch_dpid", "in_port"]
    for campo in campos:
        if campo not in data:
            return jsonify({"error": f"Campo requerido: {campo}"}), 400

    resultado = asignar_ip_rol(
        mac=data["mac"],
        rol=data["rol"],
        codigo_pucp=data["codigo_pucp"],
        switch_dpid=data["switch_dpid"],
        in_port=int(data["in_port"])
    )

    status = 200 if resultado["exito"] else 500
    return jsonify(resultado), status


@app.route("/dhcp/release", methods=["POST"])
def api_liberar():
    """
    POST /dhcp/release
    Body JSON: {mac}
    """
    data = request.get_json()
    if not data or "mac" not in data:
        return jsonify({"error": "Campo mac requerido"}), 400

    resultado = liberar_ip(data["mac"])
    status = 200 if resultado["exito"] else 404
    return jsonify(resultado), status


@app.route("/dhcp/status", methods=["GET"])
def api_status():
    """GET /dhcp/status — ver reservas activas."""
    reservas = _leer_reservas()
    return jsonify({
        "total_reservas": len(reservas),
        "reservas": list(reservas.values())
    })


if __name__ == "__main__":
    # Crear archivo de reservas si no existe
    Path(RESERVATIONS_FILE).touch(exist_ok=True)
    log.info("DHCP Manager iniciado en puerto 5001")
    app.run(host="0.0.0.0", port=5001, debug=False)