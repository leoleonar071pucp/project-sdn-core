#!/usr/bin/env python3
"""
dhcp_manager.py - Modulo DHCP para SDN PUCP
Reemplaza dhcp_simulado.py con logica completa de 2 momentos.

Compatible con portal_cautivo.py existente:
  - Exporta asignar_ip_cuarentena() igual que dhcp_simulado.py
  - Exporta ejecutar_flujo_dhcp_completo() igual que dhcp_simulado.py
  - Anade asignar_ip_rol() con logica real y actualizacion en DB

LOGICA:
  Momento 1: asigna IP de cuarentena (192.168.100.x)
             consulta DB para evitar IPs duplicadas
  Momento 2: libera IP cuarentena, asigna IP del rol
             actualiza sesiones_activas con IP definitiva

DIFERENCIA CON dhcp_simulado.py:
  - El Momento 2 ahora actualiza correctamente la sesion en DB
  - Libera la IP de cuarentena antes de asignar la del rol
  - Maneja correctamente el caso de MAC ya registrada
  - Logs mas detallados para debugging

DEPENDENCIAS:
  pip3 install pyyaml mysql-connector-python
"""

import yaml
import mysql.connector
import datetime
import os
import time

# ============================================================
# CONFIGURACION
# ============================================================

YAML_PATH = os.path.join(os.path.dirname(__file__), "dhcp_pools.yaml")

DB_CONFIG = {
    "host":     "127.0.0.1",
    "port":     3306,
    "user":     "radius",
    "password": "radius_pass",
    "database": "radius_db"
}


# ============================================================
# CARGA DEL YAML
# ============================================================

def cargar_pools():
    if not os.path.exists(YAML_PATH):
        raise FileNotFoundError(
            f"No se encontro: {YAML_PATH}\n"
            f"Asegurate de que dhcp_pools.yaml este en la misma carpeta."
        )
    with open(YAML_PATH, "r") as f:
        return yaml.safe_load(f)


# ============================================================
# CONSULTAS A LA DB
# ============================================================

def _get_db():
    return mysql.connector.connect(**DB_CONFIG)


def obtener_ips_en_uso():
    """
    Retorna el conjunto de IPs asignadas en sesiones ACTIVAS.
    Evita asignar la misma IP a dos dispositivos.
    """
    try:
        conn = _get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip_asignada FROM sesiones_activas WHERE estado = 'ACTIVA'"
        )
        ips = {fila[0] for fila in cursor.fetchall()}
        cursor.close()
        conn.close()
        return ips
    except mysql.connector.Error as e:
        print(f"  [WARN DHCP] No se pudo consultar IPs en uso: {e}")
        return set()


def obtener_ip_por_mac(mac_address):
    """
    Busca si esa MAC ya tiene sesion ACTIVA con IP asignada.
    """
    try:
        conn = _get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip_asignada, nombre_rol FROM sesiones_activas "
            "WHERE mac_address = %s AND estado = 'ACTIVA'",
            (mac_address,)
        )
        fila = cursor.fetchone()
        cursor.close()
        conn.close()
        return fila  # (ip, rol) o None
    except mysql.connector.Error as e:
        print(f"  [WARN DHCP] No se pudo consultar IP por MAC: {e}")
        return None


# ============================================================
# MOMENTO 1 - IP DE CUARENTENA
# ============================================================

def asignar_ip_cuarentena(mac_address):
    """
    Asigna una IP del pool de cuarentena para la MAC indicada.
    Si la MAC ya tiene IP activa, la retorna sin asignar nueva.

    Retorna dict con ip, subred, gateway, lease_segundos
    o None si no hay IPs disponibles.
    """
    # Verificar si esa MAC ya tiene sesion activa
    existente = obtener_ip_por_mac(mac_address)
    if existente:
        ip_existente, rol_existente = existente
        print(f"  [DHCP] MAC {mac_address} ya tiene IP: {ip_existente} ({rol_existente})")
        # Determinar subred segun si es cuarentena o rol
        if ip_existente.startswith("192.168.100."):
            subred = "192.168.100.0/24"
            gateway = "192.168.100.1"
            lease = 300
        else:
            pools = cargar_pools()
            cfg = pools["roles"].get(rol_existente, {})
            subred = cfg.get("subred", "desconocido")
            gateway = cfg.get("gateway", "desconocido")
            lease = cfg.get("lease_segundos", 28800)
        return {
            "ip": ip_existente,
            "subred": subred,
            "gateway": gateway,
            "lease_segundos": lease,
            "ya_existia": True
        }

    pools = cargar_pools()
    pool_cuarentena = pools["cuarentena"]
    ips_disponibles = pool_cuarentena["pool"]
    ips_en_uso = obtener_ips_en_uso()

    for ip in ips_disponibles:
        if ip not in ips_en_uso:
            return {
                "ip": ip,
                "subred": pool_cuarentena["subred"],
                "gateway": pool_cuarentena["gateway"],
                "lease_segundos": pool_cuarentena["lease_segundos"],
                "ya_existia": False
            }

    print("  [DHCP] Pool de cuarentena agotado.")
    return None


# ============================================================
# MOMENTO 2 - IP DEL ROL
# ============================================================

def asignar_ip_rol(mac_address, nombre_rol):
    """
    Asigna una IP del pool del rol autenticado.
    Consulta la DB para evitar IPs duplicadas.

    Retorna dict con ip, subred, gateway, lease_segundos
    o None si no hay IPs disponibles o el rol no existe.
    """
    pools = cargar_pools()

    if nombre_rol not in pools["roles"]:
        print(f"  [DHCP] Rol '{nombre_rol}' no encontrado en dhcp_pools.yaml")
        return None

    pool_rol = pools["roles"][nombre_rol]
    ips_disponibles = pool_rol["pool"]
    ips_en_uso = obtener_ips_en_uso()

    for ip in ips_disponibles:
        if ip not in ips_en_uso:
            return {
                "ip": ip,
                "subred": pool_rol["subred"],
                "gateway": pool_rol["gateway"],
                "lease_segundos": pool_rol["lease_segundos"],
                "ya_existia": False
            }

    print(f"  [DHCP] Pool de {nombre_rol} agotado.")
    return None


# ============================================================
# LIBERACION Y ACTUALIZACION EN DB
# ============================================================

def liberar_ip_cuarentena(mac_address):
    """
    Marca como CERRADA la sesion de cuarentena de esa MAC.
    Libera la IP para que otro dispositivo la use.
    """
    try:
        conn = _get_db()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE sesiones_activas
            SET estado = 'CERRADA'
            WHERE mac_address = %s
              AND estado = 'ACTIVA'
              AND ip_asignada LIKE '192.168.100.%'
        """, (mac_address,))
        filas = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        if filas > 0:
            print(f"  [DHCP] IP de cuarentena liberada para {mac_address}")
        return filas > 0
    except mysql.connector.Error as e:
        print(f"  [ERROR DHCP] No se pudo liberar IP cuarentena: {e}")
        return False


def actualizar_ip_sesion(mac_address, ip_nueva, cidr_nuevo, nombre_rol):
    """
    Actualiza ip_asignada y cidr_rol en sesiones_activas
    cuando el dispositivo obtiene su IP definitiva del rol.
    """
    try:
        conn = _get_db()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE sesiones_activas
            SET ip_asignada = %s,
                cidr_rol    = %s,
                nombre_rol  = %s
            WHERE mac_address = %s
              AND estado = 'ACTIVA'
        """, (ip_nueva, cidr_nuevo, nombre_rol, mac_address))
        conn.commit()
        filas = cursor.rowcount
        cursor.close()
        conn.close()
        return filas > 0
    except mysql.connector.Error as e:
        print(f"  [ERROR DHCP] No se pudo actualizar IP en sesion: {e}")
        return False


# ============================================================
# FLUJO COMPLETO - llamado desde portal_cautivo.py
# ============================================================

def ejecutar_flujo_dhcp_completo(mac_address, nombre_rol, cidr_rol):
    """
    Ejecuta el flujo completo de los dos momentos DHCP.
    Esta funcion es llamada desde portal_cautivo.py despues
    del Access-Accept de FreeRADIUS.

    Momento 1: asigna IP cuarentena (ya fue hecho antes del login,
               aqui solo se registra para liberarla)
    Momento 2: libera IP cuarentena, asigna IP del rol,
               actualiza sesiones_activas

    Retorna dict con ip_cuarentena, ip_definitiva, subred, gateway, lease
    o None si alguno de los pasos falla.
    """

    # ── MOMENTO 2 PASO A: Liberar IP de cuarentena ────────
    print(f"\n  [DHCP Momento 2] Autenticacion exitosa. Rol: {nombre_rol}")
    print(f"  [DHCP Momento 2] Simulando DHCP Release de IP cuarentena...")
    time.sleep(0.4)

    liberar_ip_cuarentena(mac_address)

    # ── MOMENTO 2 PASO B: Asignar IP del rol ──────────────
    print(f"  [DHCP Momento 2] Simulando DHCP Discover para pool {cidr_rol}...")
    time.sleep(0.4)

    asignacion_rol = asignar_ip_rol(mac_address, nombre_rol)

    if not asignacion_rol:
        print(f"  [ERROR DHCP] No se pudo asignar IP del rol {nombre_rol}.")
        print(f"  [ERROR DHCP] Verifica que dhcp_pools.yaml tiene IPs disponibles.")
        return None

    ip_definitiva = asignacion_rol["ip"]
    subred        = asignacion_rol["subred"]
    gateway       = asignacion_rol["gateway"]
    lease         = asignacion_rol["lease_segundos"]

    print(f"  [DHCP Momento 2] DHCP Offer  → IP definitiva : {ip_definitiva}")
    print(f"  [DHCP Momento 2] DHCP Ack    → Dispositivo con IP de rol")
    print(f"  [DHCP Momento 2] Subred      : {subred}")
    print(f"  [DHCP Momento 2] Gateway     : {gateway}")
    print(f"  [DHCP Momento 2] Lease       : {lease} seg")

    # ── MOMENTO 2 PASO C: Actualizar sesion en DB ─────────
    actualizado = actualizar_ip_sesion(mac_address, ip_definitiva, subred, nombre_rol)
    if actualizado:
        print(f"  [DHCP] sesiones_activas actualizada: {mac_address} → {ip_definitiva}")
    else:
        print(f"  [WARN DHCP] No se actualizo sesiones_activas (puede que aun no exista).")
        print(f"  [WARN DHCP] portal_cautivo.py la registrara despues con m1_registrar_sesion()")

    return {
        "ip_cuarentena": "liberada",
        "ip_definitiva": ip_definitiva,
        "subred":        subred,
        "gateway":       gateway,
        "lease_segundos": lease,
        "cidr_rol":      subred
    }


# ============================================================
# TEST STANDALONE - para probar sin portal_cautivo
# ============================================================

if __name__ == "__main__":
    print("="*55)
    print("  TEST STANDALONE - DHCP Manager")
    print("="*55)

    MAC_TEST = "AA:BB:CC:DD:EE:01"
    ROL_TEST  = "Estudiante_Telecom"
    CIDR_TEST = "10.2.1.0/24"

    print(f"\n[TEST] MAC: {MAC_TEST}")
    print(f"[TEST] Rol: {ROL_TEST}")

    # Probar Momento 1
    print("\n--- MOMENTO 1: Cuarentena ---")
    asig = asignar_ip_cuarentena(MAC_TEST)
    if asig:
        print(f"  OK - IP cuarentena: {asig['ip']}")
    else:
        print("  FALLO - Sin IPs disponibles")

    # Probar Momento 2
    print("\n--- MOMENTO 2: IP del Rol ---")
    resultado = ejecutar_flujo_dhcp_completo(MAC_TEST, ROL_TEST, CIDR_TEST)
    if resultado:
        print(f"\n  OK - IP definitiva: {resultado['ip_definitiva']}")
        print(f"       Subred       : {resultado['subred']}")
        print(f"       Gateway      : {resultado['gateway']}")
    else:
        print("  FALLO - Ver errores arriba")

    print("\n--- IPs en uso tras el test ---")
    ips = obtener_ips_en_uso()
    for ip in sorted(ips):
        print(f"  {ip}")

    print("\n" + "="*55)
    print("  Test completado")
    print("="*55)
