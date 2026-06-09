#!/usr/bin/env python3
"""
dhcp_simulado.py - Simulador de DHCP para el proyecto SDN PUCP
Modulo M1 - Gestion de asignacion de IPs

LOGICA:
  Simula el comportamiento de un servidor DHCP real usando un archivo
  YAML como fuente de pools de IPs. Consulta sesiones_activas en MySQL
  para saber que IPs ya estan en uso antes de asignar una nueva.

  Momento 1: asigna IP de cuarentena (192.168.100.x)
  Momento 2: asigna IP del rol (segun CIDR del rol autenticado)

DEPENDENCIAS:
  pip3 install pyyaml mysql-connector-python
"""

import yaml
import mysql.connector
import datetime
import os

# ============================================================
# CONFIGURACION
# ============================================================

# Ruta del archivo YAML con los pools de IPs
YAML_PATH = os.path.join(os.path.dirname(__file__), "dhcp_pools.yaml")

# Configuracion de MySQL (mismo que portal_cautivo.py)
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
    """
    Carga el archivo dhcp_pools.yaml y retorna el diccionario de pools.
    Si el archivo no existe, lanza un error descriptivo.
    """
    if not os.path.exists(YAML_PATH):
        raise FileNotFoundError(
            f"No se encontro el archivo de pools: {YAML_PATH}\n"
            f"Asegurate de que dhcp_pools.yaml este en la misma carpeta."
        )
    with open(YAML_PATH, "r") as f:
        return yaml.safe_load(f)


# ============================================================
# CONSULTAS A LA DB
# ============================================================

def obtener_ips_en_uso():
    """
    Consulta sesiones_activas y retorna el conjunto de IPs
    que ya estan asignadas en sesiones ACTIVAS.
    Esto evita asignar la misma IP a dos dispositivos.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_asignada FROM sesiones_activas
            WHERE estado = 'ACTIVA'
        """)
        ips_en_uso = {fila[0] for fila in cursor.fetchall()}
        cursor.close()
        conn.close()
        return ips_en_uso
    except mysql.connector.Error as e:
        print(f"  [WARN DHCP] No se pudo consultar IPs en uso: {e}")
        return set()


def obtener_ip_por_mac(mac_address):
    """
    Busca en sesiones_activas si esa MAC ya tiene una IP asignada.
    Retorna la IP si existe, None si no.
    Util para evitar asignar una segunda IP a la misma MAC.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_asignada FROM sesiones_activas
            WHERE mac_address = %s AND estado = 'ACTIVA'
        """, (mac_address,))
        fila = cursor.fetchone()
        cursor.close()
        conn.close()
        return fila[0] if fila else None
    except mysql.connector.Error as e:
        print(f"  [WARN DHCP] No se pudo consultar IP por MAC: {e}")
        return None


# ============================================================
# MOMENTO 1 — ASIGNACION DE IP DE CUARENTENA
# ============================================================

def asignar_ip_cuarentena(mac_address):
    """
    Simula el DHCP Discover del Momento 1.

    Logica:
      1. Verifica si esa MAC ya tiene IP de cuarentena asignada
         (para no asignar dos veces a la misma MAC)
      2. Carga el pool de cuarentena del YAML
      3. Consulta sesiones_activas para saber que IPs ya estan en uso
      4. Toma la primera IP disponible del pool
      5. Retorna los datos de la asignacion

    Retorna dict con ip, subred, gateway, lease_segundos
    o None si no hay IPs disponibles.
    """
    # Verificar si esa MAC ya tiene sesion activa
    ip_existente = obtener_ip_por_mac(mac_address)
    if ip_existente:
        print(f"  [DHCP] MAC {mac_address} ya tiene IP asignada: {ip_existente}")
        return {
            "ip":             ip_existente,
            "subred":         "192.168.100.0/24",
            "gateway":        "192.168.100.1",
            "lease_segundos": 300,
            "ya_existia":     True
        }

    pools = cargar_pools()
    pool_cuarentena = pools["cuarentena"]
    ips_disponibles = pool_cuarentena["pool"]
    ips_en_uso = obtener_ips_en_uso()

    # Buscar primera IP libre
    for ip in ips_disponibles:
        if ip not in ips_en_uso:
            return {
                "ip":             ip,
                "subred":         pool_cuarentena["subred"],
                "gateway":        pool_cuarentena["gateway"],
                "lease_segundos": pool_cuarentena["lease_segundos"],
                "ya_existia":     False
            }

    # Pool agotado
    print("  [DHCP] No hay IPs disponibles en el pool de cuarentena.")
    return None


# ============================================================
# MOMENTO 2 — ASIGNACION DE IP DEL ROL
# ============================================================

def asignar_ip_rol(mac_address, nombre_rol):
    """
    Simula el DHCP Discover del Momento 2, despues de autenticarse.

    Logica:
      1. Carga el pool del rol desde el YAML
      2. Consulta sesiones_activas para saber que IPs ya estan en uso
      3. Toma la primera IP disponible del pool del rol
      4. Retorna los datos de la asignacion

    Retorna dict con ip, subred, gateway, lease_segundos
    o None si el rol no existe o no hay IPs disponibles.
    """
    pools = cargar_pools()

    if nombre_rol not in pools["roles"]:
        print(f"  [DHCP] Rol '{nombre_rol}' no encontrado en dhcp_pools.yaml")
        return None

    pool_rol = pools["roles"][nombre_rol]
    ips_disponibles = pool_rol["pool"]
    ips_en_uso = obtener_ips_en_uso()

    # Buscar primera IP libre del pool del rol
    for ip in ips_disponibles:
        if ip not in ips_en_uso:
            return {
                "ip":             ip,
                "subred":         pool_rol["subred"],
                "gateway":        pool_rol["gateway"],
                "lease_segundos": pool_rol["lease_segundos"],
                "ya_existia":     False
            }

    print(f"  [DHCP] No hay IPs disponibles en el pool de {nombre_rol}.")
    return None


# ============================================================
# LIBERACION DE IP
# ============================================================

def liberar_ip_cuarentena(mac_address):
    """
    Simula el DHCP Release del Momento 1.
    Marca la sesion de cuarentena de esa MAC como CERRADA
    para que su IP quede disponible para otro dispositivo.

    En un DHCP real esto ocurre cuando el cliente envia
    un mensaje DHCP Release al servidor.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Solo cerramos sesiones que tengan IP de cuarentena
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
            print(f"  [DHCP] IP de cuarentena liberada para MAC {mac_address}")
            return True
        return False

    except mysql.connector.Error as e:
        print(f"  [ERROR DHCP] No se pudo liberar IP de cuarentena: {e}")
        return False


# ============================================================
# ACTUALIZACION DE IP EN SESION ACTIVA
# ============================================================

def actualizar_ip_sesion(mac_address, ip_nueva, cidr_nuevo):
    """
    Actualiza la IP en sesiones_activas cuando el dispositivo
    obtiene su IP definitiva del rol (Momento 2).

    En produccion esto ocurre cuando M1 recibe confirmacion
    del DHCP server de que el dispositivo ya tiene su IP del rol.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE sesiones_activas
            SET ip_asignada = %s,
                cidr_rol    = %s
            WHERE mac_address = %s
              AND estado = 'ACTIVA'
        """, (ip_nueva, cidr_nuevo, mac_address))
        conn.commit()
        filas = cursor.rowcount
        cursor.close()
        conn.close()
        return filas > 0
    except mysql.connector.Error as e:
        print(f"  [ERROR DHCP] No se pudo actualizar IP en sesion: {e}")
        return False


# ============================================================
# FUNCION PRINCIPAL: FLUJO COMPLETO DHCP MOMENTO 1 + 2
# ============================================================

def ejecutar_flujo_dhcp_completo(mac_address, nombre_rol, cidr_rol):
    """
    Ejecuta el flujo completo de los dos momentos DHCP:

    Momento 1: asigna IP de cuarentena y la registra en sesiones_activas
    Momento 2: libera la IP de cuarentena, asigna IP del rol
               y actualiza sesiones_activas

    Retorna dict con ip_cuarentena e ip_definitiva,
    o None si alguno de los pasos falla.
    """
    import time

    # ── MOMENTO 1 ──────────────────────────────────────────
    print("\n  [DHCP Momento 1] Simulando DHCP Discover inicial...")
    time.sleep(0.5)

    asignacion_cuarentena = asignar_ip_cuarentena(mac_address)
    if not asignacion_cuarentena:
        print("  [ERROR] No se pudo asignar IP de cuarentena.")
        return None

    ip_cuarentena = asignacion_cuarentena["ip"]
    print(f"  [DHCP Momento 1] DHCP Offer  → IP cuarentena: {ip_cuarentena}")
    print(f"  [DHCP Momento 1] DHCP Ack    → Dispositivo en cuarentena")
    print(f"  [DHCP Momento 1] Subred      : {asignacion_cuarentena['subred']}")
    print(f"  [DHCP Momento 1] Lease       : {asignacion_cuarentena['lease_segundos']} seg")

    # ── ENTRE MOMENTOS: autenticacion con FreeRADIUS ──────
    # (esto lo maneja portal_cautivo.py - aqui solo simulamos la espera)
    print("\n  [DHCP] Esperando autenticacion del usuario...")
    time.sleep(0.5)

    # ── MOMENTO 2 ──────────────────────────────────────────
    print(f"\n  [DHCP Momento 2] Autenticacion exitosa. Rol: {nombre_rol}")
    print(f"  [DHCP Momento 2] Simulando DHCP Release de {ip_cuarentena}...")
    time.sleep(0.5)

    liberar_ip_cuarentena(mac_address)

    print(f"  [DHCP Momento 2] Simulando DHCP Discover para pool {cidr_rol}...")
    time.sleep(0.5)

    asignacion_rol = asignar_ip_rol(mac_address, nombre_rol)
    if not asignacion_rol:
        print(f"  [ERROR] No se pudo asignar IP del rol {nombre_rol}.")
        return None

    ip_definitiva = asignacion_rol["ip"]
    print(f"  [DHCP Momento 2] DHCP Offer  → IP definitiva: {ip_definitiva}")
    print(f"  [DHCP Momento 2] DHCP Ack    → Dispositivo con IP de rol")
    print(f"  [DHCP Momento 2] Subred      : {asignacion_rol['subred']}")
    print(f"  [DHCP Momento 2] Lease       : {asignacion_rol['lease_segundos']} seg")

    # Actualizar sesiones_activas con la IP definitiva
    actualizar_ip_sesion(mac_address, ip_definitiva, cidr_rol)
    print(f"  [DHCP] sesiones_activas actualizada con IP definitiva: {ip_definitiva}")

    return {
        "ip_cuarentena": ip_cuarentena,
        "ip_definitiva": ip_definitiva,
        "subred":        asignacion_rol["subred"],
        "gateway":       asignacion_rol["gateway"],
        "lease_segundos":asignacion_rol["lease_segundos"]
    }


# ============================================================
# TEST STANDALONE
# ============================================================

