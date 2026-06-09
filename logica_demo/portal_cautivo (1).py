#!/usr/bin/env python3
"""
portal_cautivo.py - Portal Cautivo CLI - Proyecto SDN PUCP
Modulo: Portal Cautivo + M1 integrado + DHCP simulado

FLUJO COMPLETO:
  1. DHCP Momento 1: asigna IP de cuarentena al dispositivo
  2. Usuario ingresa credenciales en el portal
  3. Portal envia Access-Request a FreeRADIUS
  4. FreeRADIUS valida contra MySQL y devuelve Access-Accept/Reject
  5. Si Accept:
       - DHCP Momento 2: libera IP cuarentena, asigna IP del rol
       - M1 registra sesion en sesiones_activas con IP definitiva
       - M1 emite Token de Rol hacia M6
  6. Si 3 intentos fallidos: M1 bloquea la cuenta en usuarios

DEPENDENCIAS:
  pip3 install pyrad mysql-connector-python pyyaml
"""

import getpass
import sys
import time
import datetime
import mysql.connector
import pyrad.client
import pyrad.packet
import pyrad.dictionary
import subprocess
import re

# Importar el modulo DHCP simulado
from dhcp_manager import (
    asignar_ip_cuarentena,
    ejecutar_flujo_dhcp_completo
)

# ============================================================
# CONFIGURACION - FreeRADIUS
# ============================================================
RADIUS_SERVER  = "127.0.0.1"
RADIUS_PORT    = 1812
RADIUS_SECRET  = b"testing123"
NAS_IP         = "10.0.0.10"
NAS_IDENTIFIER = "portal_cautivo_pucp"

# ============================================================
# CONFIGURACION - MySQL (M1 integrado)
# ============================================================
DB_CONFIG = {
    "host":     "127.0.0.1",
    "port":     3306,
    "user":     "radius",
    "password": "radius_pass",
    "database": "radius_db"
}

# ============================================================
# CONFIGURACION - Demo
# ============================================================
DEMO_MAC         = "AA:BB:CC:DD:EE:FF"
DEMO_SWITCH_DPID = "of:0000000000000001"
DEMO_IN_PORT     = 1
MAX_INTENTOS     = 3

# Mapa rol → CIDR
CIDR_POR_ROL = {
    "Estudiante_Telecom":     "10.2.1.0/24",
    "Estudiante_Informatica": "10.2.2.0/24",
    "Estudiante_Electronica": "10.2.3.0/24",
    "Docente":                "10.3.0.0/24",
    "Admin_TI":               "10.4.0.0/24",
}

# Recursos accesibles por rol
RECURSOS_POR_ROL = {
    "Estudiante_Telecom":     ["Cursos Telecom      → 10.0.0.21 (TCP 80/443)"],
    "Estudiante_Informatica": ["Cursos Informatica  → 10.0.0.22 (TCP 80/443)"],
    "Estudiante_Electronica": ["Cursos Electronica  → 10.0.0.23 (TCP 80/443)"],
    "Docente": [
        "Cursos Telecom      → 10.0.0.21 (TCP 80/443)",
        "Cursos Informatica  → 10.0.0.22 (TCP 80/443)",
        "Cursos Electronica  → 10.0.0.23 (TCP 80/443)",
        "Notas               → 10.0.0.30 (TCP 80/443)",
    ],
    "Admin_TI": ["Acceso total a la infraestructura SDN"],
}


# ============================================================
# MODULO RADIUS
# ============================================================

def enviar_access_request(codigo_pucp, password, mac_address, switch_dpid, in_port, ip_cuarentena):
    """Envía Access-Request usando radclient (más confiable que pyrad)"""
    
    # Construir el string de entrada para radclient
    rad_input = f"User-Name={codigo_pucp},User-Password={password},NAS-IP-Address=127.0.0.1,NAS-Port={in_port},Calling-Station-Id={mac_address},Called-Station-Id={switch_dpid},Framed-IP-Address={ip_cuarentena}"
    
    cmd = f'echo "{rad_input}" | radclient -x 127.0.0.1:1812 auth testing123'
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
        
        if "Access-Accept" in output:
            # Extraer Filter-Id (rol)
            match = re.search(r'Filter-Id = "([^"]+)"', output)
            rol = match.group(1) if match else None
            return True, rol, None
        else:
            return False, None, None
    except Exception as e:
        print(f"  [ERROR] radclient falló: {e}")
        return False, None, None


# ============================================================
# MODULO M1 — gestion de sesiones
# ============================================================

def conectar_db():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as e:
        print(f"\n  [ERROR DB] No se pudo conectar a MySQL: {e}")
        return None


def m1_obtener_id_usuario(conn, codigo_pucp):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id_usuario FROM usuarios WHERE codigo_pucp = %s",
        (codigo_pucp,)
    )
    fila = cursor.fetchone()
    cursor.close()
    return fila[0] if fila else None


def m1_cuenta_bloqueada(codigo_pucp):
    """Verifica si la cuenta esta BLOQUEADA antes de autenticar."""
    conn = conectar_db()
    if not conn:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT estado_cuenta FROM usuarios WHERE codigo_pucp = %s",
            (codigo_pucp,)
        )
        fila = cursor.fetchone()
        cursor.close()
        conn.close()
        return fila and fila[0] == "BLOQUEADO"
    except mysql.connector.Error:
        conn.close()
        return False


def m1_registrar_sesion(codigo_pucp, rol, cidr_rol, mac_address,
                         switch_dpid, in_port, ip_asignada):
    """
    M1: Registra la sesion en sesiones_activas con la IP de cuarentena.
    La IP se actualizara en el Momento 2 cuando se asigne la IP del rol.
    """
    conn = conectar_db()
    if not conn:
        return False
    try:
        id_usuario = m1_obtener_id_usuario(conn, codigo_pucp)
        if not id_usuario:
            print(f"  [WARN M1] Usuario {codigo_pucp} no encontrado en usuarios.")
            return False

        cursor = conn.cursor()

        # Cerrar sesion anterior de esa MAC si existe
        cursor.execute(
            "UPDATE sesiones_activas SET estado='CERRADA' "
            "WHERE mac_address = %s AND estado='ACTIVA'",
            (mac_address,)
        )

        # Insertar nueva sesion con IP de cuarentena inicial
        cursor.execute("""
            INSERT INTO sesiones_activas
                (id_usuario, mac_address, ip_asignada, cidr_rol,
                 nombre_rol, switch_dpid, in_port, estado)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'ACTIVA')
        """, (id_usuario, mac_address, ip_asignada, cidr_rol,
              rol, switch_dpid, in_port))

        conn.commit()
        cursor.close()
        conn.close()
        return True

    except mysql.connector.Error as e:
        print(f"  [ERROR M1] No se pudo registrar sesion: {e}")
        conn.close()
        return False


def m1_bloquear_cuenta(codigo_pucp):
    """M1: Bloquea la cuenta por 3 intentos fallidos."""
    conn = conectar_db()
    if not conn:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE usuarios
            SET estado_cuenta = 'BLOQUEADO',
                fecha_bloqueo = %s
            WHERE codigo_pucp = %s
        """, (datetime.datetime.now(), codigo_pucp))
        conn.commit()
        filas = cursor.rowcount
        cursor.close()
        conn.close()
        return filas > 0
    except mysql.connector.Error as e:
        print(f"  [ERROR M1] No se pudo bloquear cuenta: {e}")
        conn.close()
        return False


def m1_emitir_token_rol(codigo_pucp, rol, cidr_rol, ip_definitiva,
                         mac_address, switch_dpid, in_port):
    """
    M1: Emite el Token de Rol hacia M6 con todos los datos
    de la sesion autenticada, incluyendo la IP definitiva del rol.

    En produccion este token se envia via HTTP POST a M6.
    En el demo se imprime en pantalla.
    """
    token = {
        "codigo_pucp": codigo_pucp,
        "rol":         rol,
        "ip_asignada": ip_definitiva,
        "cidr_rol":    cidr_rol,
        "mac_address": mac_address,
        "switch_dpid": switch_dpid,
        "in_port":     in_port,
        "hora":        datetime.datetime.now().isoformat()
    }

    print("\n  [M1 → M6] Token de Rol emitido:")
    print("  " + "-"*45)
    for k, v in token.items():
        print(f"    {k}: {v}")
    print("  " + "-"*45)
    print("  M6 procesara este token para instalar flows en ONOS.")
    return token


# ============================================================
# INTERFAZ CLI
# ============================================================

def mostrar_banner(ip_cuarentena):
    print("\n" + "="*55)
    print("        PORTAL CAUTIVO - RED PUCP")
    print("        Sistema de Autenticacion SDN")
    print("="*55)
    print(f"  Estado     : Cuarentena")
    print(f"  IP actual  : {ip_cuarentena}")
    print(f"  FreeRADIUS : {RADIUS_SERVER}:{RADIUS_PORT}")
    print("="*55)
    print("  Ingrese sus credenciales PUCP para acceder\n")


def mostrar_acceso_aceptado(codigo_pucp, rol, cidr,
                             ip_cuarentena, ip_definitiva,
                             sesion_registrada):
    print("\n" + "="*55)
    print("  ✓ Access-Accept recibido")
    print(f"  ✓ Rol asignado    : {rol}")
    print(f"  ✓ CIDR asignado   : {cidr}")
    print(f"  ✓ IP cuarentena   : {ip_cuarentena}  (liberada)")
    print(f"  ✓ IP definitiva   : {ip_definitiva}")
    if sesion_registrada:
        print("  ✓ Sesion registrada en sesiones_activas")
    else:
        print("  ! Sesion no registrada (revisar DB)")
    print("="*55)
    print(f"\n  Bienvenido/a, {codigo_pucp}")
    print("  Acceso habilitado a:")
    for recurso in RECURSOS_POR_ROL.get(rol, ["Sin recursos definidos"]):
        print(f"    → {recurso}")
    print()


def mostrar_acceso_rechazado(intentos_fallidos, max_intentos):
    restantes = max_intentos - intentos_fallidos
    print(f"\n  ✗ Access-Reject — Credenciales invalidas")
    if restantes > 0:
        print(f"    Intentos restantes: {restantes}\n")


def mostrar_cuenta_bloqueada():
    print("\n" + "="*55)
    print("  ✗ CUENTA BLOQUEADA")
    print("="*55)
    print("  Ha superado el maximo de intentos fallidos.")
    print("  Contacte al Administrador TI para desbloquear.")
    print("="*55 + "\n")


# ============================================================
# FLUJO PRINCIPAL
# ============================================================

def ejecutar_portal():

    mac_address  = DEMO_MAC
    switch_dpid  = DEMO_SWITCH_DPID
    in_port      = DEMO_IN_PORT

    # ── MOMENTO 1: DHCP Cuarentena ────────────────────────
    print("\n  Iniciando conexion a la red...")
    print("  Simulando DHCP Discover...")
    time.sleep(0.5)

    asignacion = asignar_ip_cuarentena(mac_address)
    if not asignacion:
        print("  [ERROR] No hay IPs disponibles en el pool de cuarentena.")
        sys.exit(1)

    ip_cuarentena = asignacion["ip"]
    print(f"  DHCP Offer recibido  → IP: {ip_cuarentena}")
    print(f"  DHCP Ack confirmado  → Dispositivo en cuarentena")
    time.sleep(0.5)

    # Mostrar banner con IP de cuarentena
    mostrar_banner(ip_cuarentena)

    intentos_fallidos = 0

    while intentos_fallidos < MAX_INTENTOS:

        # Pedir credenciales
        try:
            codigo_pucp = input("  Codigo PUCP : ").strip()
            password    = getpass.getpass("  Contrasena  : ")
        except KeyboardInterrupt:
            print("\n\n  Sesion cancelada.")
            sys.exit(0)

        if not codigo_pucp or not password:
            print("  [!] Ingrese codigo y contrasena.\n")
            continue

        # Verificar si la cuenta ya esta bloqueada
        if m1_cuenta_bloqueada(codigo_pucp):
            mostrar_cuenta_bloqueada()
            sys.exit(1)

        # Animacion
        print("\n  Autenticando", end="", flush=True)
        for _ in range(3):
            time.sleep(0.4)
            print(".", end="", flush=True)
        print()

        # ── Enviar Access-Request a FreeRADIUS ────────────
        autenticado, rol, cidr = enviar_access_request(
            codigo_pucp, password, mac_address,
            switch_dpid, in_port, ip_cuarentena
        )

        if autenticado:

            # ── MOMENTO 2: DHCP del Rol ───────────────────
            print(f"\n  Access-Accept recibido. Procesando Momento 2 DHCP...")

            resultado_dhcp = ejecutar_flujo_dhcp_completo(
                mac_address, rol, cidr
            )

            if resultado_dhcp:
                ip_definitiva = resultado_dhcp["ip_definitiva"]
                cidr_rol = resultado_dhcp.get("cidr_rol", cidr)  # ← USAR EL CIDR DEVUELTO
            else:
                ip_definitiva = ip_cuarentena
                cidr_rol = cidr

            # ── M1 registra sesion con IP definitiva ──────
            sesion_ok = m1_registrar_sesion(
                codigo_pucp, rol, cidr_rol, mac_address,
                switch_dpid, in_port, ip_definitiva
            )

            # ── Mostrar resultado ─────────────────────────
            mostrar_acceso_aceptado(
                codigo_pucp, rol, cidr_rol,
                ip_cuarentena, ip_definitiva,
                sesion_ok
            )

            # ── M1 emite Token de Rol hacia M6 ────────────
            m1_emitir_token_rol(
                codigo_pucp, rol, cidr_rol, ip_definitiva,
                mac_address, switch_dpid, in_port
            )

            sys.exit(0)

        else:
            intentos_fallidos += 1
            mostrar_acceso_rechazado(intentos_fallidos, MAX_INTENTOS)

            if intentos_fallidos >= MAX_INTENTOS:
                m1_bloquear_cuenta(codigo_pucp)
                mostrar_cuenta_bloqueada()
                sys.exit(1)


if __name__ == "__main__":
    ejecutar_portal()
