#!/usr/bin/env python3
"""
portal_cautivo.py — Portal Cautivo CLI — SDN PUCP
Módulo M1 integrado | Arquitectura CIDR + doble DHCP
Grupo 2 - TEL354

FLUJO COMPLETO:
  1. DHCP Momento 1 : asigna IP de cuarentena (192.168.100.x)
  2. Usuario ingresa credenciales en el portal
  3. Portal envía Access-Request a FreeRADIUS
  4. FreeRADIUS valida contra MySQL y devuelve Access-Accept / Reject
  5. Si Accept:
       - DHCP Momento 2: libera IP cuarentena, asigna IP del bloque del rol
       - M1 verifica anti-spoofing (ip_mac_binding)
       - M1 registra sesión en sesiones_activas con IP definitiva
       - M1 crea binding IP+MAC
       - M1 emite Token de Rol hacia M6
  6. Menú interactivo: ver recursos, cerrar sesión
  7. Al cerrar sesión:
       - INSERT en historial_sesiones (motivo LOGOUT)
       - DELETE ip_mac_binding
       - DELETE sesiones_activas
  8. Si 3 intentos fallidos: M1 bloquea la cuenta en usuarios

DEPENDENCIAS:
  pip3 install pyrad mysql-connector-python pyyaml

ARCHIVOS REQUERIDOS (misma carpeta):
  dhcp_manager.py
  dhcp_pools.yaml
"""

import sys
import os
import getpass
import json
import time
import datetime

try:
    import pyrad.client
    import pyrad.dictionary
    import pyrad.packet
    PYRAD_OK = True
except ImportError:
    PYRAD_OK = False
    print("[ADVERTENCIA] pyrad no instalado. Ejecuta: pip3 install pyrad")

try:
    import mysql.connector
    MYSQL_OK = True
except ImportError:
    MYSQL_OK = False
    print("[ADVERTENCIA] mysql-connector-python no instalado. Ejecuta: pip3 install mysql-connector-python")

from dhcp_manager import (
    asignar_ip_cuarentena,
    ejecutar_flujo_dhcp_completo
)

# CONFIGURACIÓN

RADIUS_HOST   = "127.0.0.1"
RADIUS_PORT   = 1812
RADIUS_SECRET = b"testing123"
NAS_IP        = "10.0.0.10"

MYSQL_HOST    = "localhost"
MYSQL_PORT    = 3306
MYSQL_USER    = "radius"
MYSQL_PASS    = "radius_pass"
MYSQL_DB      = "radius_db"

M6_URL        = "http://localhost:8080/api/m6/token"

SWITCH_DPID   = "of:0000000000000001"
IN_PORT       = 3
DEMO_MAC      = "AA:BB:CC:DD:EE:FF"
MAX_INTENTOS  = 3

# Mapa rol → CIDR (para validación local)
CIDR_POR_ROL = {
    "Visitante":              "10.1.0.0/24",
    "Estudiante_Telecom":     "10.2.1.0/24",
    "Estudiante_Informatica": "10.2.2.0/24",
    "Estudiante_Electronica": "10.2.3.0/24",
    "Docente":                "10.3.0.0/24",
    "Admin_TI":               "10.4.0.0/24",
}

# PYRAD — diccionario en memoria

DICT_CONTENT = """\
ATTRIBUTE User-Name           1  string
ATTRIBUTE User-Password       2  string
ATTRIBUTE NAS-IP-Address      4  ipaddr
ATTRIBUTE NAS-Port            5  integer
ATTRIBUTE Filter-Id          11  string
ATTRIBUTE Reply-Message      18  string
ATTRIBUTE Calling-Station-Id 31  string
ATTRIBUTE Called-Station-Id  30  string
ATTRIBUTE Framed-IP-Address   8  ipaddr
ATTRIBUTE Session-Timeout    27  integer
ATTRIBUTE NAS-Identifier     32  string
"""

def get_dict():
    import tempfile
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.dict',
                                      delete=False, encoding='utf-8')
    tmp.write(DICT_CONTENT)
    tmp.flush()
    d = pyrad.dictionary.Dictionary(tmp.name)
    tmp.close()
    os.unlink(tmp.name)
    return d

# BASE DE DATOS

def get_db():
    if not MYSQL_OK:
        return None
    try:
        return mysql.connector.connect(
            host=MYSQL_HOST, port=MYSQL_PORT,
            user=MYSQL_USER, password=MYSQL_PASS,
            database=MYSQL_DB, autocommit=False
        )
    except mysql.connector.Error as e:
        print(f"  [DB] Error al conectar: {e}")
        return None

# RADIUS

def autenticar(codigo_pucp, password, ip_cuarentena):
    """
    Envía Access-Request a FreeRADIUS.
    Retorna (nombre_rol, session_timeout) si Access-Accept.
    Retorna (None, None) si Access-Reject o error.
    """
    if not PYRAD_OK:
        print("  [ERROR] pyrad no disponible.")
        return None, None
    try:
        client = pyrad.client.Client(
            server=RADIUS_HOST,
            authport=RADIUS_PORT,
            secret=RADIUS_SECRET,
            dict=get_dict()
        )
        client.timeout = 5
        client.retries = 1

        req = client.CreateAuthPacket(
            code=pyrad.packet.AccessRequest,
            User_Name=codigo_pucp
        )
        req["User-Password"]      = req.PwCrypt(password)
        req["NAS-IP-Address"]     = NAS_IP
        req["NAS-Port"]           = IN_PORT
        req["Calling-Station-Id"] = DEMO_MAC
        req["Called-Station-Id"]  = SWITCH_DPID
        req["Framed-IP-Address"]  = ip_cuarentena

        reply = client.SendPacket(req)

        if reply.code == pyrad.packet.AccessAccept:
            nombre_rol = None
            if 11 in reply:
                nombre_rol = reply[11][0]
                if isinstance(nombre_rol, bytes):
                    nombre_rol = nombre_rol.decode()
            session_timeout = 28800
            if 27 in reply:
                val = reply[27][0]
                session_timeout = (int.from_bytes(val, 'big')
                                   if isinstance(val, bytes) else int(val))
            return nombre_rol, session_timeout

        return None, None

    except Exception as e:
        print(f"  [RADIUS] Error: {e}")
        return None, None

# M1 — USUARIOS Y CUENTAS

def verificar_cuenta_bloqueada(codigo_pucp):
    db = get_db()
    if not db:
        return False
    try:
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT estado_cuenta FROM usuarios WHERE codigo_pucp = %s",
            (codigo_pucp,)
        )
        row = cur.fetchone()
        return bool(row and row["estado_cuenta"] == "BLOQUEADO")
    except Exception:
        return False
    finally:
        db.close()


def obtener_id_usuario(codigo_pucp):
    db = get_db()
    if not db:
        return None
    try:
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id_usuario FROM usuarios WHERE codigo_pucp = %s",
            (codigo_pucp,)
        )
        row = cur.fetchone()
        return row["id_usuario"] if row else None
    finally:
        db.close()


def incrementar_intento_fallido(codigo_pucp):
    """Suma 1 al contador. Si llega a MAX_INTENTOS bloquea la cuenta."""
    db = get_db()
    if not db:
        return 0
    try:
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT intentos_fallidos FROM usuarios WHERE codigo_pucp = %s",
            (codigo_pucp,)
        )
        row = cur.fetchone()
        if not row:
            return 0
        nuevos = row["intentos_fallidos"] + 1
        if nuevos >= MAX_INTENTOS:
            cur.execute(
                "UPDATE usuarios SET intentos_fallidos=%s, "
                "estado_cuenta='BLOQUEADO', fecha_bloqueo=NOW() "
                "WHERE codigo_pucp=%s",
                (nuevos, codigo_pucp)
            )
        else:
            cur.execute(
                "UPDATE usuarios SET intentos_fallidos=%s "
                "WHERE codigo_pucp=%s",
                (nuevos, codigo_pucp)
            )
        db.commit()
        return nuevos
    except Exception as e:
        db.rollback()
        print(f"  [M1] Error al actualizar intentos: {e}")
        return 0
    finally:
        db.close()


def resetear_intentos(codigo_pucp):
    db = get_db()
    if not db:
        return
    try:
        cur = db.cursor()
        cur.execute(
            "UPDATE usuarios SET intentos_fallidos=0 WHERE codigo_pucp=%s",
            (codigo_pucp,)
        )
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

# M1 — IP-MAC BINDING 

def verificar_ip_mac_disponible(ip, mac):
    """
    Verifica que IP y MAC no estén ya bindeadas a otra sesión activa.
    Retorna (True, None) si están libres.
    Retorna (False, motivo) si hay conflicto.
    """
    db = get_db()
    if not db:
        return True, None
    try:
        cur = db.cursor(dictionary=True)

        # ¿Esta IP está bindeada a otra MAC?
        cur.execute("""
            SELECT b.mac_address, u.codigo_pucp
            FROM ip_mac_binding b
            JOIN sesiones_activas s ON b.id_sesion = s.id_sesion
            JOIN usuarios u ON s.id_usuario = u.id_usuario
            WHERE b.ip_asignada = %s AND b.mac_address != %s
        """, (ip, mac))
        row = cur.fetchone()
        if row:
            return False, (f"IP {ip} ya está en uso por "
                           f"MAC {row['mac_address']} "
                           f"(usuario: {row['codigo_pucp']})")

        # ¿Esta MAC está bindeada a otra IP?
        cur.execute("""
            SELECT b.ip_asignada, u.codigo_pucp
            FROM ip_mac_binding b
            JOIN sesiones_activas s ON b.id_sesion = s.id_sesion
            JOIN usuarios u ON s.id_usuario = u.id_usuario
            WHERE b.mac_address = %s AND b.ip_asignada != %s
        """, (mac, ip))
        row = cur.fetchone()
        if row:
            return False, (f"MAC {mac} ya tiene sesión activa "
                           f"con IP {row['ip_asignada']} "
                           f"(usuario: {row['codigo_pucp']})")

        return True, None
    except Exception:
        return True, None
    finally:
        db.close()


def crear_binding(ip, mac, id_sesion):
    """Registra el par IP+MAC al iniciar sesión."""
    db = get_db()
    if not db:
        return
    try:
        cur = db.cursor()
        cur.execute("""
            INSERT INTO ip_mac_binding (ip_asignada, mac_address, id_sesion)
            VALUES (%s, %s, %s)
        """, (ip, mac, id_sesion))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"  [M1] Error al crear binding: {e}")
    finally:
        db.close()

# M1 — SESIONES

def registrar_sesion(id_usuario, mac, ip_definitiva, cidr_rol,
                     nombre_rol, dpid, port):
    """
    INSERT en sesiones_activas con la IP definitiva del rol.
    Retorna id_sesion (int) si OK, None si falla.
    """
    db = get_db()
    if not db:
        return None
    try:
        cur = db.cursor()
        cur.execute("""
            INSERT INTO sesiones_activas
                (id_usuario, mac_address, ip_asignada, cidr_rol,
                 nombre_rol, switch_dpid, in_port, estado)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'ACTIVA')
        """, (id_usuario, mac, ip_definitiva, cidr_rol,
              nombre_rol, dpid, port))
        db.commit()
        return cur.lastrowid
    except mysql.connector.Error as e:
        db.rollback()
        print(f"  [M1] Error al registrar sesión: {e}")
        return None
    finally:
        db.close()


def cerrar_sesion_db(mac, id_usuario):
    """
    Cierra la sesión del usuario en esa MAC:
      1. INSERT en historial_sesiones (motivo LOGOUT)
      2. DELETE ip_mac_binding
      3. DELETE sesiones_activas
    Retorna dict con datos de la sesión cerrada, o None si no se encontró.
    """
    db = get_db()
    if not db:
        return None
    try:
        cur = db.cursor(dictionary=True)

        # Buscar sesión activa
        cur.execute("""
            SELECT s.id_sesion, s.id_usuario, s.mac_address,
                   s.ip_asignada, s.cidr_rol, s.nombre_rol,
                   s.switch_dpid, s.in_port, s.login_timestamp,
                   u.codigo_pucp
            FROM sesiones_activas s
            JOIN usuarios u ON s.id_usuario = u.id_usuario
            WHERE s.mac_address = %s
              AND s.id_usuario  = %s
              AND s.estado      = 'ACTIVA'
        """, (mac, id_usuario))
        sesion = cur.fetchone()
        if not sesion:
            return None

        # 1. Guardar en historial
        cur.execute("""
            INSERT INTO historial_sesiones
                (id_usuario, mac_address, ip_asignada, cidr_rol,
                 nombre_rol, switch_dpid, in_port,
                 login_timestamp, logout_timestamp, motivo_cierre)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'LOGOUT')
        """, (
            sesion["id_usuario"],
            sesion["mac_address"],
            sesion["ip_asignada"],
            sesion["cidr_rol"],
            sesion["nombre_rol"],
            sesion["switch_dpid"],
            sesion["in_port"],
            sesion["login_timestamp"]
        ))

        # 2. Eliminar binding IP+MAC
        cur.execute(
            "DELETE FROM ip_mac_binding WHERE id_sesion = %s",
            (sesion["id_sesion"],)
        )

        # 3. Eliminar sesión activa
        cur.execute(
            "DELETE FROM sesiones_activas WHERE id_sesion = %s",
            (sesion["id_sesion"],)
        )

        db.commit()
        return sesion

    except Exception as e:
        db.rollback()
        print(f"  [M1] Error al cerrar sesión: {e}")
        return None
    finally:
        db.close()


def obtener_recursos_rol(nombre_rol):
    """Consulta politicas_rbac para obtener recursos ALLOW del rol."""
    db = get_db()
    if not db:
        return []
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("""
            SELECT rec.nombre_recurso, rec.ip_dst, rec.puerto,
                   rec.protocolo, p.tabla_of
            FROM politicas_rbac p
            JOIN roles_facultad rf ON p.id_rol     = rf.id_rol
            JOIN recursos rec      ON p.id_recurso = rec.id_recurso
            WHERE rf.nombre_rol = %s
              AND p.accion      = 'ALLOW'
              AND p.activo      = 1
            ORDER BY rec.ip_dst, rec.puerto
        """, (nombre_rol,))
        return cur.fetchall()
    except Exception as e:
        print(f"  [DB] Error al obtener recursos: {e}")
        return []
    finally:
        db.close()

# M1 — TOKEN DE ROL HACIA M6

def emitir_token_rol(codigo_pucp, nombre_rol, cidr_rol,
                     ip_definitiva, mac, dpid, port):
    """
    Emite el Token de Rol hacia M6 con todos los datos de la sesión.
    En producción: POST HTTP a M6_URL.
    En demo: imprime en pantalla y simula el envío.
    """
    token = {
        "codigo_pucp": codigo_pucp,
        "rol":         nombre_rol,
        "ip_asignada": ip_definitiva,
        "cidr_rol":    cidr_rol,
        "mac_address": mac,
        "switch_dpid": dpid,
        "in_port":     port,
        "hora":        datetime.datetime.now().isoformat()
    }

    try:
        import urllib.request
        data = json.dumps(token).encode()
        req  = urllib.request.Request(
            M6_URL, data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            print(f"  [M1→M6] Token enviado — HTTP {resp.status}")
    except Exception:
        print("\n  [M1→M6] Token de Rol (simulado):")
        print("  " + "─"*46)
        for k, v in token.items():
            print(f"    {k:<14}: {v}")
        print("  " + "─"*46)
        print("  M6 instalará flows en ONOS según este token.\n")

    return token

# PANTALLAS

SEP  = "═" * 55
SEP2 = "─" * 55

def cls():
    print("\n")


def pantalla_bienvenida(codigo_pucp, nombre_rol, cidr_rol,
                        ip_cuarentena, ip_definitiva,
                        id_usuario, id_sesion):
    while True:
        cls()
        print(SEP)
        print("  ✓  ACCESO CONCEDIDO — Sesión activa")
        print(SEP)
        print(f"  Usuario      : {codigo_pucp}")
        print(f"  Rol          : {nombre_rol}")
        print(f"  CIDR         : {cidr_rol}")
        print(f"  IP cuarentena: {ip_cuarentena}  (liberada)")
        print(f"  IP definitiva: {ip_definitiva}")
        print(f"  Binding      : IP+MAC registrado")
        print(f"  Inicio       : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(SEP2)
        print("  [1] Ver recursos permitidos")
        print("  [2] Cerrar sesión")
        print(SEP)

        opcion = input("  Opción: ").strip()

        if opcion == "1":
            pantalla_recursos(nombre_rol, cidr_rol)

        elif opcion == "2":
            cls()
            print(SEP)
            print("  Cerrando sesión...")

            sesion = cerrar_sesion_db(DEMO_MAC, id_usuario)

            if sesion:
                print(f"  ✓ Sesión #{sesion['id_sesion']} eliminada de sesiones_activas")
                print(f"  ✓ Registro guardado en historial_sesiones (motivo: LOGOUT)")
                print(f"  ✓ Binding IP+MAC eliminado — MAC e IP libres")
            else:
                print("  ⚠  No se encontró sesión activa para este usuario.")

            print(SEP)
            input("  Presiona Enter para volver al menú principal...")
            return


def pantalla_recursos(nombre_rol, cidr_rol):
    cls()
    print(SEP)
    print(f"  Recursos permitidos — {nombre_rol}  ({cidr_rol})")
    print(SEP)

    recursos = obtener_recursos_rol(nombre_rol)

    if not recursos:
        print("  Sin recursos definidos en la base de datos.")
    else:
        print(f"  {'RECURSO':<28} {'IP DESTINO':<16} "
              f"{'PUERTO':>6}  {'PROTO':<5}  TABLA")
        print("  " + "─" * 62)
        for r in recursos:
            print(f"  {r['nombre_recurso']:<28} {r['ip_dst']:<16} "
                  f"{r['puerto']:>6}  {r['protocolo']:<5}  {r['tabla_of']}")

    print(SEP)
    input("  Presiona Enter para volver...")

# FLUJO DE LOGIN

def flujo_login():
    cls()

    # ── MOMENTO 1: DHCP Cuarentena ────────────────────────────────────────
    print(SEP)
    print("  Iniciando conexión a la red...")
    print("  Simulando DHCP Discover (cuarentena)...")
    time.sleep(0.5)

    asignacion = asignar_ip_cuarentena(DEMO_MAC)
    if not asignacion:
        print("  [ERROR] No hay IPs disponibles en el pool de cuarentena.")
        input("  Presiona Enter para volver...")
        return

    ip_cuarentena = asignacion["ip"]
    print(f"  DHCP Offer → IP cuarentena : {ip_cuarentena}")
    print(f"  DHCP Ack   → Dispositivo en cuarentena (solo portal visible)")
    time.sleep(0.4)

    print(SEP)
    print(f"  IP actual  : {ip_cuarentena}  (192.168.100.0/24)")
    print("  Ingresa tus credenciales PUCP para acceder a la red")
    print(SEP2)

    intentos = 0
    while intentos < MAX_INTENTOS:

        try:
            codigo   = input("  Código PUCP : ").strip()
            password = getpass.getpass("  Contraseña  : ")
        except KeyboardInterrupt:
            print("\n\n  Sesión cancelada.")
            return

        if not codigo or not password:
            print("  [!] Ingresa código y contraseña.\n")
            continue

        # 1. Verificar bloqueo
        if verificar_cuenta_bloqueada(codigo):
            print(SEP)
            print("  ✗ Cuenta bloqueada.")
            print("    Contacta al Administrador TI.")
            print(SEP)
            input("  Presiona Enter para volver...")
            return

        # 2. Enviar Access-Request
        print("\n  Autenticando...", end="", flush=True)
        for _ in range(3):
            time.sleep(0.3)
            print(".", end="", flush=True)
        print()

        nombre_rol, session_timeout = autenticar(codigo, password, ip_cuarentena)

        # ── Access-Accept ─────────────────────────────────────────────────
        if nombre_rol is not None:

            # 3. Verificar que el rol existe en el mapa
            cidr_rol = CIDR_POR_ROL.get(nombre_rol)
            if not cidr_rol:
                print(f"  ✗ Rol '{nombre_rol}' no reconocido. Contacta a TI.")
                input("  Presiona Enter para volver...")
                return

            # 4. DHCP Momento 2: liberar cuarentena, asignar IP del rol
            print(f"\n  Access-Accept recibido. Iniciando DHCP Momento 2...")
            resultado_dhcp = ejecutar_flujo_dhcp_completo(
                DEMO_MAC, nombre_rol, cidr_rol
            )

            if not resultado_dhcp:
                print(f"  [ERROR] No se pudo asignar IP del rol {nombre_rol}.")
                input("  Presiona Enter para volver...")
                return

            ip_definitiva = resultado_dhcp["ip_definitiva"]
            cidr_rol      = resultado_dhcp.get("cidr_rol", cidr_rol)

            # 5. Anti-spoofing: verificar IP+MAC libres
            libre, motivo = verificar_ip_mac_disponible(ip_definitiva, DEMO_MAC)
            if not libre:
                print(f"\n  ✗ Acceso denegado — {motivo}")
                print("    La sesión activa debe cerrarse primero.")
                input("  Presiona Enter para volver...")
                return

            # 6. Obtener id_usuario
            id_usuario = obtener_id_usuario(codigo)
            if not id_usuario:
                print("  [ERROR] Usuario no encontrado en la base de datos.")
                input("  Presiona Enter para volver...")
                return

            # 7. Registrar sesión con IP definitiva
            id_sesion = registrar_sesion(
                id_usuario, DEMO_MAC, ip_definitiva,
                cidr_rol, nombre_rol, SWITCH_DPID, IN_PORT
            )
            if id_sesion is None:
                print("  ✗ Error al registrar sesión. Intenta nuevamente.")
                input("  Presiona Enter para volver...")
                return

            # 8. Crear binding IP+MAC
            crear_binding(ip_definitiva, DEMO_MAC, id_sesion)
            print(f"  ✓ Sesión #{id_sesion} registrada en sesiones_activas")
            print(f"  ✓ Binding IP+MAC creado (anti-spoofing activo)")

            # 9. Resetear intentos fallidos
            resetear_intentos(codigo)

            # 10. Emitir Token de Rol hacia M6
            emitir_token_rol(
                codigo, nombre_rol, cidr_rol,
                ip_definitiva, DEMO_MAC, SWITCH_DPID, IN_PORT
            )

            # 11. Pantalla de sesión activa
            pantalla_bienvenida(
                codigo, nombre_rol, cidr_rol,
                ip_cuarentena, ip_definitiva,
                id_usuario, id_sesion
            )
            return

        # ── Access-Reject ─────────────────────────────────────────────────
        else:
            intentos += 1
            total     = incrementar_intento_fallido(codigo)
            restantes = MAX_INTENTOS - total

            if total >= MAX_INTENTOS:
                print(SEP)
                print("  ✗ Credenciales inválidas.")
                print("  ✗ Cuenta bloqueada por 3 intentos fallidos.")
                print("    Contacta al Administrador TI.")
                print(SEP)
                input("  Presiona Enter para volver...")
                return
            else:
                print(f"  ✗ Credenciales inválidas. "
                      f"({restantes} intento(s) restante(s))\n")

# MENÚ PRINCIPAL

def menu_principal():
    cls()
    print(SEP)
    print("        PORTAL CAUTIVO — RED PUCP")
    print("        Sistema de Autenticación SDN")
    print(SEP)
    print(f"  Estado     : Cuarentena (esperando autenticación)")
    print(f"  FreeRADIUS : {RADIUS_HOST}:{RADIUS_PORT}")
    print(SEP2)
    print("  [1] Iniciar sesión")
    print("  [2] Soy visitante  (no implementado)")
    print("  [3] Salir")
    print(SEP)


def main():
    while True:
        menu_principal()
        opcion = input("  Opción: ").strip()

        if opcion == "1":
            flujo_login()

        elif opcion == "2":
            cls()
            print(SEP)
            print("  Flujo visitante — no implementado aún.")
            print(SEP)
            input("  Presiona Enter para volver...")

        elif opcion in ("3", "q", "salir"):
            print("\n  Saliendo del portal.\n")
            sys.exit(0)

        else:
            print("  Opción no válida.\n")


if __name__ == "__main__":
    main()