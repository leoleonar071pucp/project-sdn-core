#!/usr/bin/env python3
"""
Portal Cautivo CLI — SDN PUCP
Módulo M1 integrado — Arquitectura IP única + VLAN tag por rol
Grupo 2 - TEL354

LÓGICA DE SESIONES:
  - sesiones_activas: solo contiene sesiones ACTIVAS
    Al cerrar sesión → fila se ELIMINA (no se marca CERRADA)
  - historial_sesiones: registro permanente de todas las sesiones
    Al cerrar sesión → fila se INSERT aquí con timestamp de cierre
  - ip_mac_binding: par IP+MAC vinculado a sesión activa
    Al cerrar sesión → fila se ELIMINA (MAC/IP quedan libres)
"""

import sys
import os
import getpass
import json
from datetime import datetime

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

# ════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ════════════════════════════════════════════════════════════════════════════

RADIUS_HOST   = "127.0.0.1"
RADIUS_PORT   = 1812
RADIUS_SECRET = b"testing123"
NAS_IP        = "10.0.0.10"

MYSQL_HOST    = "localhost"
MYSQL_PORT    = 3306
MYSQL_USER    = "radius"
MYSQL_PASS    = "radius_pass"
MYSQL_DB      = "radius_db"

M6_URL        = "http://localhost:8080/api/m6/vlan"

SWITCH_DPID   = "of:0000000000000001"
IN_PORT       = 3
IP_CUARENTENA = "192.168.100.45"
DEMO_MAC      = "AA:BB:CC:DD:EE:FF"
MAX_INTENTOS  = 3

VLAN_POR_ROL = {
    "Visitante":              100,
    "Estudiante_Telecom":     210,
    "Estudiante_Informatica": 220,
    "Estudiante_Electronica": 230,
    "Docente":                300,
    "Admin_TI":               400,
}

# ════════════════════════════════════════════════════════════════════════════
# PYRAD — diccionario en memoria
# ════════════════════════════════════════════════════════════════════════════

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

# ════════════════════════════════════════════════════════════════════════════
# BASE DE DATOS
# ════════════════════════════════════════════════════════════════════════════

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

# ════════════════════════════════════════════════════════════════════════════
# IP-MAC BINDING — anti-spoofing
# ════════════════════════════════════════════════════════════════════════════

def verificar_ip_mac_disponible(ip, mac):
    """
    Verifica que la IP y la MAC no estén bindeadas
    a una sesión activa de otro usuario.
    Retorna (True, None) si están libres.
    Retorna (False, motivo) si hay conflicto.
    """
    db = get_db()
    if not db:
        return True, None
    try:
        cur = db.cursor(dictionary=True)

        # ¿Hay binding activo para esta IP con otra MAC?
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

        # ¿Hay binding activo para esta MAC con otra IP?
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


def eliminar_binding(id_sesion):
    """Elimina el binding al cerrar sesión — libera IP y MAC."""
    db = get_db()
    if not db:
        return
    try:
        cur = db.cursor()
        cur.execute(
            "DELETE FROM ip_mac_binding WHERE id_sesion = %s",
            (id_sesion,)
        )
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

# ════════════════════════════════════════════════════════════════════════════
# LÓGICA M1 — usuarios y sesiones
# ════════════════════════════════════════════════════════════════════════════

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


def registrar_sesion(id_usuario, mac, ip, vlan_id, nombre_rol, dpid, port):
    """
    INSERT en sesiones_activas.
    Retorna id_sesion (int) si OK, None si falla.
    No hace UPDATE previo — si hay sesión activa con esa MAC
    el UNIQUE de la tabla lo bloqueará (está protegido por el binding).
    """
    db = get_db()
    if not db:
        return None
    try:
        cur = db.cursor()
        cur.execute("""
            INSERT INTO sesiones_activas
                (id_usuario, mac_address, ip_asignada, vlan_id,
                 nombre_rol, switch_dpid, in_port, estado)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'ACTIVA')
        """, (id_usuario, mac, ip, vlan_id, nombre_rol, dpid, port))
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
    Cierra la sesión de ese usuario en ese MAC:
      1. Guarda en historial_sesiones antes de borrar
      2. Elimina binding IP-MAC
      3. Elimina la fila de sesiones_activas (DELETE, no UPDATE)
    Retorna los datos de la sesión cerrada, o None si no se encontró.
    """
    db = get_db()
    if not db:
        return None
    try:
        cur = db.cursor(dictionary=True)

        # Buscar sesión activa del usuario en esa MAC
        cur.execute("""
            SELECT s.id_sesion, u.codigo_pucp, s.id_usuario,
                   s.nombre_rol, s.vlan_id, s.ip_asignada,
                   s.mac_address, s.switch_dpid, s.in_port,
                   s.login_timestamp
            FROM sesiones_activas s
            JOIN usuarios u ON s.id_usuario = u.id_usuario
            WHERE s.mac_address = %s
              AND s.id_usuario  = %s
              AND s.estado      = 'ACTIVA'
        """, (mac, id_usuario))
        sesion = cur.fetchone()
        if not sesion:
            return None

        # 1. Guardar en historial antes de borrar
        cur.execute("""
            INSERT INTO historial_sesiones
                (id_usuario, mac_address, ip_asignada, vlan_id,
                 nombre_rol, switch_dpid, in_port,
                 login_timestamp, logout_timestamp, motivo_cierre)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'LOGOUT')
        """, (
            sesion["id_usuario"],
            sesion["mac_address"],
            sesion["ip_asignada"],
            sesion["vlan_id"],
            sesion["nombre_rol"],
            sesion["switch_dpid"],
            sesion["in_port"],
            sesion["login_timestamp"]
        ))

        # 2. Eliminar binding IP-MAC
        cur.execute(
            "DELETE FROM ip_mac_binding WHERE id_sesion = %s",
            (sesion["id_sesion"],)
        )

        # 3. Eliminar sesión activa — MAC queda libre
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
            SELECT r.nombre_recurso, r.ip_dst, r.puerto,
                   r.protocolo, p.tabla_of
            FROM politicas_rbac p
            JOIN roles_facultad rf ON p.id_rol = rf.id_rol
            JOIN recursos r        ON p.id_recurso = r.id_recurso
            WHERE rf.nombre_rol = %s
              AND p.accion = 'ALLOW'
            ORDER BY r.ip_dst, r.puerto
        """, (nombre_rol,))
        return cur.fetchall()
    except Exception as e:
        print(f"  [DB] Error al obtener recursos: {e}")
        return []
    finally:
        db.close()

# ════════════════════════════════════════════════════════════════════════════
# M6 — notificación al controlador
# ════════════════════════════════════════════════════════════════════════════

def notificar_m6(switch_dpid, in_port, vlan_id, mac):
    payload = {
        "switch_dpid": switch_dpid,
        "in_port":     in_port,
        "vlan_id":     vlan_id,
        "mac":         mac,
        "accion":      "set_vlan"
    }
    try:
        import urllib.request
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            M6_URL, data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            print(f"  [M6] Flow instalado en ONOS — HTTP {resp.status}")
    except Exception:
        print(f"  [M6] (simulado) SET_FIELD vlan_vid={vlan_id} "
              f"en switch={switch_dpid} puerto={in_port}")

# ════════════════════════════════════════════════════════════════════════════
# RADIUS
# ════════════════════════════════════════════════════════════════════════════

def autenticar(codigo_pucp, password):
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
        req["Framed-IP-Address"]  = IP_CUARENTENA

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

# ════════════════════════════════════════════════════════════════════════════
# PANTALLAS
# ════════════════════════════════════════════════════════════════════════════

SEP  = "═" * 54
SEP2 = "─" * 54

def cls():
    print("\n")


def pantalla_bienvenida(codigo_pucp, nombre_rol, vlan_id,
                        id_usuario, id_sesion):
    while True:
        cls()
        print(SEP)
        print("  ✓ Sesión activa")
        print(SEP)
        print(f"  Usuario  : {codigo_pucp}")
        print(f"  Rol      : {nombre_rol}")
        print(f"  VLAN     : {vlan_id}")
        print(f"  IP       : {IP_CUARENTENA}  (no cambia)")
        print(f"  Binding  : IP+MAC registrado  (anti-spoofing)")
        print(f"  Inicio   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(SEP2)
        print("  [1] Ver recursos permitidos")
        print("  [2] Cerrar sesión")
        print(SEP)

        opcion = input("  Opción: ").strip()

        if opcion == "1":
            pantalla_recursos(nombre_rol, vlan_id)

        elif opcion == "2":
            cls()
            print(SEP)
            print("  Cerrando sesión...")

            sesion = cerrar_sesion_db(DEMO_MAC, id_usuario)

            if sesion:
                print(f"  ✓ Sesión #{sesion['id_sesion']} eliminada de sesiones_activas")
                print(f"  ✓ Registro guardado en historial_sesiones")
                print(f"  ✓ Binding IP+MAC eliminado — MAC y IP libres")
                notificar_m6(SWITCH_DPID, IN_PORT, 90, DEMO_MAC)
                print(f"  ✓ Puerto revertido a VLAN 90 (cuarentena)")
            else:
                print("  ⚠ No se encontró sesión activa para este usuario.")

            print(SEP)
            input("  Presiona Enter para volver al menú principal...")
            return


def pantalla_recursos(nombre_rol, vlan_id):
    cls()
    print(SEP)
    print(f"  Recursos permitidos — {nombre_rol}  (VLAN {vlan_id})")
    print(SEP)

    recursos = obtener_recursos_rol(nombre_rol)

    if not recursos:
        print("  Sin recursos definidos en la base de datos.")
    else:
        print(f"  {'RECURSO':<26} {'IP DESTINO':<16} "
              f"{'PUERTO':>6}  {'PROTO':<5}  TABLA")
        print("  " + "─" * 62)
        for r in recursos:
            print(f"  {r['nombre_recurso']:<26} {r['ip_dst']:<16} "
                  f"{r['puerto']:>6}  {r['protocolo']:<5}  {r['tabla_of']}")

    print(SEP)
    input("  Presiona Enter para volver...")

# ════════════════════════════════════════════════════════════════════════════
# MENÚ PRINCIPAL Y FLUJO DE LOGIN
# ════════════════════════════════════════════════════════════════════════════

def menu_principal():
    cls()
    print(SEP)
    print("       PORTAL CAUTIVO — SDN PUCP")
    print("       Sistema de Autenticación")
    print(SEP)
    print(f"  IP actual : {IP_CUARENTENA}  (VLAN 90 — cuarentena)")
    print(SEP2)
    print("  [1] Iniciar sesión")
    print("  [2] Soy visitante  (no implementado)")
    print("  [3] Salir")
    print(SEP)


def flujo_login():
    cls()
    print(SEP)
    print("  Iniciar sesión — credenciales PUCP")
    print(SEP)

    intentos = 0
    while intentos < MAX_INTENTOS:

        codigo   = input("  Código PUCP : ").strip()
        password = getpass.getpass("  Contraseña  : ")

        if not codigo or not password:
            print("  [!] Ingresa código y contraseña.\n")
            continue

        # 1. Verificar bloqueo de cuenta
        if verificar_cuenta_bloqueada(codigo):
            print(SEP)
            print("  ✗ Cuenta bloqueada.")
            print("    Contacta al Administrador TI.")
            print(SEP)
            input("  Presiona Enter para volver...")
            return

        print("\n  Autenticando...", end="", flush=True)
        nombre_rol, resultado = autenticar(codigo, password)
        print()

        # ── Access-Accept ────────────────────────────────────────────────
        if nombre_rol is not None:

            # 2. Traducir rol → vlan_id
            vlan_id = VLAN_POR_ROL.get(nombre_rol)
            if vlan_id is None:
                print(f"  ✗ Rol '{nombre_rol}' no reconocido. Contacta a TI.")
                input("  Presiona Enter para volver...")
                return

            # 3. Verificar IP-MAC disponible (anti-spoofing)
            libre, motivo = verificar_ip_mac_disponible(IP_CUARENTENA, DEMO_MAC)
            if not libre:
                print(f"\n  ✗ Acceso denegado — {motivo}")
                print("    La sesión activa debe cerrarse primero.")
                input("  Presiona Enter para volver...")
                return

            # 4. Obtener id_usuario
            id_usuario = obtener_id_usuario(codigo)

            # 5. Registrar sesión — retorna id_sesion
            id_sesion = registrar_sesion(
                id_usuario, DEMO_MAC, IP_CUARENTENA,
                vlan_id, nombre_rol, SWITCH_DPID, IN_PORT
            )
            if id_sesion is None:
                print("  ✗ Error al registrar sesión. Intenta nuevamente.")
                input("  Presiona Enter para volver...")
                return

            # 6. Crear binding IP+MAC
            crear_binding(IP_CUARENTENA, DEMO_MAC, id_sesion)
            print(f"  ✓ Sesión #{id_sesion} registrada en sesiones_activas")
            print(f"  ✓ Binding IP+MAC creado  (anti-spoofing activo)")

            # 7. Resetear intentos fallidos
            resetear_intentos(codigo)

            # 8. Notificar M6
            notificar_m6(SWITCH_DPID, IN_PORT, vlan_id, DEMO_MAC)

            # 9. Pantalla de bienvenida
            pantalla_bienvenida(codigo, nombre_rol, vlan_id,
                                id_usuario, id_sesion)
            return

        # ── Access-Reject ────────────────────────────────────────────────
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
