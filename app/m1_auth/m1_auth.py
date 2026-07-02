#!/usr/bin/env python3
"""
m1_authYo.py — Núcleo de autenticación M1 — SDN PUCP
Grupo 2 | TEL354
- Sheila J 
Contiene toda la lógica de negocio (RADIUS, MySQL, M6) sin ninguna dependencia de interfaz (sin input()/print()). Las interfaces
(cli.py, web.py) llaman a las funciones autenticar(), autenticar_visitante() y cerrar_sesion() de este módulo.

Cada función retorna un dict estructurado:
  {"ok": True,  ...datos de la sesión...}
  {"ok": False, "motivo": "...", "codigo_error": "..."}
"""
import os
import time
import datetime
import tempfile
import urllib.request as _ul
import json as _js
import uuid
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
    print("[ADVERTENCIA] mysql-connector-python no instalado.")

# ── Cliente M5 (auditoría) 
from observability import (Observability,TelemetryConfig, Events)

obsConfig = TelemetryConfig(
    service_name="m1-auth",
    service_version="1.0.0",
)
obs = Observability(obsConfig)

# Configuración base 
class Config:
    # FreeRADIUS
    RADIUS_HOST   = "127.0.0.1"
    RADIUS_PORT   = 1812
    RADIUS_SECRET = b"testing123"
    NAS_IP        = "192.168.200.200"

    # MySQL
    MYSQL_HOST = "localhost"
    MYSQL_USER = "radius"
    MYSQL_PASS = "radius_pass"
    MYSQL_DB   = "radius_db"

    # M6 — Módulo Traductor
    M6_URL = "http://127.0.0.1:8080/m6/token_rol"

    MAX_INTENTOS = 3

    VLAN_CUARENTENA = 90

    # Duración fija de la sesión de visitante (en segundos)
    VISITANTE_TIMEOUT_SEG = 1800  # 30 minutos

    # MODO DE PRUEBA 
    # Pon esto en False mientras pruebas solo RADIUS + MySQL, sin M6/ONOS.
    # Cuando M6_HABILITADO=False:
    #   - No se llama a resolver_host() ni emitir_token()
    #   - Se usan mac/switch_dpid/in_port "dummy" para poder seguir
    #     probando el registro en sesiones_activas / ip_mac_binding
    M6_HABILITADO = True

    # Valores dummy usados solo cuando M6_HABILITADO = False
    MAC_DUMMY         = "00:00:00:00:00:01"
    SWITCH_DPID_DUMMY = "of:0000000000000001"
    IN_PORT_DUMMY     = 1

    SEP  = "═" * 55
    SEP2 = "─" * 55


# Conexión MySQL 
class DatabaseManager:

    def get_connection(self):
        if not MYSQL_OK:
            print("  [DB] mysql-connector no instalado.")
            return None
        try:
            return mysql.connector.connect(
                host=Config.MYSQL_HOST, user=Config.MYSQL_USER,
                password=Config.MYSQL_PASS, database=Config.MYSQL_DB,
                autocommit=False, use_pure=True, ssl_disabled=True
            )
        except mysql.connector.Error as e:
            print(f"  [DB] Error de conexión: {e}")
            return None


# Cliente RADIUS 
RADIUS_DICT = """\
ATTRIBUTE User-Name           1  string
ATTRIBUTE User-Password       2  string
ATTRIBUTE NAS-IP-Address      4  ipaddr
ATTRIBUTE NAS-Port            5  integer
ATTRIBUTE Filter-Id          11  string
ATTRIBUTE Calling-Station-Id 31  string
ATTRIBUTE Called-Station-Id  30  string
ATTRIBUTE Framed-IP-Address   8  ipaddr
ATTRIBUTE Session-Timeout    27  integer
ATTRIBUTE Acct-Status-Type   40  integer
ATTRIBUTE Acct-Session-Id    44  string
"""


class RadiusClient:

    def _build_dict(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".dict", delete=False, encoding="utf-8"
        )
        tmp.write(RADIUS_DICT)
        tmp.flush()
        d = pyrad.dictionary.Dictionary(tmp.name)
        tmp.close()
        os.unlink(tmp.name)
        return d

    def authenticate(self, codigo_pucp, password, ip_cuarentena):
        """
        Envía Access-Request a FreeRADIUS.
        Retorna (nombre_rol, session_timeout) o (None, None). session_timeout viene en segundos, tomado del atributo
        Session-Timeout (27) que FreeRADIUS devuelve en el Access-Accept. Si el atributo no viene, se usa 3600 (1h) como valor por defecto.
        """
        if not PYRAD_OK:
            print("  [RADIUS] pyrad no disponible.")
            return None, None
        try:
            cliente = pyrad.client.Client(
                server=Config.RADIUS_HOST, authport=Config.RADIUS_PORT,
                secret=Config.RADIUS_SECRET, dict=self._build_dict()
            )
            cliente.timeout = 5
            cliente.retries = 1

            paquete = cliente.CreateAuthPacket(
                code=pyrad.packet.AccessRequest, User_Name=codigo_pucp
            )
            paquete["User-Password"]     = paquete.PwCrypt(password)
            paquete["NAS-IP-Address"]    = Config.NAS_IP
            paquete["Framed-IP-Address"] = ip_cuarentena

            respuesta = cliente.SendPacket(paquete)

            if respuesta.code == pyrad.packet.AccessAccept:
                nombre_rol = None
                if 11 in respuesta:
                    nombre_rol = respuesta[11][0]
                    if isinstance(nombre_rol, bytes):
                        nombre_rol = nombre_rol.decode()

                session_timeout = 3600
                if 27 in respuesta:
                    val = respuesta[27][0]
                    session_timeout = (
                        int.from_bytes(val, "big")
                        if isinstance(val, bytes) else int(val)
                    )
                return nombre_rol, session_timeout

            return None, None

        except Exception as e:
            print(f"  [RADIUS] Error: {e}")
            return None, None

    def accounting_start(self, codigo_pucp, ip_asignada, mac, session_id=None):
        if not PYRAD_OK:
            return
        try:
            cliente = pyrad.client.Client(
                server=Config.RADIUS_HOST, acctport=1813,
                secret=Config.RADIUS_SECRET, dict=self._build_dict()
            )
            cliente.timeout = 5
            cliente.retries = 1
            sid = session_id or f"{codigo_pucp}-{int(time.time())}"

            paquete = cliente.CreateAcctPacket(
                code=pyrad.packet.AccountingRequest, User_Name=codigo_pucp
            )
            paquete["Acct-Status-Type"]   = 1
            paquete["Acct-Session-Id"]    = sid
            paquete["NAS-IP-Address"]     = Config.NAS_IP
            paquete["Framed-IP-Address"]  = ip_asignada
            paquete["Calling-Station-Id"] = mac

            cliente.SendPacket(paquete)
            print(f"  [RADIUS] ✓ Accounting-Start enviado (sid={sid})")
        except Exception as e:
            print(f"  [RADIUS] Accounting-Start error: {e}")

    def accounting_stop(self, codigo_pucp, ip_asignada, mac, session_id=None):
        if not PYRAD_OK:
            return
        try:
            cliente = pyrad.client.Client(
                server=Config.RADIUS_HOST, acctport=1813,
                secret=Config.RADIUS_SECRET, dict=self._build_dict()
            )
            cliente.timeout = 5
            cliente.retries = 1
            sid = session_id or f"{codigo_pucp}-{int(time.time())}"

            paquete = cliente.CreateAcctPacket(
                code=pyrad.packet.AccountingRequest, User_Name=codigo_pucp
            )
            paquete["Acct-Status-Type"]   = 2
            paquete["Acct-Session-Id"]    = sid
            paquete["NAS-IP-Address"]     = Config.NAS_IP
            paquete["Framed-IP-Address"]  = ip_asignada
            paquete["Calling-Station-Id"] = mac

            cliente.SendPacket(paquete)
            print(f"  [RADIUS] ✓ Accounting-Stop enviado (sid={sid})")
        except Exception as e:
            print(f"  [RADIUS] Accounting-Stop error: {e}")


#  Mapeo Rol → VLAN 
class RoleMapper:

    VLAN_POR_ROL = {
        "Visitante":              100,
        "Estudiante_Telecom":     210,
        "Estudiante_Informatica": 220,
        "Estudiante_Electronica": 230,
        "Docente":                300,
        "Admin_TI":               400,
    }

    def get_vlan_id(self, nombre_rol):
        return self.VLAN_POR_ROL.get(nombre_rol)


#  Usuarios: bloqueo, intentos, visitantes 
class UserManager:

    def __init__(self, db):
        self.db = db

    def get_id(self, codigo_pucp):
        conn = self.db.get_connection()
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
        finally:
            conn.close()

    def is_blocked(self, codigo_pucp):
        conn = self.db.get_connection()
        if not conn:
            return False
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT estado_cuenta FROM usuarios WHERE codigo_pucp = %s",
                (codigo_pucp,)
            )
            row = cur.fetchone()
            return bool(row and row["estado_cuenta"] == "BLOQUEADO")
        finally:
            conn.close()

    def increment_failed_attempt(self, codigo_pucp):
        conn = self.db.get_connection()
        if not conn:
            return 0
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT intentos_fallidos FROM usuarios WHERE codigo_pucp = %s",
                (codigo_pucp,)
            )
            row = cur.fetchone()
            if not row:
                return 0
            nuevos = row["intentos_fallidos"] + 1
            if nuevos >= Config.MAX_INTENTOS:
                cur.execute(
                    "UPDATE usuarios SET intentos_fallidos = %s, "
                    "estado_cuenta = 'BLOQUEADO', fecha_bloqueo = NOW() "
                    "WHERE codigo_pucp = %s",
                    (nuevos, codigo_pucp)
                )
            else:
                cur.execute(
                    "UPDATE usuarios SET intentos_fallidos = %s "
                    "WHERE codigo_pucp = %s",
                    (nuevos, codigo_pucp)
                )
            conn.commit()
            return nuevos
        except Exception as e:
            conn.rollback()
            print(f"  [UserManager] Error: {e}")
            return 0
        finally:
            conn.close()

    def reset_failed_attempts(self, codigo_pucp):
        conn = self.db.get_connection()
        if not conn:
            return
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE usuarios SET intentos_fallidos = 0 "
                "WHERE codigo_pucp = %s",
                (codigo_pucp,)
            )
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            conn.close()

    def registrar_visitante(self, correo, password):
        conn = self.db.get_connection()
        if not conn:
            return False
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO radcheck (username, attribute, op, value)
                VALUES (%s, 'Cleartext-Password', ':=', %s)
            """, (correo, password))
            cur.execute("""
                INSERT INTO radusergroup (username, groupname, priority)
                VALUES (%s, 'Visitante', 1)
            """, (correo,))
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            print(f"  [UserManager] Error al registrar visitante: {e}")
            return False
        finally:
            conn.close()

    def eliminar_visitante(self, correo):
        conn = self.db.get_connection()
        if not conn:
            return
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM radcheck WHERE username = %s", (correo,))
            cur.execute("DELETE FROM radusergroup WHERE username = %s", (correo,))
            conn.commit()
            print(f"  [DB] ✓ Credenciales visitante eliminadas ({correo})")
        except Exception as e:
            conn.rollback()
            print(f"  [UserManager] Error al eliminar visitante: {e}")
        finally:
            conn.close()


#  Sesiones: registro, binding, cierre 
class SessionManager:

    def __init__(self, db):
        self.db = db

    def get_session_by_usuario(self, id_usuario: int):
        """Retorna la sesión activa de un usuario si existe, o None."""
        conn = self.db.get_connection()
        if not conn:
            return None
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT id_sesion, mac_address, ip_asignada, nombre_rol, switch_dpid, in_port
                FROM sesiones_activas
                WHERE id_usuario = %s
                LIMIT 1
            """, (id_usuario,))
            return cur.fetchone()
        except Exception:
            return None
        finally:
            conn.close()

    def verify_antispoofing(self, ip, mac):
        conn = self.db.get_connection()
        if not conn:
            return True, None
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT mac_address FROM ip_mac_binding
                WHERE ip_asignada = %s AND mac_address != %s
            """, (ip, mac))
            if cur.fetchone():
                return False, f"IP {ip} ya en uso por otra MAC"

            cur.execute("""
                SELECT ip_asignada FROM ip_mac_binding
                WHERE mac_address = %s AND ip_asignada != %s
            """, (mac, ip))
            if cur.fetchone():
                return False, f"MAC {mac} ya tiene sesión con otra IP"

            return True, None
        except Exception:
            return True, None
        finally:
            conn.close()

    def register_session(self, id_usuario, mac, ip_asignada, vlan_id, nombre_rol, switch_dpid, in_port):
        conn = self.db.get_connection()
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
                    id_sesion       = LAST_INSERT_ID(id_sesion)
            """, (id_usuario, mac, ip_asignada, vlan_id, nombre_rol,
                  switch_dpid, in_port))
            conn.commit()
            id_sesion = cur.lastrowid or None
            if not id_sesion:
                cur.execute(
                    "SELECT id_sesion FROM sesiones_activas WHERE mac_address = %s",
                    (mac,)
                )
                row = cur.fetchone()
                id_sesion = row[0] if row else None
            return id_sesion
        except Exception as e:
            conn.rollback()
            print(f"  [SessionManager] Error al registrar sesión: {e}")
            return None
        finally:
            conn.close()

    def get_active_session(self, mac=None, ip_asignada=None):
        """
        Consulta de SOLO LECTURA. Busca una fila en sesiones_activas que coincida por MAC y IP. Usada por obtener_sesion_actual() para
        que cli.py pueda resumir sesión sin pedir login otra vez.
        No instala flows ni modifica nada.
        """
        conn = self.db.get_connection()
        if not conn:
            return None
        try:
            cur = conn.cursor(dictionary=True)
            filtros = []
            params = []
            if mac:
                filtros.append("s.mac_address = %s")
                params.append(mac)
            if ip_asignada:
                filtros.append("s.ip_asignada = %s")
                params.append(ip_asignada)
            if not filtros:
                return None

            cur.execute(f"""
                SELECT s.id_sesion, s.id_usuario, s.mac_address AS mac,
                       s.ip_asignada, s.vlan_id, s.nombre_rol,
                       s.switch_dpid, s.in_port, s.login_timestamp,
                       u.codigo_pucp
                FROM sesiones_activas s
                LEFT JOIN usuarios u ON s.id_usuario = u.id_usuario
                WHERE {' AND '.join(filtros)}
                ORDER BY s.login_timestamp DESC
                LIMIT 1
            """, tuple(params))
            sesion = cur.fetchone()
            if sesion and not sesion.get("codigo_pucp"):
                sesion["codigo_pucp"] = "VISITANTE"
            return sesion
        except Exception as e:
            print(f"  [SessionManager] Error al consultar sesion activa: {e}")
            return None
        finally:
            conn.close()

    def create_binding(self, ip, mac, id_usuario, switch_dpid, in_port, id_sesion):
        conn = self.db.get_connection()
        if not conn:
            return
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO ip_mac_binding
                    (ip_asignada, mac_address, id_usuario, switch_dpid, in_port, id_sesion)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    switch_dpid = VALUES(switch_dpid),
                    in_port     = VALUES(in_port),
                    id_sesion   = VALUES(id_sesion)
            """, (ip, mac, id_usuario, switch_dpid, in_port, id_sesion))
            conn.commit()
            print(f"  ✓ Binding creado: {ip} ↔ {mac}")
        except Exception as e:
            conn.rollback()
            print(f"  [SessionManager] Error al crear binding: {e}")
        finally:
            conn.close()

    def close_session(self, mac, id_usuario):
        conn = self.db.get_connection()
        if not conn:
            return None
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT s.id_sesion, s.id_usuario, s.mac_address,
                       s.ip_asignada, s.vlan_id, s.nombre_rol,
                       s.switch_dpid, s.in_port, s.login_timestamp
                FROM sesiones_activas s
                WHERE s.mac_address = %s AND s.id_usuario = %s
            """, (mac, id_usuario))
            sesion = cur.fetchone()
            if not sesion:
                return None

            cur.execute("""
                INSERT INTO historial_sesiones
                    (id_sesion_orig, id_usuario, mac_address,
                     ip_asignada, vlan_id, nombre_rol,
                     switch_dpid, in_port, login_timestamp,
                     logout_timestamp, motivo_cierre)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(),
                        'LOGOUT_VOLUNTARIO')
            """, (
                sesion["id_sesion"],   sesion["id_usuario"],
                sesion["mac_address"], sesion["ip_asignada"],
                sesion["vlan_id"],     sesion["nombre_rol"],
                sesion["switch_dpid"], sesion["in_port"],
                sesion["login_timestamp"]
            ))

            cur.execute(
                "DELETE FROM ip_mac_binding WHERE mac_address = %s", (mac,)
            )
            cur.execute(
                "DELETE FROM sesiones_activas WHERE id_sesion = %s",
                (sesion["id_sesion"],)
            )
            conn.commit()

            # Notificar a M6 para eliminar flows — desactivado en modo prueba
            if Config.M6_HABILITADO and sesion and Config.M6_URL:
                # --- INICIO bloque M6 real (comentado/desactivado en modo prueba) ---
                try:
                    m6_base = Config.M6_URL.rsplit("/m6/", 1)[0]
                    _body = _js.dumps({"mac": sesion["mac_address"]}).encode("utf-8")
                    _req = _ul.Request(
                        f"{m6_base}/m6/cerrar_sesion", data=_body,
                        headers={"Content-Type": "application/json"}
                    )
                    _ul.urlopen(_req, timeout=3)
                    print(f"  [M1→M6] cerrar_sesion notificado — " f"mac={sesion['mac_address']}")
                except Exception as e:
                    print(f"  [M1→M6] Error al notificar M6: {e}")
                # --- FIN bloque M6 real ---
            elif sesion:
                print("  [MODO PRUEBA] M6 deshabilitado — no se notifica cierre de sesión")

            return sesion
        except Exception as e:
            conn.rollback()
            print(f"  [SessionManager] Error al cerrar sesión: {e}")
            return None
        finally:
            conn.close()

    def get_allowed_resources(self, nombre_rol):
        conn = self.db.get_connection()
        if not conn:
            return []
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT rec.nombre_recurso, srv.ip_servidor AS ip_dst,
                       rec.puerto, rec.protocolo, p.prioridad
                FROM politicas_rbac p
                JOIN roles_facultad rf ON p.id_rol     = rf.id_rol
                JOIN recursos      rec ON p.id_recurso = rec.id_recurso
                JOIN servidores    srv ON rec.id_servidor = srv.id_servidor
                WHERE rf.nombre_rol = %s AND p.activo = 1
                ORDER BY srv.ip_servidor, rec.puerto
            """, (nombre_rol,))
            return cur.fetchall()
        except Exception as e:
            print(f"  [SessionManager] Error al obtener recursos: {e}")
            return []
        finally:
            conn.close()

    def get_session_resources(self, id_usuario, nombre_rol):
        """
        Combina T2 (politicas_rbac, por rol) y T3 (politicas_temporales, excepciones del id_usuario que no han expirado). Solo lectura.
        Cada fila viene marcada con 'tabla': 'T2' o 'T3' para que la  interfaz (cli.py) pueda mostrarlas en secciones separadas.
        """
        conn = self.db.get_connection()
        if not conn:
            return []
        try:
            cur = conn.cursor(dictionary=True)
            recursos = []

            cur.execute("""
                SELECT rec.nombre_recurso, srv.ip_servidor AS ip_dst,
                       rec.puerto, rec.protocolo, p.prioridad,
                       'T2' AS tabla, 'Rol principal' AS origen,
                       NULL AS razon
                FROM politicas_rbac p
                JOIN roles_facultad rf ON p.id_rol = rf.id_rol
                JOIN recursos rec ON p.id_recurso = rec.id_recurso
                JOIN servidores srv ON rec.id_servidor = srv.id_servidor
                WHERE rf.nombre_rol = %s AND p.activo = 1
                ORDER BY srv.ip_servidor, rec.puerto
            """, (nombre_rol,))
            recursos.extend(cur.fetchall())

            if id_usuario and int(id_usuario) > 0:
                cur.execute("""
                    SELECT rec.nombre_recurso, srv.ip_servidor AS ip_dst,
                           rec.puerto, rec.protocolo, pt.prioridad,
                           'T3' AS tabla, 'Excepcion' AS origen,
                           pt.razon
                    FROM politicas_temporales pt
                    JOIN recursos rec ON pt.id_recurso = rec.id_recurso
                    JOIN servidores srv ON rec.id_servidor = srv.id_servidor
                    WHERE pt.id_usuario = %s
                      AND pt.allow = TRUE
                      AND pt.activo = 1
                      AND pt.expiration > NOW()
                    ORDER BY srv.ip_servidor, rec.puerto
                """, (id_usuario,))
                recursos.extend(cur.fetchall())

            return recursos
        except Exception as e:
            print(f"  [SessionManager] Error al obtener recursos de sesion: {e}")
            return []
        finally:
            conn.close()


# Comunicación con M6 
class TokenEmitter:

    def _llamar_m6(self, endpoint, body):
        try:
            m6_base = Config.M6_URL.rsplit("/m6/", 1)[0]
            _body = _js.dumps(body).encode("utf-8")
            _req = _ul.Request(
                f"{m6_base}{endpoint}", data=_body,
                headers={"Content-Type": "application/json"}
            )
            with _ul.urlopen(_req, timeout=12) as _resp:
                if _resp.status == 200:
                    return _js.loads(_resp.read())
        except Exception as e:
            print(f"  [M1→M6] Error en {endpoint}: {e}")
        return None

    def resolver_host(self, ip_asignada):
        """Primera llamada — M6 consulta ONOS, no instala flows."""
        resultado = self._llamar_m6("/m6/resolver_host",  {"ip_asignada": ip_asignada})
        if resultado:
            print(f"  [M1→M6] ✓ Host resuelto — mac={resultado.get('mac')}")
            return resultado
        print("  [M1→M6] M6 no disponible — host no resuelto")
        return None

    def emitir_token(self, codigo_pucp, nombre_rol, vlan_id,
                     ip_asignada, mac, switch_dpid, in_port):
        """Segunda llamada — instala flows. Solo tras registrar en DB."""
        token = {
            "codigo_pucp": codigo_pucp, "nombre_rol": nombre_rol,
            "vlan_id": vlan_id, "ip_asignada": ip_asignada,
            "mac": mac, "switch_dpid": switch_dpid, "in_port": in_port
        }
        resultado = self._llamar_m6("/m6/token_rol", token)
        if resultado:
            print("  [M1→M6] ✓ Token emitido — flows instalados en ONOS")
            return True
        print("  [M1→M6] Token no emitido (M6 no disponible — modo simulado)")
        return False


# ─── Componentes compartidos (singleton simple por proceso) ──────────────────
_db       = DatabaseManager()
_radius   = RadiusClient()
_roles    = RoleMapper()
_users    = UserManager(_db)
_sessions = SessionManager(_db)
_tokens   = TokenEmitter()


def _serializar_sesion(sesion):
    """Convierte una fila de sesion (dict de MySQL) en un dict JSON-friendly, agregando 'mac', 'es_visitante' e 'idle_timeout_seg' para consumo
    directo por cli.py/web.py."""
    if not sesion:
        return None
    data = dict(sesion)
    ts = data.get("login_timestamp")
    if hasattr(ts, "isoformat"):
        data["login_timestamp"] = ts.isoformat(sep=" ")
    data["mac"] = data.get("mac") or data.get("mac_address")
    data["es_visitante"] = int(data.get("id_usuario") or 0) == 0
    data["idle_timeout_seg"] = 600
    return data


def _resolver_host_para_ip(ip_asignada):
    """Resuelve mac/switch_dpid/in_port para una IP, vía M6 si está habilitado, o con los valores dummy en modo prueba."""
    if Config.M6_HABILITADO:
        host = _tokens.resolver_host(ip_asignada)
        if not host:
            return None
        return host
    return {
        "mac": Config.MAC_DUMMY,
        "switch_dpid": Config.SWITCH_DPID_DUMMY,
        "in_port": Config.IN_PORT_DUMMY,
    }


def obtener_sesion_actual(ip_asignada: str) -> dict:
    """
    Resuelve la MAC de la IP dada y consulta si existe una sesión activa para ese host. Solo lectura. Usado por cli.py al iniciar/reiniciar
    para resumir sesión sin pedir login otra vez.
    """
    host = _resolver_host_para_ip(ip_asignada)
    if host:
        sesion = _sessions.get_active_session(
            mac=host.get("mac"),
            ip_asignada=ip_asignada,
        )
    else:
        sesion = _sessions.get_active_session(ip_asignada=ip_asignada)

    if not sesion:
        return {"ok": True, "activa": False}

    return {
        "ok": True,
        "activa": True,
        "sesion": _serializar_sesion(sesion),
    }


# ─── Funciones núcleo (sin input()/print() de interfaz) ───────────────────────

def autenticar(codigo_pucp: str, password: str, ip_asignada: str) -> dict:
    """
    Ejecuta el flujo completo de autenticación M1 para un usuario normal.

    ip_asignada debe venir resuelta por la interfaz que llama:
      - cli.py:  os.environ.get("SSH_CLIENT") o input manual
      - web.py:  request.remote_addr

    Retorna un dict:
      {"ok": True,  "codigo_pucp", "nombre_rol", "vlan_id",
       "ip_asignada", "mac", "id_sesion", "session_timeout"}
      {"ok": False, "motivo": "...", "codigo_error": "..."}

    session_timeout (en segundos) viene del atributo Session-Timeout que
    FreeRADIUS devuelve en el Access-Accept (configurado por rol en
    radgroupreply / radcheck). El cliente (cli.py/web.py) lo usa para
    mostrar la cuenta regresiva real hasta el cierre automático de sesión.
    """
    if not codigo_pucp or not password:
        return {"ok": False, "motivo": "Faltan credenciales.", "codigo_error": "CREDENCIALES_VACIAS"}

    if _users.is_blocked(codigo_pucp):
        return {"ok": False, "motivo": "Cuenta bloqueada. Contacta al Administrador TI.", "codigo_error": "CUENTA_BLOQUEADA"}

    context_id = str(uuid.uuid4())
    obs.update_context(context_id=context_id, host_ip=ip_asignada, user_code=codigo_pucp)
    with obs.span("auth.authenticate"):
        obs.event(
            Events.AUTH_LOGIN_STARTED,
            attributes={"user.credential": codigo_pucp},
        )

        # ── M5: medir latencia RADIUS ─────────────────────────────
        t0 = time.time()
        nombre_rol, session_timeout = _radius.authenticate(codigo_pucp, password, ip_asignada)
        duracion_ms = int((time.time() - t0) * 1000)
        # ─────────────────────────────────────────────────────────

        if nombre_rol is None:
            total = _users.increment_failed_attempt(codigo_pucp)
            restantes = Config.MAX_INTENTOS - total
            if total >= Config.MAX_INTENTOS:
                # ── M5: cuenta bloqueada ──────────────────────────
                obs.event(
                    Events.AUTH_ACCOUNT_LOCKED,
                    attributes={
                        "auth.duration.ms": duracion_ms,
                        "auth.failed_attempts": total,
                        "auth.cause": "BLOQUEADO_POR_INTENTOS",
                    },
                )
                # ─────────────────────────────────────────────────
                return {"ok": False,
                        "motivo": "Credenciales inválidas. Cuenta bloqueada por 3 intentos fallidos. Contacta al Administrador TI.", "codigo_error": "BLOQUEADO_POR_INTENTOS"}
            # ── M5: login fallido ─────────────────────────────────
            #_emitir_evento_m5("login_fallido", usuario=codigo_pucp,ip=ip_asignada, duracion_ms=duracion_ms, detalle={"intentos_restantes": restantes})
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "auth.duration.ms": duracion_ms,
                    "auth.remaining_attempts": restantes,
                    "auth.cause": "CREDENCIALES_INVALIDAS",
                },
            )
            # ─────────────────────────────────────────────────────
            return {"ok": False,
                    "motivo": f"Credenciales inválidas. ({restantes} intento(s) restante(s))",
                    "codigo_error": "CREDENCIALES_INVALIDAS", "intentos_restantes": restantes}

        vlan_id = _roles.get_vlan_id(nombre_rol)
        if vlan_id is None:
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "auth.duration.ms": duracion_ms,
                    "auth.role": nombre_rol,
                    "auth.cause": "ROL_NO_RECONOCIDO",
                },
            )
            return {"ok": False, "motivo": f"Rol '{nombre_rol}' no reconocido.", "codigo_error": "ROL_NO_RECONOCIDO"}

        id_usuario = _users.get_id(codigo_pucp)
        if not id_usuario:
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "auth.duration.ms": duracion_ms,
                    "user.credential": codigo_pucp,
                    "auth.cause": "USUARIO_NO_EXISTE",
                },
            )
            return {"ok": False, "motivo": "Usuario no encontrado en base de datos.", "codigo_error": "USUARIO_NO_EXISTE"}

        obs.update_context(user_id=id_usuario, user_role=nombre_rol)

        sesion_existente = _sessions.get_session_by_usuario(id_usuario) 
        # ── Resolución de host (MAC, switch, puerto) ─────────────────────────────
        # En modo de prueba (M6_HABILITADO=False) se omite la llamada real a M6
        # y se usan valores dummy, para poder seguir probando RADIUS + MySQL
        # sin depender de que M6/ONOS estén corriendo.
        if Config.M6_HABILITADO:
            # --- INICIO bloque M6 real ---
            host = _tokens.resolver_host(ip_asignada)
            if not host:
                obs.event(
                    Events.AUTH_LOGIN_FAILED,
                    attributes={
                        "auth.duration.ms": duracion_ms,
                        "network.ip": ip_asignada,
                        "auth.cause": "HOST_NO_RESUELTO",
                    },
                )
                return {"ok": False, "motivo": "No se pudo resolver el host en ONOS.",  "codigo_error": "HOST_NO_RESUELTO"}
            mac, switch_dpid, in_port = host["mac"], host["switch_dpid"], host["in_port"]
            # --- FIN bloque M6 real ---
        else:
            print("  [MODO PRUEBA] M6 deshabilitado — usando mac/switch/puerto dummy")
            mac         = Config.MAC_DUMMY
            switch_dpid = Config.SWITCH_DPID_DUMMY
            in_port     = Config.IN_PORT_DUMMY

        libre, motivo = _sessions.verify_antispoofing(ip_asignada, mac)
        if not libre:
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "auth.duration.ms": duracion_ms,
                    "network.ip": ip_asignada,
                    "network.mac": mac,
                    "auth.cause": "ANTISPOOFING",
                },
            )
            return {"ok": False, "motivo": f"Anti-spoofing: {motivo}",  "codigo_error": "ANTISPOOFING"}

        id_sesion = _sessions.register_session(
            id_usuario, mac, ip_asignada, vlan_id, nombre_rol, switch_dpid, in_port
        )
        if id_sesion is None:
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "auth.duration.ms": duracion_ms,
                    "network.ip": ip_asignada,
                    "network.mac": mac,
                    "network.vlan_id": vlan_id,
                    "network.switch_dpid": switch_dpid,
                    "network.in_port": in_port,
                    "auth.cause": "ERROR_REGISTRO_SESION",
                },
            )
            return {"ok": False, "motivo": "Error al registrar sesión en base de datos.", "codigo_error": "ERROR_REGISTRO_SESION"}

        obs.update_context(session_id=id_sesion)

        _sessions.create_binding(ip_asignada, mac, id_usuario, switch_dpid, in_port, id_sesion)
        _users.reset_failed_attempts(codigo_pucp)
        _radius.accounting_start(codigo_pucp, ip_asignada, mac)

        obs.event(
            Events.AUTH_SESSION_STARTED,
            attributes={
                "auth.duration.ms": duracion_ms,
                "network.ip": ip_asignada,
                "network.mac": mac,
                "network.vlan_id": vlan_id,
                "network.switch_dpid": switch_dpid,
                "network.in_port": in_port,
            },
        )

        # Segunda llamada a M6 — ya con sesión confirmada en DB, instala flows.
        if Config.M6_HABILITADO:
            # --- INICIO bloque M6 real ---
            _tokens.emitir_token(codigo_pucp, nombre_rol, vlan_id, ip_asignada, mac, switch_dpid, in_port)
            # --- FIN bloque M6 real ---
        else:
            print("  [MODO PRUEBA] M6 deshabilitado — no se emite token (no se instalan flows en ONOS)")

        # ── M5: login exitoso ─────────────────────────────────────
        obs.event(
            Events.AUTH_LOGIN_SUCCESS,
            attributes={
                "auth.duration.ms": duracion_ms,
            },
        )        

        return {
            "ok": True,
            "codigo_pucp": codigo_pucp,
            "nombre_rol": nombre_rol,
            "vlan_id": vlan_id,
            "ip_asignada": ip_asignada,
            "mac": mac,
            "id_usuario": id_usuario,
            "id_sesion": id_sesion,
            "session_timeout": session_timeout,
        }


def autenticar_visitante(correo: str, password: str, ip_asignada: str) -> dict:
    """
    Ejecuta el flujo de acceso temporal de visitante.
    Mismo contrato de retorno que autenticar(), agregando
    "session_timeout" fijo (Config.VISITANTE_TIMEOUT_SEG = 1800s = 30 min),
    ya que el visitante no tiene Session-Timeout configurado en RADIUS,
    su límite de tiempo es una regla de negocio fija del sistema.
    """
    if not correo or not password:
        return {"ok": False, "motivo": "Ingresa correo y contraseña.", "codigo_error": "CREDENCIALES_VACIAS"}

    context_id = str(uuid.uuid4())
    obs.update_context(context_id=context_id, host_ip=ip_asignada, user_code=correo)
    with obs.span("auth.authenticate"):
        obs.event(
            Events.AUTH_LOGIN_STARTED,
            attributes={"user.correo": correo, "user.visitante": True},
        )

        ok = _users.registrar_visitante(correo, password)
        if not ok:
            obs.event(
                Events.AUTH_REGISTER_FAILED,
                attributes={
                    "auth.cause": "ERROR_REGISTRO_VISITANTE",
                    "user.correo": correo,
                    "user.visitante": True,
                },
            )
            return {"ok": False, "motivo": "No se pudo registrar el visitante.",   "codigo_error": "ERROR_REGISTRO_VISITANTE"}

        nombre_rol, _ = _radius.authenticate(correo, password, ip_asignada)
        if nombre_rol is None:
            _users.eliminar_visitante(correo)
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "auth.cause": "CREDENCIALES_INVALIDAS",
                    "user.correo": correo,
                    "user.visitante": True,
                    "radius.response": "Access-Reject",
                },
            )
            return {"ok": False, "motivo": "FreeRADIUS rechazó las credenciales.", "codigo_error": "CREDENCIALES_INVALIDAS"}

        vlan_id = _roles.get_vlan_id(nombre_rol)
        if vlan_id is None:
            _users.eliminar_visitante(correo)
            return {"ok": False, "motivo": f"Rol '{nombre_rol}' no reconocido.",  "codigo_error": "ROL_NO_RECONOCIDO"}

        obs.update_context(user_role=nombre_rol)

        # Resolución de host — mismo criterio que autenticar() (ver arriba)
        if Config.M6_HABILITADO:
            # --- INICIO bloque M6 real ---
            host = _tokens.resolver_host(ip_asignada)
            if not host:
                obs.event(
                    Events.AUTH_LOGIN_FAILED,
                    attributes={
                        "auth.role": nombre_rol,
                        "user.correo": correo,
                        "user.visitante": True,
                        "auth.cause": "HOST_NO_RESUELTO",
                    },
                )
                _users.eliminar_visitante(correo)
                return {"ok": False, "motivo": "No se pudo resolver el host en ONOS.",   "codigo_error": "HOST_NO_RESUELTO"}
            mac, switch_dpid, in_port = host["mac"], host["switch_dpid"], host["in_port"]
            # --- FIN bloque M6 real ---
        else:
            print("  [MODO PRUEBA] M6 deshabilitado — usando mac/switch/puerto dummy")
            mac         = Config.MAC_DUMMY
            switch_dpid = Config.SWITCH_DPID_DUMMY
            in_port     = Config.IN_PORT_DUMMY

        libre, motivo = _sessions.verify_antispoofing(ip_asignada, mac)
        if not libre:
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "user.correo": correo,
                    "user.visitante": True,
                    "auth.cause": "ANTISPOOFING",
                },
            )
            _users.eliminar_visitante(correo)
            return {"ok": False, "motivo": f"Anti-spoofing: {motivo}", "codigo_error": "ANTISPOOFING"}

        # id_usuario=0 reservado para visitantes (no tienen fila en `usuarios`)
        id_sesion = _sessions.register_session(
            0, mac, ip_asignada, vlan_id, nombre_rol, switch_dpid, in_port
        )
        if id_sesion is None:
            _users.eliminar_visitante(correo)
            obs.event(
                Events.AUTH_LOGIN_FAILED,
                attributes={
                    "user.correo": correo,
                    "user.visitante": True,
                    "network.ip": ip_asignada,
                    "network.mac": mac,
                    "network.vlan_id": vlan_id,
                    "network.switch_dpid": switch_dpid,
                    "network.in_port": in_port,
                    "auth.cause": "ERROR_REGISTRO_SESION",
                },
            )
            return {"ok": False, "motivo": "No se pudo registrar la sesión.",  "codigo_error": "ERROR_REGISTRO_SESION"}

        obs.update_context(session_id=id_sesion)

        _sessions.create_binding(ip_asignada, mac, 0, switch_dpid, in_port, id_sesion)
        _radius.accounting_start(correo, ip_asignada, mac)

        obs.event(
                Events.AUTH_SESSION_STARTED,
                attributes={
                    "user.correo": correo,
                    "user.visitante": True,
                    "network.ip": ip_asignada,
                    "network.mac": mac,
                    "network.vlan_id": vlan_id,
                    "network.switch_dpid": switch_dpid,
                    "network.in_port": in_port,
                },
            )

        # Emisión de token a M6 — desactivada en modo prueba (ver autenticar())
        if Config.M6_HABILITADO:
            # --- INICIO bloque M6 real ---
            _tokens.emitir_token(correo, nombre_rol, vlan_id, ip_asignada, mac, switch_dpid, in_port)
            # --- FIN bloque M6 real ---
        else:
            print("  [MODO PRUEBA] M6 deshabilitado — no se emite token")

        # ── M5: login visitante exitoso ─────────────────────────────────────
            obs.event(
                Events.AUTH_LOGIN_SUCCESS,
                attributes={
                    "user.correo": correo,
                    "user.visitante": True,
                },
            )  

        return {
            "ok": True,
            "correo": correo,
            "nombre_rol": nombre_rol,
            "vlan_id": vlan_id,
            "ip_asignada": ip_asignada,
            "mac": mac,
            "id_sesion": id_sesion,
            "es_visitante": True,
            "session_timeout": Config.VISITANTE_TIMEOUT_SEG,
        }


def cerrar_sesion(mac: str, id_usuario: int, codigo_pucp: str = None, ip_asignada: str = None, es_visitante: bool = False) -> dict:
    """
    Cierra una sesión activa (normal o visitante).
    Retorna {"ok": True/False, "motivo": "..."}.
    """

    context_id = str(uuid.uuid4())
    obs.update_context(context_id=context_id, host_ip=ip_asignada, user_code=codigo_pucp, user_id=id_usuario)
    with obs.span("auth.authenticate"):
        obs.event(
            Events.AUTH_LOGOUT,
            attributes={"user.visitante": es_visitante, "network.host.mac": mac, "network.host.ip": ip_asignada},
        )

        sesion = _sessions.close_session(mac, id_usuario)
        if not sesion:
            return {"ok": False, "motivo": "No se encontró sesión activa."}

        if codigo_pucp and ip_asignada:
            _radius.accounting_stop(codigo_pucp, ip_asignada, mac)

        if es_visitante and codigo_pucp:
            _users.eliminar_visitante(codigo_pucp)
            
        # ── M5: logout ────────────────────────────────────────────
        obs.event(
            Events.AUTH_SESSION_ENDED,
            attributes={
                "auth.role": sesion.get("nombre_rol"),
                "user.visitante": es_visitante,
                "auth.login_timestamp": sesion.get("login_timestamp") if sesion.get("login_timestamp") else None,
            },
        )

        return {"ok": True, "motivo": "Sesión cerrada correctamente."}


def obtener_recursos_permitidos(nombre_rol: str) -> list:
    """Lista de recursos (ALLOW) permitidos para un rol, leídos directamente
    de politicas_rbac/recursos/servidores. Es solo lectura — no instala
    flows ni modifica nada, únicamente informa al usuario qué tiene
    acceso permitido según su rol."""
    return _sessions.get_allowed_resources(nombre_rol)


def obtener_recursos_sesion(ip_asignada: str) -> dict:
    """
    Devuelve T2+T3 combinados para la sesión activa resuelta por IP. Solo lectura. Si no hay sesión activa, responde ok=false.
    """
    estado = obtener_sesion_actual(ip_asignada)
    if not estado.get("activa"):
        return {"ok": False, "motivo": "No hay sesion activa."}

    sesion = estado["sesion"]
    recursos = _sessions.get_session_resources(
        sesion.get("id_usuario"),
        sesion.get("nombre_rol"),
    )
    return {
        "ok": True,
        "sesion": sesion,
        "recursos": recursos,
    }
    
    
# ════════════════════════════════════════════════════════════════════════
#  JP / Multi-rol — postulaciones, aprobacion, revocacion
# ════════════════════════════════════════════════════════════════════════
#
# Reglas confirmadas:
#   - codigo_pucp del solicitante siempre viene de la sesion activa.
#   - JP de la propia carrera -> T3 solo notas. JP de otra carrera -> T3
#     cursos de esa carrera + notas.
#   - Un usuario solo tiene una solicitud viva (PENDIENTE o APROBADA) a la
#     vez. Nueva postulacion aprobada revoca automaticamente la APROBADA
#     previa (si existia).
#   - Admin_TI puede revocar manualmente una APROBADA.
#   - Ciclo: PENDIENTE -> APROBADA/RECHAZADA ; APROBADA -> REVOCADA
# ════════════════════════════════════════════════════════════════════════
 
RECURSOS_CURSOS_POR_ROL_JP = {
    3: [3, 4],   # Estudiante_Telecom      -> cursos_telecom_http/https
    4: [5, 6],   # Estudiante_Informatica  -> cursos_info_http/https
    5: [7, 8],   # Estudiante_Electronica  -> cursos_electro_http/https
}
RECURSOS_NOTAS_JP = [9, 10]  # notas_http, notas_https
 
 
def _jp_nombre_rol_a_id(nombre_rol: str):
    conn = _db.get_connection()
    if not conn:
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id_rol FROM roles_facultad WHERE nombre_rol = %s", (nombre_rol,))
        row = cur.fetchone()
        return row["id_rol"] if row else None
    finally:
        conn.close()
 
 
def _jp_solicitud_viva_existente(id_usuario: int):
    conn = _db.get_connection()
    if not conn:
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT s.id_solicitud, s.id_rol_facultad, s.estado, rf.nombre_rol AS nombre_rol_facultad
            FROM solicitudes_jp s
            JOIN roles_facultad rf ON s.id_rol_facultad = rf.id_rol
            WHERE s.id_usuario = %s AND s.estado IN ('PENDIENTE', 'APROBADA')
            ORDER BY s.fecha_solicitud DESC LIMIT 1
        """, (id_usuario,))
        return cur.fetchone()
    finally:
        conn.close()
 
 
def _jp_recursos_para(id_usuario: int, id_rol_facultad_jp: int) -> list:
    conn = _db.get_connection()
    if not conn:
        return list(RECURSOS_NOTAS_JP)
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT rf.id_rol FROM sesiones_activas s
            JOIN roles_facultad rf ON s.nombre_rol = rf.nombre_rol
            WHERE s.id_usuario = %s ORDER BY s.login_timestamp DESC LIMIT 1
        """, (id_usuario,))
        row = cur.fetchone()
        rol_propio_id = row["id_rol"] if row else None
    finally:
        conn.close()
    if rol_propio_id == id_rol_facultad_jp:
        return list(RECURSOS_NOTAS_JP)
    cursos = RECURSOS_CURSOS_POR_ROL_JP.get(id_rol_facultad_jp, [])
    return cursos + RECURSOS_NOTAS_JP
 
 
def _jp_insertar_t3(id_usuario: int, ids_recurso: list, razon: str, expiration: str) -> bool:
    conn = _db.get_connection()
    if not conn:
        return False
    try:
        cur = conn.cursor()
        for id_recurso in ids_recurso:
            # Trae el ancho_banda_default del recurso en vez de un valor fijo
            cur.execute("SELECT ancho_banda_default FROM recursos WHERE id_recurso = %s", (id_recurso,))
            row = cur.fetchone()
            ancho_banda = row[0] if row else None  # NULL -> usa el DEFAULT '50Mbps' de la tabla

            cur.execute("""
                INSERT INTO politicas_temporales
                    (id_usuario, id_recurso, allow, razon, ancho_banda, expiration)
                VALUES (%s, %s, TRUE, %s, %s, %s)
            """, (id_usuario, id_recurso, razon, ancho_banda, expiration))
            # prioridad se omite -> usa el DEFAULT 800 de la tabla
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"  [JP] Error al insertar T3: {e}")
        return False
    finally:
        conn.close()
 
def _jp_eliminar_t3(id_usuario: int, ids_recurso: list):
    conn = _db.get_connection()
    if not conn:
        return
    try:
        cur = conn.cursor()
        placeholders = ",".join(["%s"] * len(ids_recurso))
        cur.execute(f"""
            DELETE FROM politicas_temporales
            WHERE id_usuario = %s AND id_recurso IN ({placeholders}) AND razon LIKE 'JP%%'
        """, (id_usuario, *ids_recurso))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  [JP] Error al eliminar T3: {e}")
    finally:
        conn.close()
 
 
def _jp_set_estado(id_solicitud: int, nuevo_estado: str, id_admin: int, motivo: str = None):
    conn = _db.get_connection()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE solicitudes_jp SET estado = %s, fecha_resolucion = NOW(),
                id_admin_resuelve = %s, motivo_revocacion = %s WHERE id_solicitud = %s
        """, (nuevo_estado, id_admin, motivo, id_solicitud))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  [JP] Error al actualizar estado: {e}")
    finally:
        conn.close()
 
 
def solicitar_jp(ip_asignada: str, nombre_rol_facultad_jp: str) -> dict:
    """
    Registra postulacion a JP. codigo_pucp se resuelve de la sesion activa.
    nombre_rol_facultad_jp: 'Estudiante_Telecom' | 'Estudiante_Informatica' | 'Estudiante_Electronica'
    """
    estado = obtener_sesion_actual(ip_asignada)
    if not estado.get("activa"):
        return {"ok": False, "motivo": "No hay sesion activa.", "codigo_error": "SIN_SESION"}
    sesion = estado["sesion"]
    id_usuario = sesion.get("id_usuario")
    if not id_usuario or int(id_usuario) == 0:
        return {"ok": False, "motivo": "Los visitantes no pueden postular a JP.",
                "codigo_error": "VISITANTE_NO_ELEGIBLE"}
    id_rol_jp = _jp_nombre_rol_a_id(nombre_rol_facultad_jp)
    if id_rol_jp is None or id_rol_jp not in RECURSOS_CURSOS_POR_ROL_JP:
        return {"ok": False, "motivo": f"Carrera '{nombre_rol_facultad_jp}' no valida para JP.", "codigo_error": "CARRERA_INVALIDA"}
    existente = _jp_solicitud_viva_existente(id_usuario)
    if existente:
        return {"ok": False, "motivo": f"Ya tienes una solicitud {existente['estado']} para JP de "
                f"{existente['nombre_rol_facultad']}. Debe resolverse antes de postular de nuevo.", "codigo_error": "SOLICITUD_YA_EXISTE", "solicitud_existente": existente}
    conn = _db.get_connection()
    if not conn:
        return {"ok": False, "motivo": "Error de conexion a base de datos.", "codigo_error": "ERROR_DB"}
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO solicitudes_jp (id_usuario, id_rol_facultad, estado) " "VALUES (%s, %s, 'PENDIENTE')", (id_usuario, id_rol_jp))
        conn.commit()
        return {"ok": True, "id_solicitud": cur.lastrowid, "estado": "PENDIENTE", "carrera_jp": nombre_rol_facultad_jp}
    except Exception as e:
        conn.rollback()
        return {"ok": False, "motivo": f"Error al registrar solicitud: {e}", "codigo_error": "ERROR_REGISTRO"}
    finally:
        conn.close()
 
 
def historial_jp(ip_asignada: str) -> dict:
    estado = obtener_sesion_actual(ip_asignada)
    if not estado.get("activa"):
        return {"ok": False, "motivo": "No hay sesion activa."}
    id_usuario = estado["sesion"].get("id_usuario")
    conn = _db.get_connection()
    if not conn:
        return {"ok": False, "motivo": "Error de conexion a base de datos."}
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT s.id_solicitud, rf.nombre_rol AS carrera_jp, s.estado, s.fecha_solicitud,
                   s.fecha_resolucion, s.motivo_revocacion
            FROM solicitudes_jp s
            JOIN roles_facultad rf ON s.id_rol_facultad = rf.id_rol
            WHERE s.id_usuario = %s ORDER BY s.fecha_solicitud DESC
        """, (id_usuario,))
        return {"ok": True, "solicitudes": cur.fetchall()}
    finally:
        conn.close()
 
 
def listar_solicitudes_jp(filtro_estado: str = "PENDIENTE") -> dict:
    """Uso exclusivo de Admin_TI. filtro_estado=None lista todas."""
    conn = _db.get_connection()
    if not conn:
        return {"ok": False, "motivo": "Error de conexion a base de datos."}
    try:
        cur = conn.cursor(dictionary=True)
        query = """
            SELECT s.id_solicitud, u.codigo_pucp, s.id_usuario, rf.nombre_rol AS carrera_jp,
                   s.estado, s.fecha_solicitud, s.fecha_resolucion
            FROM solicitudes_jp s
            JOIN usuarios u ON s.id_usuario = u.id_usuario
            JOIN roles_facultad rf ON s.id_rol_facultad = rf.id_rol
        """
        params = ()
        if filtro_estado:
            query += " WHERE s.estado = %s"
            params = (filtro_estado,)
        query += " ORDER BY s.fecha_solicitud ASC"
        cur.execute(query, params)
        return {"ok": True, "solicitudes": cur.fetchall()}
    finally:
        conn.close()
 
 
def resolver_solicitud_jp(id_solicitud: int, id_admin: int, accion: str, expiration: str = None, motivo: str = None) -> dict:
        """
        Uso exclusivo de Admin_TI. accion: 'APROBAR' | 'RECHAZAR' | 'REVOCAR'
        expiration: requerido solo si accion='APROBAR'. Formato 'YYYY-MM-DD HH:MM:SS'.
        """
        conn = _db.get_connection()
        if not conn:
            return {"ok": False, "motivo": "Error de conexion a base de datos."}
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id_solicitud, id_usuario, id_rol_facultad, estado "
                    "FROM solicitudes_jp WHERE id_solicitud = %s", (id_solicitud,))
            sol = cur.fetchone()
        finally:
            conn.close()

        if not sol:
            return {"ok": False, "motivo": "Solicitud no encontrada.", "codigo_error": "NO_ENCONTRADA"}

        if accion == "APROBAR":
            if sol["estado"] != "PENDIENTE":
                return {"ok": False, "motivo": f"Solo se puede aprobar una solicitud PENDIENTE "
                        f"(estado actual: {sol['estado']}).", "codigo_error": "ESTADO_INVALIDO"}
            if not expiration:
                return {"ok": False, "motivo": "Debes indicar la fecha de expiracion del permiso JP.",
                        "codigo_error": "FALTA_EXPIRATION"}
            previa = _jp_solicitud_viva_existente(sol["id_usuario"])
            if previa and previa["estado"] == "APROBADA" and previa["id_solicitud"] != id_solicitud:
                recursos_previos = _jp_recursos_para(sol["id_usuario"], previa["id_rol_facultad"])
                _jp_eliminar_t3(sol["id_usuario"], recursos_previos)
                _jp_set_estado(previa["id_solicitud"], "REVOCADA", id_admin,  motivo="Revocada automaticamente por nueva postulacion aprobada")
            recursos = _jp_recursos_para(sol["id_usuario"], sol["id_rol_facultad"])
            ok = _jp_insertar_t3(sol["id_usuario"], recursos, razon="JP - excepcion T3 por usuario",
                                expiration=expiration)
            if not ok:
                return {"ok": False, "motivo": "Error al generar permisos T3.", "codigo_error": "ERROR_T3"}
            _jp_set_estado(id_solicitud, "APROBADA", id_admin)
            return {"ok": True, "id_solicitud": id_solicitud, "estado": "APROBADA", "recursos_otorgados": recursos}

        elif accion == "RECHAZAR":
            if sol["estado"] != "PENDIENTE":
                return {"ok": False, "motivo": f"Solo se puede rechazar una solicitud PENDIENTE "  f"(estado actual: {sol['estado']}).", "codigo_error": "ESTADO_INVALIDO"}
            _jp_set_estado(id_solicitud, "RECHAZADA", id_admin)
            return {"ok": True, "id_solicitud": id_solicitud, "estado": "RECHAZADA"}

        elif accion == "REVOCAR":
            if sol["estado"] != "APROBADA":
                return {"ok": False, "motivo": f"Solo se puede revocar una solicitud APROBADA " f"(estado actual: {sol['estado']}).", "codigo_error": "ESTADO_INVALIDO"}
            recursos = _jp_recursos_para(sol["id_usuario"], sol["id_rol_facultad"])
            _jp_eliminar_t3(sol["id_usuario"], recursos)
            _jp_set_estado(id_solicitud, "REVOCADA", id_admin, motivo=motivo or "Revocada por Admin_TI")
            return {"ok": True, "id_solicitud": id_solicitud, "estado": "REVOCADA"}

        return {"ok": False, "motivo": f"Accion '{accion}' no reconocida.", "codigo_error": "ACCION_INVALIDA"}