#!/usr/bin/env python3
"""
portal_cautivo.py — Portal Cautivo CLI — SDN PUCP
Módulo M1 | Grupo 2 - TEL354
"""
import sys
import os
import json
import time
import datetime
import tempfile
# Extrasss
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
    
# Configuración base (por el momento :'v)
class Config:
    # FreeRADIUS
    RADIUS_HOST   = "127.0.0.1"  # esta ip cambiaria si el FreeRADIUS esta en otra VM
    RADIUS_PORT   = 1812
    RADIUS_SECRET = b"testing123"
    NAS_IP        = "192.168.200.200"  #Ip de la VM controller

    # MySQL
    MYSQL_HOST = "localhost"
    MYSQL_USER = "radius"
    MYSQL_PASS = "radius_pass"
    MYSQL_DB   = "radius_db"

    # M6 — pendiente de implementación
    # M6_URL = "http://192.168.200.200:8080/api/m6/token"

    # Máximo intentos antes de bloqueo
    MAX_INTENTOS = 3

    # Separadores UI
    SEP  = "═" * 55
    SEP2 = "─" * 55
    
# Configuramos la conexion de MySQL
class DatabaseManager:

    def get_connection(self):
        """
        Abre una conexión a MySQL y la retorna.
        Si falla, imprime el error y retorna None.
        """
        if not MYSQL_OK:
            print("  [DB] mysql-connector no instalado.")
            return None
        try:
            conexion = mysql.connector.connect(
            host         = Config.MYSQL_HOST,
            user         = Config.MYSQL_USER,
            password     = Config.MYSQL_PASS,
            database     = Config.MYSQL_DB,
            autocommit   = False,
            use_pure     = True,
            ssl_disabled = True
            )
            return conexion
        except mysql.connector.Error as e:
            print(f"  [DB] Error de conexión: {e}")
            return None
        
# Radius Client, 
# quien es responsable de enviar Access-Request a FreeRADIUS y 
# recive el nombre_rol(filter id) si es Access-Accept sino sería None
# Define los atributos que usaremos en el paquete
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
"""
class RadiusClient:

    def _build_dict(self):
        """
        Crea el diccionario RADIUS en un archivo temporal
        para que pyrad pueda leerlo.
        """
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".dict", delete=False, encoding="utf-8"
        )
        tmp.write(RADIUS_DICT)
        tmp.flush()
        d = pyrad.dictionary.Dictionary(tmp.name)
        tmp.close()
        os.unlink(tmp.name)  # elimina el archivo temporal
        return d

    def authenticate(self, codigo_pucp, password, ip_cuarentena):        
        """
        Envía Access-Request a FreeRADIUS con los datos del cliente.
        
        Parámetros:
          codigo_pucp   — usuario (ej: 20192434)
          password      — contraseña ingresada
          ip_cuarentena — IP asignada por DHCP (192.168.100.X)
          mac           — MAC del dispositivo
          dpid          — DPID del switch (ej: of:000072e0807e854c)
          port          — puerto del switch donde está conectado

        Retorna:
          (nombre_rol, session_timeout) si Access-Accept
          (None, None)                  si Access-Reject o error
        """
        if not PYRAD_OK:
            print("  [RADIUS] pyrad no disponible.")
            return None, None

        try:
            # Crear cliente RADIUS
            cliente = pyrad.client.Client(
                server   = Config.RADIUS_HOST,
                authport = Config.RADIUS_PORT,
                secret   = Config.RADIUS_SECRET,
                dict     = self._build_dict()
            )
            cliente.timeout = 5
            cliente.retries = 1

            # Construir paquete Access-Request
            paquete = cliente.CreateAuthPacket(
                code      = pyrad.packet.AccessRequest,
                User_Name = codigo_pucp
            )
            paquete["User-Password"]      = paquete.PwCrypt(password)
            paquete["NAS-IP-Address"]     = Config.NAS_IP 
            paquete["Framed-IP-Address"]  = ip_cuarentena

            # Enviar y esperar respuesta
            respuesta = cliente.SendPacket(paquete)

            # Si es Access-Accept 
            if respuesta.code == pyrad.packet.AccessAccept:
                nombre_rol = None
                if 11 in respuesta:   # atributo Filter-Id
                    nombre_rol = respuesta[11][0]
                    if isinstance(nombre_rol, bytes):
                        nombre_rol = nombre_rol.decode()

                session_timeout = 28800  # 8h por defecto aunque puede cambiar
                if 27 in respuesta:   # atributo Session-Timeout
                    val = respuesta[27][0]
                    session_timeout = (
                        int.from_bytes(val, "big")
                        if isinstance(val, bytes) else int(val)
                    )
                return nombre_rol, session_timeout

            # Si es Access-Reject 
            return None, None

        except Exception as e:
            print(f"  [RADIUS] Error: {e}")
            return None, None
        
        
# Mapeo de Rol por filter id
class RoleMapper:

    # Tabla de mapeo rol → vlan_id
    # Acordada con el equipo (M2, M6)
    VLAN_POR_ROL = {
        "Visitante":              100,
        "Estudiante_Telecom":     210,
        "Estudiante_Informatica": 220,
        "Estudiante_Electronica": 230,
        "Docente":                300,
        "Admin_TI":               400,
    }

    def get_vlan_id(self, nombre_rol):
        """
        Retorna el vlan_id del rol o None si no existe.
        Ejemplo: 'Estudiante_Telecom' → 210
        """
        return self.VLAN_POR_ROL.get(nombre_rol)
    
# vereficamos estado de cuenta /intentos fallidos o bloqueos
class UserManager:

    def __init__(self, db):
        self.db = db

    def get_id(self, codigo_pucp):
        """Retorna id_usuario del código PUCP o None si no existe."""
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
        """Retorna True si la cuenta está bloqueada."""
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
        """
        Suma 1 al contador de intentos fallidos.
        Si llega a MAX_INTENTOS bloquea la cuenta.
        Retorna el nuevo valor del contador.
        """
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
                # Bloquear cuenta
                cur.execute(
                    "UPDATE usuarios "
                    "SET intentos_fallidos = %s, "
                    "    estado_cuenta = 'BLOQUEADO', "
                    "    fecha_bloqueo = NOW() "
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
        """Resetea el contador de intentos fallidos tras login exitoso."""
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
            
# Se encarga del ciclo de vida completo de una sesion:
#   - Verificar anti-spoofing (ip_mac_binding)
#   - Registrar sesión en sesiones_activas
#   - Cerrar sesión y archivar en historial_sesiones
#   - Consultar recursos permitidos (politicas_rbac)

class SessionManager:

    def __init__(self, db):
        self.db = db

    def verify_antispoofing(self, ip, mac):
        """
        Verifica que IP y MAC no estén ya asociadas a otra sesión activa.
        Retorna (True, None) si están libres.
        Retorna (False, motivo) si hay conflicto.
        """
        conn = self.db.get_connection()
        if not conn:
            return True, None
        try:
            cur = conn.cursor(dictionary=True)

            # ¿Esta IP ya está bindeada a otra MAC?
            cur.execute("""
                SELECT mac_address
                FROM ip_mac_binding
                WHERE ip_asignada = %s AND mac_address != %s
            """, (ip, mac))
            row = cur.fetchone()
            if row:
                return False, f"IP {ip} ya en uso por otra MAC"

            # ¿Esta MAC ya tiene sesión con otra IP?
            cur.execute("""
                SELECT ip_asignada
                FROM ip_mac_binding
                WHERE mac_address = %s AND ip_asignada != %s
            """, (mac, ip))
            row = cur.fetchone()
            if row:
                return False, f"MAC {mac} ya tiene sesión con otra IP"

            return True, None

        except Exception:
            return True, None
        finally:
            conn.close()

    def register_session(self, id_usuario, mac, ip_asignada,vlan_id, nombre_rol, switch_dpid, in_port):
        """
        Registra la sesión en sesiones_activas.
        Retorna id_sesion si OK, None si falla.
        """
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
            """, (id_usuario, mac, ip_asignada, vlan_id,nombre_rol, switch_dpid, in_port))
            conn.commit()
            return cur.lastrowid
        except Exception as e:
            conn.rollback()
            print(f"  [SessionManager] Error al registrar sesión: {e}")
            return None
        finally:
            conn.close()

    def create_binding(self, ip, mac, id_usuario, switch_dpid, in_port):
        conn = self.db.get_connection()
        if not conn:
            return
        try: 
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO ip_mac_binding
                    (ip_asignada, mac_address, id_usuario,
                    switch_dpid, in_port)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    switch_dpid = VALUES(switch_dpid),
                    in_port     = VALUES(in_port)
            """, (ip, mac, id_usuario, switch_dpid, in_port))
            conn.commit()
            print(f"  ✓ Binding creado: {ip} ↔ {mac}")
        except Exception as e:
            conn.rollback()
            print(f"  [SessionManager] Error al crear binding: {e}")
        finally:
            conn.close()
    def close_session(self, mac, id_usuario):
        """
        Cierra la sesión en 3 pasos atómicos:
          1. INSERT en historial_sesiones (motivo LOGOUT_VOLUNTARIO)
          2. DELETE ip_mac_binding
          3. DELETE sesiones_activas
        Retorna dict con datos de la sesión o None si no existe.
        """
        conn = self.db.get_connection()
        if not conn:
            return None
        try:
            cur = conn.cursor(dictionary=True)

            # Buscar sesión activa
            cur.execute("""
                SELECT s.id_sesion, s.id_usuario, s.mac_address,
                       s.ip_asignada, s.vlan_id, s.nombre_rol,
                       s.switch_dpid, s.in_port, s.login_timestamp
                FROM sesiones_activas s
                WHERE s.mac_address = %s
                  AND s.id_usuario  = %s
            """, (mac, id_usuario))
            sesion = cur.fetchone()
            if not sesion:
                return None

            # 1. Archivar en historial
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

            # 2. Eliminar binding
            cur.execute(
                "DELETE FROM ip_mac_binding WHERE mac_address = %s",
                (mac,)
            )

            # 3. Eliminar sesión activa
            cur.execute(
                "DELETE FROM sesiones_activas WHERE id_sesion = %s",
                (sesion["id_sesion"],)
            )

            conn.commit()
            return sesion

        except Exception as e:
            conn.rollback()
            print(f"  [SessionManager] Error al cerrar sesión: {e}")
            return None
        finally:
            conn.close()

    def get_allowed_resources(self, nombre_rol):
        """
        Consulta politicas_rbac para obtener los recursos
        permitidos (ALLOW) del rol.
        """
        conn = self.db.get_connection()
        if not conn:
            return []
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT rec.nombre_recurso, rec.ip_dst,
                       rec.puerto, rec.protocolo, p.tabla_of
                FROM politicas_rbac p
                JOIN roles_facultad rf ON p.id_rol     = rf.id_rol
                JOIN recursos      rec ON p.id_recurso = rec.id_recurso
                WHERE rf.nombre_rol = %s
                  AND p.accion      = 'ALLOW'
                  AND p.activo      = 1
                ORDER BY rec.ip_dst, rec.puerto
            """, (nombre_rol,))
            return cur.fetchall()
        except Exception as e:
            print(f"  [SessionManager] Error al obtener recursos: {e}")
            return []
        finally:
            conn.close()
            
            
# Emite el Token, responsable de enviar e token a M6
# M6 recibe el token, consulta ONOS y devuelve
# {mac, switch_dpid, in_port} que M1 necesita
# para registrar la sesión

class TokenEmitter:

    def emit(self, codigo_pucp, nombre_rol, vlan_id, ip_asignada):
        """
        Envía token a M6 con los datos mínimos que M1 conoce.
        M6 se encarga de consultar ONOS para obtener mac/dpid/port.

        Retorna dict con {mac, switch_dpid, in_port} si M6 responde OK.
        Retorna None si M6 no está disponible (modo simulado).
        """
        token = {
            "codigo_pucp": codigo_pucp,
            "nombre_rol":  nombre_rol,
            "vlan_id":     vlan_id,
            "ip_asignada": ip_asignada
        }

        #  Intentar contactar M6 (Mark)
        # if Config.M6_URL:
        #     try:
        #         import urllib.request
        #         data = json.dumps(token).encode()
        #         req  = urllib.request.Request(
        #             Config.M6_URL, data=data,
        #             headers={"Content-Type": "application/json"},
        #             method="POST"
        #         )
        #         with urllib.request.urlopen(req, timeout=3) as resp:
        #             respuesta = json.loads(resp.read())
        #             print(f"  [M1→M6] Token enviado — HTTP {resp.status}")
        #             return respuesta  # {mac, switch_dpid, in_port}
        #     except Exception as e:
        #         print(f"  [M1→M6] M6 no disponible: {e}")
        #         return None

        # Modo simulado (M6 no disponible aún) 
        print(f"\n  [M1→M6] Token de Rol (simulado — M6 pendiente):")
        print("  " + Config.SEP2)
        for k, v in token.items():
            print(f"    {k:<14}: {v}")
        print("  " + Config.SEP2)
        print("  M6 instalará SET_FIELD vlan_vid en ONOS.\n")

        # Retornamos None para indicar que M6 no respondió
        # SessionManager usará valores por defecto
        return None
    
# Cli - Portal cautivo 
class CaptivePortal:

    def __init__(self):
        # Instanciar todos los componentes
        self.db       = DatabaseManager()
        self.radius   = RadiusClient()
        self.roles    = RoleMapper()
        self.users    = UserManager(self.db)
        self.sessions = SessionManager(self.db)
        self.tokens   = TokenEmitter()

    # Obtener IP del cliente via SSH 

    def get_client_ip(self):
        """
        Obtiene la IP del cliente desde la variable SSH_CLIENT.
        SSH_CLIENT = "192.168.100.13 54321 22"
                      ^IP cliente
        Retorna la IP o None si no está disponible.
        """
        ssh_client = os.environ.get("SSH_CLIENT", "")
        if not ssh_client:
            print("  [!] No se detectó SSH_CLIENT.")
            return None
        return ssh_client.split()[0]

    def _mostrar_menu_principal(self):
        print("\n")
        print(Config.SEP)
        print("        PORTAL CAUTIVO — RED PUCP")
        print("        Sistema de Autenticación SDN")
        print(Config.SEP)
        print("  Estado     : Cuarentena (esperando autenticación)")
        print(f"  FreeRADIUS : {Config.RADIUS_HOST}:{Config.RADIUS_PORT}")
        print(Config.SEP2)
        print("  [1] Iniciar sesión")
        print("  [2] Soy visitante  (no implementado)")
        print("  [3] Salir")
        print(Config.SEP)

    def _mostrar_recursos(self, nombre_rol, vlan_id):
        print("\n")
        print(Config.SEP)
        print(f"  Recursos permitidos — {nombre_rol}  (VLAN {vlan_id})")
        print(Config.SEP)
        recursos = self.sessions.get_allowed_resources(nombre_rol)
        if not recursos:
            print("  Sin recursos definidos.")
        else:
            print(f"  {'RECURSO':<28} {'IP DESTINO':<16} "
                  f"{'PUERTO':>6}  {'PROTO':<5}  TABLA")
            print("  " + Config.SEP2)
            for r in recursos:
                print(f"  {r['nombre_recurso']:<28} {r['ip_dst']:<16} "
                      f"{r['puerto']:>6}  {r['protocolo']:<5}  {r['tabla_of']}")
        print(Config.SEP)
        input("  Presiona Enter para volver...")

    def _mostrar_menu_sesion(self, codigo_pucp, nombre_rol,vlan_id, ip_asignada,id_usuario, mac):
        """Menú interactivo mientras la sesión está activa."""
        while True:
            print("\n")
            print(Config.SEP)
            print("  ✓  ACCESO CONCEDIDO — Sesión activa")
            print(Config.SEP)
            print(f"  Usuario     : {codigo_pucp}")
            print(f"  Rol         : {nombre_rol}")
            print(f"  VLAN        : {vlan_id}")
            print(f"  IP asignada : {ip_asignada}")
            print(f"  Inicio      : "
                  f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
            print(Config.SEP2)
            print("  [1] Ver recursos permitidos")
            print("  [2] Cerrar sesión")
            print(Config.SEP)

            opcion = input("  Opción: ").strip()

            if opcion == "1":
                self._mostrar_recursos(nombre_rol, vlan_id)

            elif opcion == "2":
                print("\n")
                print(Config.SEP)
                print("  Cerrando sesión...")
                sesion = self.sessions.close_session(mac, id_usuario)
                if sesion:
                    print(f"  ✓ Sesión cerrada correctamente")
                    print(f"  ✓ Registrada en historial_sesiones")
                    print(f"  ✓ Binding IP+MAC eliminado")
                else:
                    print("  ⚠  No se encontró sesión activa.")
                print(Config.SEP)
                input("  Presiona Enter para volver al menú principal...")
                return

    # El Flujo de login 
    def login(self):
        """
        Orquesta el flujo completo de autenticación.
        """
        print("\n")

        # 1. Obtener IP del cliente via SSH_CLIENT
        ip_asignada = self.get_client_ip()
        if not ip_asignada:
            # Para pruebas locales sin SSH
            ip_asignada = input(
                "  IP del cliente (prueba local): "
            ).strip()

        print(Config.SEP)
        print(f"  IP actual   : {ip_asignada}  (VLAN 90 — cuarentena)")
        print("  Ingresa tus credenciales PUCP para acceder a la red")
        print(Config.SEP2)

        intentos = 0
        while intentos < Config.MAX_INTENTOS:

            try:
                codigo   = input("  Código PUCP : ").strip()
                password = input("  Contraseña  : ").strip()
            except KeyboardInterrupt:
                print("\n\n  Sesión cancelada.")
                return

            if not codigo or not password:
                print("  [!] Ingresa código y contraseña.\n")
                continue

            # 2. Verificar si la cuenta está bloqueada
            if self.users.is_blocked(codigo):
                print(Config.SEP)
                print("  ✗ Cuenta bloqueada.")
                print("    Contacta al Administrador TI.")
                print(Config.SEP)
                input("  Presiona Enter para volver...")
                return

            # 3. Autenticar con FreeRADIUS
            print("\n  Autenticando", end="", flush=True)
            for _ in range(3):
                time.sleep(0.3)
                print(".", end="", flush=True)
            print()

            nombre_rol, _ = self.radius.authenticate(
                codigo, password, ip_asignada
            )

            # Si se recive un  access accept
            if nombre_rol is not None:

                # 4. Traducir rol → vlan_id
                vlan_id = self.roles.get_vlan_id(nombre_rol)
                if vlan_id is None:
                    print(f"  ✗ Rol '{nombre_rol}' no reconocido.")
                    input("  Presiona Enter para volver...")
                    return

                # 5. Enviar token a M6 (MARK)
                #    M1 solo conoce: codigo_pucp, nombre_rol, vlan_id, ip_asignada
                #    M6 debe: consultar ONOS con ip_asignada → obtener mac/dpid/port
                #             instalar SET_FIELD vlan_vid en ONOS
                #             devolver {mac, switch_dpid, in_port} a M1
                respuesta_m6 = self.tokens.emit(
                    codigo, nombre_rol, vlan_id, ip_asignada
                )

                #  PENDIENTE DE INTEGRACIÓN CON M6 
                # Cuando M6 esté disponible, respuesta_m6 debe contener:
                #   {
                #     "mac":         "FA:16:3E:14:78:63",
                #     "switch_dpid": "of:000072e0807e854c",
                #     "in_port":     2
                #   }
                # M6 obtiene esos datos consultando ONOS con ip_asignada.
                # Reemplazar el bloque 'else' por el manejo real de respuesta_m6.
                # ---------------------------------------------------------------
                if respuesta_m6:
                    mac         = respuesta_m6["mac"]
                    switch_dpid = respuesta_m6["switch_dpid"]
                    in_port     = respuesta_m6["in_port"]
                else:
                    # TODO: eliminar este bloque cuando M6 esté integrado
                    # Valores de demo para pruebas sin M6
                    print("  [AVISO] M6 no disponible — usando valores demo")
                    mac         = "00:00:00:00:00:00"
                    switch_dpid = "of:0000000000000000"
                    in_port     = 0

                # 7. Obtener id_usuario
                id_usuario = self.users.get_id(codigo)
                if not id_usuario:
                    print("  [ERROR] Usuario no encontrado en DB.")
                    input("  Presiona Enter para volver...")
                    return

                # 8. Verificar anti-spoofing
                libre, motivo = self.sessions.verify_antispoofing(
                    ip_asignada, mac
                )
                if not libre:
                    print(f"\n Anti-spoofing: {motivo}")
                    input("Presiona Enter para volver...")
                    return

                # 9. Registrar sesión en sesiones_activas
                id_sesion = self.sessions.register_session(
                    id_usuario, mac, ip_asignada,
                    vlan_id, nombre_rol,
                    switch_dpid, in_port
                )
                if id_sesion is None:
                    print("Error al registrar sesión.")
                    input("Presiona Enter para volver...")
                    return

                # 10. Crear binding IP+MAC
                self.sessions.create_binding(
                    ip_asignada, mac, id_usuario,
                    switch_dpid, in_port
                )

                # 11. Resetear contador de intentos
                self.users.reset_failed_attempts(codigo)

                print(f"Sesión #{id_sesion} registrada")
                print(f"Binding IP+MAC creado")

                # 12. Menú de sesión activa
                self._mostrar_menu_sesion(
                    codigo, nombre_rol, vlan_id,
                    ip_asignada, id_usuario, mac
                )
                return

            # si recive un acces reject
            else:
                intentos += 1
                total     = self.users.increment_failed_attempt(codigo)
                restantes = Config.MAX_INTENTOS - total

                if total >= Config.MAX_INTENTOS:
                    print(Config.SEP)
                    print("Credenciales inválidas.")
                    print("Cuenta bloqueada por 3 intentos fallidos.")
                    print("Contacta al Administrador TI.")
                    print(Config.SEP)
                    input("Presiona Enter para volver...")
                    return
                else:
                    print(f"Credenciales inválidas. "
                          f"({restantes} intento(s) restante(s))\n")

    # Loop principal 
    def run(self):
        while True:
            self._mostrar_menu_principal()
            opcion = input("  Opción: ").strip()

            if opcion == "1":
                self.login()

            elif opcion == "2":
                print(Config.SEP)
                print("  Flujo visitante — no implementado aún.")
                print(Config.SEP)
                input("  Presiona Enter para volver...")

            elif opcion in ("3", "q", "salir"):
                print("\n  Saliendo del portal.\n")
                sys.exit(0)

            else:
                print("  Opción no válida.\n")

if __name__ == "__main__":
    CaptivePortal().run()