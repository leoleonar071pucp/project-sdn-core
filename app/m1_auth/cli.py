#!/usr/bin/env python3
"""
cliYo.py — Cliente CLI del Portal Cautivo — SDN PUCP
Módulo M1 | Grupo 2 - TEL354
- Sheila J

Endpoints reales consumidos (definidos en web.py):
  POST /auth/login            {"usuario": "...", "password": "..."}
  POST /auth/visitante        {"correo": "...", "password": "..."}
  POST /auth/logout           {"mac": "...", "id_usuario": 0, ...}
  GET  /auth/recursos/<rol>
  GET  /auth/sesion/actual
  GET  /auth/sesion/recursos

Requiere:
  pip3 install requests

Uso:
  python3 cli.py
  (opcional) python3 cli.py --host 192.168.100.x --port 8282  (Ip del AAA policies)
"""
import sys
import time
import socket
import datetime
import argparse

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[ADVERTENCIA] requests no instalado. Ejecuta: pip3 install requests")


class Config:
    SEP = "═" * 55
    SEP2 = "─" * 55
    VLAN_CUARENTENA = 90


def obtener_ip_local(host_servidor):
    """
    Obtiene la IP real de ESTE equipo (el cliente), no la del servidor. Abre un socket UDP "falso" hacia el servidor y lee la IP local que el OS asignó a esa conexión. 
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host_servidor, 80))
        ip_local = s.getsockname()[0]
        s.close()
        return ip_local
    except Exception:
        return "desconocida"


class PortalClient:
    """Encapsula las llamadas HTTP al servidor web.py."""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def _post(self, endpoint, body):
        try:
            resp = requests.post(f"{self.base_url}{endpoint}", json=body, timeout=15)
            return resp.json()
        except requests.exceptions.ConnectionError:
            return {"ok": False,
                    "motivo": f"No se pudo conectar al portal cautivo " f"({self.base_url}). ¿Está corriendo web.py?"}
        except requests.exceptions.Timeout:
            return {"ok": False, "motivo": "El portal cautivo no respondió a tiempo."}
        except Exception as e:
            return {"ok": False, "motivo": f"Error inesperado: {e}"}

    def _get(self, endpoint):
        try:
            resp = requests.get(f"{self.base_url}{endpoint}", timeout=15)
            return resp.json()
        except requests.exceptions.ConnectionError:
            return {"ok": False, "motivo": f"No se pudo conectar al portal cautivo " f"({self.base_url})."}
        except Exception as e:
            return {"ok": False, "motivo": f"Error inesperado: {e}"}

    def login(self, usuario, password):
        return self._post("/auth/login", {"usuario": usuario, "password": password})

    def login_visitante(self, correo, password):
        return self._post("/auth/visitante", {"correo": correo, "password": password})

    def logout(self, mac, id_usuario, codigo_pucp=None,
               ip_asignada=None, es_visitante=False):
        return self._post("/auth/logout", {
            "mac": mac, "id_usuario": id_usuario, "codigo_pucp": codigo_pucp,
            "ip_asignada": ip_asignada, "es_visitante": es_visitante,
        })

    def recursos(self, nombre_rol):
        return self._get(f"/auth/recursos/{nombre_rol}")

    def sesion_actual(self):
        return self._get("/auth/sesion/actual")

    def recursos_sesion(self):
        return self._get("/auth/sesion/recursos")


def formatear_tiempo(segundos):
    """Convierte segundos a un string legible HH:MM:SS o MM:SS."""
    segundos = max(0, int(segundos))
    horas, resto = divmod(segundos, 3600)
    mins, segs = divmod(resto, 60)
    if horas > 0:
        return f"{horas:02d}:{mins:02d}:{segs:02d}"
    return f"{mins:02d}:{segs:02d}"


class CaptivePortalCLI:
    """Interfaz de texto. Misma UX que portal_cautivo.py original, pero ahora habla con el servidor por HTTP en vez de llamar directo a la lógica de negocio.
    """

    def __init__(self, client, host_servidor):
        self.client = client
        self.ip_local = obtener_ip_local(host_servidor)

    # Menu
    def _mostrar_menu_principal(self):
        print("\n")
        print(Config.SEP)
        print("        PORTAL CAUTIVO — RED PUCP")
        print("        Sistema de Autenticación SDN")
        print(Config.SEP)
        print("  Estado     : esperando autenticación")
        print(f"  IP local   : {self.ip_local}  (VLAN {Config.VLAN_CUARENTENA} — cuarentena)")
        print(f"  Servidor   : {self.client.base_url}")
        print(Config.SEP2)
        print("  [1] Iniciar sesión")
        print("  [2] Soy visitante")
        print("  [3] Salir")
        print(Config.SEP)

    def _animacion_autenticando(self):
        print("\n  Autenticando", end="", flush=True)
        for _ in range(3):
            time.sleep(0.3)
            print(".", end="", flush=True)
        print()

    # Formulario de ingreso para Estudiantes, Docentes y Admin TI

    def login(self):
        print("\n")
        print(Config.SEP)
        print(f"  IP local    : {self.ip_local}  (VLAN {Config.VLAN_CUARENTENA} — cuarentena)")
        print("  Ingresa tus credenciales PUCP para acceder a la red")
        print(Config.SEP2)

        try:
            codigo = input("  Código PUCP : ").strip()
            password = input("  Contraseña  : ").strip()
        except KeyboardInterrupt:
            print("\n\n  Sesión cancelada.")
            return

        if not codigo or not password:
            print("  [!] Ingresa código PUCP y contraseña.\n")
            return

        self._animacion_autenticando()
        resultado = self.client.login(codigo, password)

        if resultado.get("ok"):
            print(Config.SEP)
            print("  ✓ ACCESO CONCEDIDO")
            print(Config.SEP)
            self._sesion_activa(resultado)
        elif resultado.get("codigo_error") == "SESION_YA_ACTIVA" and resultado.get("sesion"):
            print(Config.SEP)
            print("  Ya existe una sesion activa para este host.")
            print(Config.SEP)
            self._sesion_activa(resultado["sesion"])
        else:
            print(Config.SEP)
            print(f"  ✗ {resultado.get('motivo', 'Error desconocido')}")
            print(Config.SEP)
            input("  Presiona Enter para volver...")

    def _mostrar_recursos_sesion(self, nombre_rol, vlan_id):
            """
            Vista de recursos para la sesión activa actual, separados por tabla de origen: T2 (rol principal) y T3 (excepción temporal).
            Si una sección no tiene recursos, se imprime su encabezado igual, con la leyenda "No hay recursos permitidos" en lugar de la tabla.
            """
            print("\n")
            print(Config.SEP)
            print(f"  Recursos permitidos - {nombre_rol}  (VLAN {vlan_id})")
            print(Config.SEP)
            resp = self.client.recursos_sesion()
            if not resp.get("ok"):
                resp = self.client.recursos(nombre_rol)
            recursos = resp.get("recursos", []) if resp.get("ok") else []

            for tabla, titulo in (("T2", "T2 / Rol principal"),
                                ("T3", "T3 / Excepcion")):
                items = [r for r in recursos if r.get("tabla", "T2") == tabla]
                print(f"  {titulo}")
                if not items:
                    print("  No hay recursos permitidos")
                else:
                    print(f"  {'RECURSO':<28} {'IP DESTINO':<16} "
                        f"{'PUERTO':>6}  {'PROTO':<5}")
                    print("  " + Config.SEP2)
                    for r in items:
                        print(f"  {r.get('nombre_recurso',''):<28} "
                            f"{r.get('ip_dst',''):<16} "
                            f"{str(r.get('puerto','')):>6}  "
                            f"{r.get('protocolo',''):<5}")
                print()
            print(Config.SEP)
            input("  Presiona Enter para volver...")

    def _sesion_activa(self, sesion):
        """
        Menú único de sesión activa (estudiante/docente/admin/visitante).
        Calcula y muestra en vivo el tiempo restante antes del cierre automático, basado en session_timeout (segundos): 
        para usuarios normales viene del atributo Session-Timeout de FreeRADIUS; para visitantes es el valor fijo de 1800s (30 min) que envía el servidor.

        Solo dos opciones: ver recursos permitidos o cerrar sesión.
        
        Si el usuario no elige nada antes de que el tiempo se agote, la
        sesión se cierra sola.
        """
        codigo_pucp = sesion.get("codigo_pucp") or sesion.get("correo") or "VISITANTE"
        nombre_rol = sesion.get("nombre_rol")
        vlan_id = sesion.get("vlan_id")
        ip_asignada = sesion.get("ip_asignada")
        mac = sesion.get("mac") or sesion.get("mac_address")
        id_usuario = sesion.get("id_usuario", 0)
        es_visitante = sesion.get("es_visitante", False)
        session_timeout = sesion.get("session_timeout", 28800)

        inicio = datetime.datetime.now()
        limite = inicio + datetime.timedelta(seconds=session_timeout)

        while True:
            restante = (limite - datetime.datetime.now()).total_seconds()

            if restante <= 0:
                print("\n")
                print(Config.SEP)
                print("  ⚠  Tiempo de sesión agotado. Cerrando automáticamente...")
                resp = self.client.logout(
                    mac=mac, id_usuario=id_usuario,
                    codigo_pucp=codigo_pucp, ip_asignada=ip_asignada,
                    es_visitante=es_visitante
                )
                if resp.get("ok"):
                    print("  ✓ Sesión cerrada por expiración de tiempo")
                else:
                    print(f"  ⚠  {resp.get('motivo', '')}")
                print(Config.SEP)
                input("  Presiona Enter para volver al menú principal...")
                return

            print("\n")
            print(Config.SEP)
            print("  ✓  ACCESO CONCEDIDO — Sesión activa")
            print(Config.SEP)
            print(f"  Usuario       : {codigo_pucp}")
            print(f"  Rol           : {nombre_rol}")
            print(f"  VLAN          : {vlan_id}")
            print(f"  IP asignada   : {ip_asignada}")
            print(f"  Tiempo rest.  : {formatear_tiempo(restante)} "
                  f"(antes de cierre automático)")
            print(Config.SEP2)
            print("  [1] Ver recursos permitidos")
            print("  [2] Cerrar sesión")
            print(Config.SEP)

            try:
                opcion = input("  Opción: ").strip()
            except KeyboardInterrupt:
                print("\n\n  Saliendo del CLI. La sesión sigue activa.\n")
                sys.exit(0)

            if opcion == "1":
                self._mostrar_recursos_sesion(nombre_rol, vlan_id)

            elif opcion == "2":
                print("\n")
                print(Config.SEP)
                print("  Cerrando sesión...")
                resp = self.client.logout(
                    mac=mac, id_usuario=id_usuario, codigo_pucp=codigo_pucp,
                    ip_asignada=ip_asignada, es_visitante=es_visitante
                )
                if resp.get("ok"):
                    print("  ✓ Sesión cerrada correctamente")
                else:
                    print(f"  ⚠  {resp.get('motivo', 'No se pudo cerrar sesión')}")
                print(Config.SEP)
                input("  Presiona Enter para volver al menú principal...")
                return
            else:
                print("  Opción no válida.\n")

    # Formulario de ingreso para Visitante

    def flujo_visitante(self):
        print("\n")
        print(Config.SEP)
        print("        ACCESO VISITANTE — RED PUCP")
        print(Config.SEP)
        print("  Acceso temporal de 30 minutos.")
        print("  Solo disponible: internet externo")
        print(Config.SEP2)

        try:
            correo = input("  Correo    : ").strip()
            password = input("  Contraseña: ").strip()
        except KeyboardInterrupt:
            print("\n\n  Cancelado.")
            return

        if not correo or not password:
            print("  [!] Ingresa correo y contraseña.")
            input("  Presiona Enter para volver...")
            return

        self._animacion_autenticando()
        resultado = self.client.login_visitante(correo, password)

        if resultado.get("ok"):
            print(f"  ✓ Sesión registrada — 30 minutos de acceso")
            self._sesion_activa(resultado)
        elif resultado.get("codigo_error") == "SESION_YA_ACTIVA" and resultado.get("sesion"):
            print(Config.SEP)
            print("  Ya existe una sesion activa para este host.")
            print(Config.SEP)
            self._sesion_activa(resultado["sesion"])
        else:
            print(Config.SEP)
            print(f"  ✗ {resultado.get('motivo', 'Error desconocido')}")
            print(Config.SEP)
            input("  Presiona Enter para volver...")

    # El loop del menú para que sea interactivo
    def run(self):
        while True:
            estado = self.client.sesion_actual()
            if estado.get("ok") and estado.get("activa") and estado.get("sesion"):
                self._sesion_activa(estado["sesion"])
                continue

            self._mostrar_menu_principal()
            try:
                opcion = input("  Opción: ").strip()
            except KeyboardInterrupt:
                print("\n  Saliendo del portal.\n")
                sys.exit(0)

            if opcion == "1":
                self.login()
            elif opcion == "2":
                self.flujo_visitante()
            elif opcion in ("3", "q", "salir"):
                print("\n  Saliendo del portal.\n")
                sys.exit(0)
            else:
                print("  Opción no válida.\n")


def main():
    parser = argparse.ArgumentParser(description="Cliente CLI del Portal Cautivo PUCP")
    parser.add_argument("--host", default="192.168.100.110", help="IP del servidor del portal cautivo (VM-Auth)")
    parser.add_argument("--port", default="8282", help="Puerto del servidor del portal cautivo")
    args = parser.parse_args()

    if not REQUESTS_OK:
        sys.exit(1)

    base_url = f"http://{args.host}:{args.port}"
    client = PortalClient(base_url)
    CaptivePortalCLI(client, args.host).run()


if __name__ == "__main__":
    main()