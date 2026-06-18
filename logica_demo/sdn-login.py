#!/usr/bin/env python3
import argparse
import getpass
import json
import subprocess
import sys
import urllib.error
import urllib.request


DEFAULT_M6_URL = "http://192.168.201.212:8080/m6/cli_login"
DEFAULT_LOGOUT_URL = "http://192.168.201.212:8080/m6/cerrar_sesion"


def detect_sdn_ip():
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            universal_newlines=True,
        )
    except Exception:
        return None

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        ip = parts[3].split("/", 1)[0]
        if ip.startswith("192.168.100."):
            return ip
    return None


def detect_sdn_mac():
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            universal_newlines=True,
        )
        iface = None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3].split("/", 1)[0].startswith("192.168.100."):
                iface = parts[1]
                break
        if not iface:
            return None
        link = subprocess.check_output(
            ["ip", "-o", "link", "show", "dev", iface],
            universal_newlines=True,
        )
        parts = link.split()
        if "link/ether" in parts:
            return parts[parts.index("link/ether") + 1].upper()
    except Exception:
        return None
    return None


def post_json(url, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode("utf-8"))
        except Exception:
            data = {"ok": False, "error": "http_%s" % e.code}
        return e.code, data
    except Exception as e:
        return 0, {"ok": False, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Login CLI para la red SDN")
    parser.add_argument("--ip", help="IP SDN del host, ej. 192.168.100.12")
    parser.add_argument("--m6-url", default=DEFAULT_M6_URL)
    parser.add_argument("--logout", action="store_true", help="Cerrar sesion SDN de este host")
    parser.add_argument("--logout-url", default=DEFAULT_LOGOUT_URL)
    args = parser.parse_args()

    ip = args.ip or detect_sdn_ip()
    if not ip:
        print("No pude detectar una IP 192.168.100.x. Usa: sdn-login --ip <ip>")
        return 2

    if args.logout:
        mac = detect_sdn_mac()
        if not mac:
            print("No pude detectar la MAC SDN del host.")
            return 2
        status, data = post_json(args.logout_url, {"mac": mac})
        if status != 200:
            print("Logout fallido:", data.get("error", "error_desconocido"))
            return 1
        print("Logout OK")
        print("MAC:", mac)
        return 0

    print("Portal cautivo SDN CLI")
    print("Host SDN:", ip)
    codigo = input("Codigo PUCP: ").strip()
    password = getpass.getpass("Password: ")

    status, data = post_json(args.m6_url, {
        "codigo_pucp": codigo,
        "password": password,
        "ip_asignada": ip,
    })

    if status != 200 or not data.get("ok"):
        print("Login rechazado:", data.get("error", "error_desconocido"))
        return 1

    sesion = data["sesion"]
    print("Login OK")
    print("Rol:", sesion.get("nombre_rol"))
    print("VLAN:", sesion.get("vlan_id"))
    print("MAC:", sesion.get("mac"))
    print("Switch:", sesion.get("switch_dpid"))
    print("Puerto:", sesion.get("in_port"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
