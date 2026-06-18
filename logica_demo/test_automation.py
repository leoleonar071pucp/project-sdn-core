#!/usr/bin/env python3
import json
import subprocess
import sys
import time
import urllib.request

M6_URL = "http://192.168.201.212:8080/m6/token_rol"
SERVER_CURSOS_IP = "192.168.100.200"


def print_green(msg):
    print(f"\033[92m{msg}\033[0m")


def print_red(msg):
    print(f"\033[91m{msg}\033[0m")


def authenticate():
    print("[TEST] Iniciando autenticacion silenciosa (Estudiante_Telecom)...")
    payload = {
        "codigo_pucp": "20192434",
        "nombre_rol": "Estudiante_Telecom",
        "vlan_id": 210,
        "ip_asignada": "192.168.100.10",
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        M6_URL,
        data=data,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status in [200, 201]:
                print_green("  OK - Autenticacion exitosa. VLAN actualizada a 210.")
                return True
    except Exception as e:
        print_red(f"  ERROR - Fallo la autenticacion con M6: {e}")
        return False

    return False


def test_tcp_port(port, should_pass=True):
    print(f"[TEST] Verificando flujo TCP hacia {SERVER_CURSOS_IP}:{port} (Permitido: {should_pass})...")
    # Usamos curl con un timeout de 2 segundos.
    # Codigos de curl:
    # 0  = Exito HTTP (Servidor encendido)
    # 7  = Connection Refused (El paquete llego, pero el servidor esta apagado). = EXITO DE RED.
    # 52 = Empty reply from server = EXITO DE RED.
    # 28 = Timeout (El paquete fue bloqueado por SDN).
    
    cmd = ["curl", "-s", "-m", "2", f"http://{SERVER_CURSOS_IP}:{port}"]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    exit_code = result.returncode

    if should_pass:
        if exit_code in [0, 7, 52]: 
            print_green(f"  OK - M6 inyecto el Flow TCP. El SDN permitio el trafico. (Codigo: {exit_code})")
            return True
        else:
            print_red(f"  ERROR - SDN bloqueo el puerto {port} o la red no esta lista. (Codigo: {exit_code})")
            return False
    else:
        if exit_code == 28:
            print_green(f"  OK - OPA/SDN bloqueo correctamente el acceso (Timeout).")
            return True
        else:
            print_red(f"  ERROR - SDN permitio trafico a un puerto prohibido. (Codigo: {exit_code})")
            return False

def run_all_tests():
    success = True
    print("\n--- PRUEBAS DE PUERTOS AUTORIZADOS ---")
    if not test_tcp_port(8083, should_pass=True):
        success = False

    print("\n--- PRUEBAS DE PUERTOS BLOQUEADOS (SEGURIDAD) ---")
    for p in [8081, 8082]:
        if not test_tcp_port(p, should_pass=False):
            success = False

    print("\n--- PRUEBAS DE BLOQUEO ADICIONAL ---")
    if not test_tcp_port(8099, should_pass=False):
        success = False
        
    return success

if __name__ == "__main__":
    print("========================================")
    print("   INICIANDO AUTOMATIZACION DE TEST")
    print("========================================")

    time.sleep(10)

    if authenticate():
        time.sleep(5)
        if run_all_tests():
            print("\n========================================")
            print_green("  TEST END-TO-END EXITOSO")
            print("========================================")
            sys.exit(0)

    print("\n========================================")
    print_red("  EL TEST HA FALLADO")
    print("========================================")
    sys.exit(1)
