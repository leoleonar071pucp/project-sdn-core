# En Config — descomentar y ajustar:
M6_URL = "http://127.0.0.1:8080/m6/token_rol"

# En TokenEmitter.emit() — reemplazar el bloque comentado por:
def emit(self, codigo_pucp, nombre_rol, vlan_id, ip_asignada):
    token = {
        "codigo_pucp": codigo_pucp,
        "nombre_rol":  nombre_rol,
        "vlan_id":     vlan_id,
        "ip_asignada": ip_asignada
    }
    try:
        resp = requests.post(
            Config.M6_URL,
            json=token,
            timeout=5
        )
        if resp.status_code == 200:
            resultado = resp.json()
            print(f"  [M1→M6] Token enviado OK — "
                  f"mac={resultado.get('mac')}")
            return resultado  # {mac, switch_dpid, in_port}
        else:
            print(f"  [M1→M6] M6 respondió HTTP {resp.status_code}")
            return None
    except Exception as e:
        print(f"  [M1→M6] M6 no disponible: {e}")
        return None