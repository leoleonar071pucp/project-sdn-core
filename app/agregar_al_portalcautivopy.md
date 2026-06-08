# ── AÑADIR AL INICIO DE portal_cautivo.py ────────────────────────────────────
import requests as http_requests  
# para llamar al dhcp_manager
# (si ya tiene 'import requests', renombrar uno de los dos)

DHCP_MANAGER_URL = "http://localhost:5001"  # mismo host, mismo VM


# ── FUNCIÓN NUEVA — añadir en portal_cautivo.py ───────────────────────────────

def asignar_ip_definitiva(mac: str, rol: str, codigo_pucp: str,
                           switch_dpid: str, in_port: int) -> dict:
    """
    Llama al dhcp_manager para asignar la IP definitiva del rol.
    Retorna el resultado con ip_asignada.
    """
    try:
        resp = http_requests.post(
            f"{DHCP_MANAGER_URL}/dhcp/assign",
            json={
                "mac":         mac,
                "rol":         rol,
                "codigo_pucp": codigo_pucp,
                "switch_dpid": switch_dpid,
                "in_port":     in_port
            },
            timeout=5
        )
        return resp.json()
    except Exception as e:
        print(f"[DHCP] Error llamando dhcp_manager: {e}")
        return {"exito": False, "mensaje": str(e)}


# ── MODIFICAR ESTA PARTE DEL FLUJO EXISTENTE en portal_cautivo.py ─────────────
# Buscar donde se procesa el Access-Accept y añadir justo después:

# ANTES (lo que ya existe aproximadamente):
# if respuesta == "Access-Accept":
#     rol = extraer_rol(respuesta)
#     print(f"Rol asignado: {rol}")
#     # ... registrar sesión ...

# DESPUÉS (lo que hay que añadir):
# if respuesta == "Access-Accept":
#     rol      = filter_id   # el Filter-Id que devuelve FreeRADIUS
#     mac      = calling_station_id   # MAC del dispositivo
#     dpid     = called_station_id    # DPID del switch
#     in_port  = nas_port             # puerto físico
#
#     resultado_dhcp = asignar_ip_definitiva(
#         mac=mac,
#         rol=rol,
#         codigo_pucp=codigo_pucp,
#         switch_dpid=dpid,
#         in_port=in_port
#     )
#
#     if resultado_dhcp["exito"]:
#         ip_asignada = resultado_dhcp["ip_asignada"]
#         print(f"IP asignada: {ip_asignada} ({rol})")
#         # La sesión ya fue guardada en sesiones_activas por dhcp_manager
#     else:
#         print(f"Error DHCP: {resultado_dhcp['mensaje']}")

El cambio en portal_cautivo.py es mínimo. Busca la parte donde imprime "✓ Rol asignado : Estudiante_Telecom" (visible en la imagen que mostraste) y justo después de esa línea añade:
python# Llamar al DHCP manager para asignar IP definitiva
resultado_dhcp = asignar_ip_definitiva(
    mac=mac_dispositivo,      # variable que ya tienen
    rol=nombre_rol,            # el Filter-Id del Access-Accept
    codigo_pucp=usuario,       # el código que ingresó el usuario
    switch_dpid=dpid_switch,   # ya lo tienen del Access-Request
    in_port=puerto_fisico      # ya lo tienen del NAS-Port
)
print(f"✓ IP asignada     : {resultado_dhcp.get('ip_asignada', 'ERROR')}")
Eso es todo del lado del portal. El dhcp_manager hace el resto solo.