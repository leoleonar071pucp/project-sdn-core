def build_block_mac_rule(device_id: str, mac_address: str) -> dict:
    """
    Regla para la Tabla 0: Bloquear una MAC maliciosa (T0).
    """
    return {
        "flows": [
            {
                "priority": 50000,
                "timeout": 0,
                "isPermanent": True,
                "deviceId": device_id,
                "tableId": 0,
                "treatment": {
                    "instructions": [{"type": "NOACTION"}] # Equivalente a DROP en ONOS si no hay OUTPUT
                },
                "selector": {
                    "criteria": [
                        {"type": "ETH_SRC", "mac": mac_address}
                    ]
                }
            }
        ]
    }


def build_allow_cidr_to_ip_rule(device_id: str, cidr_src: str, ip_dst: str, port: int, protocol: int = 6) -> dict:
    """
    Regla para la Tabla 2: Permitir a un CIDR acceder a un servidor específico (Política Macro).
    """
    # protocol 6 = TCP, 17 = UDP
    criteria = [
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "IP_PROTO", "protocol": protocol},
        {"type": "IPV4_SRC", "ip": cidr_src},
        {"type": "IPV4_DST", "ip": f"{ip_dst}/32"}
    ]
    
    if protocol == 6:
        criteria.append({"type": "TCP_DST", "tcpPort": port})
    elif protocol == 17:
        criteria.append({"type": "UDP_DST", "udpPort": port})

    return {
        "flows": [
            {
                "priority": 30000,
                "timeout": 0,
                "isPermanent": True,
                "deviceId": device_id,
                "tableId": 2,
                "treatment": {
                    # Delegate routing to NORMAL pipeline or specific port
                    "instructions": [{"type": "L2MODIFICATION", "subtype": "NOACTION"}]
                },
                "selector": {
                    "criteria": criteria
                }
            }
        ]
    }


def build_temporal_allow_rule(device_id: str, ip_src: str, ip_dst: str, port: int, timeout_sec: int, protocol: int = 6) -> dict:
    """
    Regla para la Tabla 3: Excepción micro temporal (T3).
    """
    criteria = [
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "IP_PROTO", "protocol": protocol},
        {"type": "IPV4_SRC", "ip": f"{ip_src}/32"},
        {"type": "IPV4_DST", "ip": f"{ip_dst}/32"}
    ]
    
    if protocol == 6:
        criteria.append({"type": "TCP_DST", "tcpPort": port})
    elif protocol == 17:
        criteria.append({"type": "UDP_DST", "udpPort": port})

    return {
        "flows": [
            {
                "priority": 35000,
                "timeout": timeout_sec,
                "isPermanent": False,
                "deviceId": device_id,
                "tableId": 3,
                "treatment": {
                    "instructions": [{"type": "L2MODIFICATION", "subtype": "NOACTION"}]
                },
                "selector": {
                    "criteria": criteria
                }
            }
        ]
    }
