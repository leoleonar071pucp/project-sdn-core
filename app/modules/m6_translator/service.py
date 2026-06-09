from app.modules.m6_translator.onos_client import ONOSClient
from app.modules.m6_translator.flow_builder import build_allow_cidr_to_ip_rule, build_block_mac_rule, build_temporal_allow_rule

def install_macro_flow(client: ONOSClient, device_id: str, cidr_src: str, ip_dst: str, port: int, protocol: int = 6) -> dict:
    flow = build_allow_cidr_to_ip_rule(device_id, cidr_src, ip_dst, port, protocol)
    return client.install_flow(device_id, flow)

def block_mac(client: ONOSClient, device_id: str, mac_address: str) -> dict:
    flow = build_block_mac_rule(device_id, mac_address)
    return client.install_flow(device_id, flow)

def install_temporal_flow(client: ONOSClient, device_id: str, ip_src: str, ip_dst: str, port: int, timeout_sec: int, protocol: int = 6) -> dict:
    flow = build_temporal_allow_rule(device_id, ip_src, ip_dst, port, timeout_sec, protocol)
    return client.install_flow(device_id, flow)

def remove_flow(client: ONOSClient, device_id: str, flow_id: str) -> dict:
    return client.remove_flow(device_id=device_id, flow_id=flow_id)
