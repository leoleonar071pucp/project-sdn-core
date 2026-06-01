from app.modules.m6_translator.onos_client import ONOSClient


def install_flow(client: ONOSClient, device_id: str, flow: dict) -> dict:
    return client.install_flow(device_id=device_id, flow=flow)


def remove_flow(client: ONOSClient, device_id: str, flow_id: str) -> dict:
    return client.remove_flow(device_id=device_id, flow_id=flow_id)
