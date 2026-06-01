from dataclasses import dataclass


@dataclass
class ONOSClient:
    base_url: str
    username: str
    password: str

    def install_flow(self, device_id: str, flow: dict) -> dict:
        return {"status": "queued", "action": "install", "device_id": device_id, "flow": flow}

    def remove_flow(self, device_id: str, flow_id: str) -> dict:
        return {"status": "queued", "action": "remove", "device_id": device_id, "flow_id": flow_id}
