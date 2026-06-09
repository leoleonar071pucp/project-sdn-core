import logging
import requests
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ONOSClient:
    base_url: str
    username: str
    password: str

    def _get_auth(self):
        return (self.username, self.password)

    def install_flow(self, device_id: str, flow: dict) -> dict:
        url = f"{self.base_url}/flows/{device_id}"
        logger.info(f"Instalando flow en ONOS {url}")
        try:
            response = requests.post(
                url, 
                json=flow, 
                auth=self._get_auth(),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=5
            )
            response.raise_for_status()
            logger.info(f"Flow instalado exitosamente: {response.status_code}")
            return {"status": "success", "action": "install", "device_id": device_id}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error instalando flow en ONOS: {e}")
            return {"status": "error", "action": "install", "device_id": device_id, "error": str(e)}

    def remove_flow(self, device_id: str, flow_id: str) -> dict:
        url = f"{self.base_url}/flows/{device_id}/{flow_id}"
        logger.info(f"Eliminando flow en ONOS {url}")
        try:
            response = requests.delete(
                url, 
                auth=self._get_auth(),
                timeout=5
            )
            response.raise_for_status()
            logger.info(f"Flow {flow_id} eliminado exitosamente")
            return {"status": "success", "action": "remove", "device_id": device_id, "flow_id": flow_id}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error eliminando flow en ONOS: {e}")
            return {"status": "error", "action": "remove", "device_id": device_id, "flow_id": flow_id, "error": str(e)}
