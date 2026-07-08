import requests


class OnosClient:
    
    def __init__(self, config):
        self.base_url = (
            f"http://{config.onos_host}:{config.onos_port}/onos/v1"
        )

        self.session = requests.Session()
        self.session.auth = (
            config.username,
            config.password,
        )

        self.verify_ssl = config.verify_ssl
        self.timeout = config.timeout

    def _get(self, endpoint: str) -> dict: 
        response = self.session.get(
            f"{self.base_url}{endpoint}",
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()

    def get_devices(self) -> dict:
        return self._get("/devices")

    def get_links(self) -> dict:
        return self._get("/links")

    def get_flows(self, device_id: str) -> dict:
        """Return flows installed on a device."""
        return self._get(f"/flows/{device_id}")

    def get_port_statistics(self, device_id: str) -> dict:
        """Return port statistics for a device."""
        return self._get(f"/statistics/ports/{device_id}")