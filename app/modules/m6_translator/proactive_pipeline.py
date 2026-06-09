import json
import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("m6_proactive_pipeline")

class ONOSProactivePipeline:
    def __init__(self, onos_ip: str = "127.0.0.1", port: int = 8181, user: str = "onos", password: str = "rocks"):
        self.base_url = f"http://{onos_ip}:{port}/onos/v1/flows"
        self.auth = (user, password)
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}

    def generate_portal_redirect_json(self, device_id: str) -> dict:
        """
        Tabla 1: Regla Proactiva para secuestrar el tráfico HTTP (puerto 80)
        de los usuarios no autenticados (Cuarentena) y mandarlos al Portal Cautivo.
        """
        return {
            "flows": [
                {
                    "priority": 40000,
                    "timeout": 0, # 0 = Permanente (Proactiva)
                    "isPermanent": True,
                    "deviceId": device_id,
                    "tableId": 1, # Tabla 1: Infraestructura y Portal
                    "treatment": {
                        "instructions": [
                            {
                                "type": "OUTPUT",
                                "port": "CONTROLLER" # Envía a ONOS para redirección o directo al puerto del portal
                            }
                        ]
                    },
                    "selector": {
                        "criteria": [
                            {"type": "ETH_TYPE", "ethType": "0x0800"}, # IPv4
                            {"type": "IP_PROTO", "protocol": 6},       # TCP
                            {"type": "TCP_DST", "tcpPort": 80},        # HTTP
                            {"type": "IPV4_SRC", "ip": "192.168.100.0/24"} # CIDR Cuarentena
                        ]
                    }
                }
            ]
        }

    def generate_dns_dhcp_allow_json(self, device_id: str) -> dict:
        """
        Tabla 1: Reglas Proactivas para que el DHCP y DNS siempre pasen.
        """
        return {
            "flows": [
                {
                    "priority": 45000,
                    "timeout": 0,
                    "isPermanent": True,
                    "deviceId": device_id,
                    "tableId": 1,
                    "treatment": {
                        "instructions": [{"type": "L2MODIFICATION", "subtype": "NOACTION"}] # Acción: Pasar normal (o GOTO T2)
                        # En un pipeline real aquí pondríamos un GOTO_TABLE 2
                    },
                    "selector": {
                        "criteria": [
                            {"type": "ETH_TYPE", "ethType": "0x0800"},
                            {"type": "IP_PROTO", "protocol": 17}, # UDP
                            {"type": "UDP_DST", "udpPort": 67}    # DHCP Server
                        ]
                    }
                }
            ]
        }

    def push_flows(self, device_id: str, flow_payload: dict):
        """
        Envía el JSON a la API REST de ONOS.
        """
        url = f"{self.base_url}/{device_id}"
        try:
            logger.info(f"Instalando flujos proactivos en {device_id}...")
            # Descomentar la siguiente línea cuando la red ONOS esté viva:
            # response = requests.post(url, json=flow_payload, auth=self.auth, headers=self.headers, timeout=5)
            # response.raise_for_status()
            logger.info(f"JSON a enviar: {json.dumps(flow_payload, indent=2)}")
            logger.info("Flujos empujados exitosamente (simulado).")
        except Exception as e:
            logger.error(f"Error comunicando con ONOS: {e}")

    def boot_network(self, device_id: str):
        """
        Función principal que se ejecutará cuando la red se prenda.
        Instala todas las tablas proactivas de golpe en un switch.
        """
        logger.info(f"--- Iniciando Boot de Pipeline para el Switch: {device_id} ---")
        
        # 1. Empujar redirección al portal cautivo
        portal_flow = self.generate_portal_redirect_json(device_id)
        self.push_flows(device_id, portal_flow)

        # 2. Empujar permitir DHCP/DNS
        dns_flow = self.generate_dns_dhcp_allow_json(device_id)
        self.push_flows(device_id, dns_flow)
        
        logger.info("--- Boot de Pipeline completado ---")

if __name__ == "__main__":
    # Ejemplo de ejecución al arrancar el sistema
    pipeline = ONOSProactivePipeline(onos_ip="192.168.1.50")
    
    # Imaginemos que este es tu switch troncal principal
    switch_principal = "of:0000000000000001"
    pipeline.boot_network(device_id=switch_principal)
