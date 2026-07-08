from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Config:
    onos_host: str = os.getenv("ONOS_HOST", "192.168.201.200")  #192.168.201.200
    onos_port: int = int(os.getenv("ONOS_PORT", "8181"))

    username: str = os.getenv("ONOS_USERNAME", "onos")
    password: str = os.getenv("ONOS_PASSWORD", "rocks")

    poll_interval: int = int(os.getenv("POLL_INTERVAL", "5"))

    collector_host: str = os.getenv("COLLECTOR_HOST", "otel-collector")
    collector_port: int = int(os.getenv("COLLECTOR_PORT", "4318"))

    verify_ssl: bool = False
    timeout: int = 5

    max_flows_per_device: int = int(os.getenv("MAX_FLOWS_PER_DEVICE", "50"))
    max_port_errors: int = int(os.getenv("MAX_PORT_ERRORS", "15"))
    max_port_drops: int = int(os.getenv("MAX_PORT_DROPS", "25"))