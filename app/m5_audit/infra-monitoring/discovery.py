from time import time
from models import (
    Device,
    FlowSummary,
    Link,
    NetworkSnapshot,
    PortStats,
)
from onos_client import OnosClient


class Discovery:

    def __init__(self, config):
        self.client = OnosClient(config)

    def collect(self) -> NetworkSnapshot:
        devices = self._discover_devices()

        return NetworkSnapshot(
            timestamp=time(),
            devices=devices,
            links=self._discover_links(),
            flows=self._discover_flows(devices),
            ports=self._discover_ports(devices),
        )


    def _discover_devices(self) -> dict[str, Device]:
        devices = {}

        response = self.client.get_devices()

        for item in response.get("devices", []):
            annotations = item["annotations"]
            device = Device(
                id=item["id"],
                available=item.get("available", False),
                role=item.get("role", ""),
                mgmAdd=annotations["managementAddress"],
                protocol=annotations["protocol"]
            )

            devices[device.id] = device

        return devices


    def _discover_links(self) -> dict[str, Link]:

        links = {}

        response = self.client.get_links()

        for item in response.get("links", []):
            src = item["src"]
            dst = item["dst"]

            link = Link(
                id=self._make_link_id(
                    src["device"],
                    src["port"],
                    dst["device"],
                    dst["port"],
                ),
                src_device=src["device"],
                src_port=str(src["port"]),
                dst_device=dst["device"],
                dst_port=str(dst["port"]),
                state=item.get("state", "ACTIVE"),
            )

            links[link.id] = link

        return links


    def _discover_flows(
        self,
        devices: dict[str, Device],
    ) -> dict[str, FlowSummary]:

        flows = {}

        for device in devices.values():
            flows[device.id] = self._discover_device_flows(device.id)

        return flows

    def _discover_device_flows(
        self,
        device_id: str,
    ) -> FlowSummary:

        response = self.client.get_flows(device_id)

        tables = {}

        total = 0

        for flow in response.get("flows", []):

            table = int(flow.get("tableId", 0))

            tables[table] = tables.get(table, 0) + 1

            total += 1

        return FlowSummary(
            device=device_id,
            total_flows=total,
            tables=tables,
        )


    def _discover_ports(
        self,
        devices: dict[str, Device],
    ) -> dict[str, PortStats]:

        ports = {}

        for device in devices.values():
            ports.update(
                self._discover_device_ports(device.id)
            )

        return ports

    def _discover_device_ports(
        self,
        device_id: str,
    ) -> dict[str, PortStats]:

        ports = {}

        response = self.client.get_port_statistics(device_id)

        for device in response.get("statistics", []):
            for item in device.get("ports", []):

                port = PortStats(
                    device=device_id,
                    port=str(item["port"]),

                    rx_bytes=item.get("bytesReceived", 0),
                    tx_bytes=item.get("bytesSent", 0),

                    rx_packets=item.get("packetsReceived", 0),
                    tx_packets=item.get("packetsSent", 0),

                    rx_errors=item.get("packetsRxErrors", 0),
                    tx_errors=item.get("packetsTxErrors", 0),

                    rx_dropped=item.get("packetsRxDropped", 0),
                    tx_dropped=item.get("packetsTxDropped", 0),
                )

                ports[self._make_port_id(device_id, port.port)] = port

        return ports


    @staticmethod
    def _make_link_id(
        src_device: str,
        src_port: str,
        dst_device: str,
        dst_port: str,
    ) -> str:

        return f"{src_device}:{src_port}->{dst_device}:{dst_port}"

    @staticmethod
    def _make_port_id(
        device_id: str,
        port: str,
    ) -> str:

        return f"{device_id}:{port}"