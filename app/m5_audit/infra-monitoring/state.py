from dataclasses import dataclass, field
from typing import Any
from models import NetworkSnapshot


@dataclass(slots=True)
class ResourceChanges:
    added: dict[str, Any] = field(default_factory=dict)
    removed: dict[str, Any] = field(default_factory=dict)
    changed: dict[str, tuple[Any, Any]] = field(default_factory=dict)

@dataclass(slots=True)
class PortDelta:
    device: str
    port: str
    durationSec: float

    delta_rx_bytes: int
    delta_tx_bytes: int

    delta_rx_packets: int
    delta_tx_packets: int

    delta_rx_errors: int
    delta_tx_errors: int

    delta_rx_dropped: int
    delta_tx_dropped: int

@dataclass(slots=True)
class FlowDelta:
    device: str
    delta_total_flows: int
    delta_tables: dict[int, int] = field(default_factory=dict)

@dataclass(slots=True)
class DiffResult:
    devices: ResourceChanges = field(default_factory=ResourceChanges)
    links: ResourceChanges = field(default_factory=ResourceChanges)
    flows: ResourceChanges = field(default_factory=ResourceChanges)
    flow_deltas: dict[str, FlowDelta] = field(default_factory=dict)
    ports: ResourceChanges = field(default_factory=ResourceChanges)
    port_deltas: dict[str, PortDelta] = field(default_factory=dict)

class State:

    def __init__(self):
        self.previous: NetworkSnapshot | None = None
        self.current: NetworkSnapshot | None = None

    @property
    def initialized(self) -> bool:
        return self.previous is not None

    def update(self, snapshot: NetworkSnapshot) -> DiffResult | None:
        previous = self.current
        self.previous = previous
        self.current = snapshot

        if previous is None:
            return None

        return self.diff()

    def diff(self) -> DiffResult:
        if not self.initialized:
            return DiffResult()

        return DiffResult(
            devices=self._compare(
                self.previous.devices,
                self.current.devices,
            ),
            links=self._compare(
                self.previous.links,
                self.current.links,
            ),
            flows=self._compare(
                self.previous.flows,
                self.current.flows,
            ),
            ports=self._compare(
                self.previous.ports,
                self.current.ports,
            ),
            port_deltas=self._calculate_port_deltas(),
            flow_deltas=self._calculate_flow_deltas(),
        )

    @staticmethod
    def _compare(previous: dict, current: dict) -> ResourceChanges:

        added_keys = current.keys() - previous.keys()
        removed_keys = previous.keys() - current.keys()
        common_keys = previous.keys() & current.keys()

        changes = ResourceChanges()

        changes.added = {
            key: current[key]
            for key in added_keys
        }

        changes.removed = {
            key: previous[key]
            for key in removed_keys
        }

        changes.changed = {
            key: (previous[key], current[key])
            for key in common_keys
            if previous[key] != current[key]
        }

        return changes
    
    def _calculate_port_deltas(self) -> dict[str, PortDelta]:

        deltas = {}

        common_ports = (
            self.previous.ports.keys()
            & self.current.ports.keys()
        )

        for key in common_ports:

            previous = self.previous.ports[key]
            current = self.current.ports[key]

            deltas[key] = PortDelta(
                device=current.device,
                port=current.port,
                durationSec=self.current.timestamp - self.previous.timestamp,

                delta_rx_bytes=max(0, current.rx_bytes - previous.rx_bytes),
                delta_tx_bytes=max(0, current.tx_bytes - previous.tx_bytes),

                delta_rx_packets=max(0, current.rx_packets - previous.rx_packets),
                delta_tx_packets=max(0, current.tx_packets - previous.tx_packets),

                delta_rx_errors=max(0, current.rx_errors - previous.rx_errors),
                delta_tx_errors=max(0, current.tx_errors - previous.tx_errors),

                delta_rx_dropped=max(0, current.rx_dropped - previous.rx_dropped),
                delta_tx_dropped=max(0, current.tx_dropped - previous.tx_dropped),
            )

        return deltas
    
    def _calculate_flow_deltas(self) -> dict[str, FlowDelta]:

        deltas = {}

        common_devices = (
            self.previous.flows.keys()
            & self.current.flows.keys()
        )

        for key in common_devices:

            previous = self.previous.flows[key]
            current = self.current.flows[key]

            tables = {}

            table_ids = (
                previous.tables.keys()
                | current.tables.keys()
            )

            for table in table_ids:

                tables[table] = (
                    current.tables.get(table, 0)
                    - previous.tables.get(table, 0)
                )

            deltas[key] = FlowDelta(
                device=current.device,
                delta_total_flows=(
                    current.total_flows
                    - previous.total_flows
                ),
                delta_tables=tables,
            )

        return deltas