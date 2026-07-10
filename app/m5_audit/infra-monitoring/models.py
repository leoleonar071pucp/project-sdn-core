from dataclasses import dataclass, field


@dataclass(slots=True)
class Device:
    id: str
    available: bool
    role: str
    mgmAdd: str
    protocol: str


@dataclass(slots=True)
class Link:
    id: str

    src_device: str
    src_port: str

    dst_device: str
    dst_port: str

    state: str


@dataclass(slots=True)
class FlowSummary:
    device: str
    total_flows: int
    tables: dict[int, int] = field(default_factory=dict)


@dataclass(slots=True)
class PortStats:
    device: str
    port: str

    rx_bytes: int
    tx_bytes: int

    rx_packets: int
    tx_packets: int

    rx_errors: int
    tx_errors: int

    rx_dropped: int
    tx_dropped: int


@dataclass(slots=True)
class NetworkSnapshot:
    timestamp: float

    devices: dict[str, Device] = field(default_factory=dict)
    links: dict[str, Link] = field(default_factory=dict)
    flows: dict[str, FlowSummary] = field(default_factory=dict)
    ports: dict[str, PortStats] = field(default_factory=dict)