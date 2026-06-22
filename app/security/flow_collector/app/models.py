from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class FlowRecord:
    source: str
    exporter: str
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    packets: int = 0
    bytes: int = 0
    input_if: int = 0
    output_if: int = 0
    sampling_rate: int = 1
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def as_dict(self) -> dict:
        return asdict(self)
