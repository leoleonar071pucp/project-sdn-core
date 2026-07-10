from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from time import time
from uuid import uuid4

from .models import FlowRecord


@dataclass
class Thresholds:
    window_seconds: int = 60
    byte_threshold: int = 100_000_000
    packet_threshold: int = 100_000
    unique_destinations: int = 20
    unique_ports: int = 30
    exfiltration_bytes: int = 500_000_000
    max_sources: int = 10000


class FlowDetector:
    def __init__(self, thresholds: Thresholds | None = None, clock=time):
        self.thresholds = thresholds or Thresholds()
        self.clock = clock
        self.windows: dict[str, deque[tuple[float, FlowRecord]]] = defaultdict(deque)

    def observe(self, record: FlowRecord) -> list[dict]:
        now = self.clock()
        if record.src_ip not in self.windows and len(self.windows) >= self.thresholds.max_sources:
            oldest = next(iter(self.windows))
            del self.windows[oldest]
        bucket = self.windows[record.src_ip]
        bucket.append((now, record))
        while bucket and now - bucket[0][0] > self.thresholds.window_seconds:
            bucket.popleft()
        return self._events(record, [item[1] for item in bucket])

    def _events(self, current: FlowRecord, records: list[FlowRecord]) -> list[dict]:
        total_bytes = sum(item.bytes for item in records)
        total_packets = sum(item.packets for item in records)
        destinations = {item.dst_ip for item in records}
        ports = {item.dst_port for item in records if item.dst_port}
        candidates = []
        if len(ports) >= self.thresholds.unique_ports:
            candidates.append(("port_scan", 55))
        if len(destinations) >= self.thresholds.unique_destinations:
            candidates.append(("fan_out", 45))
        if total_packets >= self.thresholds.packet_threshold:
            candidates.append(("possible_ddos", 65))
        if total_bytes >= self.thresholds.exfiltration_bytes and len(destinations) <= 3:
            candidates.append(("possible_exfiltration", 60))
        elif total_bytes >= self.thresholds.byte_threshold:
            candidates.append(("traffic_spike", 35))
        return [
            {
                "idempotency_key": str(uuid4()),
                "source": current.source,
                "event_type": event_type,
                "timestamp": current.timestamp,
                "src_ip": current.src_ip,
                "dst_ip": current.dst_ip,
                "dst_port": current.dst_port,
                "protocol": str(current.protocol),
                "severity": severity,
                "metadata": {
                    "exporter": current.exporter,
                    "bytes": total_bytes,
                    "packets": total_packets,
                    "unique_destinations": len(destinations),
                    "unique_ports": len(ports),
                    "window_seconds": self.thresholds.window_seconds,
                    "input_if": current.input_if,
                    "output_if": current.output_if,
                    "sampling_rate": current.sampling_rate,
                },
            }
            for event_type, severity in candidates
        ]
