from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Callable

import httpx

from .detector import FlowDetector
from .parsers import FlowParseError, parse_netflow_v5, parse_sflow_v5


class FlowCollector:
    def __init__(
        self,
        detector: FlowDetector,
        dry_run: bool = True,
        output_path: Path = Path("./state/telemetry-events.jsonl"),
        m4_url: str = "http://m4:8084",
        token: str = "change-me",
        sender: Callable[[dict], None] | None = None,
        max_datagram_size: int = 65535,
    ):
        self.detector = detector
        self.dry_run = dry_run
        self.output_path = output_path
        self.m4_url = m4_url
        self.token = token
        self.sender = sender or self._send
        self.max_datagram_size = max_datagram_size

    def process_datagram(self, protocol: str, data: bytes, exporter: str) -> dict:
        if len(data) > self.max_datagram_size:
            return {"accepted": False, "error": "datagram too large"}
        try:
            records = (
                parse_sflow_v5(data, exporter)
                if protocol == "sflow"
                else parse_netflow_v5(data, exporter)
            )
        except FlowParseError as exc:
            return {"accepted": False, "error": str(exc)}
        events = []
        for record in records:
            for event in self.detector.observe(record):
                self.sender(event)
                events.append(event)
        return {"accepted": True, "records": len(records), "events": events}

    def _send(self, event: dict) -> None:
        if self.dry_run:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with self.output_path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(event) + "\n")
            return
        response = httpx.post(
            f"{self.m4_url}/m4/events/telemetry",
            json=event,
            headers={"X-Security-Token": self.token},
            timeout=3,
        )
        response.raise_for_status()

    def serve_udp(self, protocol: str, host: str, port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind((host, port))
            while True:
                data, address = server.recvfrom(self.max_datagram_size + 1)
                self.process_datagram(protocol, data, address[0])
