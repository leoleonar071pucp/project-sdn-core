from app.detector import FlowDetector, Thresholds
from app.models import FlowRecord


def record(dst, port, bytes_=100, packets=1):
    return FlowRecord(
        source="sflow",
        exporter="switch",
        src_ip="10.2.1.10",
        dst_ip=dst,
        dst_port=port,
        bytes=bytes_,
        packets=packets,
    )


def test_detects_port_scan_and_fan_out():
    detector = FlowDetector(
        Thresholds(unique_ports=3, unique_destinations=3, byte_threshold=10**9)
    )
    events = []
    for index in range(3):
        events = detector.observe(record(f"10.0.0.{index + 1}", 100 + index))
    types = {event["event_type"] for event in events}
    assert {"port_scan", "fan_out"} <= types


def test_detects_exfiltration():
    detector = FlowDetector(
        Thresholds(exfiltration_bytes=1000, byte_threshold=500)
    )
    events = detector.observe(record("10.0.0.30", 443, bytes_=1200))
    assert "possible_exfiltration" in {event["event_type"] for event in events}
