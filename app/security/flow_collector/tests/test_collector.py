from app.collector import FlowCollector
from app.detector import FlowDetector, Thresholds
from app.models import FlowRecord


def test_rejects_oversized_datagram_without_parsing():
    collector = FlowCollector(FlowDetector(), max_datagram_size=10)
    result = collector.process_datagram("sflow", b"x" * 11, "switch")
    assert result["accepted"] is False


def test_dry_run_sender_never_calls_http(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("HTTP is forbidden in dry-run")

    monkeypatch.setattr("app.collector.httpx.post", forbidden)
    collector = FlowCollector(
        FlowDetector(Thresholds(byte_threshold=1)),
        dry_run=True,
        output_path=tmp_path / "events.jsonl",
    )
    collector._send(
        {
            "source": "sflow",
            "event_type": "traffic_spike",
            "src_ip": "10.0.0.1",
        }
    )
    assert collector.output_path.exists()
