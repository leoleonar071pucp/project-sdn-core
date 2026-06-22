from app.correlator import EventCorrelator
from app.adapters.suricata_adapter import normalize_suricata_event
from app.models import EventSource, SecurityEvent


def test_suricata_and_m6_correlate_by_source_ip_without_mac():
    correlator = EventCorrelator(60)
    m6 = SecurityEvent(
        source=EventSource.M6,
        event_type="policy_denial",
        src_ip="10.2.1.10",
        src_mac="00:11:22:33:44:55",
    )
    suricata = SecurityEvent(
        source=EventSource.SURICATA,
        event_type="web_attack",
        src_ip="10.2.1.10",
    )
    correlator.add(m6)
    evidence = correlator.add(suricata)
    assert len(evidence.events) == 2
    assert evidence.sources == {EventSource.M6, EventSource.SURICATA}


def test_suricata_adapter_preserves_permanent_asset_context():
    event = normalize_suricata_event(
        {
            "event_id": "critical",
            "event_type": "alert",
            "src_ip": "10.2.1.10",
            "dest_ip": "10.0.0.30",
            "mirror_scope": "permanent",
            "asset_id": "grades",
            "alert": {"severity": 2, "signature": "demo"},
        }
    )
    assert event.metadata["mirror_scope"] == "permanent"
    assert event.metadata["asset_id"] == "grades"
