from app.correlator import EventCorrelator
from app.models import EventSource, SecurityEvent


def test_correlates_events_for_same_network_identity():
    correlator = EventCorrelator(window_seconds=60)
    first = SecurityEvent(
        source=EventSource.M6,
        event_type="policy_denial",
        src_ip="10.2.1.105",
        src_mac="00:11:22:33:44:55",
        switch_dpid="of:1",
        in_port=2,
    )
    second = first.model_copy(
        update={"idempotency_key": "second", "event_type": "port_scan"}
    )

    correlator.add(first)
    evidence = correlator.add(second)

    assert len(evidence.events) == 2
    assert evidence.incident_key == first.identity_key()
