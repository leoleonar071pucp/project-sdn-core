from app.models import CorrelatedEvidence, EventSource, SecurityAction, SecurityEvent
from app.risk_engine import RiskEngine
from app.adapters.suricata_adapter import normalize_suricata_event


def test_invalid_binding_recommends_temporary_block():
    event = SecurityEvent(
        source=EventSource.M6,
        event_type="invalid_ip_mac_binding",
        src_ip="10.2.1.105",
        severity=80,
    )
    evidence = CorrelatedEvidence(
        incident_key=event.identity_key(),
        events=[event],
        sources={EventSource.M6},
    )

    decision = RiskEngine().evaluate(evidence)

    assert decision.score == 80
    assert decision.recommended_action == SecurityAction.TEMP_BLOCK


def test_multiple_sources_add_correlation_score():
    events = [
        SecurityEvent(source=EventSource.M6, event_type="policy_denial_burst"),
        SecurityEvent(source=EventSource.SFLOW, event_type="traffic_spike"),
    ]
    evidence = CorrelatedEvidence(
        incident_key=events[0].identity_key(),
        events=events,
        sources={EventSource.M6, EventSource.SFLOW},
    )

    decision = RiskEngine().evaluate(evidence)

    assert decision.score == 80
    assert decision.recommended_action == SecurityAction.BLOCK


def test_suricata_syn_scan_maps_to_temporary_block():
    event = normalize_suricata_event(
        {
            "event_type": "alert",
            "src_ip": "192.168.100.55",
            "dest_ip": "192.168.100.101",
            "dest_port": 11,
            "proto": "TCP",
            "alert": {
                "signature_id": 9000001,
                "signature": "SDN DEMO TCP SYN port scan",
                "severity": 3,
            },
        }
    )
    evidence = CorrelatedEvidence(
        incident_key=event.identity_key(),
        events=[event],
        sources={EventSource.SURICATA},
    )

    decision = RiskEngine().evaluate(evidence)

    assert event.event_type == "port_scan"
    assert event.severity == 50
    assert decision.recommended_action == SecurityAction.TEMP_BLOCK


def test_suricata_sqli_maps_to_temporary_block():
    event = normalize_suricata_event(
        {
            "event_type": "alert",
            "src_ip": "192.168.100.55",
            "dest_ip": "192.168.100.101",
            "dest_port": 8001,
            "proto": "TCP",
            "alert": {
                "signature_id": 9000002,
                "signature": "SDN DEMO possible SQL injection",
                "severity": 2,
            },
        }
    )
    evidence = CorrelatedEvidence(
        incident_key=event.identity_key(),
        events=[event],
        sources={EventSource.SURICATA},
    )

    decision = RiskEngine().evaluate(evidence)

    assert event.event_type == "web_attack"
    assert event.severity == 70
    assert decision.recommended_action == SecurityAction.TEMP_BLOCK


def test_suricata_large_icmp_maps_to_temporary_block():
    event = normalize_suricata_event(
        {
            "event_type": "alert",
            "src_ip": "192.168.100.55",
            "dest_ip": "192.168.100.101",
            "proto": "ICMP",
            "alert": {
                "signature_id": 9000018,
                "signature": "SDN DEMO possible ICMP tunneling - large payload",
                "severity": 2,
            },
        }
    )
    evidence = CorrelatedEvidence(
        incident_key=event.identity_key(),
        events=[event],
        sources={EventSource.SURICATA},
    )

    decision = RiskEngine().evaluate(evidence)

    assert event.event_type == "icmp_large_payload"
    assert event.severity == 55
    assert decision.recommended_action == SecurityAction.TEMP_BLOCK
