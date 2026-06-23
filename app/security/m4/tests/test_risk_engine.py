from app.models import CorrelatedEvidence, EventSource, SecurityAction, SecurityEvent
from app.risk_engine import RiskEngine


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
