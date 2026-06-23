from app.incident_manager import IncidentManager
from app.models import (
    EventSource,
    RiskDecision,
    SecurityAction,
    SecurityEvent,
)


def test_does_not_repeat_identical_action():
    manager = IncidentManager()
    event = SecurityEvent(
        source=EventSource.M6,
        event_type="port_scan",
        src_ip="10.2.1.105",
    )
    decision = RiskDecision(
        score=60,
        confidence="medium",
        threat_type="port_scan",
        recommended_action=SecurityAction.TEMP_BLOCK,
    )

    incident, first_execute = manager.update(None, event, decision, 1)
    incident, second_execute = manager.update(incident, event, decision, 2)

    assert first_execute is True
    assert second_execute is False
