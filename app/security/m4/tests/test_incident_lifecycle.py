from datetime import datetime, timedelta, timezone

from app.incident_manager import IncidentManager
from app.models import (
    ActionStatus,
    IncidentState,
    RiskDecision,
    SecurityAction,
    SecurityEvent,
    SecurityIncident,
)


def decision(action=SecurityAction.TEMP_BLOCK):
    return RiskDecision(
        score=70,
        confidence="high",
        threat_type="web_attack",
        recommended_action=action,
        reasons=["test"],
    )


def event():
    return SecurityEvent(
        source="suricata",
        event_type="web_attack",
        src_ip="192.168.100.55",
    )


def executed_action(expires_at):
    return {
        "action": SecurityAction.TEMP_BLOCK.value,
        "status": ActionStatus.EXECUTED.value,
        "expires_at": expires_at.isoformat(),
    }


def test_active_mitigation_does_not_execute_again():
    manager = IncidentManager()
    incident = SecurityIncident(
        incident_key="ip|192.168.100.55",
        src_ip="192.168.100.55",
        state=IncidentState.CONTAINED,
        recommended_action=SecurityAction.TEMP_BLOCK,
        action_history=[
            executed_action(datetime.now(timezone.utc) + timedelta(minutes=5))
        ],
    )

    updated, should_execute = manager.update(
        incident,
        event(),
        decision(),
        event_count=2,
    )

    assert updated.state == IncidentState.CONTAINED
    assert should_execute is False


def test_expired_mitigation_reopens_and_executes_again():
    manager = IncidentManager()
    incident = SecurityIncident(
        incident_key="ip|192.168.100.55",
        src_ip="192.168.100.55",
        state=IncidentState.CONTAINED,
        recommended_action=SecurityAction.TEMP_BLOCK,
        last_action_fingerprint="old",
        action_history=[
            executed_action(datetime.now(timezone.utc) - timedelta(minutes=5))
        ],
    )

    updated, should_execute = manager.update(
        incident,
        event(),
        decision(),
        event_count=2,
    )

    assert updated.state == IncidentState.REOPENED
    assert updated.last_action_fingerprint != "old"
    assert should_execute is True


def test_mark_expired_clears_action_fingerprint():
    manager = IncidentManager()
    incident = SecurityIncident(
        incident_key="ip|192.168.100.55",
        state=IncidentState.CONTAINED,
        last_action_fingerprint="old",
    )

    manager.mark_expired(incident)

    assert incident.state == IncidentState.EXPIRED
    assert incident.last_action_fingerprint is None
