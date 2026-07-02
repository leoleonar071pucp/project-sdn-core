import hashlib
from datetime import datetime, timezone
from typing import Any

from .models import (
    ActionStatus,
    IncidentState,
    RiskDecision,
    SecurityAction,
    SecurityEvent,
    SecurityIncident,
)


STATE_BY_ACTION = {
    SecurityAction.LOG: IncidentState.NEW,
    SecurityAction.WATCH: IncidentState.WATCHING,
    SecurityAction.MIRROR: IncidentState.MIRRORING,
    SecurityAction.TEMP_BLOCK: IncidentState.CONTAINED,
    SecurityAction.BLOCK: IncidentState.BLOCKED,
    SecurityAction.UNBLOCK: IncidentState.CLOSED,
}

ACTIONABLE = {
    SecurityAction.MIRROR,
    SecurityAction.TEMP_BLOCK,
    SecurityAction.BLOCK,
}

ACTIVE_STATES = {
    IncidentState.MIRRORING,
    IncidentState.CONTAINED,
    IncidentState.BLOCKED,
}


class IncidentManager:
    def update(
        self,
        incident: SecurityIncident | None,
        event: SecurityEvent,
        decision: RiskDecision,
        event_count: int,
    ) -> tuple[SecurityIncident, bool]:
        if incident is None:
            incident = SecurityIncident(
                incident_key=event.identity_key(),
                src_ip=event.src_ip,
                src_mac=event.src_mac,
                switch_dpid=event.switch_dpid,
                in_port=event.in_port,
            )
        else:
            self.refresh_expiration_state(incident)

        incident.score = decision.score
        incident.threat_type = decision.threat_type
        incident.recommended_action = decision.recommended_action
        if (
            incident.state == IncidentState.EXPIRED
            and decision.recommended_action in ACTIONABLE
        ):
            incident.state = IncidentState.REOPENED
        elif decision.recommended_action not in ACTIONABLE:
            incident.state = STATE_BY_ACTION[decision.recommended_action]
        incident.event_count = event_count
        if event.metadata.get("mirror_scope") == "permanent":
            incident.mirror_mode = "permanent"
        incident.critical_asset_id = (
            event.metadata.get("asset_id") or incident.critical_asset_id
        )
        incident.evidence = [
            {
                "idempotency_key": event.idempotency_key,
                "source": event.source.value,
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "severity": event.severity,
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "protocol": event.protocol,
                "metadata": event.metadata,
            }
        ] + [
            item
            for item in incident.evidence
            if item.get("idempotency_key") != event.idempotency_key
        ][:49]
        incident.updated_at = datetime.now(timezone.utc)

        fingerprint = self.action_fingerprint(incident, decision)
        has_active_action = self.has_active_action(
            incident,
            decision.recommended_action,
        )
        should_execute = (
            decision.recommended_action in ACTIONABLE
            and not has_active_action
        )
        if should_execute:
            incident.last_action_fingerprint = fingerprint

        return incident, should_execute

    def refresh_expiration_state(self, incident: SecurityIncident) -> bool:
        if incident.state not in ACTIVE_STATES:
            return False
        if self.has_active_action(incident, incident.recommended_action):
            return False
        incident.state = IncidentState.EXPIRED
        incident.last_action_fingerprint = None
        return True

    def mark_expired(self, incident: SecurityIncident) -> SecurityIncident:
        incident.state = IncidentState.EXPIRED
        incident.last_action_fingerprint = None
        incident.updated_at = datetime.now(timezone.utc)
        return incident

    @classmethod
    def has_active_action(
        cls,
        incident: SecurityIncident,
        action: SecurityAction,
    ) -> bool:
        now = datetime.now(timezone.utc)
        for item in incident.action_history:
            if item.get("action") != action.value:
                continue
            if item.get("status") != ActionStatus.EXECUTED.value:
                continue
            expires_at = cls._parse_datetime(item.get("expires_at"))
            if expires_at is None or expires_at > now:
                return True
            return False
        return False

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            normalized = value.replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(normalized)
            except ValueError:
                return None
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return None

    @staticmethod
    def action_fingerprint(
        incident: SecurityIncident,
        decision: RiskDecision,
    ) -> str:
        raw = "|".join(
            [
                incident.incident_id,
                decision.recommended_action.value,
                incident.src_ip or "",
                incident.src_mac or "",
                incident.switch_dpid or "",
                str(incident.in_port or ""),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
