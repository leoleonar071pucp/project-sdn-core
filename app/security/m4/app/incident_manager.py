import hashlib
from datetime import datetime, timezone

from .models import (
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

        incident.score = decision.score
        incident.threat_type = decision.threat_type
        incident.recommended_action = decision.recommended_action
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
                "metadata": event.metadata,
            }
        ] + [
            item
            for item in incident.evidence
            if item.get("idempotency_key") != event.idempotency_key
        ][:49]
        incident.updated_at = datetime.now(timezone.utc)

        fingerprint = self.action_fingerprint(incident, decision)
        should_execute = (
            decision.recommended_action
            in {SecurityAction.MIRROR, SecurityAction.TEMP_BLOCK, SecurityAction.BLOCK}
            and fingerprint != incident.last_action_fingerprint
        )
        if should_execute:
            incident.last_action_fingerprint = fingerprint

        return incident, should_execute

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
