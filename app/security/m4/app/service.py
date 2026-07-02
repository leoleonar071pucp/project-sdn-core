import logging

from .clients.m6_client import M6Client
from .clients.telemetry_client import TelemetryClient
from .correlator import EventCorrelator
from .incident_manager import IncidentManager, STATE_BY_ACTION
from .models import (
    ActionStatus,
    IncidentState,
    ProcessedEventResponse,
    SecurityAction,
    SecurityEvent,
)
from .repositories.event_repository import SecurityRepository
from .risk_engine import RiskEngine


logger = logging.getLogger(__name__)


class SecurityService:
    def __init__(
        self,
        repository: SecurityRepository,
        correlator: EventCorrelator,
        risk_engine: RiskEngine,
        incident_manager: IncidentManager,
        m6_client: M6Client,
        telemetry_client: TelemetryClient,
    ):
        self.repository = repository
        self.correlator = correlator
        self.risk_engine = risk_engine
        self.incident_manager = incident_manager
        self.m6_client = m6_client
        self.telemetry_client = telemetry_client

    async def process(self, event: SecurityEvent) -> ProcessedEventResponse:
        logger.info(
            "security_event_received source=%s type=%s src_ip=%s dst_ip=%s dst_port=%s",
            event.source.value,
            event.event_type,
            event.src_ip,
            event.dst_ip,
            event.dst_port,
        )
        if not self.repository.add_event(event):
            logger.info(
                "security_event_duplicate idempotency_key=%s source=%s",
                event.idempotency_key,
                event.source.value,
            )
            return ProcessedEventResponse(duplicate=True)

        evidence = self.correlator.add(event)
        decision = self.risk_engine.evaluate(evidence)
        logger.info(
            "risk_decision incident_key=%s score=%s action=%s reasons=%s",
            evidence.incident_key,
            decision.score,
            decision.recommended_action.value,
            decision.reasons,
        )
        current = self.repository.get_incident_by_key(evidence.incident_key)
        incident, should_execute = self.incident_manager.update(
            current,
            event,
            decision,
            event_count=len(evidence.events),
        )
        self.repository.save_incident(incident)

        action_result = None
        if should_execute:
            incident.state = IncidentState.MITIGATING
            self.repository.save_incident(incident)
            logger.info(
                "security_action_requested incident_id=%s action=%s src_ip=%s",
                incident.incident_id,
                decision.recommended_action.value,
                incident.src_ip,
            )
            if decision.recommended_action == SecurityAction.MIRROR:
                action_result = await self.telemetry_client.activate_mirror(incident)
            else:
                action_result = await self.m6_client.execute(
                    incident,
                    decision.recommended_action,
                )
            logger.info(
                "security_action_result incident_id=%s action=%s status=%s detail=%s",
                incident.incident_id,
                action_result.action.value,
                action_result.status.value,
                action_result.detail,
            )
            self.repository.save_action(action_result)
            incident.action_history = [
                action_result.model_dump(mode="json")
            ] + incident.action_history[:49]
            if action_result.status == ActionStatus.EXECUTED:
                incident.state = STATE_BY_ACTION[action_result.action]
            else:
                incident.state = IncidentState.WATCHING
            self.repository.save_incident(incident)

        return ProcessedEventResponse(
            incident=incident,
            decision=decision,
            action_result=action_result,
        )

    def mark_incident_expired(self, incident_id: str) -> bool:
        incident = self.repository.get_incident(incident_id)
        if incident is None:
            return False
        self.incident_manager.mark_expired(incident)
        self.repository.save_incident(incident)
        logger.info("incident_marked_expired incident_id=%s", incident_id)
        return True
