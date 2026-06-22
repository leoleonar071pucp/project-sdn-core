from .clients.m6_client import M6Client
from .clients.telemetry_client import TelemetryClient
from .correlator import EventCorrelator
from .incident_manager import IncidentManager
from .models import (
    ActionStatus,
    IncidentState,
    ProcessedEventResponse,
    SecurityAction,
    SecurityEvent,
)
from .repositories.event_repository import SecurityRepository
from .risk_engine import RiskEngine


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
        if not self.repository.add_event(event):
            return ProcessedEventResponse(duplicate=True)

        evidence = self.correlator.add(event)
        decision = self.risk_engine.evaluate(evidence)
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
            if decision.recommended_action == SecurityAction.MIRROR:
                action_result = await self.telemetry_client.activate_mirror(incident)
            else:
                action_result = await self.m6_client.execute(
                    incident,
                    decision.recommended_action,
                )
            self.repository.save_action(action_result)
            incident.action_history = [
                action_result.model_dump(mode="json")
            ] + incident.action_history[:49]
            if action_result.status in {
                ActionStatus.SIMULATED,
                ActionStatus.FAILED,
            }:
                incident.state = IncidentState.WATCHING
            self.repository.save_incident(incident)

        return ProcessedEventResponse(
            incident=incident,
            decision=decision,
            action_result=action_result,
        )
