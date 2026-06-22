import asyncio

from app.clients.m6_client import M6Client
from app.clients.telemetry_client import TelemetryClient
from app.config import Settings
from app.correlator import EventCorrelator
from app.incident_manager import IncidentManager
from app.models import EventSource, SecurityEvent
from app.repositories.event_repository import MemorySecurityRepository
from app.risk_engine import RiskEngine
from app.service import SecurityService


def test_multisource_incident_exposes_evidence_and_simulated_action():
    settings = Settings()
    repository = MemorySecurityRepository()
    service = SecurityService(
        repository,
        EventCorrelator(60),
        RiskEngine(),
        IncidentManager(),
        M6Client(settings),
        TelemetryClient(settings),
    )
    asyncio.run(
        service.process(
            SecurityEvent(
                source=EventSource.M6,
                event_type="policy_denial_burst",
                src_ip="10.2.1.10",
            )
        )
    )
    result = asyncio.run(
        service.process(
            SecurityEvent(
                source=EventSource.SURICATA,
                event_type="web_attack",
                src_ip="10.2.1.10",
            )
        )
    )
    assert len(result.incident.evidence) == 2
    assert result.action_result.status.value == "SIMULATED"
    assert result.incident.action_history
