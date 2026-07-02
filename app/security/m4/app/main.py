from fastapi import Depends, FastAPI, Header, HTTPException, status

from .adapters import (
    normalize_m6_event,
    normalize_netflow_event,
    normalize_sflow_event,
    normalize_suricata_event,
)
from .clients import M6Client, TelemetryClient
from .config import Settings, get_settings
from .correlator import EventCorrelator
from .incident_manager import IncidentManager
from .models import ProcessedEventResponse, SecurityEvent
from .repositories import MemorySecurityRepository, MySQLSecurityRepository
from .risk_engine import RiskEngine
from .service import SecurityService


def build_service(settings: Settings) -> SecurityService:
    repository = (
        MySQLSecurityRepository(settings)
        if settings.mysql_persistence_enabled
        else MemorySecurityRepository()
    )
    return SecurityService(
        repository=repository,
        correlator=EventCorrelator(settings.event_window_seconds),
        risk_engine=RiskEngine(),
        incident_manager=IncidentManager(),
        m6_client=M6Client(settings),
        telemetry_client=TelemetryClient(settings),
    )


settings = get_settings()
service = build_service(settings)
app = FastAPI(title="M4 Security Correlator", version="0.1.0")


def require_security_token(
    x_security_token: str | None = Header(default=None),
) -> None:
    if x_security_token != settings.security_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid security token",
        )


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "network_actions_enabled": settings.network_actions_enabled,
        "onos_writes_enabled": settings.onos_writes_enabled,
        "ovsdb_actions_enabled": settings.ovsdb_actions_enabled,
        "automatic_actions_enabled": settings.m4_automatic_actions_enabled,
        "persistence": (
            "mysql" if settings.mysql_persistence_enabled else "memory"
        ),
    }


@app.post(
    "/m4/events",
    response_model=ProcessedEventResponse,
    dependencies=[Depends(require_security_token)],
)
async def receive_normalized_event(
    event: SecurityEvent,
) -> ProcessedEventResponse:
    return await service.process(event)


@app.post(
    "/m4/events/m6",
    response_model=ProcessedEventResponse,
    dependencies=[Depends(require_security_token)],
)
async def receive_m6_event(payload: dict) -> ProcessedEventResponse:
    return await service.process(normalize_m6_event(payload))


@app.post(
    "/m4/events/suricata",
    response_model=ProcessedEventResponse,
    dependencies=[Depends(require_security_token)],
)
async def receive_suricata_event(payload: dict) -> ProcessedEventResponse:
    if not settings.suricata_ingestion_enabled:
        raise HTTPException(status_code=503, detail="Suricata ingestion is disabled")
    return await service.process(normalize_suricata_event(payload))


@app.post(
    "/m4/events/telemetry",
    response_model=ProcessedEventResponse,
    dependencies=[Depends(require_security_token)],
)
async def receive_telemetry_event(payload: dict) -> ProcessedEventResponse:
    if not settings.flow_telemetry_ingestion_enabled:
        raise HTTPException(status_code=503, detail="Telemetry ingestion is disabled")
    source = str(payload.get("source", "sflow")).lower()
    event = (
        normalize_netflow_event(payload)
        if source == "netflow"
        else normalize_sflow_event(payload)
    )
    return await service.process(event)


@app.get(
    "/m4/incidents",
    dependencies=[Depends(require_security_token)],
)
def list_incidents() -> list:
    return service.repository.list_incidents()


@app.get(
    "/m4/incidents/{incident_id}",
    dependencies=[Depends(require_security_token)],
)
def get_incident(incident_id: str):
    incident = service.repository.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@app.post(
    "/m4/incidents/{incident_id}/expire",
    dependencies=[Depends(require_security_token)],
)
def expire_incident(incident_id: str) -> dict:
    if not service.mark_incident_expired(incident_id):
        raise HTTPException(status_code=404, detail="incident not found")
    return {"ok": True, "incident_id": incident_id, "state": "EXPIRED"}
