from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EventSource(str, Enum):
    M6 = "m6"
    SURICATA = "suricata"
    SFLOW = "sflow"
    NETFLOW = "netflow"


class SecurityAction(str, Enum):
    LOG = "LOG"
    WATCH = "WATCH"
    MIRROR = "MIRROR"
    TEMP_BLOCK = "TEMP_BLOCK"
    BLOCK = "BLOCK"
    UNBLOCK = "UNBLOCK"


class IncidentState(str, Enum):
    NEW = "NEW"
    WATCHING = "WATCHING"
    MIRRORING = "MIRRORING"
    CONTAINED = "CONTAINED"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


class ActionStatus(str, Enum):
    RECOMMENDED = "RECOMMENDED"
    SIMULATED = "SIMULATED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class SecurityEvent(BaseModel):
    idempotency_key: str = Field(default_factory=lambda: str(uuid4()))
    source: EventSource
    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    src_ip: str | None = None
    src_mac: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    switch_dpid: str | None = None
    in_port: int | None = Field(default=None, ge=0)
    username: str | None = None
    role: str | None = None
    severity: int = Field(default=0, ge=0, le=100)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def identity_key(self) -> str:
        if self.src_ip:
            return f"ip|{self.src_ip}"
        if self.src_mac:
            return f"mac|{self.src_mac.lower()}"
        return "|".join(
            [
                (self.src_mac or "unknown-mac").lower(),
                self.src_ip or "unknown-ip",
                self.switch_dpid or "unknown-switch",
                str(self.in_port if self.in_port is not None else "unknown-port"),
            ]
        )


class CorrelatedEvidence(BaseModel):
    incident_key: str
    events: list[SecurityEvent]
    sources: set[EventSource]


class RiskDecision(BaseModel):
    score: int = Field(ge=0, le=100)
    confidence: str
    threat_type: str
    recommended_action: SecurityAction
    reasons: list[str] = Field(default_factory=list)


class SecurityIncident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_key: str
    state: IncidentState = IncidentState.NEW
    score: int = 0
    threat_type: str = "unknown"
    recommended_action: SecurityAction = SecurityAction.LOG
    src_ip: str | None = None
    src_mac: str | None = None
    switch_dpid: str | None = None
    in_port: int | None = None
    event_count: int = 0
    mirror_mode: str = "temporary"
    critical_asset_id: str | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    action_history: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_action_fingerprint: str | None = None


class ActionResult(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    action: SecurityAction
    status: ActionStatus
    flow_ids: list[str] = Field(default_factory=list)
    devices: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    detail: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProcessedEventResponse(BaseModel):
    accepted: bool = True
    duplicate: bool = False
    incident: SecurityIncident | None = None
    decision: RiskDecision | None = None
    action_result: ActionResult | None = None
