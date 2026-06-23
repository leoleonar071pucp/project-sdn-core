from datetime import datetime, timedelta, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class MirrorStatus(str, Enum):
    PLANNED = "PLANNED"
    SIMULATED = "SIMULATED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REMOVED = "REMOVED"
    FAILED = "FAILED"


class MirrorRequest(BaseModel):
    incident_id: str
    switch_dpid: str
    bridge: str | None = None
    source_port: str | None = None
    output_tunnel_port: str | None = None
    in_port: int | None = Field(default=None, ge=0)
    src_mac: str | None = None
    permanent: bool = False
    asset_id: str | None = None
    ttl_seconds: int = Field(default=300, ge=1, le=86400)


class MirrorRecord(BaseModel):
    mirror_id: str = Field(default_factory=lambda: f"mirror-{uuid4()}")
    incident_id: str
    switch_dpid: str
    bridge: str
    source_port: str
    output_tunnel_port: str
    in_port: int | None = None
    src_mac: str | None = None
    permanent: bool = False
    asset_id: str | None = None
    status: MirrorStatus = MirrorStatus.PLANNED
    create_operation: list[str] = Field(default_factory=list)
    delete_operation: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_request(cls, request: MirrorRequest, **resolved):
        expires_at = None
        if not request.permanent:
            expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=request.ttl_seconds
            )
        return cls(
            incident_id=request.incident_id,
            switch_dpid=request.switch_dpid,
            bridge=resolved["bridge"],
            source_port=resolved["source_port"],
            output_tunnel_port=resolved["output_tunnel_port"],
            in_port=request.in_port,
            src_mac=request.src_mac,
            permanent=request.permanent,
            asset_id=request.asset_id,
            expires_at=expires_at,
        )
