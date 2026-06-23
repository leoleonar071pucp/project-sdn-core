from uuid import uuid4

from ..models import EventSource, SecurityEvent


def normalize_sflow_event(payload: dict) -> SecurityEvent:
    data = dict(
        idempotency_key=payload.get("idempotency_key") or str(uuid4()),
        source=EventSource.SFLOW,
        event_type=payload.get("event_type", "traffic_spike"),
        src_ip=payload.get("src_ip"),
        src_mac=payload.get("src_mac"),
        dst_ip=payload.get("dst_ip"),
        dst_port=payload.get("dst_port"),
        protocol=payload.get("protocol"),
        switch_dpid=payload.get("switch_dpid"),
        in_port=payload.get("in_port"),
        severity=payload.get("severity", 30),
        metadata=payload.get("metadata", {}),
    )
    if payload.get("timestamp"):
        data["timestamp"] = payload["timestamp"]
    return SecurityEvent(**data)
