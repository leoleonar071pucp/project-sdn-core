from uuid import uuid4

from ..models import EventSource, SecurityEvent


def normalize_netflow_event(payload: dict) -> SecurityEvent:
    data = dict(
        idempotency_key=payload.get("idempotency_key") or str(uuid4()),
        source=EventSource.NETFLOW,
        event_type=payload.get("event_type", "possible_exfiltration"),
        src_ip=payload.get("src_ip"),
        src_mac=payload.get("src_mac"),
        dst_ip=payload.get("dst_ip"),
        dst_port=payload.get("dst_port"),
        protocol=payload.get("protocol"),
        severity=payload.get("severity", 50),
        metadata=payload.get("metadata", {}),
    )
    if payload.get("timestamp"):
        data["timestamp"] = payload["timestamp"]
    return SecurityEvent(**data)
