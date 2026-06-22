from uuid import uuid4

from ..models import EventSource, SecurityEvent


def normalize_suricata_event(payload: dict) -> SecurityEvent:
    alert = payload.get("alert", {})
    raw_type = payload.get("event_type", "alert")
    numeric_severity = int(alert.get("severity", 3))
    severity = {1: 90, 2: 60, 3: 30}.get(numeric_severity, 20)
    if raw_type == "alert":
        event_type = "suricata_critical" if numeric_severity == 1 else "web_attack"
    else:
        event_type = f"suricata_{raw_type}"
        severity = {"anomaly": 40, "http": 15, "tls": 10, "flow": 5}.get(
            raw_type, 10
        )
    data = dict(
        idempotency_key=str(
            payload.get("flow_id") or payload.get("event_id") or uuid4()
        ),
        source=EventSource.SURICATA,
        event_type=event_type,
        src_ip=payload.get("src_ip"),
        dst_ip=payload.get("dest_ip"),
        dst_port=payload.get("dest_port"),
        protocol=payload.get("proto"),
        severity=severity,
        metadata={
            "sensor_id": payload.get("sensor_id") or payload.get("host"),
            "mirror_scope": payload.get("mirror_scope"),
            "asset_id": payload.get("asset_id"),
            "suricata_event_type": raw_type,
            "signature": alert.get("signature"),
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category"),
            "http": payload.get("http"),
            "tls": payload.get("tls"),
            "flow": payload.get("flow"),
            "anomaly": payload.get("anomaly"),
        },
    )
    if payload.get("timestamp"):
        data["timestamp"] = payload["timestamp"]
    return SecurityEvent(**data)
