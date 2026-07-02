from uuid import uuid4

from ..models import EventSource, SecurityEvent


SURICATA_SID_POLICY = {
    9000001: ("port_scan", 50),
    9000008: ("port_scan", 50),
    9000009: ("port_scan", 50),
    9000010: ("port_scan", 50),
    9000002: ("web_attack", 70),
    9000014: ("web_attack", 70),
    9000018: ("suricata_medium", 45),
    9000027: ("suricata_medium", 50),
    9000028: ("suricata_medium", 50),
    9000029: ("suricata_medium", 50),
    9000015: ("suricata_high", 70),
    9000013: ("suricata_high", 70),
    9000012: ("suricata_high", 70),
    9000026: ("suricata_medium", 50),
    9000037: ("suricata_medium", 50),
    9000024: ("suricata_medium", 50),
    9000036: ("suricata_high", 70),
}


def normalize_suricata_event(payload: dict) -> SecurityEvent:
    alert = payload.get("alert", {})
    raw_type = payload.get("event_type", "alert")
    signature_id = alert.get("signature_id")
    try:
        signature_id = int(signature_id) if signature_id is not None else None
    except (TypeError, ValueError):
        signature_id = None
    numeric_severity = int(alert.get("severity", 3))
    if signature_id in SURICATA_SID_POLICY:
        event_type, severity = SURICATA_SID_POLICY[signature_id]
    elif raw_type == "alert":
        event_type = "suricata_critical" if numeric_severity == 1 else "web_attack"
        severity = {1: 90, 2: 60, 3: 30}.get(numeric_severity, 20)
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
            "signature_id": signature_id,
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
