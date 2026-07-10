from ..models import EventSource, SecurityEvent


def normalize_m6_event(payload: dict) -> SecurityEvent:
    normalized = dict(payload)
    normalized["source"] = EventSource.M6
    return SecurityEvent.model_validate(normalized)
