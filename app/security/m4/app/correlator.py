from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from .models import CorrelatedEvidence, SecurityEvent


class EventCorrelator:
    def __init__(self, window_seconds: int = 60):
        self.window = timedelta(seconds=window_seconds)
        self._events: dict[str, deque[SecurityEvent]] = defaultdict(deque)

    def add(self, event: SecurityEvent) -> CorrelatedEvidence:
        key = event.identity_key()
        bucket = self._events[key]
        bucket.append(event)

        now = datetime.now(timezone.utc)
        while bucket and now - bucket[0].timestamp > self.window:
            bucket.popleft()

        events = list(bucket)
        return CorrelatedEvidence(
            incident_key=key,
            events=events,
            sources={item.source for item in events},
        )
