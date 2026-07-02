from collections.abc import Mapping
from typing import Any

from .telemetry import TelemetryConfig
from .context import Context
from .events import EventDefinition
from .telemetry import Telemetry

from opentelemetry.sdk._logs import LogRecord
from opentelemetry.sdk._logs.severity import SeverityNumber


_RESERVED_ATTRIBUTES = frozenset({
    "event.name",
    "event.domain",
    "context.id",
    "host.ip",
    "session.id",
    "user.id",
    # "user.code",
    "role.name",
    "role2.name",
})

_SEVERITY_MAP = {
    "INFO": SeverityNumber.INFO,
    "WARN": SeverityNumber.WARN,
    "ERROR": SeverityNumber.ERROR,
}

class Observability:

    def __init__(self, config: TelemetryConfig) -> None:
        self._telemetry = Telemetry()
        self._telemetry.initialize(config)

    # ------------------------------------------------------------------
    # Tracing
    # ------------------------------------------------------------------

    def span(self, name: str):
        return self._telemetry.tracer.start_as_current_span(name)

    # ------------------------------------------------------------------
    # Context
    # ------------------------------------------------------------------

    def update_context(
        self,
        *,
        context_id: str | None = None,
        host_ip: str | None = None,
        session_id: str | None = None,
        user_id: str | None = None,
        role: str | None = None,
        role2: str | None = None,
    ) -> None:
        """
        Add or update distributed context values.
        """

        Context.update(
            context_id=context_id,
            host_ip=host_ip,
            session_id=session_id,
            user_id=user_id,
            role=role,
            role2=role2,
        )

    def get_context(self) -> dict[str, Any]:
        return Context.to_dict()

    def clear_context(self) -> None:
        Context.clear()

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def event(
        self,
        event: EventDefinition,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:

        attrs = {
            "event.name": event.name,
            "event.domain": event.domain,
        }

        attrs.update(Context.to_dict())

        if attributes:

            duplicated = _RESERVED_ATTRIBUTES.intersection(attributes)

            if duplicated:
                duplicated = ", ".join(sorted(duplicated))
                raise ValueError(
                    f"Reserved attribute(s): {duplicated}"
                )

            attrs.update(attributes)

        try:
            record = LogRecord(
                body=event.message,
                severity_text=event.severity,
                severity_number=_SEVERITY_MAP[event.severity],
                attributes=attrs,
            )

            self._telemetry.logger.emit(record)

        except Exception as exc:
            print(f"[Observability] {exc}")
            return