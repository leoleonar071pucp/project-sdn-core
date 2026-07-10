from collections.abc import Mapping

try:
    from opentelemetry import baggage
    from opentelemetry.context import attach, get_current
    OTEL_CONTEXT_OK = True
except ImportError:
    baggage = None
    attach = None
    get_current = None
    OTEL_CONTEXT_OK = False


class Context:
    """
    Distributed business context stored in OpenTelemetry Baggage.
    """

    _KEYS = (
        "context.id",
        "host.ip",
        "session.id",
        "user.id",
        "user.code",
        "role.name",
        "role2.name",
    )

    _LOCAL: dict[str, str] = {}

    @staticmethod
    def update(**values: str | None) -> None:
        """
        Add or update one or more context values.

        Example:
            Context.update(context_id="CTX-001", host_ip="192.168.1.1")
            Context.update(user_id="20201234", role_name="student")
            Context.update(session_id="S-123")
        """

        key_map = {
            "context_id": "context.id",
            "host_ip": "host.ip",
            "session_id": "session.id",
            "user_id": "user.id",
            "user_code": "user.code",
            "user_role": "role.name",
            "user_role2": "role2.name",
        }

        ctx = get_current() if OTEL_CONTEXT_OK else None

        for key, value in values.items():

            if value is None:
                continue

            baggage_key = key_map.get(key)

            if baggage_key is None:
                raise ValueError(f"Unknown context field: {key}")

            if not OTEL_CONTEXT_OK:
                Context._LOCAL[baggage_key] = value
                continue

            ctx = baggage.set_baggage(
                baggage_key,
                value,
                ctx,
            )

        if OTEL_CONTEXT_OK:
            attach(ctx)

    @staticmethod
    def get(key: str):
        if not OTEL_CONTEXT_OK:
            return Context._LOCAL.get(key)
        return baggage.get_baggage(key)

    @staticmethod
    def clear() -> None:

        if not OTEL_CONTEXT_OK:
            Context._LOCAL.clear()
            return

        ctx = get_current()

        for key in Context._KEYS:
            ctx = baggage.remove_baggage(key, ctx)

        attach(ctx)

    @staticmethod
    def to_dict() -> dict[str, str]:
        """
        Return only existing context values.
        """

        result: dict[str, str] = {}

        for key in Context._KEYS:

            if not OTEL_CONTEXT_OK:
                value = Context._LOCAL.get(key)
                if value is not None:
                    result[key] = value
                continue

            value = baggage.get_baggage(key)

            if value is not None:
                result[key] = value

        return result
