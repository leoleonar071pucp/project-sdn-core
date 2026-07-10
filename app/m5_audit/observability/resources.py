import socket

from opentelemetry.sdk.resources import Resource


class ResourceFactory:
    """Factory for OpenTelemetry Resources."""

    @staticmethod
    def build(
        service_name: str,
        service_version: str,
        environment: str = "development",
        instance_id: str | None = None,
    ) -> Resource:

        if instance_id is None:
            instance_id = socket.gethostname()

        return Resource.create(
            {
                "service.name": service_name,
                "service.version": service_version,
                "service.instance.id": instance_id,
                "deployment.environment": environment,
            }
        )