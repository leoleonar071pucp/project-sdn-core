from opentelemetry import trace, _logs
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

from .resources import ResourceFactory

class TelemetryConfig:
    service_name: str
    service_version: str
    collector_endpoint: str = "http://otel-collector:4318"
    environment: str = "development"
    instance_id: str | None = None

class Telemetry:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def initialize(self, config: TelemetryConfig) -> None:

        if self._initialized:
            return

        self._config = config

        resource = ResourceFactory.build(
            service_name=config.service_name,
            service_version=config.service_version,
            environment=config.environment,
            instance_id=config.instance_id,
        )

        # ---------------- TRACE ----------------
        tracer_provider = TracerProvider(resource=resource)

        span_exporter = OTLPSpanExporter(
            endpoint=f"{config.collector_endpoint}/v1/traces",
        )

        tracer_provider.add_span_processor(
            BatchSpanProcessor(span_exporter)
        )

        trace.set_tracer_provider(tracer_provider)

        self._tracer = trace.get_tracer(
            config.service_name,
            config.service_version,
        )

        # ---------------- LOGS ----------------
        logger_provider = LoggerProvider(resource=resource)

        log_exporter = OTLPLogExporter(
            endpoint=f"{config.collector_endpoint}/v1/logs",
        )

        logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(log_exporter)
        )

        _logs.set_logger_provider(logger_provider)

        self._logger_provider = logger_provider

        self._logger = logger_provider.get_logger(
            config.service_name,
            config.service_version,
        )

        self._initialized = True

    @property
    def tracer(self):
        return self._tracer

    @property
    def logger(self):
        return self._logger
    
    @property
    def config(self):
        return self._config