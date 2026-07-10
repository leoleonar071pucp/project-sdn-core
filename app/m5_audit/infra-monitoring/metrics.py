from opentelemetry import metrics
from opentelemetry.metrics import Observation

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter


class Metrics:
    """
    Publishes ONOS infrastructure metrics using OpenTelemetry Metrics.

    The monitor periodically updates the current network snapshot.
    ObservableGauge callbacks read that snapshot whenever the SDK
    performs a metrics collection.
    """

    def __init__(self, config):

        self.snapshot = None
        self.diff = None

        resource = Resource.create(
            {
                "service.name": "m5_observability",
                "service.version": "1.0.0",
                "service.instance.id": "m5_observability",
            }
        )

        exporter = OTLPMetricExporter(
            endpoint=(
                f"http://{config.collector_host}:"f"{config.collector_port}/v1/metrics"
            )
        )

        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=config.poll_interval * 2000,
        )

        provider = MeterProvider(
            resource=resource,
            metric_readers=[reader],
        )

        metrics.set_meter_provider(provider)

        self.provider = provider

        self.meter = metrics.get_meter(
            "m5_observability",
            "1.0.0",
        )


        self.meter.create_observable_gauge(
            name="onos.switches.total",
            description="Total switches",
            callbacks=[self._observe_switches_total],
        )

        self.meter.create_observable_gauge(
            name="onos.switches.available",
            description="Available switches",
            callbacks=[self._observe_switches_available],
        )

        self.meter.create_observable_gauge(
            name="onos.links.total",
            description="Total links",
            callbacks=[self._observe_links_total],
        )

        self.meter.create_observable_gauge(
            name="onos.links.active",
            description="Active links",
            callbacks=[self._observe_links_active],
        )


        self.meter.create_observable_gauge(
            name="onos.device.available",
            description="Switch availability",
            callbacks=[self._observe_device_available],
        )

        self.meter.create_observable_gauge(
            name="onos.device.flows",
            description="Flows installed per switch",
            callbacks=[self._observe_device_flows],
        )

        self.meter.create_observable_gauge(
            name="onos.device.table.flows",
            description="Flows per OpenFlow table",
            callbacks=[self._observe_table_flows],
        )


        port_metrics = [
            ("rx_bytes", "onos.port.rx.bytes"),
            ("tx_bytes", "onos.port.tx.bytes"),
            ("rx_packets", "onos.port.rx.packets"),
            ("tx_packets", "onos.port.tx.packets"),
            ("rx_errors", "onos.port.rx.errors"),
            ("tx_errors", "onos.port.tx.errors"),
            ("rx_dropped", "onos.port.rx.dropped"),
            ("tx_dropped", "onos.port.tx.dropped"),
        ]

        for field, metric_name in port_metrics:

            self.meter.create_observable_gauge(
                name=metric_name,
                description=field,
                callbacks=[
                    self._build_port_callback(field)
                ],
            )


        self.meter.create_observable_gauge(
            name="onos.device.flows.delta",
            description="New flows installed since previous snapshot",
            callbacks=[self._observe_flow_deltas],
        )

        self.meter.create_observable_gauge(
            name="onos.device.table.flows.delta",
            description="Flow delta per OpenFlow table",
            callbacks=[self._observe_table_flow_deltas],
        )

        
        self.meter.create_observable_gauge(
            name="onos.port.rx.bps",
            description="RX bandwidth per port in bits per second",
            callbacks=[
                self._observe_port_rx_bps
            ],
        )

        self.meter.create_observable_gauge(
            name="onos.port.tx.bps",
            description="TX bandwidth per port in bits per second",
            callbacks=[
                self._observe_port_tx_bps
            ],
        )

    def set_snapshot(self, snapshot, diff=None):
        self.snapshot = snapshot
        self.diff = diff

    def _observe_switches_total(self, options):
        if self.snapshot is None:
            return

        yield Observation(
            value=len(self.snapshot.devices),
            attributes={},
        )

    def _observe_switches_available(self, options):
        if self.snapshot is None:
            return

        available = sum(
            device.available
            for device in self.snapshot.devices.values()
        )

        yield Observation(
            value=available,
            attributes={},
        )

    def _observe_links_total(self, options):
        if self.snapshot is None:
            return

        yield Observation(
            value=len(self.snapshot.links),
            attributes={},
        )

    def _observe_links_active(self, options):
        if self.snapshot is None:
            return

        active = sum(
            link.state == "ACTIVE"
            for link in self.snapshot.links.values()
        )

        yield Observation(
            value=active,
            attributes={},
        )


    def _observe_device_available(self, options):
        if self.snapshot is None:
            return

        for device in self.snapshot.devices.values():
            yield Observation(
                value=int(device.available),
                attributes={
                    "device": device.id,
                    "role": device.role,
                    "protocol": device.protocol,
                },
            )

    def _observe_device_flows(self, options):
        if self.snapshot is None:
            return

        for flow in self.snapshot.flows.values():
            yield Observation(
                value=flow.total_flows,
                attributes={
                    "device": flow.device,
                },
            )

    def _observe_table_flows(self, options):
        if self.snapshot is None:
            return

        for flow in self.snapshot.flows.values():

            for table_id, total in flow.tables.items():
                yield Observation(
                    value=total,
                    attributes={
                        "device": flow.device,
                        "table": table_id,
                    },
                )
    

    def _build_port_callback(self, field):
        def callback(options):
            if self.snapshot is None:
                return

            for port in self.snapshot.ports.values():
                yield Observation(
                    value=getattr(port, field),
                    attributes={
                        "device": port.device,
                        "port": str(port.port),
                    },
                )

        return callback

    def _observe_flow_deltas(self, options):
        if self.diff is None:
            return

        for flow in self.diff.flow_deltas.values():
            yield Observation(
                value=flow.delta_total_flows,
                attributes={
                    "device": flow.device,
                },
            )

    def _observe_table_flow_deltas(self, options):
        if self.diff is None:
            return

        for flow in self.diff.flow_deltas.values():

            for table_id, delta in flow.delta_tables.items():

                yield Observation(
                    value=delta,
                    attributes={
                        "device": flow.device,
                        "table": table_id,
                    },
                )

    def _observe_port_rx_bps(self, options):
        if self.diff is None:
            return

        for delta in self.diff.port_deltas.values():
            if delta.durationSec <= 0:
                continue

            bps = (
                delta.delta_rx_bytes * 8
                /
                delta.durationSec
            )

            yield Observation(
                value=bps,
                attributes={
                    "device": delta.device,
                    "port": str(delta.port),
                },
            )


    def _observe_port_tx_bps(self, options):
        if self.diff is None:
            return

        for delta in self.diff.port_deltas.values():
            if delta.durationSec <= 0:
                continue

            bps = (
                delta.delta_tx_bytes * 8
                /
                delta.durationSec
            )

            yield Observation(
                value=bps,
                attributes={
                    "device": delta.device,
                    "port": str(delta.port),
                },
            )

    def shutdown(self):
        self.provider.shutdown()