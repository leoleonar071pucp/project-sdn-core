from models import NetworkSnapshot
from observability import (Observability, TelemetryConfig, Events)

obsConfig = TelemetryConfig(
    service_name="m5-observability",
    service_version="1.0.0",
)

obs = Observability(obsConfig)


class Alerts:

    def __init__(self, config):

        self.MAX_FLOWS = config.max_flows_per_device
        self.MAX_ERRORS = config.max_port_errors
        self.MAX_DROPS = config.max_port_drops

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def evaluate(self, snapshot: NetworkSnapshot, diff):

        if diff is None:
            return

        self._check_device_events(diff)
        self._check_link_events(diff)

        self._check_switch_health(snapshot)

        self._check_ports(diff)
        self._check_flows(snapshot, diff)

    # ------------------------------------------------------------------
    # Device events
    # ------------------------------------------------------------------

    def _check_device_events(self, diff):

        for device in diff.devices.removed.values():

            obs.event(
                Events.SWITCH_DISCONNECTED,
                attributes={
                    "event": "switch_down",
                    "device": device.id,
                },
            )

        for device in diff.devices.added.values():

            obs.event(
                Events.SWITCH_CONNECTED,
                attributes={
                    "event": "switch_up",
                    "device": device.id,
                },
            )

    # ------------------------------------------------------------------
    # Link events
    # ------------------------------------------------------------------

    def _check_link_events(self, diff):

        for link in diff.links.removed.values():

            obs.event(
                Events.LINK_DOWN,
                attributes={
                    "link": link.id,
                    "src_device": link.src_device,
                    "src_port": link.src_port,
                    "dst_device": link.dst_device,
                    "dst_port": link.dst_port,
                },
            )

        for link in diff.links.added.values():

            obs.event(
                Events.LINK_UP,
                attributes={
                    "link": link.id,
                    "src_device": link.src_device,
                    "src_port": link.src_port,
                    "dst_device": link.dst_device,
                    "dst_port": link.dst_port,
                },
            )

    # ------------------------------------------------------------------
    # Snapshot-based alerts
    # ------------------------------------------------------------------

    def _check_switch_health(self, snapshot):

        for device in snapshot.devices.values():

            if not device.available:

                obs.event(
                    Events.SWITCH_DOWN,
                    attributes={
                        "device": device.id,
                    },
                )

    # ------------------------------------------------------------------
    # Delta-based alerts
    # ------------------------------------------------------------------

    def _check_ports(self, diff):

        for delta in diff.port_deltas.values():

            if (
                delta.delta_rx_errors > self.MAX_ERRORS
                or delta.delta_tx_errors > self.MAX_ERRORS
            ):

                obs.event(
                    Events.PORT_ERROR_THRESHOLD_EXCEEDED,
                    attributes={
                        "device": delta.device,
                        "port": delta.port,
                        "rx_errors": delta.delta_rx_errors,
                        "tx_errors": delta.delta_tx_errors,
                    },
                )

            if (
                delta.delta_rx_dropped > self.MAX_DROPS
                or delta.delta_tx_dropped > self.MAX_DROPS
            ):

                obs.event(
                    Events.PORT_DROP_THRESHOLD_EXCEEDED,
                    attributes={
                        "device": delta.device,
                        "port": delta.port,
                        "rx_dropped": delta.delta_rx_dropped,
                        "tx_dropped": delta.delta_tx_dropped,
                    },
                )

    # ------------------------------------------------------------------
    # Flow alerts
    # ------------------------------------------------------------------

    def _check_flows(self, snapshot, diff):

        #
        # Current number of installed flows
        #
        for flow in snapshot.flows.values():

            if flow.total_flows > self.MAX_FLOWS:

                obs.event(
                    Events.FLOW_THRESHOLD_EXCEEDED,
                    attributes={
                        "device": flow.device,
                        "total_flows": flow.total_flows,
                    },
                )

        #
        # Sudden increase in installed flows
        #
        for delta in diff.flow_deltas.values():

            if delta.delta_total_flows > self.MAX_FLOWS:

                obs.event(
                    Events.FLOW_INSTALLATION_SPIKE,
                    attributes={
                        "device": delta.device,
                        "delta_flows": delta.delta_total_flows,
                    },
                )