import time

from discovery import Discovery
from state import State
from metrics import Metrics
from alerts import Alerts

from observability import (Observability,TelemetryConfig,Events)

obsConfig = TelemetryConfig(
    service_name="m3-monitoring",
    service_version="1.0.0",
)

obs = Observability(obsConfig)


class MonitoringService:

    def __init__(self, config):

        self.discovery = Discovery(config)
        self.state = State()

        self.metrics = Metrics(config)
        self.alerts = Alerts(config)

        self.interval = config.poll_interval

        self.retry_delay = 5
        self.max_retry_delay = 120

    # ------------------------------------------------------------------
    # MAIN LOOP
    # ------------------------------------------------------------------

    def run(self):

        try:
            while True:
                start = time.time()

                try:
                    snapshot = self.discovery.collect()
                    #
                    # First successful snapshot
                    #
                    if not self.state.initialized:
                        self.state.update(snapshot)
                        self.metrics.set_snapshot(snapshot)
                        self.retry_delay = 5
                        obs.event(Events.MONITORING_STARTED, attributes={
                            "poll_interval": self.interval,
                        })

                    #
                    # Normal monitoring
                    #
                    else:
                        diff = self.state.update(snapshot)
                        self.metrics.set_snapshot(snapshot, diff)
                        self.alerts.evaluate(snapshot, diff)
                        self.retry_delay = 5

                    #
                    # Keep polling period constant
                    #
                    elapsed = time.time() - start
                    time.sleep(max(0,self.interval - elapsed))

                except Exception as e:
                    obs.event(
                        Events.MONITORING_FAILED,
                        attributes={
                            "error": str(e),
                            "retry_in": str(self.retry_delay)+" seconds",
                        },
                    )
                    time.sleep(self.retry_delay)
                    self.retry_delay = min(self.retry_delay * 2,self.max_retry_delay)

        except KeyboardInterrupt:
            obs.event(Events.MONITORING_STOPPED)

        finally:
            self.metrics.shutdown()