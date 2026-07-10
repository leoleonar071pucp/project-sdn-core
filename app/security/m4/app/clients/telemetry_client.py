from uuid import uuid4

import httpx

from ..config import Settings
from ..models import ActionResult, ActionStatus, SecurityAction, SecurityIncident


class TelemetryClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def activate_mirror(self, incident: SecurityIncident) -> ActionResult:
        if not (
            self.settings.network_actions_enabled
            and self.settings.ovsdb_actions_enabled
            and self.settings.m4_automatic_actions_enabled
        ):
            return ActionResult(
                incident_id=incident.incident_id,
                action=SecurityAction.MIRROR,
                status=ActionStatus.SIMULATED,
                flow_ids=[f"simulated-mirror-{uuid4()}"],
                devices=[incident.switch_dpid or "simulated-device"],
                detail="OVSDB actions are disabled; no mirror was created.",
                metadata={
                    "mirror_mode": incident.mirror_mode,
                    "asset_id": incident.critical_asset_id,
                },
            )

        async with httpx.AsyncClient(
            timeout=self.settings.http_timeout_seconds
        ) as client:
            response = await client.post(
                f"{self.settings.telemetry_manager_url}/mirrors",
                json={
                    "incident_id": incident.incident_id,
                    "switch_dpid": incident.switch_dpid,
                    "in_port": incident.in_port,
                    "src_mac": incident.src_mac,
                    "ttl_seconds": 300,
                    "permanent": incident.mirror_mode == "permanent",
                    "asset_id": incident.critical_asset_id,
                },
                headers={"X-Security-Token": self.settings.security_token},
            )
            response.raise_for_status()
            body = response.json()
        return ActionResult(
            incident_id=incident.incident_id,
            action=SecurityAction.MIRROR,
            status=ActionStatus.EXECUTED,
            devices=body.get("devices", []),
            detail=body.get("mirror_id"),
            metadata={"mirror_mode": incident.mirror_mode},
        )
