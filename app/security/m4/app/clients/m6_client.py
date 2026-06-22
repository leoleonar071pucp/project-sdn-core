from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx

from ..config import Settings
from ..models import (
    ActionResult,
    ActionStatus,
    SecurityAction,
    SecurityIncident,
)


class M6Client:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def execute(
        self,
        incident: SecurityIncident,
        action: SecurityAction,
    ) -> ActionResult:
        ttl = (
            self.settings.temporary_block_seconds
            if action == SecurityAction.TEMP_BLOCK
            else self.settings.long_block_seconds
        )
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        if not (
            self.settings.network_actions_enabled
            and self.settings.onos_writes_enabled
            and self.settings.m4_automatic_actions_enabled
        ):
            return ActionResult(
                incident_id=incident.incident_id,
                action=action,
                status=ActionStatus.SIMULATED,
                flow_ids=[f"simulated-{uuid4()}"],
                devices=[incident.switch_dpid or "simulated-device"],
                expires_at=expires_at,
                detail="Network actions are disabled; no request was sent to M6.",
            )

        payload = {
            "incident_id": incident.incident_id,
            "accion": action.value,
            "ip_atacante": incident.src_ip,
            "mac_atacante": incident.src_mac,
            "switch_dpid": incident.switch_dpid,
            "in_port": incident.in_port,
            "tipo": incident.threat_type,
            "prioridad": 50000,
            "ttl_segundos": ttl,
        }
        headers = {"X-Security-Token": self.settings.security_token}
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.http_timeout_seconds
            ) as client:
                response = await client.post(
                    f"{self.settings.m6_base_url}/m6/mitigacion",
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()
                body = response.json()
            return ActionResult(
                incident_id=incident.incident_id,
                action=action,
                status=ActionStatus.EXECUTED,
                flow_ids=body.get("flow_ids", []),
                devices=body.get("devices", []),
                expires_at=body.get("expires_at"),
            )
        except Exception as exc:
            return ActionResult(
                incident_id=incident.incident_id,
                action=action,
                status=ActionStatus.FAILED,
                detail=str(exc),
            )

    async def get_host_network_state(
        self,
        ip: str,
        mac: str | None = None,
    ) -> dict:
        if not self.settings.network_actions_enabled:
            return {"ip": ip, "mac": mac, "blocked": False, "simulated": True}
        params = {"ip": ip}
        if mac:
            params["mac"] = mac
        async with httpx.AsyncClient(
            timeout=self.settings.http_timeout_seconds
        ) as client:
            response = await client.get(
                f"{self.settings.m6_base_url}/m6/security/host-state",
                params=params,
                headers={"X-Security-Token": self.settings.security_token},
            )
            response.raise_for_status()
            return response.json()
