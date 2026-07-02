import logging
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

logger = logging.getLogger(__name__)


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
            "source": "m4",
            "src_ip": incident.src_ip,
            "src_mac": incident.src_mac,
            "switch_dpid": incident.switch_dpid,
            "in_port": incident.in_port,
            "tipo": incident.threat_type,
            "ttl_segundos": ttl,
        }
        if incident.evidence:
            evidence = incident.evidence[0]
            metadata = evidence.get("metadata") or {}
            payload.update(
                {
                    "sid": metadata.get("signature_id"),
                    "signature": metadata.get("signature"),
                    "dst_ip": evidence.get("dst_ip"),
                    "dst_port": evidence.get("dst_port"),
                    "proto": evidence.get("protocol"),
                }
            )
        headers = {"X-Security-Token": self.settings.security_token}
        try:
            logger.info(
                "requesting_m6_mitigation incident_id=%s action=%s src_ip=%s sid=%s",
                incident.incident_id,
                action.value,
                incident.src_ip,
                payload.get("sid"),
            )
            async with httpx.AsyncClient(
                timeout=self.settings.http_timeout_seconds
            ) as client:
                response = await client.post(
                    f"{self.settings.m6_base_url}/m6/security/mitigate",
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()
                body = response.json()
            logger.info(
                "m6_mitigation_response incident_id=%s status=%s flow_ids=%s",
                incident.incident_id,
                body.get("status"),
                body.get("flow_ids", []),
            )
            return ActionResult(
                incident_id=incident.incident_id,
                action=action,
                status=ActionStatus.EXECUTED,
                flow_ids=body.get("flow_ids", []),
                devices=body.get("devices", []),
                expires_at=body.get("expires_at"),
            )
        except Exception as exc:
            logger.exception(
                "m6_mitigation_failed incident_id=%s action=%s",
                incident.incident_id,
                action.value,
            )
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
