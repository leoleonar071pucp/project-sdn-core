import asyncio
from datetime import datetime, timezone

import httpx

from app.clients.m6_client import M6Client
from app.config import Settings
from app.models import SecurityAction, SecurityIncident


def test_m6_client_posts_security_mitigate_payload(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "status": "EXECUTED",
                "flow_ids": ["flow-1"],
                "devices": ["of:edge"],
                "expires_at": datetime.now(timezone.utc).isoformat(),
            }

    class FakeClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url, json, headers):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    settings = Settings(
        network_actions_enabled=True,
        onos_writes_enabled=True,
        m4_automatic_actions_enabled=True,
        m6_base_url="http://m6.test",
    )
    incident = SecurityIncident(
        incident_id="inc-1",
        incident_key="ip|192.168.100.55",
        src_ip="192.168.100.55",
        evidence=[
            {
                "metadata": {
                    "signature_id": 9000002,
                    "signature": "SQLi",
                },
                "dst_ip": "192.168.100.101",
                "dst_port": 8001,
                "protocol": "TCP",
            }
        ],
    )

    result = asyncio.run(
        M6Client(settings).execute(incident, SecurityAction.TEMP_BLOCK)
    )

    assert result.status.value == "EXECUTED"
    assert captured["url"] == "http://m6.test/m6/security/mitigate"
    assert captured["json"]["sid"] == 9000002
    assert captured["json"]["src_ip"] == "192.168.100.55"
    assert captured["json"]["dst_ip"] == "192.168.100.101"
    assert captured["json"]["dst_port"] == 8001
    assert captured["json"]["proto"] == "TCP"
