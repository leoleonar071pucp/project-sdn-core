from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)
HEADERS = {"X-Security-Token": "change-me"}


def test_health_reports_all_network_actions_disabled():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["network_actions_enabled"] is False
    assert body["onos_writes_enabled"] is False
    assert body["ovsdb_actions_enabled"] is False


def test_m6_event_is_processed_without_external_call():
    response = client.post(
        "/m4/events/m6",
        headers=HEADERS,
        json={
            "idempotency_key": "api-invalid-binding",
            "event_type": "invalid_ip_mac_binding",
            "src_ip": "10.2.1.105",
            "src_mac": "00:11:22:33:44:55",
            "switch_dpid": "of:1",
            "in_port": 2,
            "severity": 80,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["recommended_action"] == "TEMP_BLOCK"
    assert body["action_result"]["status"] == "SIMULATED"


def test_duplicate_event_is_idempotent():
    payload = {
        "idempotency_key": "api-duplicate",
        "event_type": "policy_denial",
        "src_ip": "10.2.1.106",
    }
    first = client.post("/m4/events/m6", headers=HEADERS, json=payload)
    second = client.post("/m4/events/m6", headers=HEADERS, json=payload)

    assert first.status_code == 200
    assert second.json()["duplicate"] is True
