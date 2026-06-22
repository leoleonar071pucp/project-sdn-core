from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)
HEADERS = {"X-Security-Token": "change-me"}


def test_health_confirms_ovsdb_disabled():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["ovsdb_actions_enabled"] is False


def test_api_returns_simulated_operation():
    response = client.post(
        "/mirrors",
        headers=HEADERS,
        json={
            "incident_id": "api-inc",
            "switch_dpid": "of:1",
            "bridge": "br-test",
            "source_port": "p2",
            "output_tunnel_port": "gre-security",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "SIMULATED"
