import importlib.util
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "app"
    / "m6_traductor"
    / "m6_traductor.py"
)
SPEC = importlib.util.spec_from_file_location("m6_traductor_security_test", MODULE_PATH)
m6_module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(m6_module)


HEADERS = {"X-Security-Token": "change-me"}


def test_mitigation_is_simulated_without_network(monkeypatch):
    def fail_request(*args, **kwargs):
        raise AssertionError("No external HTTP call is allowed in safe mode")

    monkeypatch.setattr(m6_module.requests, "post", fail_request)
    client = m6_module.app.test_client()

    response = client.post(
        "/m6/mitigacion",
        headers=HEADERS,
        json={
            "incident_id": "inc-test",
            "accion": "TEMP_BLOCK",
            "ip_atacante": "10.2.1.105",
            "mac_atacante": "00:11:22:33:44:55",
            "switch_dpid": "of:1",
            "in_port": 2,
            "ttl_segundos": 600,
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "SIMULATED"
    assert body["flow_ids"][0].startswith("simulated-")
    criteria = body["flows"][0]["selector"]["criteria"]
    assert {"type": "IPV4_SRC", "ip": "10.2.1.105/32"} in criteria
    assert {"type": "ETH_SRC", "mac": "00:11:22:33:44:55"} in criteria
    assert {"type": "IN_PORT", "port": 2} in criteria


def test_unblock_is_simulated_without_network(monkeypatch):
    def fail_request(*args, **kwargs):
        raise AssertionError("No external HTTP call is allowed in safe mode")

    monkeypatch.setattr(m6_module.requests, "delete", fail_request)
    client = m6_module.app.test_client()
    client.post(
        "/m6/mitigacion",
        headers=HEADERS,
        json={
            "incident_id": "inc-unblock",
            "ip_atacante": "10.2.1.106",
            "switch_dpid": "of:1",
        },
    )

    response = client.post(
        "/m6/unblock",
        headers=HEADERS,
        json={"incident_id": "inc-unblock"},
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "SIMULATED"


def test_packet_in_invalid_binding_does_not_call_external_services(monkeypatch):
    def fail_request(*args, **kwargs):
        raise AssertionError("No external HTTP call is allowed in safe mode")

    monkeypatch.setattr(m6_module.requests, "post", fail_request)
    client = m6_module.app.test_client()

    response = client.post(
        "/m6/packet-in",
        headers=HEADERS,
        json={
            "src_ip": "10.2.1.250",
            "src_mac": "00:11:22:33:44:55",
            "dst_ip": "192.168.100.201",
            "dst_port": 443,
            "protocol": "TCP",
            "switch_dpid": "of:1",
            "in_port": 2,
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["decision"] == "DENY"
    assert body["reason"] == "invalid_ip_mac_binding"


def test_packet_in_allowed_builds_flow_without_external_services(monkeypatch):
    def fail_request(*args, **kwargs):
        raise AssertionError("No external HTTP call is allowed in safe mode")

    monkeypatch.setattr(m6_module.requests, "post", fail_request)
    client = m6_module.app.test_client()

    response = client.post(
        "/m6/packet-in",
        headers=HEADERS,
        json={
            "src_ip": "10.3.0.105",
            "src_mac": "00:11:22:33:44:66",
            "dst_ip": "192.168.100.201",
            "dst_port": 443,
            "protocol": "TCP",
            "switch_dpid": "of:1",
            "in_port": 2,
            "codigo_pucp": "DOC-TEST",
            "nombre_rol": "Docente",
            "simulated_session": True,
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["decision"] == "ALLOW"
    assert body["status"] == "SIMULATED"
    assert body["flow_id"].startswith("simulated-")


def test_startup_endpoint_never_installs_flows_in_safe_mode(monkeypatch):
    def fail_install():
        raise AssertionError("Startup flow installation must remain disabled")

    monkeypatch.setattr(m6_module.m6, "instalar_cuarentena_arranque", fail_install)
    response = m6_module.app.test_client().post("/m6/arranque")

    assert response.status_code == 200
    assert response.get_json()["status"] == "SIMULATED"
