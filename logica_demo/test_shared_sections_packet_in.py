#!/usr/bin/env python3
"""Prueba demo de secciones por puerto contra /m6/packet_in."""

import json
import sys
import urllib.request


M6_PACKET_IN_URL = "http://192.168.100.1:8080/m6/packet_in"
SHARED_SERVER_IP = "192.168.100.200"
DEVICE_ID = "of:000072e0807e854c"


def post_packet_in(vlan_id, tcp_port):
    payload = {
        "vlan_id": vlan_id,
        "ip_dst": SHARED_SERVER_IP,
        "tcp_port": tcp_port,
        "device_id": DEVICE_ID,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        M6_PACKET_IN_URL,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        body = json.loads(response.read().decode("utf-8"))
        return response.status, body


def expect(vlan_id, tcp_port, expected_status):
    http_status, body = post_packet_in(vlan_id, tcp_port)
    actual = body.get("status")
    ok = actual == expected_status
    marker = "OK" if ok else "ERROR"
    print(
        f"[{marker}] VLAN {vlan_id} -> {SHARED_SERVER_IP}:{tcp_port} "
        f"status={actual} http={http_status}"
    )
    return ok


if __name__ == "__main__":
    checks = [
        expect(210, 8083, "installed"),
        expect(210, 8082, "denied"),
        expect(220, 8082, "installed"),
        expect(220, 8083, "denied"),
    ]
    sys.exit(0 if all(checks) else 1)
