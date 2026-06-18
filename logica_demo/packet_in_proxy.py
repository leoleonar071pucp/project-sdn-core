#!/usr/bin/env python3
"""Proxy demo: recibe Packet-In legacy en ONOS y lo reenvia a M6."""

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


M6_URL = os.environ.get("M6_URL", "http://192.168.201.212:8080/m6/packet_in")


def pick(data, *names, default=None):
    for name in names:
        if name in data and data[name] not in (None, ""):
            return data[name]
    return default


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(size)
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            data = {}

        payload = {
            "src_mac": pick(data, "src_mac", "srcMac", "mac_src", "macSrc", "eth_src", default=""),
            "src_ip": pick(data, "src_ip", "srcIp", "ip_src", "ipSrc", default=""),
            "vlan_id": int(pick(data, "vlan_id", "vlanId", "vlan", default=0) or 0),
            "ip_dst": pick(data, "ip_dst", "dstIp", "ipDst", "dst_ip", "dstIp", default=""),
            "tcp_port": int(pick(data, "tcp_port", "tcpDst", "tcp_dst", "dstPort", default=0) or 0),
            "device_id": pick(data, "device_id", "deviceId", "switch", default=""),
            "in_port": str(pick(data, "in_port", "inPort", "port", default="")),
        }

        body = json.dumps(payload).encode("utf-8")
        status = 502
        response = b""
        try:
            req = urllib.request.Request(
                M6_URL,
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.getcode()
                response = resp.read()
        except Exception as exc:
            response = str(exc).encode("utf-8")

        print("packet-in", data, "=>", payload, "status", status, flush=True)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


if __name__ == "__main__":
    print("Packet-In proxy escuchando en 0.0.0.0:5000 -> %s" % M6_URL, flush=True)
    HTTPServer(("0.0.0.0", 5000), Handler).serve_forever()
