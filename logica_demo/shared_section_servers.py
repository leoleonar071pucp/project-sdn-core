#!/usr/bin/env python3
"""Servidor demo: varias secciones HTTP en la misma IP, diferenciadas por puerto."""

from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from threading import Thread


SECTIONS = {
    8081: ("electronica_web", "Contenido de la Facultad de Electronica"),
    8082: ("informatica_web", "Contenido de la Facultad de Informatica"),
    8083: ("telecom_web", "Contenido de Telecomunicaciones"),
}


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class SectionHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        name, body = SECTIONS[self.server.server_port]
        payload = (
            f"{name}\n"
            f"{body}\n"
            f"puerto={self.server.server_port}\n"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"[{self.server.server_port}] {self.address_string()} - {fmt % args}")


def serve(port):
    server = ThreadingHTTPServer(("0.0.0.0", port), SectionHandler)
    name, _ = SECTIONS[port]
    print(f"{name} escuchando en 0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    threads = []
    for port in SECTIONS:
        thread = Thread(target=serve, args=(port,), daemon=True)
        thread.start()
        threads.append(thread)

    print("Servidor compartido listo. Ctrl+C para detener.")
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\nDetenido.")
