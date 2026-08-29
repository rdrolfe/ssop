#!/usr/bin/env python3
"""Telemetry-host console proxy — serves the adjudication console on the
Wazuh dashboard's hostname (192.168.1.75) so the iframe is same-host and
uses the already-accepted cert. Proxies /tickets + /adjudicate to the
adjudication API on infra-ops (.29:8787).

Run on the telemetry host:  python3 console_proxy.py  (port 5602)
Iframe URL: https://192.168.1.75:5602/console
"""
from __future__ import annotations

import json
import ssl
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ADJUDICATE_API = "https://192.168.1.29:8787"
CONSOLE_HTML = Path(__file__).resolve().parent / "adjudication-console.html"


class ProxyHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, html):
        data = html.encode()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.rstrip("/")
        if path in ("/", "/console"):
            try:
                self._html(CONSOLE_HTML.read_text())
            except OSError:
                self._json(500, {"ok": False, "error": "console html missing"})
            return
        if path == "/tickets":
            # proxy to the adjudication API (server-side, trusted)
            try:
                with urllib.request.urlopen(ADJUDICATE_API + "/tickets", timeout=15,
                                            context=ssl._create_unverified_context()) as r:
                    self._json(200, json.loads(r.read().decode()))
            except Exception as e:  # noqa: BLE001
                self._json(502, {"ok": False, "error": str(e)})
            return
        self._json(404, {"ok": False, "error": f"unknown {path}"})

    def do_POST(self):
        if self.path.rstrip("/") != "/adjudicate":
            self._json(404, {"ok": False, "error": "unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(length)
            req = urllib.request.Request(
                ADJUDICATE_API + "/adjudicate", data=payload,
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=15,
                                        context=ssl._create_unverified_context()) as r:
                self._json(200, json.loads(r.read().decode()))
        except Exception as e:  # noqa: BLE001
            self._json(502, {"ok": False, "error": str(e)})

    def log_message(self, format, *args):
        pass


def main():
    # Use the Wazuh dashboard's OWN cert (dashboard.pem) — the browser already
    # trusts it for 192.168.1.75, so the iframe gets no cert warning.
    cert = "/tmp/telemetry_cert.pem"
    key = "/tmp/telemetry_key.pem"
    server = HTTPServer(("0.0.0.0", 5602), ProxyHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("console proxy on https://192.168.1.75:5602/console", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
