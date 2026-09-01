#!/usr/bin/env python3
"""Telemetry-host console proxy — serves the SSOP human console on the Wazuh
dashboard's hostname (192.168.1.75) so the iframe is same-host and uses the
already-accepted cert.

Proxies the console HTML + read/write API paths to the adjudication API on
infra-ops (.29:8787) server-side — the browser never hits the indexer or a
second service directly (CORS + self-signed-ssl safe).

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
from urllib.parse import urlparse

ADJUDICATE_API = "https://192.168.1.29:8787"
CONSOLE_HTML = Path(__file__).resolve().parent / "adjudication-console.html"

# GET paths proxied 1:1 to the adjudication API (read-through).
GET_ROUTES = ("/tickets", "/tuning", "/cases", "/report", "/reports", "/health")


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

    def _proxy_get(self, path):
        # Forward a read path to the adjudication API (server-side, trusted).
        # JSON responses are re-emitted as JSON; non-JSON (e.g. the markdown
        # /report deliverable) is passed through with its content type intact.
        try:
            with urllib.request.urlopen(ADJUDICATE_API + path, timeout=15,
                                        context=ssl._create_unverified_context()) as r:
                body = r.read()
                ctype = r.headers.get("Content-Type", "")
                if "application/json" in ctype:
                    self._json(r.status, json.loads(body.decode()))
                else:
                    self.send_response(r.status)
                    self._cors()
                    self.send_header("Content-Type", ctype or "application/octet-stream")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
        except urllib.error.HTTPError as e:
            try:
                self._json(e.code, json.loads(e.read().decode()))
            except Exception:  # noqa: BLE001
                self._json(e.code, {"ok": False, "error": str(e)})
        except Exception as e:  # noqa: BLE001
            self._json(502, {"ok": False, "error": str(e)})

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        # Route on the path WITHOUT the query string, but forward the full
        # path (including ?query) to the backend so ?case_id= survives.
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path in ("/", "/console"):
            try:
                self._html(CONSOLE_HTML.read_text())
            except OSError:
                self._json(500, {"ok": False, "error": "console html missing"})
            return
        if path in GET_ROUTES:
            self._proxy_get(self.path)
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
    # Cert lives in a durable path next to this script (not /tmp, which is
    # wiped on reboot) — see the start script for how it's refreshed.
    cert_dir = Path(__file__).resolve().parent / "certs"
    cert = cert_dir / "cert.pem"
    key = cert_dir / "key.pem"
    server = HTTPServer(("0.0.0.0", 5602), ProxyHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("console proxy on https://192.168.1.75:5602/console", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
