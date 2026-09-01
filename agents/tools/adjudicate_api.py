"""Tiny adjudication API — human approve/deny for tier1/tier2 tickets.

A minimal stdlib HTTP endpoint (no web framework deps) that wraps
SupervisoryClient.adjudicate(). The human (or a dashboard button) calls:

    POST /adjudicate
    {"ticket_id": "abc123", "decision": "approve", "rationale": "..."}

The responder already polls ticket status; this is the human write-path.
Binds to localhost by default (infra-ops) — exposed only to the admin.

Usage:  python3 -m tools.adjudicate_api [--host 0.0.0.0] [--port 8787]
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# Explicit .env path — a background/harness process may not inherit the
# shell's cwd, so never rely on the cwd default.
from pathlib import Path as _Path
from typing import Any

_AGENT_RUNTIME = _Path(__file__).resolve().parent.parent


def _load_env_into_os() -> None:
    """Read .env into os.environ explicitly, BEFORE any config/settings snapshot.

    The frozen `settings` dataclass snapshots env at import; a background
    process may not inherit the shell's env, so inject from the file directly.
    """
    env_path = _AGENT_RUNTIME / ".env"
    try:
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())
    except OSError:
        pass


_load_env_into_os()  # MUST run before any module that imports config

# Defensive: if the injection didn't take, log it loudly — this is the trap
# that silently broke the Qdrant URL in a background process.
import os as _os

_qurl = _os.environ.get("QDRANT_URL", "")
if not _qurl:
    print("WARN: QDRANT_URL empty after _load_env_into_os", flush=True)

from logging_setup import get_logger
from tools.supervisory_tools import SupervisoryClient

logger = get_logger(__name__)
_sup = SupervisoryClient()

# Log the resolved Qdrant URL at startup — a background process can silently
# inherit a wrong env; seeing it on boot catches that immediately.
try:
    from tools.qdrant_tools import QdrantMemory
    _mem = QdrantMemory()
    logger.info("adjudicate-api: qdrant url = %s", _mem.url)
except Exception as e:  # noqa: BLE001 — non-fatal diagnostic
    logger.warning("adjudicate-api: qdrant probe failed: %s", e)


def _list_open_tier2() -> list[dict[str, Any]]:
    """Fetch open tier-2 tickets from the indexer (server-side, CORS-safe).

    Returns the ticket docs the console renders. Mirrors the dashboard's
    approvals query: ssop.source=tickets AND status=open AND tier=2.
    """
    try:
        from tools.indexer_client import IndexerTransport
        t = IndexerTransport()
        body = {
            "size": 50,
            "query": {"bool": {"filter": [
                {"term": {"ssop.source": "tickets"}},
                {"term": {"status.keyword": "open"}},
                {"term": {"tier": 2}}]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        r = t.search(body, index="ssop-events")
        tickets = [h.get("_source", {}) for h in r.get("hits", {}).get("hits", [])]
        # JOIN with the case spine: enrich each ticket with its case's
        # observables/enrichments/checklist/techniques (the adopted SO
        # concepts live on the case in Qdrant, not on the ticket doc).
        # Older tickets (pre case-spine) have no case_id — they render as-is.
        try:
            from tools.case_tools import CaseStore
            _cs = CaseStore()
            for tk in tickets:
                cid = (tk.get("detail") or {}).get("case_id") or tk.get("case_id")
                if not cid:
                    continue
                case = _cs.get_case(cid)
                if case:
                    tk["case"] = {
                        "case_id": cid,
                        "observables": case.get("observables", []),
                        "enrichments": case.get("enrichments", []),
                        "checklist": case.get("checklist"),
                        # techniques ride at TOP level (escalate spreads detail)
                        # or in detail — check both.
                        "techniques": (tk.get("detail") or {}).get("techniques")
                                      or tk.get("techniques", []),
                    }
        except Exception as e:  # noqa: BLE001 — case join must never break ticket list
            logger.warning("case join failed: %s", e)
        return tickets
    except Exception as e:
        logger.warning("tickets fetch failed: %s", e)
        raise


def _load_console_html() -> str:
    """Read the adjudication console HTML from the runtime dir."""
    try:
        p = _Path(__file__).resolve().parent.parent / "adjudication-console.html"
        return p.read_text()
    except OSError:
        return "<html><body><h3>console html not found</h3></body></html>"


_CONSOLE_HTML = _load_console_html()


class AdjudicateHandler(BaseHTTPRequestHandler):
    def _cors_headers(self) -> None:
        """Allow the dashboard console (file:// or localhost origins) to call us."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self) -> None:
        """Preflight for cross-origin browser calls."""
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def _send(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, html: str) -> None:
        data = html.encode()
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        """GET /health — liveness + open-ticket count. GET /tickets — open tier-2 queue.
        GET /cases[?case_id=id] — recent cases, or ONE case by id."""
        # Route on the path WITHOUT the query string; handlers that want
        # query params (e.g. /cases?case_id=) parse self.path themselves.
        path = urlparse(self.path).path.rstrip("/")
        try:
            if path == "/health":
                open_t = len(_sup.list_tickets(status="open"))
                self._send(200, {"ok": True, "open_tickets": open_t})
            elif path == "/tickets":
                # Fetch open tier-2 tickets from the indexer, server-side —
                # avoids the browser's CORS/self-signed-ssl block on the indexer.
                self._send(200, {"ok": True, "tickets": _list_open_tier2()})
            elif path == "/tuning":
                # Managed-tuning surface (adopted SO concept 4): the tuning
                # ledger with attribution, so the human sees WHAT is tuned,
                # WHO decided, and WHY — the human-managed view of our Qdrant
                # ledger that was previously invisible.
                from tools.tuning_tools import TuningLedger
                entries = TuningLedger().list_all()
                self._send(200, {"ok": True, "tuning": entries})
            elif path == "/cases":
                # Closed-loop view: recent cases with their investigation
                # (hypothesis, severity, kill_chain, evidence) and the
                # supervisor's adjudication — the human sees the whole chain
                # (recognize -> investigate -> adjudicate -> respond).
                #
                # Supports ?case_id=<id> to return ONE case by id from the
                # spine (Qdrant holds all cases; the old code only scanned the
                # last 50 receipt lines, so an older fully-decided case was
                # invisible to the human — the bake-off parity finding #2).
                # Default (no case_id) keeps the recent-cases view.
                import json as _json

                from tools.case_tools import CaseStore
                cs = CaseStore()
                q = parse_qs(urlparse(self.path).query)
                want_id = (q.get("case_id") or [""])[0].strip()

                def _view(cid: str) -> dict | None:
                    case = cs.get_case(cid)
                    if not case:
                        return None
                    inv = adj = resp = None
                    for ev in case.get("timeline", []):
                        d = ev.get("detail", {})
                        if ev.get("type") == "investigation":
                            inv = d
                        elif ev.get("role") == "supervisory" and ev.get("type") == "adjudication":
                            adj = d
                        elif ev.get("role") == "responder":
                            resp = d
                    return {
                        "case_id": cid,
                        "title": case.get("title", ""),
                        "status": case.get("status", ""),
                        "supervisory": case.get("supervisory"),
                        "investigation": inv,
                        "adjudication": adj,
                        "responder": resp,
                        "observables": case.get("observables", []),
                        "timeline": [
                            {"role": e.get("role"), "type": e.get("type"),
                             "ts": e.get("ts"), "detail": e.get("detail")}
                            for e in case.get("timeline", [])
                        ],
                    }

                out: list[dict] = []
                if want_id:
                    v = _view(want_id)
                    if v is None:
                        self._send(404, {"ok": False, "error": f"case {want_id} not found in spine"})
                        return
                    self._send(200, {"ok": True, "case": v})
                    return
                try:
                    with open(cs.cases_file, encoding="utf-8") as f:
                        lines = list(f)[-50:]  # last 50 receipt lines
                except OSError as e:
                    self._send(500, {"ok": False, "error": f"cases read: {e}"})
                    return
                for line in lines:
                    try:
                        rec = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    cid = rec.get("case_id") or rec.get("id")
                    v = _view(cid) if cid else None
                    if v:
                        out.append(v)
                self._send(200, {"ok": True, "cases": out})
            elif path == "/report":
                # Final-report deliverable: render a fully-decided case as a
                # human-readable report for a larger audience. The bake-off
                # axis-6 output — compiled from the spine OR SO's native case
                # store, so it's backend-comparable.
                #   /report?case_id=<id>                     -> markdown (spine)
                #   /report?case_id=<id>&format=html         -> standalone HTML
                #   /report?case_id=<id>&backend=so          -> SO-native store
                q = parse_qs(urlparse(self.path).query)
                rid = (q.get("case_id") or [""])[0].strip()
                fmt = (q.get("format") or ["md"])[0].strip().lower()
                backend = (q.get("backend") or ["spine"])[0].strip().lower()
                if not rid:
                    self._send(400, {"ok": False, "error": "case_id required"})
                    return
                try:
                    from tools import report_gen
                    if backend == "so":
                        md = report_gen.render_so_case_report(rid)
                        html = report_gen._md_to_html(md, f"Incident Report {rid} (SO)")
                    else:
                        md = report_gen.render_case_report(rid)
                        html = report_gen.render_case_report_html(rid)
                    if fmt == "html":
                        self._send_html(html)
                    else:
                        data = md.encode()
                        self.send_response(200)
                        self._cors_headers()
                        self.send_header("Content-Type", "text/markdown; charset=utf-8")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                except KeyError:
                    self._send(404, {"ok": False, "error": f"case {rid} not found ({backend} backend)"})
            elif path == "/reports":
                # Combined decision report: all decided cases in the last N
                # days as one deliverable.  /reports?days=7[&format=html]
                q = parse_qs(urlparse(self.path).query)
                try:
                    days = int((q.get("days") or ["7"])[0])
                except ValueError:
                    days = 7
                fmt = (q.get("format") or ["md"])[0].strip().lower()
                from tools import report_gen
                if fmt == "html":
                    self._send_html(report_gen.render_reports_html(days))
                else:
                    data = report_gen.render_reports(days).encode()
                    self.send_response(200)
                    self._cors_headers()
                    self.send_header("Content-Type", "text/markdown; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
            elif path in ("/", "/console"):
                # Serve the adjudication console HTML (hosted here so the
                # Wazuh dashboard can iframe it over HTTP).
                self._send_html(_CONSOLE_HTML)
            else:
                self._send(404, {"ok": False, "error": f"unknown path {path}"})
        except Exception as e:  # noqa: BLE001 — surface honestly
            self._send(500, {"ok": False, "error": str(e)})

    def do_POST(self) -> None:
        """POST /adjudicate — approve/deny a ticket by id."""
        if self.path.rstrip("/") != "/adjudicate":
            self._send(404, {"ok": False, "error": f"unknown path {self.path}"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode() or "{}")
        except (ValueError, json.JSONDecodeError) as e:
            self._send(400, {"ok": False, "error": f"bad json: {e}"})
            return
        ticket_id = payload.get("ticket_id", "")
        decision = payload.get("decision", "")
        rationale = payload.get("rationale", "")
        if not ticket_id or decision not in ("approve", "deny", "fp"):
            self._send(400, {"ok": False,
                             "error": "ticket_id + decision (approve|deny|fp) required"})
            return
        try:
            tickets = {t["ticket_id"]: t for t in _sup.list_tickets()}
            ticket = tickets.get(ticket_id)
            if not ticket:
                self._send(404, {"ok": False, "error": f"ticket {ticket_id} not found"})
                return
            _sup.adjudicate(ticket, decision, rationale)
            logger.info("adjudicated %s -> %s via API", ticket_id, decision)
            self._send(200, {"ok": True, "ticket_id": ticket_id,
                             "decision": decision, "status": "adjudicated"})
        except Exception as e:
            logger.exception("adjudicate API failed for %s", ticket_id)
            self._send(500, {"ok": False, "error": str(e)})

    def log_message(self, format: str, *args: Any) -> None:  # route to our logger
        logger.info("adjudicate-api: " + format, *args)


def main() -> None:
    parser = argparse.ArgumentParser(description="SSOP adjudication API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--tls", action="store_true",
                        help="serve HTTPS (self-signed cert at /tmp/api_cert.pem,key)")
    args = parser.parse_args()
    server = HTTPServer((args.host, args.port), AdjudicateHandler)
    logger.info("adjudication API listening on %s:%s (%s)",
                args.host, args.port, "HTTPS" if args.tls else "HTTP")
    if args.tls:
        import ssl
        # Durable cert path next to the runtime (not /tmp — wiped on reboot).
        cert_dir = _AGENT_RUNTIME / "certs"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_dir / "api_cert.pem"),
                            str(cert_dir / "api_key.pem"))
        # Tighten key perms: the private key must not be world-readable
        # (bandit B108 — secure the temp file).
        try:
            import os
            os.chmod(cert_dir / "api_key.pem", 0o600)
            os.chmod(cert_dir / "api_cert.pem", 0o644)
        except OSError as e:
            logger.warning("could not chmod api key/cert: %s", e)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
