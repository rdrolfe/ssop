#!/usr/bin/env python3
"""Shared DFIR-IRIS API client for SSOP spine-side tooling.

Extracted from publish_case_iris.py (which kept its own copy to avoid a
risky refactor mid-flight; this module is the home for NEW read/write
paths: sync_iris_to_spine.py, the bake-off engine-parity checker, etc.).

Credentials come from the runtime .env on the host (IRIS_URL + per-role
IRIS_KEY_* / IRIS_API_KEY) — never literals in code. API shape verified
against IRIS v2.4.29 live.

Timeline-event attribution: the REST API omits user_id/user_name in the
events payload, so author attribution is read from the IRIS Postgres via
`docker exec iriswebapp_db psql` on the IRIS host (the sync script needs
it for faithful spine timeline entries).
"""
from __future__ import annotations

import json
import ssl
import subprocess
import urllib.error
import urllib.request
from pathlib import Path


class IrisClient:
    def __init__(self, role: str = "automation") -> None:
        self.url = ""
        self.key = ""
        self._role = role
        self._load_env()

    # --- credential loading (host-only, never in the repo) ---
    def _load_env(self) -> None:
        role_key_env = {
            "analyst": "IRIS_KEY_ANALYST", "supervisor": "IRIS_KEY_SUPERVISOR",
            "supervisory": "IRIS_KEY_SUPERVISOR",
            "responder": "IRIS_KEY_RESPONDER", "hunt": "IRIS_KEY_HUNT",
        }
        want_key = role_key_env.get(self._role, "") or "IRIS_API_KEY"
        for env in (Path.home() / "agent-runtime" / ".env",
                    Path.home() / "iris-web" / ".env"):
            if not env.exists():
                continue
            for line in env.read_text().splitlines():
                if line.startswith(f"{want_key}="):
                    self.key = line.split("=", 1)[1].strip()
                elif line.startswith("IRIS_URL=") and not self.url:
                    self.url = line.split("=", 1)[1].strip()
                elif line.startswith("INTERFACE_HTTPS_PORT=") and not self.url:
                    port = line.split("=", 1)[1].strip()
                    self.url = f"https://192.168.1.75:{port}"

    @staticmethod
    def _ctx() -> ssl.SSLContext:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c

    # --- raw HTTP ---
    def req(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{self.url}{path}", data=data, method=method,
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=25, context=self._ctx()) as r:
            return json.loads(r.read().decode())

    # --- IRIS case reads ---
    def list_cases(self) -> list[dict]:
        """All cases. Each has case_id, case_soc_id, case_name, state_name."""
        d = self.req("GET", "/manage/cases/list")
        return d.get("data") or []

    def get_timeline(self, case_id: int) -> list[dict]:
        d = self.req("GET", f"/case/timeline/events/list?cid={case_id}")
        return (d.get("data") or {}).get("timeline", [])

    def get_human_activity(self, case_id: int) -> list[dict]:
        """Human-authored IRIS activity (notes + non-SSOP events), REST-only.

        The publish path (spine -> IRIS) writes timeline events tagged
        `event_tags: "ssop"` as the service accounts; mirroring those back
        would duplicate the spine timeline. So:
          - events WITHOUT the ssop tag = human/UI-created -> sync
          - notes whose note_user is not a service account -> sync
        Service-account user ids: 2=Automation, 3=Analyst, 4=Supervisor,
        5=Responder, 6=Hunt. Returns [{kind, author, title, content, ts}].
        """
        # known human id -> name (IRIS users table; service ids filtered)
        _KNOWN = {1: "administrator", 7: "Ryan"}

        out: list[dict] = []
        # 1. timeline events without the ssop tag (not written by our publisher)
        try:
            for e in self.get_timeline(case_id):
                tags = str(e.get("event_tags") or "")
                if "ssop" in tags:
                    continue  # automation mirror — skip
                uid = e.get("user_id")
                out.append({
                    "kind": "event",
                    "author": _KNOWN.get(uid, f"iris-user-{uid}") if uid else "iris-human",
                    "title": e.get("event_title") or "",
                    "content": (e.get("event_content") or "")[:2000],
                    "ts": e.get("event_date") or "",
                })
        except Exception as e:  # noqa: BLE001
            print(f"  events read failed: {e}")
        # 2. notes via the search API (GET; route reads request.args, not the
        # body — search_input=%25 (URL-encoded %) matches all notes)
        try:
            d = self.req("GET", f"/case/notes/search?cid={case_id}&search_input=%25")
            for n in (d.get("data") or []):
                uid = n.get("note_user")
                if uid is not None and int(uid) in (2, 3, 4, 5, 6):
                    continue  # service account
                out.append({
                    "kind": "note",
                    "author": _KNOWN.get(uid, f"iris-user-{uid}") if uid else "iris-human",
                    "title": n.get("note_title") or "",
                    "content": (n.get("note_content") or "")[:2000],
                    "ts": n.get("note_lastupdate") or n.get("note_creationdate") or "",
                })
        except Exception as e:  # noqa: BLE001
            print(f"  notes read failed: {e}")
        out.sort(key=lambda a: a["ts"])
        return out

    def get_notes(self, case_id: int) -> list[dict]:
        """Read notes straight from the IRIS Postgres (no list API endpoint).

        Runs `docker exec iriswebapp_db psql` on the IRIS host via ssh.
        Returns [{note_id, author, title, content, ts}].
        """
        sql = (
            "SELECT n.note_id, COALESCE(u.name,'-') AS author, "
            "COALESCE(n.note_title,''), LEFT(n.note_content, 2000), "
            "n.note_lastupdate "
            f"FROM notes n LEFT JOIN \\\"user\\\" u ON u.id = n.note_user "
            f"WHERE n.note_case_id = {int(case_id)} ORDER BY n.note_id;"
        )
        out = self._psql(sql)
        rows = []
        for line in (out or "").splitlines():
            parts = line.split("|")
            if len(parts) < 5:
                continue
            rows.append({
                "note_id": parts[0].strip(), "author": parts[1].strip(),
                "title": parts[2].strip(), "content": parts[3].strip(),
                "ts": parts[4].strip(),
            })
        return rows

    @staticmethod
    def _psql(sql: str) -> str:
        """Run psql on the IRIS host's db container over ssh (from .29)."""
        cmd = [
            "ssh", "-i", "/home/rdrolfe/.ssh/hermes_ssop",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=5",
            "rdrolfe@192.168.1.75",
            f"docker exec iriswebapp_db psql -U postgres -d iris_db -t -c \"{sql}\"",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            return r.stdout
        except Exception as e:  # noqa: BLE001
            return f"ERR {e}"


if __name__ == "__main__":
    c = IrisClient()
    print("url:", c.url)
    cases = c.list_cases()
    print(f"cases: {len(cases)}")
    for cse in cases[-3:]:
        print(f"  id={cse.get('case_id')} soc={cse.get('case_soc_id')}")
