#!/usr/bin/env python3
"""Egress gate — every EXTERNAL network destination in agents/**.py must be
declared in agents/transport.yaml `external_calls` (the egress registry).

SOVEREIGNTY DOCTRINE (operator, 2026-09-09): sovereignty covers AI INFERENCE
— no cloud provider owns our decisions. It does NOT forbid external
data-plane calls; it REQUIRES them DECLARED. An undeclared external endpoint
is a build error: the disclosure decision must be made explicitly at
development time, never implicitly at runtime.

Detection: regex scan of agents/**.py for http(s) URL literals. URLs whose
host is not localhost/127.0.0.1/172.17-31/192.168/10. private and not in the
registry -> FAIL. Returns 0 (ok) / 1 (undeclared egress found).
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

REPO = Path(__file__).resolve().parent.parent
TRANSPORT = REPO / "transport.yaml"

# Local/private hosts that are NOT external egress.
_LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "::1/128", "fe80::/10")]

_URL_RE = re.compile(
    r"""["'](https?://[^"'\s]+?)["']""", re.IGNORECASE)

# $-template placeholders and doc-comment examples are not real egress.
_EXCLUDE_TOKENS = ("{", "}", "example", "localhost", "CHANGE_ME", "your-")


def _is_local(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() in ("localhost", "")
    return any(addr in net for net in _LOCAL_NETS)


def _declared_hosts() -> dict[str, dict]:
    data = yaml.safe_load(TRANSPORT.read_text()) or {}
    out = {}
    for name, entry in (data.get("external_calls") or {}).items():
        host = urlparse(str(entry.get("endpoint", ""))).hostname or str(
            entry.get("endpoint", "")).split("/")[0]
        out[host.lower()] = {"name": name,
                             "class": entry.get("class", "?"),
                             "data_sent": entry.get("data_sent", "?")}
    return out


def check_egress() -> list[dict[str, str]]:
    """Scan agents/**.py for undeclared external http(s) endpoints."""
    declared = _declared_hosts()
    problems: list[dict[str, str]] = []
    for py in sorted(REPO.glob("agents/**/*.py")):
        text = py.read_text(errors="replace")
        for m in _URL_RE.finditer(text):
            url = m.group(1)
            if any(tok in url for tok in _EXCLUDE_TOKENS):
                continue
            host = urlparse(url).hostname or ""
            if not host or _is_local(host):
                continue
            if host.lower() in declared:
                continue
            rel = str(py.relative_to(REPO))
            lineno = text[:m.start()].count("\n") + 1
            problems.append({"file": rel, "line": str(lineno), "url": url,
                             "hint": f"declare under external_calls.{host.lower()}"
                                     " in agents/transport.yaml"})
    # the gate module itself references docs paths only
    return problems


def main() -> int:
    problems = check_egress()
    print(f"egress registry: {len(_declared_hosts())} declared external endpoint(s)")
    for p in problems:
        print(f"  [FAIL] undeclared external call: {p['file']}:{p['line']} {p['url']}")
        print(f"         -> {p['hint']}")
    if problems:
        print(f"\nEGRESS GATE: FAIL ({len(problems)} undeclared)")
        return 1
    print("EGRESS GATE: PASS — all external calls declared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
