#!/usr/bin/env python3
"""Standalone entry for the adjudication API.

Runs from the agent-runtime root (NOT via `-m tools.adjudicate_api`), so this
module body executes BEFORE the `tools` package __init__ eagerly imports
config — avoiding the frozen-settings trap that breaks QDRANT_URL in
background processes.

Usage:  python3 adjudicate_api_entry.py [--host 0.0.0.0] [--port 8787]
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Inject .env into os.environ BEFORE anything imports config (frozen settings).
_RUNTIME = Path(__file__).resolve().parent
_env_path = _RUNTIME / ".env"
try:
    for _line in _env_path.read_text().splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#") or "=" not in _line:
            continue
        _k, _v = _line.split("=", 1)
        os.environ.setdefault(_k.strip(), _v.strip())
except OSError:
    pass

# Now safe to import the package (config sees the injected env).
from tools.adjudicate_api import main  # noqa: E402

if __name__ == "__main__":
    # Serve HTTPS by default so the Wazuh dashboard (https) can iframe the
    # console without mixed-content blocking.
    sys.argv = [sys.argv[0]] + [a for a in sys.argv[1:]] + (["--tls"] if "--tls" not in sys.argv else [])
    sys.exit(main())
