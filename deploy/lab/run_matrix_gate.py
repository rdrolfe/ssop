#!/usr/bin/env python3
"""Run the verify matrix and publish its result for the digest to read.

WHY THIS IS SEPARATE FROM THE DIGEST
The matrix takes ~460s (measured 2026-09-28) and the digest used to run it
inline, which made the whole digest unable to finish inside a single
terminal call. The digest is the thing that has to reach a human; a slow
gate must not be able to stop it. So the matrix runs on its own schedule
and writes a small result file, and the digest only READS that file.

The read side has to be honest about staleness — a gate result from
yesterday presented as today's is the exact failure this platform keeps
earning the hard way. The digest therefore reports the age of the result
and says so loudly when it is too old to trust.

Writes atomically (tmp + rename) so a reader can never observe a half
-written file if this is killed mid-write.
"""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _runtime_dir() -> Path:
    """Locate the runtime root from wherever this script was invoked.

    It runs from TWO places: the repo copy at deploy/lab/, and the deployed
    copy at the runtime root (that is the path the cron job invokes). A
    fixed parent.parent is wrong for one of them — from the runtime root it
    walks up to the home directory and then looks for agent-env in the wrong
    place. The venv is the reliable marker, so probe for it.
    """
    here = Path(__file__).resolve().parent
    for cand in (here, here.parent, here.parent.parent):
        if (cand / "agent-env" / "bin" / "python3").exists():
            return cand
    raise SystemExit(f"runtime root not found (no agent-env near {here})")


RUNTIME = _runtime_dir()
STATE_DIR = Path(os.getenv("SSOP_STATE_DIR") or str(RUNTIME / ".ssop" / "state"))
RESULT = STATE_DIR / "matrix-last.json"

SUMMARY_RE = re.compile(r"([0-9]+ passed / [0-9]+ failed / [0-9]+ blocked / [0-9]+ total)")
GATE_RE = re.compile(r"^(timer liveness|docs citations|registry reentrancy|misp corpus|bake-off parity)")


def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    log = STATE_DIR / "matrix-last.log"
    started = time.monotonic()
    # 1800s is a runaway guard, not a budget: a genuine hang should be
    # recorded as a hang (rc=124) rather than silently truncated.
    with open(log, "w", encoding="utf-8") as fh:
        proc = subprocess.run(
            [str(RUNTIME / "agent-env" / "bin" / "python3"), "-m", "verify.matrix"],
            cwd=str(RUNTIME), stdout=fh, stderr=subprocess.STDOUT, timeout=1800,
        )
    rc = proc.returncode
    duration = round(time.monotonic() - started, 1)

    text = log.read_text(encoding="utf-8", errors="replace")
    m = SUMMARY_RE.search(text)
    problems = [ln.strip() for ln in text.splitlines()
                if GATE_RE.match(ln.strip()) and ("FAIL" in ln or "problem" in ln)]
    fails = [ln.strip() for ln in text.splitlines() if re.match(r"^\s+fail ", ln)][:6]

    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "exit": rc,
        "timed_out": rc == 124,
        "duration_s": duration,
        "summary": m.group(1) if m else None,
        "problems": problems[:6],
        "fails": fails,
        "log": str(log),
    }
    tmp = RESULT.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, RESULT)  # atomic — a reader never sees a partial file

    print(json.dumps({k: payload[k] for k in ("summary", "exit", "duration_s", "timed_out")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
