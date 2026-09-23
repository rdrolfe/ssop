#!/usr/bin/env python3
"""Prove the ADR-008 boundary from the AUTOMATION side of it.

Run this AS the unattended user (temporarily set as a unit's ExecStart, since
`sudo -u` needs a password this account does not have). It asserts five things:

  1. who we are            — the UID/GID the automation actually runs as
  2. the private key        — MUST be unreadable (that is the boundary)
  3. the public key         — must be readable, or the unattended plane could
                              not verify committed entries and would stop
                              suppressing anything (a self-inflicted outage)
  4. verification works     — a real committed entry verifies from here
  5. commit() refuses       — an unattended writer cannot mint a commit

Reads the ledger only; the one file it writes is a temp entry in the state dir,
immediately removed, to prove that directory is writable from this plane.
"""
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, "/home/rdrolfe/agent-runtime")

from dotenv import load_dotenv  # noqa: E402

load_dotenv("/home/rdrolfe/agent-runtime/.env")

fails = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global fails
    print(f"[{'OK  ' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        fails += 1


from tools.tuning_tools import (  # noqa: E402
    TuningError,
    TuningLedger,
    _commit_key_paths,
    signing_available,
    tuning_state,
    verify_entry,
)

key_path, pub_path = _commit_key_paths()

# 1. identity
try:
    import pwd
    who = pwd.getpwuid(os.getuid()).pw_name
except Exception:  # noqa: BLE001
    who = "?"
print(f"running as: uid={os.getuid()} gid={os.getgid()} user={who} "
      f"cwd={os.getcwd()}")
check("not the human-plane account", who not in ("rdrolfe", "root"),
      f"user={who}")

# 2. the private key must be unreadable
readable = False
try:
    with open(key_path, "rb") as fh:
        fh.read(1)
        readable = True
except (OSError, PermissionError):
    readable = False
check("private commit key is NOT readable", not readable, str(key_path))
check("signing_available() is False here", not signing_available())

# 3. the public key must be readable (verification is the unattended plane's job)
pub_ok = False
try:
    pub_ok = len(pub_path.read_bytes()) > 0
except OSError as e:
    pub_ok = False
    print(f"     public key error: {e}")
check("public commit key IS readable", pub_ok, str(pub_path))

# permission detail for the record
try:
    st = key_path.stat()
    print(f"     key mode={stat.filemode(st.st_mode)} owner_uid={st.st_uid}")
except OSError as e:
    print(f"     key stat failed: {e}")

# 4. verification of a real committed entry works from here
led = TuningLedger()
entries = led.list_all(limit=500)
committed = [e for e in entries if tuning_state(e) == "committed"]
verified = [e for e in committed if verify_entry(e)]
check("committed entries verify from the automation plane",
      bool(committed) and len(verified) == len(committed),
      f"{len(verified)}/{len(committed)} verified")

# 5. commit() must refuse — but ONLY meaningful from the automation plane.
# Running this on the human plane would SUCCEED, and that write is pollution:
# a scratch tuning entry in the real ledger. Guard it, so a probe run by the
# wrong account reports "not applicable" instead of leaving litter behind.
if signing_available():
    print("[SKIP] commit() refusal — not applicable here: this account holds "
          "the private key (human plane). Run the probe AS the automation user.")
else:
    try:
        led.commit("__boundary_probe__", "auto_fp", "should never be written",
                   committed_by="ssop-agent")
        check("commit() refuses from the automation plane", False,
              "it WROTE a commit — the boundary is not real")
    except TuningError as e:
        check("commit() refuses from the automation plane", True, str(e)[:80])
    except Exception as e:  # noqa: BLE001
        check("commit() refuses from the automation plane", False,
              f"unexpected {type(e).__name__}: {e}")

# 6. the plane must be able to WRITE its own state dir. Receipts (drill, sweep,
#    infra disposition) and the boot-evidence log live there, and after the
#    split a $HOME-derived path pointed at a directory the agent could not
#    write — the drill would fail to record its own result. A probe that only
#    reads would have called that healthy.
state_dir = Path(os.getenv("SSOP_STATE_DIR") or (Path.home() / ".ssop" / "state"))
probe_file = state_dir / ".probe-write-check"
try:
    probe_file.write_text("probe")
    probe_file.unlink()
    check("state dir is WRITABLE from the automation plane", True, str(state_dir))
except OSError as e:
    check("state dir is WRITABLE from the automation plane", False,
          f"{state_dir}: {type(e).__name__} {e}")

print("\nBOUNDARY HOLDS" if fails == 0 else f"\n{fails} BOUNDARY FAILURES")
sys.exit(0 if fails == 0 else 1)
