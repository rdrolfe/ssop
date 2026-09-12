#!/usr/bin/env python3
"""Write the MISP settings into the runtime .env, idempotently.

Kept as a FILE rather than an inline heredoc: the inline version died on nested
quote escaping, and this touches a secret — it must be boring and repeatable.
The key is read from a 0600 staging file and never printed (only a length and a
fingerprint).
"""
import hashlib
import os
import pathlib
import sys

env = pathlib.Path.home() / "agent-runtime" / ".env"
stage = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/misp_key_final")

if not stage.is_file():
    print(f"staging file missing: {stage}")
    sys.exit(1)
key = stage.read_text().strip()
if len(key) != 40:
    print(f"refusing: key length {len(key)} is not the expected 40")
    sys.exit(1)

lines = [l for l in env.read_text().splitlines()
         if not l.startswith(("MISP_URL=", "MISP_API_KEY="))]
lines += ["MISP_URL=https://192.168.1.80", f"MISP_API_KEY={key}"]
env.write_text("\n".join(lines) + "\n")
os.chmod(env, 0o600)
stage.unlink(missing_ok=True)

print("MISP_URL=https://192.168.1.80 written")
print(f"MISP_API_KEY written: len={len(key)} "
      f"sha256_prefix={hashlib.sha256(key.encode()).hexdigest()[:16]}")
