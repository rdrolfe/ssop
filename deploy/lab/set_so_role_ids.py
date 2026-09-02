#!/usr/bin/env python3
"""Set the SO per-role identity env vars in the runtime .env on the
infra-ops host, by editing ~/agent-runtime/.env.

Mappings (Kratos identity UUIDs, from `so-kratos` identities list):
  analyst     -> SO_USER_ID_ANALYST
  supervisor  -> SO_USER_ID_SUPERVISOR  (16ae082b-b13f-4a31-9edf-a13bd54b73d5)
  responder   -> SO_USER_ID_RESPONDER   (338bad95-2d8e-465b-81a0-2f9380443189)
  hunt        -> SO_USER_ID_HUNT        (1a6624d1-6c93-4b90-a39d-c6381b550b1e)
  automation  -> SO_USER_ID_AUTOMATION  (from identities list)
  (admin 96203a00-9881-4b54-9cf6-44104757c876 is the fallback for create)
Usage: python3 set_so_role_ids.py <analyst_uuid> <automation_uuid>
"""
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: set_so_role_ids.py <analyst_uuid> <automation_uuid>")
        return 1
    analyst_uuid, automation_uuid = sys.argv[1], sys.argv[2]
    mapping = {
        "SO_USER_ID_ANALYST": analyst_uuid,
        "SO_USER_ID_SUPERVISOR": "16ae082b-b13f-4a31-9edf-a13bd54b73d5",
        "SO_USER_ID_RESPONDER": "338bad95-2d8e-465b-81a0-2f9380443189",
        "SO_USER_ID_HUNT": "1a6624d1-6c93-4b90-a39d-c6381b550b1e",
        "SO_USER_ID_AUTOMATION": automation_uuid,
    }
    env_path = Path.home() / "agent-runtime" / ".env"
    if not env_path.exists():
        print(f"no .env at {env_path}")
        return 1
    lines = env_path.read_text().splitlines()
    present = {ln.split("=", 1)[0] for ln in lines if "=" in ln and not ln.strip().startswith("#")}
    out = []
    for key, val in mapping.items():
        if key in present:
            out.append(f"{key}={val}")
        else:
            out.append(f"{key}={val}")
    # replace existing occurrences, append missing
    for key, val in mapping.items():
        lines = [ln if not ln.startswith(f"{key}=") else f"{key}={val}" for ln in lines]
    have_keys = {ln.split("=", 1)[0] for ln in lines if "=" in ln and not ln.strip().startswith("#")}
    for key, val in mapping.items():
        if key not in have_keys:
            lines.append(f"{key}={val}")
    env_path.write_text("\n".join(lines) + "\n")
    print("set in", env_path)
    for k in mapping:
        print(f"  {k}={mapping[k]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
