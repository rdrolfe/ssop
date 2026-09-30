#!/usr/bin/env python3
"""Render + build the cloud-init NoCloud seed for the Matrix-Chat host (VM 801).

Same model as provision_misp.py: reuse the SSOP single-NIC autoinstall template,
GENERATE the console password, RECORD it outside the repo, and never ship it in
the seed as plaintext (only its SHA-512 crypt).

Why this exists: VM 801 was left in a state where the guest booted but never
completed provisioning, so it held an unconfigured address and was unreachable
(no SSH, no console output — the guest was never built with console=ttyS0). Its
disk was snapshotted as `pre-rebuild-20260929` before this rebuild, so the
original 43.2 GB is recoverable if it turns out to matter.

Usage:  python3 provision_matrixchat.py [--ip 192.168.1.82]
Outputs:  /tmp/matrixchat-cidata.iso  and prints the chosen parameters.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

NAME = "matrixchat"
VMID = 801
GATEWAY = "192.168.1.1"
DNS = "192.168.1.1"
DEFAULT_IP = "192.168.1.82"

_here = Path(__file__).resolve().parent
SEED_TEMPLATE = _here / "ubuntu-autoinstall-single-nic.yaml"


def derive_pubkey(priv: Path) -> str | None:
    """Return the public half of a private key, or None. Some fleet keys ship
    WITHOUT a .pub on the provisioning host — `ssh-keygen -y` is the fix."""
    if not priv.exists():
        return None
    try:
        out = subprocess.check_output(
            ["ssh-keygen", "-y", "-f", str(priv)],
            stderr=subprocess.DEVNULL, text=True).strip()
        return out if out else None
    except (subprocess.CalledProcessError, OSError):
        return None


def collect_pubkeys() -> list[str]:
    """Keys injected into the new host: the agent key (.29 manages the fleet)
    plus the Hermes key (lets the Hermes host drive hands-off)."""
    keys: list[str] = []
    for path in (Path.home() / ".ssh/agent-ssh.pub",
                 Path.home() / ".ssh/hermes_ssop.pub"):
        if path.exists():
            text = path.read_text().strip()
            if text:
                keys.append(text)
    if not keys:
        # Derive from private keys when the .pub is absent.
        for priv in (Path.home() / ".ssh/agent-ssh",
                     Path.home() / ".ssh/hermes_ssop"):
            pub = derive_pubkey(priv)
            if pub:
                keys.append(f"{pub} {priv.stem}")
    try:
        for line in (Path.home() / ".ssh/authorized_keys").read_text().splitlines():
            line = line.strip()
            if line and "hermes-ssop-agent" in line and line not in keys:
                keys.append(line)
    except OSError:
        pass
    return keys


def get_or_create_password() -> str:
    """GENERATE here, RECORD outside the repo at ~/.ssop/<name>-password.txt
    (0600). Recording it costs one file and removes a whole class of lockout."""
    # SSOP_STATE_DIR is pinned in the tree .env so both planes name the same
    # place; this records an OPERATOR credential outside the runtime tree, so
    # it follows the state dir's parent (not the state dir itself).
    secrets_dir = Path(os.getenv("SSOP_STATE_DIR") or (Path.home() / ".ssop" / "state")).parent
    secrets_dir.mkdir(parents=True, exist_ok=True)
    pw_file = secrets_dir / f"{NAME}-password.txt"
    if pw_file.exists():
        return pw_file.read_text().strip()
    pw = os.urandom(9).hex()
    pw_file.write_text(pw + "\n")
    pw_file.chmod(0o600)
    print(f"  console login password recorded: {pw_file} (0600)")
    return pw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default=DEFAULT_IP,
                    help=f"static address (default {DEFAULT_IP})")
    ap.add_argument("--mac", default=None,
                    help="NIC MAC to match; defaults to the live VM 801 net0 MAC")
    args = ap.parse_args()

    if not SEED_TEMPLATE.exists():
        print(f"ERROR: seed template not found: {SEED_TEMPLATE}", file=sys.stderr)
        return 1

    # MAC: read the live VM so the match rule binds to the real NIC.
    mac = args.mac
    if not mac:
        try:
            qcfg = subprocess.check_output(
                ["ssh", "-i", str(Path.home() / ".ssh/hermes_ssop"),
                 "-o", "BatchMode=yes", "root@192.168.1.169",
                 "qm config 801 | grep -oE 'virtio=([0-9A-F:]+)' | cut -d= -f2"],
                text=True).strip()
            mac = qcfg.splitlines()[-1].strip() if qcfg else ""
        except (subprocess.CalledProcessError, OSError):
            mac = ""
    if not mac:
        print("ERROR: could not determine VM 801 MAC; pass --mac", file=sys.stderr)
        return 1

    pw = get_or_create_password()
    pw_hash = subprocess.check_output(
        ["openssl", "passwd", "-6", pw], text=True).strip()

    keys = collect_pubkeys()
    if not keys:
        print("ERROR: no SSH public keys available to inject", file=sys.stderr)
        return 1

    ud = SEED_TEMPLATE.read_text()
    for token, value in (("__HOSTNAME__", NAME),
                         ("__PASSWORD_HASH__", pw_hash),
                         ("__SSH_PUBKEY__", "\n      - ".join(keys)),
                         ("__MAC__", mac),
                         ("__IP__", args.ip),
                         ("__GATEWAY__", GATEWAY),
                         ("__DNS__", DNS)):
        ud = ud.replace(token, value)

    if "__" in ud:
        print("ERROR: unsubstituted placeholder remains in seed:\n" +
              "\n".join(l for l in ud.splitlines() if "__" in l), file=sys.stderr)
        return 1

    d = f"/tmp/seed-{NAME}"
    os.makedirs(d, exist_ok=True)
    Path(d, "user-data").write_text(ud)
    Path(d, "meta-data").write_text(f"instance-id: {NAME}\nlocal-hostname: {NAME}\n")

    out = f"/tmp/{NAME}-cidata.iso"
    subprocess.check_call(["genisoimage", "-quiet", "-output", out,
                           "-volid", "cidata", "-joliet", "-rock", d])

    print(f"  vmid     : {VMID}")
    print(f"  hostname : {NAME}")
    print(f"  mac      : {mac}")
    print(f"  ip       : {args.ip}/24  gw {GATEWAY}  dns {DNS}")
    print(f"  keys     : {len(keys)} injected")
    print(f"  seed iso : {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
