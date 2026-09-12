#!/usr/bin/env python3
"""Provision the MISP feed-platform VM (707) on Proxmox.

Single-NIC service host — deliberately NOT on the SSOP agent plane, not exposed
inbound, and not co-hosted with the SIEM manager or the IRIS case record
(ADR-007: MISP syncs from third-party feeds, so it gets its own trust domain).

    vmid 707  "misp"  4 vCPU / 8 GB / 100 GB on local-zfs
    static ip 192.168.1.80 on vmbr0 (operator-confirmed outside the DHCP pool)

This script only builds the BOX: Ubuntu 24.04 server via autoinstall +
cidata seed, static network, SSH keys. Docker and the MISP stack are installed
afterwards over SSH (each step verifiable) — see docs/feeds-and-licensing.md
and docs/wayfinder/tickets/misp-deploy-target.md for the build plan.

Idempotent: an existing vmid 707 is left alone.

Usage (from the runtime root, with agent-env — system python3 has no dotenv):
    ~/agent-runtime/agent-env/bin/python deploy/lab/provision_misp.py [--start]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

_here = os.path.dirname(os.path.abspath(__file__))
for _candidate in (
    os.path.join(_here, "..", "..", "agents"),          # repo:  deploy/lab -> agents
    os.path.normpath(os.path.join(_here, "..", "..")),   # runtime root
):
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import requests  # noqa: E402

from tools.proxmox_tools import ProxmoxClient  # noqa: E402

NODE = "prox"
STORAGE = "local-zfs"
PVE = "https://192.168.1.169:8006"

VMID = 707
NAME = "misp"
MAC = "02:00:00:00:07:01"          # deterministic, matches net0 in the seed
IP = "192.168.1.80"
GATEWAY = "192.168.1.1"
DNS = "192.168.1.1"
CORES = 4
MEMORY_MB = 8192
DISK_GB = 100

UBUNTU_ISO = "local:iso/ubuntu-24.04.4-live-server-amd64.iso"
SEED_TEMPLATE = os.path.join(_here, "ubuntu-autoinstall-single-nic.yaml")

# Fallback key so the seed is never empty; the real keys are collected below.
FALLBACK_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEhF3+07VPlNsm1lUJBMkSM9DgzYmMxD2Enxltrn7VyS infra-agent-executor"


def collect_pubkeys() -> list[str]:
    """Keys injected into the new host: the agent key (.29 manages the fleet)
    plus the Hermes key (lets the Hermes host drive hands-off)."""
    keys: list[str] = []
    for path in (os.path.expanduser("~/.ssh/agent-ssh.pub"),
                 os.path.expanduser("~/.ssh/hermes_ssop.pub")):
        try:
            keys.append(open(path).read().strip())
        except OSError:
            pass
    try:
        for line in open(os.path.expanduser("~/.ssh/authorized_keys")):
            line = line.strip()
            if line and "hermes-ssop-agent" in line and line not in keys:
                keys.append(line)
    except OSError:
        pass
    return keys


def render_seed() -> tuple[str, str]:
    """Render the autoinstall user-data.

    The identity password is GENERATED here and RECORDED on the provisioning
    host at ~/.ssop/<name>-password.txt (0600) — never in the repo, never in
    the seed as plaintext (only its SHA-512 crypt). The first version of this
    script hashed a random string and stored nothing, which is unrecoverable
    by design and left the box with no console path; recording it costs one
    file and removes a whole class of lockout.
    """
    secrets_dir = os.path.expanduser("~/.ssop")
    os.makedirs(secrets_dir, exist_ok=True)
    pw_file = os.path.join(secrets_dir, f"{NAME}-password.txt")
    if os.path.exists(pw_file):
        pw = open(pw_file).read().strip()
    else:
        pw = os.urandom(9).hex()
        with open(pw_file, "w") as f:
            f.write(pw + "\n")
        os.chmod(pw_file, 0o600)
        print(f"  console login password recorded: {pw_file} (0600)")
    pw_hash = subprocess.check_output(["openssl", "passwd", "-6", pw], text=True).strip()
    keys = "\n      - ".join(collect_pubkeys() or [FALLBACK_KEY])
    ud = open(SEED_TEMPLATE).read()
    ud = (ud
          .replace("__HOSTNAME__", NAME)
          .replace("__PASSWORD_HASH__", pw_hash)
          .replace("__SSH_PUBKEY__", keys)
          .replace("__MAC__", MAC)
          .replace("__IP__", IP)
          .replace("__GATEWAY__", GATEWAY)
          .replace("__DNS__", DNS))
    return ud, f"instance-id: {NAME}\nlocal-hostname: {NAME}\n"


def build_cidata_iso(user_data: str, meta_data: str, out: str) -> None:
    d = f"/tmp/seed-{NAME}"
    os.makedirs(d, exist_ok=True)
    open(f"{d}/user-data", "w").write(user_data)
    open(f"{d}/meta-data", "w").write(meta_data)
    subprocess.check_call(["genisoimage", "-quiet", "-output", out,
                           "-volid", "cidata", "-joliet", "-rock", d])


def upload_iso(path: str) -> str:
    """Upload an ISO via the API (proxmoxer's 5s read timeout is too short for
    multipart — raw requests, same as provision_lab.py)."""
    hdr = (f"PVEAPIToken={os.getenv('PROXMOX_USER')}!"
           f"{os.getenv('PROXMOX_TOKEN_ID')}={os.getenv('PROXMOX_TOKEN_SECRET')}")
    name = os.path.basename(path)
    with open(path, "rb") as f:
        r = requests.post(
            f"{PVE}/api2/json/nodes/{NODE}/storage/local/upload",
            headers={"Authorization": hdr},
            files={"filename": (name, f, "application/octet-stream")},
            data={"content": "iso"}, timeout=120, verify=False)
    r.raise_for_status()
    ProxmoxClient()._wait_task(NODE, r.json()["data"])
    return f"local:iso/{name}"


def _api_header() -> dict[str, str]:
    return {"Authorization": (f"PVEAPIToken={os.getenv('PROXMOX_USER')}!"
                              f"{os.getenv('PROXMOX_TOKEN_ID')}={os.getenv('PROXMOX_TOKEN_SECRET')}")}


def sendkey(vmid: int, keys: list[str]) -> None:
    """Send keystrokes to the VM console.

    There is NO `sendkey` REST endpoint on PVE 9 — POST
    /nodes/{node}/qemu/{vmid}/sendkey returns 501 "Method not implemented", and
    because the response was ignored the original version of this function
    failed SILENTLY, leaving the installer at its prompt while the script
    reported success. The working path is the QEMU monitor (`qm sendkey` uses
    QMP; the monitor endpoint accepts the equivalent HMP command).
    """
    for k in keys:
        r = requests.post(f"{PVE}/api2/json/nodes/{NODE}/qemu/{vmid}/monitor",
                          headers=_api_header(),
                          data={"command": f"sendkey {k}"},
                          timeout=20, verify=False)
        if r.status_code != 200:
            print(f"  sendkey {k!r} FAILED: HTTP {r.status_code} {r.text[:120]}")
        time.sleep(0.4)


def confirm_autoinstall(vmid: int, wait_s: int = 180, attempts: int = 4,
                        spacing_s: int = 60) -> None:
    """Answer Subiquity's 'Continue with autoinstall? (yes|no)'.

    A cloud-init seed (cidata ISO) carrying `autoinstall:` is NOT enough to run
    unattended: Subiquity asks for explicit confirmation unless `autoinstall` is
    on the KERNEL COMMAND LINE, which can't be set when booting a stock ISO
    under Proxmox. Without this step the VM sits at that prompt forever while
    sshd (the live installer's) answers and refuses every key — which reads like
    a broken seed. Verified 2026-09-12 on vm707.

    Timing matters and was wrong the first time: the prompt appears ~3 minutes
    after boot, so keystrokes sent at +120s land on the boot log and are lost.
    Retry across a window instead of guessing one instant; extra keystrokes
    after the install has started are ignored by the log view.
    """
    print(f"  waiting {wait_s}s for the installer to reach the autoinstall prompt")
    time.sleep(wait_s)
    for i in range(1, attempts + 1):
        print(f"  answering 'yes' via monitor sendkey (attempt {i}/{attempts})")
        sendkey(vmid, ["y", "e", "s", "ret"])
        time.sleep(spacing_s)


def ssh_ready(host: str, timeout_s: int = 900, poll_s: int = 20) -> bool:
    """True once the INSTALLED system accepts the injected key (not the live
    installer's sshd, which answers but refuses every key)."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = subprocess.run(
            ["ssh", "-i", os.path.expanduser("~/.ssh/agent-ssh"),
             "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
             "-o", "StrictHostKeyChecking=no", f"rdrolfe@{host}", "echo READY"],
            capture_output=True, text=True)
        if "READY" in r.stdout:
            return True
        time.sleep(poll_s)
    return False


def validate_seed(user_data: str) -> None:
    """Parse the rendered seed BEFORE it costs a 12-minute install.

    Subiquity's failure mode for a malformed late-commands section is to abort
    the whole autoinstall and sit at "An error occurred. Press enter to start a
    shell" — on a headless VM that is a 15-minute round trip to discover a YAML
    quoting mistake. Verified 2026-09-12: `NOPASSWD: ALL` written as a PLAIN
    scalar made YAML parse the entry as a mapping, and the install died.
    """
    import yaml  # local import: only the provisioner needs it

    try:
        doc = yaml.safe_load(user_data)
    except yaml.YAMLError as e:  # noqa: BLE001
        raise SystemExit(f"SEED INVALID (YAML): {e}")
    ai = (doc or {}).get("autoinstall")
    if not isinstance(ai, dict):
        raise SystemExit("SEED INVALID: no 'autoinstall' mapping at the root")
    late = ai.get("late-commands")
    if late is not None:
        if not isinstance(late, list) or not all(isinstance(c, str) for c in late):
            raise SystemExit(
                "SEED INVALID: late-commands must be a list of STRINGS "
                "(a bare ': ' in a plain scalar turns the entry into a mapping)")
        for c in late:
            if "\n" in c:
                raise SystemExit(f"SEED INVALID: late-command contains a raw newline: {c!r}")
    for key in ("identity", "ssh", "storage", "network"):
        if key not in ai:
            raise SystemExit(f"SEED INVALID: autoinstall.{key} missing")
    print(f"  seed validated: {len(late or [])} late-command(s), all strings")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", action="store_true", help="start the VM after creating it")
    args = ap.parse_args()

    c = ProxmoxClient()
    existing = {v["vmid"]: v for v in c.list_vms()}
    if VMID in existing:
        v = existing[VMID]
        print(f"vm{VMID} already exists ({v.get('name')}, {v.get('status')}) — nothing to do")
        return 0

    print(f"=== {NAME} (vm{VMID}) {CORES}c / {MEMORY_MB}M / {DISK_GB}G @ {IP} ===")
    ud, md = render_seed()
    validate_seed(ud)
    seed = f"/tmp/{NAME}-cidata.iso"
    build_cidata_iso(ud, md, seed)
    print(f"  seed built: {seed}")
    seed_vol = upload_iso(seed)
    print(f"  seed uploaded: {seed_vol}")

    r = c.create_vm(
        vmid=VMID, name=NAME, memory_mb=MEMORY_MB, cores=CORES, disk_gb=DISK_GB,
        storage=STORAGE, disk_ctl="scsi0",
        net0=f"virtio={MAC},bridge=vmbr0", iso=UBUNTU_ISO, iso2=seed_vol,
        ostype="l26", node=NODE, start=False, agent=1, onboot=1,
    )
    print(f"  create: {r}")
    if not r.get("success"):
        print("CREATE FAILED")
        return 1

    if args.start:
        c.start_vm(VMID, node=NODE)
        print(f"  started vm{VMID} — autoinstall takes ~8-12 min")
        confirm_autoinstall(VMID)
        print("  waiting for the installed system to accept SSH …")
        print(f"  ssh ready: {ssh_ready(IP)}")

    for v in c.list_vms():
        if v["vmid"] == VMID:
            print(f"  final: {v['vmid']} {v['name']}: {v['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
