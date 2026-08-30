#!/usr/bin/env python3
"""Build the SSOP purple-team lab on Proxmox.

Creates three dual-plane VMs:
  902 ubuntu-target  (.77 mgmt / 10.10.1.11 attack)  Ubuntu 24.04 + Wazuh agent + ART
  903 win-target     (.78 mgmt / 10.10.1.12 attack)  Windows Server 2019 + Wazuh agent + ART
  904 c2-sink        (.79 mgmt / 10.10.1.20 attack)  Ubuntu 24.04 fake-C2 listener

Each VM gets TWO NICs: net0 on vmbr0 (management, 192.168.1.x) and net1 on
vmbr1 (the isolated attack segment SO's sensor captures). ART traffic from
the targets crosses vmbr1 -> SO captures it live.

Usage: python3 provision_lab.py          # build everything (idempotent-ish)
Requires: genisoimage, proxmoxer, requests, .env with PROXMOX_* + WAZUH creds.
Run from the repo root (agents/ on the path).
"""
from __future__ import annotations

import os
import random
import secrets
import string
import subprocess
import sys
import time

# tools/ lives at <repo>/agents/tools (local checkout) or <runtime>/tools
# (deployed). Add both so the import works in either layout.
_here = os.path.dirname(os.path.abspath(__file__))
for _candidate in (
    os.path.join(_here, "..", "..", "agents"),   # repo: deploy/lab -> agents
    os.path.normpath(os.path.join(_here, "..", "..")),  # runtime root: deploy/lab -> ~/agent-runtime
):
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

from dotenv import load_dotenv

load_dotenv()

import requests  # noqa: E402

from tools.proxmox_tools import ProxmoxClient  # noqa: E402

NODE = "prox"
STORAGE = "local-zfs"
PVE = "https://192.168.1.169:8006"

# --- lab layout (single source of truth) ---
# (vmid, name, os, mgmt_ip, attack_ip, mgmt_mac, attack_mac)
LAB = [
    # (vmid, name, "ubuntu"|"windows", mgmt_ip, attack_ip, mgmt_mac, attack_mac)
    (902, "ubuntu-target", "ubuntu", "192.168.1.77", "10.10.1.11", "02:00:00:00:02:01", "02:00:00:00:02:02"),
    (903, "win-target", "windows", "192.168.1.78", "10.10.1.12", "02:00:00:00:03:01", "02:00:00:00:03:02"),
    (904, "c2-sink", "ubuntu", "192.168.1.79", "10.10.1.20", "02:00:00:00:04:01", "02:00:00:00:04:02"),
]

GATEWAY = "192.168.1.1"
WAZUH_MANAGER = "192.168.1.75"
UBUNTU_ISO = "local:iso/ubuntu-24.04.4-live-server-amd64.iso"
WIN_ISO = "local:iso/17763.3650.221105-1748.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"

REPO_LAB = os.path.dirname(os.path.abspath(__file__))  # deploy/lab
# SSH keys to inject into the lab VMs. Read from the build host's real files:
# agent-ssh.pub (infra-agent-executor, lets .29 manage the VMs) plus the
# hermes-ssop-agent key (present in authorized_keys, lets the Hermes host in).
def _collect_pubkeys() -> list[str]:
    keys: list[str] = []
    for path in (os.path.expanduser("~/.ssh/agent-ssh.pub"), os.path.expanduser("~/.ssh/hermes_ssop.pub")):
        try:
            keys.append(open(path).read().strip())
        except OSError:
            pass
    # hermes-ssop-agent key usually lives in authorized_keys (not as its own file)
    try:
        for line in open(os.path.expanduser("~/.ssh/authorized_keys")):
            line = line.strip()
            if line and "hermes-ssop-agent" in line and line not in keys:
                keys.append(line)
    except OSError:
        pass
    return keys


PUBKEYS = _collect_pubkeys()
AGENT_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEhF3+07VPlNsm1lUJBMkSM9DgzYmMxD2Enxltrn7VyS infra-agent-executor"


def gen_password(n: int = 16) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def render_ubuntu_seed(hostname: str, mgmt_ip: str, attack_ip: str, mgmt_mac: str,
                       attack_mac: str) -> tuple[str, str]:
    """Render user-data + meta-data for the Ubuntu autoinstall cidata ISO."""
    pw_hash = subprocess.check_output(
        ["openssl", "passwd", "-6", gen_password()], text=True).strip()
    keys = "\n".join(f"      - {k}" for k in (PUBKEYS or [AGENT_KEY]))
    user_data = open(os.path.join(REPO_LAB, "ubuntu-autoinstall.yaml")).read()
    user_data = (user_data
                 .replace("__HOSTNAME__", hostname)
                 .replace("__PASSWORD_HASH__", pw_hash)
                 .replace("__SSH_PUBKEY__", keys)
                 .replace("__MGMT_MAC__", mgmt_mac)
                 .replace("__ATTACK_MAC__", attack_mac)
                 .replace("__MGMT_IP__", mgmt_ip)
                 .replace("__ATTACK_IP__", attack_ip)
                 .replace("__GATEWAY__", GATEWAY)
                 .replace("__WAZUH_MANAGER__", WAZUH_MANAGER))
    meta_data = f"instance-id: {hostname}\nlocal-hostname: {hostname}\n"
    return user_data, meta_data


def render_windows_seed() -> tuple[str, str]:
    """Render autounattend.xml (with generated admin password) + provision.ps1."""
    admin_pw = gen_password()
    xml = open(os.path.join(REPO_LAB, "autounattend.xml")).read().replace("__ADMIN_PASSWORD__", admin_pw)
    ps1 = open(os.path.join(REPO_LAB, "provision-windows.ps1")).read()
    return xml, ps1


def build_cidata_iso(hostname: str, out: str, user_data: str, meta_data: str) -> None:
    d = f"/tmp/seed-{hostname}"
    os.makedirs(d, exist_ok=True)
    open(f"{d}/user-data", "w").write(user_data)
    open(f"{d}/meta-data", "w").write(meta_data)
    subprocess.check_call(["genisoimage", "-quiet", "-output", out, "-volid", "cidata",
                           "-joliet", "-rock", d])


def build_win_answer_iso(out: str, xml: str, ps1: str) -> None:
    d = "/tmp/seed-win"
    os.makedirs(d, exist_ok=True)
    open(f"{d}/autounattend.xml", "w").write(xml)
    open(f"{d}/provision-windows.ps1", "w").write(ps1)
    subprocess.check_call(["genisoimage", "-quiet", "-output", out, "-volid", "autounattend",
                           "-joliet", "-rock", d])


def upload_iso(pve_url: str, node: str, storage: str, path: str) -> str:
    """Upload an ISO to Proxmox storage via the API (raw requests — proxmoxer's
    5s read timeout is too short for multipart). Returns the volid."""
    hdr = (f"PVEAPIToken={os.getenv('PROXMOX_USER')}!"
           f"{os.getenv('PROXMOX_TOKEN_ID')}={os.getenv('PROXMOX_TOKEN_SECRET')}")
    name = os.path.basename(path)
    with open(path, "rb") as f:
        r = requests.post(
            f"{pve_url}/api2/json/nodes/{node}/storage/{storage}/upload",
            headers={"Authorization": hdr},
            files={"filename": (name, f, "application/octet-stream")},
            data={"content": "iso"},
            timeout=120, verify=False)
    r.raise_for_status()
    upid = r.json()["data"]
    ProxmoxClient()._wait_task(node, upid)
    return f"{storage}:iso/{name}"


def main() -> None:
    c = ProxmoxClient()
    existing = {v["vmid"] for v in c.list_vms()}

    for vmid, name, ostype, mgmt_ip, attack_ip, mgmt_mac, attack_mac in LAB:
        print(f"=== {name} (vm{vmid}) ===")
        if vmid in existing:
            print(f"  exists — skipping create")
            continue

        iso2 = None
        net0 = f"virtio={mgmt_mac},bridge=vmbr0"
        net1 = f"virtio={attack_mac},bridge=vmbr1"
        disk_ctl = "scsi0"
        ostype_cfg = "l26"
        cores, memory, disk = 2, 4096, 40

        if ostype == "ubuntu":
            ud, md = render_ubuntu_seed(name, mgmt_ip, attack_ip, mgmt_mac, attack_mac)
            seed = f"/tmp/{name}-cidata.iso"
            build_cidata_iso(name, seed, ud, md)
            iso2 = upload_iso(PVE, NODE, "local", seed)
            iso = UBUNTU_ISO
        else:  # windows
            xml, ps1 = render_windows_seed()
            seed = "/tmp/win-answer.iso"
            build_win_answer_iso(seed, xml, ps1)
            iso2 = upload_iso(PVE, NODE, "local", seed)
            iso = WIN_ISO
            # e1000 NIC + IDE disk: natively supported by Windows setup, no
            # virtio driver dance during install.
            net0 = f"e1000={mgmt_mac},bridge=vmbr0"
            net1 = f"e1000={attack_mac},bridge=vmbr1"
            disk_ctl = "ide0"
            ostype_cfg = "win11"
            cores, memory, disk = 4, 8192, 80

        print(f"  creating vm{vmid} (disk={disk_ctl} {disk}G, {cores}c/{memory}M, {ostype})")
        r = c.create_vm(
            vmid=vmid, name=name, memory_mb=memory, cores=cores, disk_gb=disk,
            storage=STORAGE, disk_ctl=disk_ctl, net0=net0, net1=net1,
            iso=iso, iso2=iso2, ostype=ostype_cfg, node=NODE,
            start=False, agent=0 if ostype == "windows" else 1,
        )
        print(" ", r)
        if not r.get("success"):
            print(f"  FAILED to create {name} — stopping")
            return
        c.start_vm(vmid, node=NODE)
        print(f"  started vm{vmid}")

    print("\n=== all VMs created+started ===")
    for v in c.list_vms():
        if v["vmid"] in (902, 903, 904):
            print(f"  {v['vmid']} {v['name']}: {v['status']}")


if __name__ == "__main__":
    main()
