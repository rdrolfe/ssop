#!/usr/bin/env python3
"""Build a plain cloud-config NoCloud seed for VM 801 (Matrix-Chat).

WHY THIS EXISTS — read before reusing the autoinstall path.

The first rebuild attempt used `ubuntu-24.04.4-live-server-amd64.iso` + an
`autoinstall:` seed (the same shape as provision_misp.py). That FAILED:

  * The live installer boots an installer-side sshd, so the host answered on
    :22 long before an OS was installed — which reads as success and is not.
  * The install then sat at an interactive prompt: RSS froze at 4.45 GB and
    uptime never advanced, so it never rebooted into an installed system.
  * With `allow-pw: false` in the seed, an install that does not reach
    authorized_keys leaves the host with NO access path at all.
  * The installer kernel has no `console=ttyS0`, so `qm terminal` shows nothing
    and the failure is invisible from the host.

The cloud-image path below has none of those failure modes: the image boots
straight into a real system, cloud-init applies the seed with no prompt, and a
static address is set in `network-config` rather than through the installer.

Password is GENERATED and RECORDED outside the repo; only its SHA-512 crypt
ships in the seed.

Usage:  python3 build_cloud_seed.py --ip 192.168.1.82 --mac BC:24:11:C3:74:27
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

NAME = "matrixchat"
GATEWAY = "192.168.1.1"
DNS = "192.168.1.1"


def collect_pubkeys() -> list[str]:
    keys: list[str] = []
    for p in (Path.home() / ".ssh/agent-ssh.pub", Path.home() / ".ssh/hermes_ssop.pub"):
        if p.exists() and p.read_text().strip():
            keys.append(p.read_text().strip())
    for priv in (Path.home() / ".ssh/agent-ssh", Path.home() / ".ssh/hermes_ssop"):
        if not any(priv.stem in k or "executor" in k for k in keys) and priv.exists():
            try:
                pub = subprocess.check_output(
                    ["ssh-keygen", "-y", "-f", str(priv)],
                    stderr=subprocess.DEVNULL, text=True).strip()
                if pub:
                    keys.append(f"{pub} {priv.stem}")
            except (subprocess.CalledProcessError, OSError):
                pass
    try:
        for line in (Path.home() / ".ssh/authorized_keys").read_text().splitlines():
            line = line.strip()
            if line and "hermes-ssop-agent" in line and line not in keys:
                keys.append(line)
    except OSError:
        pass
    # de-dup on the key material itself
    seen, out = set(), []
    for k in keys:
        mat = k.split()[1] if len(k.split()) > 1 else k
        if mat not in seen:
            seen.add(mat)
            out.append(k)
    return out


def get_or_create_password() -> str:
    d = Path.home() / ".ssop"
    d.mkdir(exist_ok=True)
    f = d / f"{NAME}-password.txt"
    if f.exists():
        return f.read_text().strip()
    pw = os.urandom(9).hex()
    f.write_text(pw + "\n")
    f.chmod(0o600)
    print(f"  console login password recorded: {f} (0600)")
    return pw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--out", default="/tmp/matrixchat-cloud-cidata.iso")
    a = ap.parse_args()

    keys = collect_pubkeys()
    if not keys:
        print("ERROR: no SSH public keys to inject", file=sys.stderr)
        return 1
    pw = get_or_create_password()
    pw_hash = subprocess.check_output(["openssl", "passwd", "-6", pw], text=True).strip()

    # Password must be a HASH in the seed; cloud-init sets it at first boot.
    # ssh_pwauth is enabled explicitly so a locked-out host always has one path.
    user_data = f"""#cloud-config
hostname: {NAME}
fqdn: {NAME}.lan
prefer_fqdn_over_hostname: false
manage_etc_hosts: true

users:
  - name: rdrolfe
    gecos: SSOP fleet
    primary_group: rdrolfe
    groups: [sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: "{pw_hash}"
    ssh_authorized_keys:
{chr(10).join('      - ' + k for k in keys)}

ssh_pwauth: true
disable_root: true

package_update: true
packages:
  - qemu-guest-agent

runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
"""

    # netplan v2 static addressing — the seed is a plain cloud-config, NOT an
    # autoinstall config, so the network block is top-level network-config.
    network_config = f"""version: 2
ethernets:
  service:
    match:
      macaddress: "{a.mac}"
    set-name: service
    dhcp4: false
    addresses: [{a.ip}/24]
    routes:
      - to: default
        via: {GATEWAY}
    nameservers:
      addresses: [{DNS}]
"""

    d = "/tmp/seed-cloud-matrixchat"
    os.makedirs(d, exist_ok=True)
    Path(d, "user-data").write_text(user_data)
    Path(d, "meta-data").write_text(
        f"instance-id: {NAME}-001\nlocal-hostname: {NAME}\n")
    Path(d, "network-config").write_text(network_config)

    subprocess.check_call(["genisoimage", "-quiet", "-output", a.out,
                           "-volid", "cidata", "-joliet", "-rock", d])
    print(f"  ip       : {a.ip}/24")
    print(f"  mac      : {a.mac}")
    print(f"  keys     : {len(keys)}")
    print(f"  seed iso : {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
