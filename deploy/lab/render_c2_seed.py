#!/usr/bin/env python3
"""One-off: render the c2-sink seed with attack NIC 10.10.1.20/31 via .13.

c2-sink's attack plane must be a /31 point-to-point link through the .13
router (peer 10.10.1.21) so its reply traffic transits Suricata, matching
ubuntu-target's side. Renders the standard ubuntu autoinstall then
post-processes the attack network block (raw string surgery — the shared
template stays /24-generic and YAML-valid).
"""
import os
import secrets
import string
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from provision_lab import (  # noqa: E402
    AGENT_KEY, GATEWAY, PUBKEYS, REPO_LAB, WAZUH_MANAGER, gen_password,
)

HOSTNAME = "c2-sink"
MGMT_IP = "192.168.1.79"
MGMT_MAC = "02:00:00:00:04:01"
ATTACK_MAC = "02:00:00:00:04:02"
ATTACK_IP = "10.10.1.20"
ATTACK_PREFIX = "31"
ATTACK_ROUTE = "10.10.1.10/31"  # ubuntu-target's link subnet, via peer .21


def render() -> str:
    pw_hash = subprocess.check_output(
        ["openssl", "passwd", "-6", gen_password()], text=True).strip()
    keys = ("\n      - ").join(PUBKEYS or [AGENT_KEY])
    ud = open(os.path.join(REPO_LAB, "ubuntu-autoinstall.yaml")).read()
    ud = (ud
          .replace("__HOSTNAME__", HOSTNAME)
          .replace("__PASSWORD_HASH__", pw_hash)
          .replace("__SSH_PUBKEY__", keys)
          .replace("__MGMT_MAC__", MGMT_MAC)
          .replace("__ATTACK_MAC__", ATTACK_MAC)
          .replace("__MGMT_IP__", MGMT_IP)
          .replace("__ATTACK_IP__", ATTACK_IP)
          .replace("__GATEWAY__", GATEWAY)
          .replace("__WAZUH_MANAGER__", WAZUH_MANAGER))
    # Post-process the attack ethernet block to /31 + route via .13 (.21).
    # NOTE: the MAC placeholder was already substituted above, so match on
    # the rendered value.
    old_attack = (
        "      attack:\n"
        "        match:\n"
        f"          macaddress: \"{ATTACK_MAC}\"\n"
        "        addresses:\n"
        f"          - {ATTACK_IP}/24\n"
    )
    new_attack = (
        "      attack:\n"
        "        match:\n"
        f"          macaddress: \"{ATTACK_MAC}\"\n"
        "        addresses:\n"
        f"          - {ATTACK_IP}/{ATTACK_PREFIX}\n"
        "        routes:\n"
        f"          - to: {ATTACK_ROUTE}\n"
        "            via: 10.10.1.21\n"
    )
    assert old_attack in ud, "attack /24 block not found in rendered seed"
    ud = ud.replace(old_attack, new_attack)
    return ud


if __name__ == "__main__":
    ud = render()
    # Validate the final YAML before writing anything.
    import yaml
    d = yaml.safe_load(ud)
    attack = d["autoinstall"]["network"]["ethernets"]["attack"]
    print("VALID. attack:", attack)
    out = "/tmp/seed-c2-sink/user-data"
    os.makedirs("/tmp/seed-c2-sink", exist_ok=True)
    with open(out, "w") as f:
        f.write(ud)
    meta = f"instance-id: {HOSTNAME}\nlocal-hostname: {HOSTNAME}\n"
    with open("/tmp/seed-c2-sink/meta-data", "w") as f:
        f.write(meta)
    print("written:", out)
