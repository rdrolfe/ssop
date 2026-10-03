# Map: lab target provisioning

**Charted:** 2026-10-01, after `provision_lab.py` failed to produce a usable
attack target across three rebuild attempts.

## Destination

A Linux target that boots unattended, holds static `192.168.1.77`, accepts the
fleet SSH keys as user `lab`, and runs a Wazuh agent registered as
`ubuntu-target` — so real adversary techniques can be fired at it and the
resulting alerts flow through the existing detection chain.

## Status: BLOCKED, and the blocker is not what we thought

The original ticket assumed the gap was "no attacker credentials on the
target". That was wrong. **The pipeline cannot complete an install at all.**

The install runs and curtin applies the seed's `late-commands` — observed on
screen: `apply networking config`, `installing openssh-server`,
`configuring cloud-init`, `installing grub to target devices`. The disk fills
to ~3–5 GB. The box reboots. And then it is **unreachable**:

```
Ubuntu 24.04 LTS ntarget tty1
cloud-init: no authorized SSH key fingerprints found
cloud-init: finished ... Datasource DataSourceNone.
```

`DataSourceNone` is the finding. The *installer* read the seed; the *installed
system's* cloud-init never does. Consequences, all confirmed on screen or by
probe: hostname is `ntarget` instead of `ubuntu-target`, the `lab` user is
never created, netplan never applies, so the host has **no network interface**
— port 22 closed, ARP entry goes `STALE`, no ping. A "successful" install that
produces a box nobody can reach.

Supporting signal: cloud-init names user `rdrolfe`, not the seed's `lab`. That
alone shows the identity block of `user-data` never reached the running system.

## What is proven

- `ssop@pve` Proxmox API token — minted, least-privilege, verified. The runtime
  `ProxmoxClient` authenticates and enumerates 21–22 VMs. (The old
  `ssop-rotated` token was dead: 401 on every call.)
- `c2-sink` (`.79`) — SSH as `lab` with `hermes_ssop`, dual-homed on
  `192.168.1.79/24` and `10.10.1.20/31` (isolated attack plane),
  `wazuh-agent` **active**. This is a working attacker platform and it needs
  no rebuild.
- The seed itself is well-formed. Installer ISO at `ide2`, cloud-init seed at
  `ide3`, seed volume id is `cidata`. **Both ISOs are required** — the
  installer media is the OS, the seed is the config. Two ISOs is not a defect.

## Traps recorded (each cost real time; none should be re-learned)

1. **Never rebuild the ISO with xorriso to inject kernel flags.** It silently
   discards the El Torito boot catalog — `-report_el_torito` comes back empty on
   the output while looking fine on stdout. The image then cannot boot. To pass
   `autoinstall`, extract `/casper/vmlinuz` + `/casper/initrd` from the ISO and
   boot them directly with `qm set --args -kernel ... -append "autoinstall ..."`.
2. **Never `--bios ovmf`.** It lands in a UEFI Interactive Shell with no CD-ROM
   mapped (`BLK0` = a SATA disk, nothing else). Use default seabios/i440fx, which
   is what `c2-sink` uses.
3. **Boot order is a race on first reboot.** `boot: order=ide2` during install;
   `scsi0` after. The `--args ... autoinstall` override **must be deleted before
   the first reboot** — if it survives, the VM re-runs the installer kernel and
   overwrites the install with ISO defaults. This is the single most likely
   cause of the `ntarget`/`DataSourceNone` outcome on attempt 1.
4. **A detached ISO fails silently.** `ide2`/`ide3` disappeared from the VM config
   across restarts more than once, leaving `boot: order=scsi0` and the operator-
   visible symptom "keeps breaking, looking for a new CD." Re-verify
   `qm config <vmid> | grep -E '^boot|^ide'` after **every** restart.
5. **`qm monitor <vmid> screendump` captures the Proxmox HOST framebuffer, not
   the guest.** It returns a healthy-looking Proxmox splash screen, which reads
   as "the VM is fine" when it is not. Use QMP (`qmp_capabilities`, then
   `screendump`) for the guest display, or serial for text.
6. **The VM has no keyboard device — only `usb-tablet`.** `send-key` and serial
   writes cannot drive it. Subiquity prompts for language / installer update /
   install type / proxy / mirror / storage, and none of it can be answered
   remotely. This is the hard blocker: the install needs one Enter per step and
   there is no channel to send one. `--usb0 host=0001:0001` did not produce a
   usable keyboard.

## Open question — what to actually fix

Make the install unattended *and* leave the seed readable by the installed
system. The installer consuming the seed during install is not sufficient;
cloud-init on first boot must also find it. Candidates, unevaluated:

- keep `ide3` attached across the first reboot **and** carry `ds=nocloud` on the
  installed system's kernel cmdline (today it boots with no cmdline at all, so
  cloud-init has nothing to look for)
- write the rendered `user-data`/`meta-data` onto the target filesystem via
  `late-commands` into `/var/lib/cloud/seed/nocloud/`, so it survives with no ISO
  attached
- attach the seed over virtio-serial or a second disk rather than a CD-ROM, so it
  cannot be detached

Any of these should be validated by asserting, post-reboot, that
`cloud-init status` is `done` and the datasource is **not** `None`.

## Interim plan

Do not rebuild `ubuntu-target` again until one of the above is proven. Use
`c2-sink` (`.79`) as the attacker platform: it is reachable, has the isolated
attack plane wired, and reports to Wazuh. Network-origin techniques (SSH
brute-force, port scan, C2 beacon, exfil to a sink) are fireable from it today
and cover the majority of the detection-validation value. Host-origin
techniques (new user, `authorized_keys` write, cron persistence) still need a
working victim.

## Out of scope

- Rewriting the daily `ssop-drill.timer` invariant — it passes and is
  independent of this work.
- Windows targeting (`win-target`/`.78`, VMID 903) until Linux is proven. It is
  running and registered as `WIN-SBUNBSBHIUG`, but `RULE_MAP` carries no Windows
  rule ids, so alerts there cannot be attributed yet.
