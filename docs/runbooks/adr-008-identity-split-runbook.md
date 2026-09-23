# Runbook — ADR-008 stage 2 (i): move the unattended plane to `ssop-agent`

**Where:** host `.29` (the SSOP platform VM, `192.168.1.29`), logged in as **`rdrolfe`**,
working from **`/home/rdrolfe/agent-runtime`**. Not the Proxmox host (`.169`), not the
Hermes desktop.

**Why this exists:** the commit boundary is only real if the unattended processes
*cannot read the private commit key*. Today all 11 units run as `rdrolfe` — the same
account that owns the key — so any authority they were asked to respect, they could
bypass. This moves the 9 unattended units onto a dedicated `ssop-agent`, while the
human console (which is what commits) keeps the key.

**Script:** `/home/rdrolfe/agent-runtime/deploy/lab/migrate_agent_plane.sh`
(md5 `885c84dcfde0b2335d8095a3653fad1a`, identical to the repo copy).
Idempotent. **Dry-run by default**; `--apply` changes things; `--rollback` undoes.

---

## Step 0 — preconditions (verified as of 2026-09-22)

| Check | State |
|---|---|
| All 11 units run as `rdrolfe` | yes |
| `ssop` group / `ssop-agent` user | **absent** — this is why the script exits 3 |
| `~/agent-runtime` md5 == repo copy | yes |
| Private key outside the tree, 0700 | yes (`~/.ssop-keys`) |

## Step 1 — the only step that needs YOUR password

`groupadd` / `useradd` / `usermod` are **not** in the NOPASSWD whitelist
(whitelisted: `apt`, `apt-get`, `dpkg`, `chown`, `chmod`, `systemctl`, `sed`,
`agent-auth`). Paste this as one block, enter your password once:

```bash
sudo groupadd -f ssop
sudo useradd --system --gid ssop --no-create-home --home-dir /home/rdrolfe/agent-runtime --shell /usr/sbin/nologin ssop-agent
sudo usermod -aG ssop rdrolfe
```

Confirm it took:

```bash
getent group ssop; getent passwd ssop-agent
```

Expected: a line for `ssop:x:…:rdrolfe` and one for
`ssop-agent:x:…:/home/rdrolfe/agent-runtime:/usr/sbin/nologin`.

> **Re-login before touching files by hand.** `usermod` does not reach your *current*
> session. Until you `newgrp ssop` or reconnect, your shell lacks the group bit and
> edits to files the agent owns will be denied.

## Step 2 — the migration itself (no password)

The script's privileged calls are all `sudo -n systemctl` (whitelisted), so it will
not prompt.

```bash
cd ~/agent-runtime
./deploy/lab/migrate_agent_plane.sh            # dry run: prints PLAN, changes nothing
./deploy/lab/migrate_agent_plane.sh --apply    # exit code = number of units that FAILED
```

What it does, in order: back up every unit file it touches → `chgrp -R ssop` +
`chmod -R g+rwX` on the runtime tree (this is also what makes `.env` and the
presently `-rw-------` tool modules readable by the agent) → set `User=`/`Group=` on
9 units → `daemon-reload` → verify.

Expected tail:

```
backed up 9 unit file(s) to /home/rdrolfe/agent-runtime/.deploy-bak/agent-plane-<stamp>
runtime tree group-shared; key dir left 0700 rdrolfe-only
  <unit>: User=ssop-agent Group=ssop          (×9)
daemon-reload done
VERIFY
  OK   ssop-supervisory -> ssop-agent:ssop    (×9)
  human-plane (unchanged): ssop-adjudicate-api -> rdrolfe
  human-plane (unchanged): ssop-qdrant-tunnel -> rdrolfe
```

The two units left on `rdrolfe` are deliberate: `ssop-adjudicate-api` is the human
console and a click is what commits, `ssop-qdrant-tunnel` uses your SSH material.

## Step 3 — timers

```bash
sudo -n systemctl restart ssop-supervisory.timer ssop-router.timer ssop-analyst.timer ssop-hunt.timer
sudo -n systemctl start ssop-supervisory.service
```

Services pick up the new `User=` on their next start, so the other timers need no
action.

## Step 4 — prove the boundary (this is the actual deliverable)

The probe must run **as `ssop-agent`**. `sudo -u` needs a password that account does
not have, so run it as a one-shot systemd unit. Create
`/home/rdrolfe/agent-runtime/ssop-plane-probe.service`:

```ini
[Unit]
Description=ADR-008 boundary probe (runs on the automation plane)
[Service]
Type=oneshot
User=ssop-agent
Group=ssop
WorkingDirectory=/home/rdrolfe/agent-runtime
ExecStart=/bin/sh -c '/home/rdrolfe/agent-runtime/agent-env/bin/python3 deploy/lab/agent_plane_probe.py > /home/rdrolfe/agent-runtime/plane-probe.out 2>&1'
```

Then:

```bash
sudo -n systemctl daemon-reload
sudo -n systemctl start ssop-plane-probe.service
cat ~/agent-runtime/plane-probe.out
```

**Pass condition:** ends in `BOUNDARY HOLDS`, with the private key *not* readable,
`signing_available() is False`, the public key readable, every committed tuning entry
still verifying, and `commit()` refusing.

If it prints `[SKIP] commit() refusal — not applicable here`, the probe ran on the
wrong plane; it proves nothing about the boundary.

## Step 5 — verify the units actually WORK (not just that User= took)

`systemctl show User` proves the setting landed; it does not prove the agent can read
what it needs. Check a real run:

```bash
systemctl show ssop-supervisory.service -p User -p ExecMainStatus -p Result
journalctl -u ssop-supervisory.service -n 30 --no-pager
```

## Rollback

```bash
cd ~/agent-runtime && ./deploy/lab/migrate_agent_plane.sh --rollback
```

Restores the 9 unit files from `.deploy-bak/agent-plane-<stamp>`, `chgrp`s the tree
back to `rdrolfe`, `daemon-reload`s. Timers keep running as `rdrolfe` throughout.

---

## Known landmines

1. **`$HOME` divergence.** `ssop-agent`'s passwd home is the runtime dir, so any code
   using `Path.home()` / `~` resolves *inside the tree* after the switch. `deploy/lab/drill.py`
   writes its receipt to `Path.home()/.ssop/state/drill-last.json` — today that is
   `/home/rdrolfe/.ssop/state/drill-last.json`, which the digest *reads*. After the
   split, the drill writes into the tree while the digest (running as you) reads the
   old path → the digest quietly reports no drill info. Same class:
   `dispose_infra_cases.py`, `sweep_case_decisions.py`. Fix is to pin one absolute path
   for both sides; `/home/rdrolfe` is `0750 rdrolfe:rdrolfe`, so the agent cannot
   traverse it and "make the old path writable" is *not* an option.
2. **The key must stay outside the tree.** The boundary rests on `~/.ssop-keys` being
   0700 and outside `~/agent-runtime`. Copy the key in and the split is cosmetic — the
   automation could read what it is only supposed to verify.
3. **`chmod -R g+rwX` makes the tree group-writable**, `.env` included. That is
   required (the units read it) and matches their old capability, but it means the
   quality of this boundary depends entirely on the key never living in that tree.