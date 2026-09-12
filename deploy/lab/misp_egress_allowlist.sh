#!/bin/bash
# MISP host egress allow-list (ADR-007 call 2: "declared AND enforced").
#
# RUN ON THE MISP HOST (192.168.1.80) as root.
#
# WHY HERE AND NOT .13 — the original plan said "an allow-list at .13" and that
# was WRONG: .13's default route is via 192.168.1.1, the same as every other host
# on the management subnet, so .13 never sees this traffic (it only routes the
# 10.10.x.x attack segment). A rule there would have been a control that gates
# nothing, which is worse than no rule because it reads like enforcement.
# MISP's egress leaves via the gateway .1, so the only honest places to pin it are
# (a) the host that owns the egress — here — or (b) the router itself (operator's
# call, and the only place that constrains a host that ignores its own firewall).
#
# WHY THERE ARE **TWO** CHAINS — measured, not assumed. The first version of this
# script installed an `output` hook only. MISP's feed workers run INSIDE
# CONTAINERS, and container egress is ROUTED (veth -> bridge -> ens18), so it
# traverses `forward`, not `output`. Proved with counters on this host:
#     container -> 1.1.1.1:443   output: 0 packets | forward: 14 packets, 2590 B
# So an output-only ruleset would have pinned the host's own egress and gated
# nothing that MISP actually does — the exact "control that gates nothing" this
# header warns about. Both hooks are now installed with the same policy.
#
# Default-deny outbound. Allowed: loopback, established/related, DNS, RFC1918
# (which is what the runtime's own `check_egress.py` already defines as LOCAL —
# using the same definition in both places keeps the two layers honest), and the
# declared destination set (feed hosts + the registries/update hosts needed to
# build and maintain the box). Everything else is DROPPED and logged.
#
# IPs churn (CDNs), so the allow-list is a set refreshed from the hostname list
# by a systemd timer — an allow-list you have to hand-edit every time a CDN moves
# is an allow-list that gets disabled.
#
# SAFETY: applying a default-drop policy can cut your own SSH session, so this
# schedules an automatic rollback (delete the table) after ROLLBACK_S seconds and
# prints the command to arm/disarm it. Verify SSH and egress, then cancel.
set -euo pipefail

ROLLBACK_S="${ROLLBACK_S:-300}"
STATE_DIR="/etc/ssop-egress"
HOSTS_FILE="$STATE_DIR/allowed-hosts.txt"
RULESET_FILE="$STATE_DIR/ruleset.nft"
REFRESH_SCRIPT="/usr/local/sbin/ssop-egress-refresh"
APPLY_SCRIPT="/usr/local/sbin/ssop-egress-apply"

# --- --persist: make it survive a reboot, then exit (never re-applies) -----
# Kept as a separate mode so the ordinary run stays a testable, rollback-armed
# action. Persist ONLY what was verified live: snapshot the running table rather
# than re-deriving it, so a boot cannot silently apply a different policy than
# the one that was tested.
if [ "${1:-}" = "--persist" ]; then
  if ! nft list table inet ssop_egress >/dev/null 2>&1; then
    echo "refusing to persist: no live 'inet ssop_egress' table to snapshot" >&2
    exit 1
  fi
  nft list table inet ssop_egress > "$RULESET_FILE"
  cat > "$APPLY_SCRIPT" <<'EOF'
#!/bin/bash
# Apply the VERIFIED SSOP egress ruleset at boot, then populate the allow-list.
set -euo pipefail
nft list table inet ssop_egress >/dev/null 2>&1 || nft -f /etc/ssop-egress/ruleset.nft
# DNS may not be up the instant this runs; an empty resolve leaves the set empty,
# which is a total external outage until the hourly refresh. Retry instead.
for _ in 1 2 3 4 5; do
  /usr/local/sbin/ssop-egress-refresh && break
  sleep 15
done
EOF
  chmod 0755 "$APPLY_SCRIPT"
  cat > /etc/systemd/system/ssop-egress.service <<'EOF'
[Unit]
Description=Apply the SSOP egress allow-list (default-deny out + forward)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ssop-egress-apply
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ssop-egress.service >/dev/null
  echo "persisted: $RULESET_FILE + ssop-egress.service (enabled)"
  echo "NOTE: not reboot-verified — a reboot would interrupt the in-flight pulls."
  exit 0
fi

# --- the declared destination set ------------------------------------------
# Feeds (docs/feeds-and-licensing.md) + what the box needs to be built and kept
# patched. Adding a feed here is a DECISION, not a convenience: record its
# licence in docs/feeds-and-licensing.md first.
#
# NOTE the abuse.ch host list matches the endpoints VERIFIED on 2026-09-12:
# Feodo Tracker is defunct (its hostname no longer resolves — harmless to list,
# and it must not be counted as a covered feed) and SSLBL's IP blacklist is
# retired; the live four are URLhaus, ThreatFox, MalwareBazaar and the SSLBL
# certificate list.
mkdir -p "$STATE_DIR"
cat > "$HOSTS_FILE" <<'EOF'
# --- enabled feeds (licences on record) ---
www.circl.lu
circl.lu
www.botvrij.eu
# --- abuse.ch (enabled in-lab only; the four endpoints that still exist) ---
urlhaus.abuse.ch
threatfox.abuse.ch
bazaar.abuse.ch
sslbl.abuse.ch
abuse.ch
auth.abuse.ch
# --- container registries (build/maintenance only) ---
download.docker.com
registry-1.docker.io
auth.docker.io
production.cloudflare.docker.com
ghcr.io
pkg-containers.githubusercontent.com
# --- OS updates + time (build/maintenance only) ---
archive.ubuntu.com
security.ubuntu.com
changelogs.ubuntu.com
esm.ubuntu.com
ntp.ubuntu.com
EOF

# --- refresh helper: hostnames -> nft set --------------------------------
cat > "$REFRESH_SCRIPT" <<'EOF'
#!/bin/bash
# Resolve the declared hostnames and replace the nft allow-list set.
#
# Uses `flush set` rather than `delete element ... { }`: an empty element list is
# a syntax error in nft, so the delete-form would abort (set -e) on the first
# refresh after a fresh table — leaving the allow-list EMPTY and every feed pull
# failing. A refresh that can only fail once, silently, is not a refresh.
set -euo pipefail
HOSTS_FILE="/etc/ssop-egress/allowed-hosts.txt"
TABLE="inet ssop_egress"
SET="ssop_egress_v4"

# No table yet (refresh timer raced the first apply): nothing to refresh.
nft list table $TABLE >/dev/null 2>&1 || { echo "ssop-egress: table absent, skipping"; exit 0; }

IPS=$(grep -vE '^\s*(#|$)' "$HOSTS_FILE" | while read -r h; do
        getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}'
      done | sort -u | tr '\n' ',' | sed 's/,$//')

# An empty resolve must NOT wipe a working allow-list: DNS being down here is a
# transient, and emptying the set would turn it into an outage of every feed.
if [ -z "$IPS" ]; then echo "ssop-egress: no IPs resolved — leaving the set unchanged"; exit 1; fi

nft -f - <<RULES
flush set $TABLE $SET
add element $TABLE $SET { $IPS }
RULES
echo "ssop-egress: allow-list refreshed ($(tr ',' '\n' <<<"$IPS" | wc -l) addresses)"
EOF
chmod 0755 "$REFRESH_SCRIPT"

# --- base ruleset (idempotent destroy+recreate) ---------------------------
apply_rules() {
  nft -f - <<'RULES'
table inet ssop_egress
delete table inet ssop_egress
table inet ssop_egress {
  set ssop_egress_v4 {
    type ipv4_addr
    flags interval
    auto-merge
    comment "declared destinations (feeds + registries), refreshed from /etc/ssop-egress/allowed-hosts.txt"
  }
  # Locally-generated traffic (the host's own).
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oifname "lo" accept
    # DNS: the configured resolver only (resolvectl: ens18 -> 192.168.1.1)
    ip daddr { 192.168.1.1, 1.1.1.1 } udp dport 53 accept
    ip daddr { 192.168.1.1, 1.1.1.1 } tcp dport 53 accept
    # RFC1918 == "local", the same definition check_egress.py uses
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
    ip daddr @ssop_egress_v4 accept
    limit rate 12/minute log prefix "ssop-egress-drop-out " level info
    counter drop
  }
  # ROUTED traffic — this is where MISP's containers actually leave.
  # priority -10 so it is evaluated BEFORE docker's iptables-nft FORWARD chains
  # (priority 0); otherwise docker's own ACCEPTs would decide the question first.
  chain forward {
    type filter hook forward priority -10; policy drop;
    ct state established,related accept
    # Covers the docker bridge networks (172.18.0.0/16) AND the inbound DNAT that
    # publishes the web UI, because DNAT rewrites the destination in PREROUTING
    # before this hook sees the packet.
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
    ip daddr @ssop_egress_v4 accept
    limit rate 12/minute log prefix "ssop-egress-drop-fwd " level info
    counter drop
  }
}
RULES
}

echo "== scheduling rollback in ${ROLLBACK_S}s (safety) =="
systemctl stop ssop-egress-rollback.timer 2>/dev/null || true
systemd-run --on-active="${ROLLBACK_S}" --unit=ssop-egress-rollback --collect \
  /usr/sbin/nft delete table inet ssop_egress >/dev/null

apply_rules
"$REFRESH_SCRIPT"

# --- refresh timer ---------------------------------------------------------
cat > /etc/systemd/system/ssop-egress-refresh.service <<'EOF'
[Unit]
Description=Refresh the SSOP egress allow-list (hostname -> nft set)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ssop-egress-refresh
EOF
cat > /etc/systemd/system/ssop-egress-refresh.timer <<'EOF'
[Unit]
Description=Hourly refresh of the SSOP egress allow-list
[Timer]
OnCalendar=*-*-* *:17:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now ssop-egress-refresh.timer >/dev/null

echo
echo "== applied =="
nft list table inet ssop_egress | sed -n '1,14p'
echo
echo "Allow-listed addresses: $(nft list set inet ssop_egress ssop_egress_v4 | grep -c ',')"
echo
echo "ROLLBACK ARMED. Verify SSH and egress now; then disarm with:"
echo "  systemctl stop ssop-egress-rollback.timer && systemctl reset-failed ssop-egress-rollback.service"
echo "Then make it survive a reboot with:  $0 --persist"
echo
