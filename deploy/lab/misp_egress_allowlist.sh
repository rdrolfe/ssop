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
# Default-deny outbound. Allowed: loopback, established/related, DNS, the SSOP
# LAN, and the declared destination set (feed hosts + the registries/update hosts
# needed to build and maintain the box). Everything else is DROPPED and logged.
#
# IPs churn (CDNs), so the allow-list is a set refreshed from the hostname list
# by a systemd timer — an allow-list you have to hand-edit every time a CDN moves
# is an allow-list that gets disabled.
#
# SAFETY: applying a default-drop OUTPUT policy can cut your own SSH session, so
# this schedules an automatic rollback (flush) after ROLLBACK_S seconds and
# prints the command to arm/disarm it. Verify SSH survives, then cancel.
set -euo pipefail

ROLLBACK_S="${ROLLBACK_S:-300}"
STATE_DIR="/etc/ssop-egress"
HOSTS_FILE="$STATE_DIR/allowed-hosts.txt"
REFRESH_SCRIPT="/usr/local/sbin/ssop-egress-refresh"

# --- the declared destination set ------------------------------------------
# Feeds (docs/feeds-and-licensing.md) + what the box needs to be built and kept
# patched. Adding a feed here is a DECISION, not a convenience: record its
# licence in docs/feeds-and-licensing.md first.
mkdir -p "$STATE_DIR"
cat > "$HOSTS_FILE" <<'EOF'
# --- enabled feeds (licences on record) ---
www.circl.lu
circl.lu
www.botvrij.eu
# --- abuse.ch (enabled in-lab only; requires an authenticated account) ---
urlhaus.abuse.ch
threatfox.abuse.ch
bazaar.abuse.ch
feodotracker.abuse.ch
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
set -euo pipefail
HOSTS_FILE="/etc/ssop-egress/allowed-hosts.txt"
SET="ssop_egress_v4"
IPS=$(grep -vE '^\s*(#|$)' "$HOSTS_FILE" | while read -r h; do
        getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}'
      done | sort -u | tr '\n' ',' | sed 's/,$//')
if [ -z "$IPS" ]; then echo "no IPs resolved — leaving the set unchanged"; exit 1; fi
nft -f - <<RULES
table inet ssop_egress
delete element inet ssop_egress $SET { }
add element inet ssop_egress $SET { $IPS }
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
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oifname "lo" accept
    # DNS: the configured resolvers only
    ip daddr { 192.168.1.1, 1.1.1.1 } udp dport 53 accept
    ip daddr { 192.168.1.1, 1.1.1.1 } tcp dport 53 accept
    # the SSOP LAN (case spine, IRIS, adjudication API, agent traffic)
    ip daddr { 192.168.1.0/24, 10.10.0.0/16 } accept
    # the declared destination set
    ip daddr @ssop_egress_v4 accept
    # everything else is a drop, and it is VISIBLE
    limit rate 12/minute log prefix "ssop-egress-drop " level info
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
nft list table inet ssop_egress | sed -n '1,12p'
echo
echo "Allow-listed addresses: $(nft list set inet ssop_egress ssop_egress_v4 | grep -c ',')"
echo
echo "ROLLBACK ARMED. Verify SSH and egress now; then disarm with:"
echo "  systemctl stop ssop-egress-rollback.timer && systemctl reset-failed ssop-egress-rollback.service"
echo "NOTE: the ruleset does NOT survive a reboot yet — make it permanent only"
echo "      after verification (see the enable step at the end of this session)."
