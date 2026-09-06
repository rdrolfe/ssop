#!/bin/bash
# SSOP containment firewall wrapper — the ONLY firewall command sudoers allows.
# Replaces the old iptables wildcard rule (which matched extra flags). The
# action is forced here; the caller may only choose the verb and a validated
# IPv4 address. Runs as root via sudo (deploy/sudoers/ssop-containment-network).
# Usage: ssop-containment-iptables.sh block|unblock <ip>
#        ssop-containment-iptables.sh list
set -euo pipefail

IPTABLES="/usr/sbin/iptables"
CHAIN="INPUT"
TARGET="DROP"

# Validate a strict dotted-quad IPv4 (no leading zeros, each octet 0-255).
is_valid_ipv4() {
  local ip="$1" octet
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for octet in "${BASH_REMATCH[@]:1}"; do
    (( 10#$octet <= 255 )) || return 1
    # reject leading zeros (010) and empty/huge octets
    [[ "$octet" == "0" || "$octet" != 0* ]] || return 1
  done
  return 0
}

ACTION="${1:-}"
case "$ACTION" in
  block)
    IP="${2:-}"
    is_valid_ipv4 "$IP" || { echo "refused: invalid or missing IPv4 address" >&2; exit 1; }
    # Action is forced: insert a DROP rule for the source. No caller flags.
    exec "$IPTABLES" -I "$CHAIN" -s "$IP" -j "$TARGET"
    ;;
  unblock)
    IP="${2:-}"
    is_valid_ipv4 "$IP" || { echo "refused: invalid or missing IPv4 address" >&2; exit 1; }
    # Action is forced: delete exactly the rule block added.
    exec "$IPTABLES" -D "$CHAIN" -s "$IP" -j "$TARGET"
    ;;
  list)
    # Read-only verification, forced flags.
    exec "$IPTABLES" -L "$CHAIN" -n
    ;;
  *)
    echo "usage: $0 block <ip> | unblock <ip> | list" >&2
    exit 1
    ;;
esac
