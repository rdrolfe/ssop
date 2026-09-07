#!/bin/bash
# SPIRE agent trust-bundle refresher.
#
# The agent does NOT auto-refresh its trust_bundle_path file — it's a static
# snapshot. When the server's root CA rotates, a stale bundle file breaks
# attestation (the Sep 6 outage: 13k restart loops). This script re-pulls
# the bundle from the local server API and restarts the agent ONLY when the
# bundle actually changed (otherwise restarts would churn SVIDs needlessly).
#
# Install as a systemd timer (every 6h, aligned inside the 24h CA TTL).
# Runs as the spire user on the AGENT host; the server's bundle API
# (spire-server bundle show) is reached via SSH with a restricted key, or
# locally when agent+server are co-located (infra-ops).
set -euo pipefail

BUNDLE_PATH="${SPIRE_BUNDLE_PATH:-$HOME/spire/conf/bundle.crt}"
SERVER_SSH="${SPIRE_SERVER_SSH:-}"   # e.g. rdrolfe@192.168.1.29; empty = local
SPIRE_SERVER_BIN="${SPIRE_SERVER_BIN:-$HOME/spire/bin/spire-server}"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

if [ -n "$SERVER_SSH" ]; then
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$SERVER_SSH" \
    "$SPIRE_SERVER_BIN bundle show -format pem" > "$tmp"
else
  "$SPIRE_SERVER_BIN" bundle show -format pem > "$tmp"
fi

# Sanity: the fetched bundle must contain at least one valid cert.
grep -q "BEGIN CERTIFICATE" "$tmp" || { echo "fetched bundle invalid"; exit 1; }

if [ -f "$BUNDLE_PATH" ] && cmp -s "$tmp" "$BUNDLE_PATH"; then
  echo "bundle unchanged"
  exit 0
fi

mkdir -p "$(dirname "$BUNDLE_PATH")"
[ -f "$BUNDLE_PATH" ] && cp -p "$BUNDLE_PATH" "$BUNDLE_PATH.bak"
mv "$tmp" "$BUNDLE_PATH"
trap - EXIT

echo "bundle updated — restarting agent"
sudo systemctl restart spire-agent
