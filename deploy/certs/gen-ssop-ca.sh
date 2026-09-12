#!/bin/bash
# SSOP internal CA + service certificates (issue #29).
# Run ON .29 (infra-ops) as rdrolfe. Idempotent: skips generation when the
# CA already exists. Certs carry IP SANs for the homelab addressing.
set -euo pipefail
CA_DIR="$HOME/agent-runtime/certs/ca"
OUT_DIR="$HOME/agent-runtime/certs/services"
DAYS_CA=3650
DAYS_SVC=825

mkdir -p "$CA_DIR" "$OUT_DIR"

# --- CA (one-time) ---
if [ ! -f "$CA_DIR/ca.key" ]; then
  echo "== generating SSOP internal CA =="
  openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS_CA" -nodes \
    -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" \
    -subj "/C=US/O=SSOP/CN=SSOP Internal Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
else
  echo "== CA already exists, skipping generation =="
fi

# --- service cert helper ---
# usage: issue <name> <SAN-entries comma separated>
issue() {
  local name="$1" san="$2"
  if [ -f "$OUT_DIR/$name.crt" ]; then echo "  $name: exists, skip"; return; fi
  echo "== issuing $name ($san) =="
  openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$OUT_DIR/$name.key" -out "$OUT_DIR/$name.csr" \
    -subj "/C=US/O=SSOP/CN=$name"
  openssl x509 -req -sha256 -in "$OUT_DIR/$name.csr" \
    -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
    -days "$DAYS_SVC" -out "$OUT_DIR/$name.crt" \
    -extfile <(printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" "$san")
  rm "$OUT_DIR/$name.csr"
}

# Services, with the SANs clients actually connect by:
# NOTE: every SAN here must match the host clients CONNECT BY, or the
# hostname check fails and the certificate is useless (verified TLS cannot
# match an IP against a CN, and a bare CN has nothing to do with an IP).
# `iris` shipped IP:192.168.1.50 — a host that does not exist — while IRIS
# runs on .75, so the mirror could never verify. Keep these honest.
issue adjudicate-api "IP:192.168.1.29,IP:127.0.0.1,DNS:infra-ops"
issue indexer        "IP:192.168.1.29,DNS:infra-ops"
issue wazuh-api      "IP:192.168.1.29,DNS:infra-ops"
issue proxmox        "IP:192.168.1.137,DNS:proxmox"
issue iris           "IP:192.168.1.75,IP:127.0.0.1,DNS:iris,DNS:telemetry"
issue qdrant         "IP:192.168.1.94,IP:127.0.0.1,DNS:kb-vec"

# --- trust bundle: everything a client host needs ---
cat "$CA_DIR/ca.crt" > "$CA_DIR/ca-bundle.crt"
echo
echo "== DONE =="
echo "CA bundle (distribute to client hosts at ~/.ssop/ca/ca-bundle.crt):"
echo "  $CA_DIR/ca-bundle.crt"
echo "Service certs: $OUT_DIR/"
ls -la "$OUT_DIR" | grep -E "\.(crt|key)$"
