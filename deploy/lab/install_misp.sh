#!/bin/bash
# Install the MISP feed platform on the dedicated VM (707 / 192.168.1.80).
# Run ON the MISP host as rdrolfe (sudo required). Idempotent.
#
# Decisions this script implements (ADR-007 + docs/feeds-and-licensing.md):
#   - Docker CE from Docker's signed apt repo (Ubuntu's docker.io is 24.x, below
#     the upstream-documented Docker 25+ requirement).
#   - misp-docker pinned to CORE_TAG=v2.5.46.
#   - VERIFIED TLS: the SSOP-CA leaf for `misp` (SAN IP:192.168.1.80,DNS:misp) is
#     installed at ./ssl/ so BASE_URL can be https://192.168.1.80 with a real
#     certificate. No CERT_NONE, no "just disable verification" shortcut.
#   - The `mail` container is NOT started: a closed lab should have no SMTP
#     egress at all, and MISP functions without it.
#   - The admin password is GENERATED here and stored 0600 on this host, never
#     in the repo and never echoed into a log.
#
# Prereqs staged by the caller (scp'd into /tmp first):
#   /tmp/misp.crt  /tmp/misp.key   (SSOP-CA leaf, from .29 certs/services/)
set -euo pipefail

MISP_DIR="/opt/misp-docker"
CORE_TAG="v2.5.46"
BASE_URL="https://192.168.1.80"
# Secrets path must NOT depend on sudo's $HOME: running this script as
# `sudo bash install_misp.sh` makes $HOME=/root, so a "$HOME/.ssop" secret
# silently lands in /root/.ssop while the operator is told to look in
# ~/.ssop/<name> — verified 2026-09-12, and it made a later login check fail
# with an EMPTY password. Pick the path from the invoking user, print it.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  SECRETS="/home/$SUDO_USER/.ssop"
else
  SECRETS="/root/.ssop"
fi

echo "=== [1/6] base packages ==="
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  ca-certificates curl gnupg qemu-guest-agent >/dev/null
sudo systemctl enable --now qemu-guest-agent >/dev/null 2>&1 || true

echo "=== [2/6] docker ce + compose plugin (signed repo) ==="
if ! command -v docker >/dev/null; then
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.asc >/dev/null
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
  sudo usermod -aG docker "$USER"
fi
DOCKER_V=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
echo "  docker engine: $(docker --version)"
awk -v v="$DOCKER_V" 'BEGIN{ if (v+0 < 25) { print "  FAIL: engine below the required 25+"; exit 1 } }'

echo "=== [3/6] TLS material (SSOP CA leaf) ==="
# Staged to /tmp first: installing it into $MISP_DIR/ssl BEFORE the clone makes
# the clone target non-empty and git refuses ("destination path already exists
# and is not an empty directory") — which is exactly how the first run of this
# script died after already completing steps 1-2.
mkdir -p "$SECRETS"
test -f /tmp/misp.crt && test -f /tmp/misp.key || {
  echo "FAIL: /tmp/misp.crt and /tmp/misp.key must be staged before running"; exit 1; }
install -m 0644 /tmp/misp.crt /tmp/misp-ssl-cert.pem
install -m 0640 /tmp/misp.key /tmp/misp-ssl-key.pem

echo "=== [4/6] misp-docker @ $CORE_TAG ==="
if [ ! -d "$MISP_DIR/.git" ]; then
  if [ -d "$MISP_DIR" ] && [ -n "$(ls -A "$MISP_DIR" 2>/dev/null)" ]; then
    echo "  $MISP_DIR exists without .git — preserving it as .pre-clone.bak and cloning clean"
    sudo mv "$MISP_DIR" "${MISP_DIR}.pre-clone.$(date +%s)"
  fi
  sudo mkdir -p "$MISP_DIR"
  sudo chown "$USER:$USER" "$MISP_DIR"
  git clone -q https://github.com/misp/misp-docker "$MISP_DIR"
fi
cd "$MISP_DIR"
git fetch -q --tags
git checkout -q "$CORE_TAG" 2>/dev/null || true

# Now the certs can land (dir is a real checkout).
mkdir -p "$MISP_DIR/ssl"
sudo install -m 0644 /tmp/misp-ssl-cert.pem "$MISP_DIR/ssl/cert.pem"
sudo install -m 0640 /tmp/misp-ssl-key.pem "$MISP_DIR/ssl/key.pem"

# OWNERSHIP IS IMAGE-SPECIFIC — PROBE IT, DON'T COPY THE LAST PRECEDENT.
# The misp-nginx container runs as uid 101 (nginx) and reads the key as that
# user, so root:root 0640 restart-loops it with
#   [emerg] cannot load certificate key "/etc/nginx/certs/key.pem":
#   BIO_new_file() failed (SSL: ... Permission denied)
# (IRIS had the same failure with uid 33/was www-data — a different number, which
# is why this is probed at install time rather than hardcoded blind.)
NGINX_UID=$(sudo docker run --rm --entrypoint id ghcr.io/misp/misp-docker/misp-nginx:latest 2>/dev/null \
            | sed -n 's/^uid=\([0-9]*\).*/\1/p')
NGINX_UID=${NGINX_UID:-101}
sudo chown "$NGINX_UID:$NGINX_UID" "$MISP_DIR/ssl/key.pem"
sudo chmod 0640 "$MISP_DIR/ssl/key.pem"
echo "  installed ssl/{cert,key}.pem from the SSOP CA leaf (SAN IP:192.168.1.80), key owned by uid $NGINX_UID"

# admin password: generated once, stored 0600 on this host only
if [ ! -f "$SECRETS/misp-admin.txt" ]; then
  printf 'admin@admin.test\n%s\n' "$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)" > "$SECRETS/misp-admin.txt"
  chmod 0600 "$SECRETS/misp-admin.txt"
fi
ADMIN_PW=$(sed -n 2p "$SECRETS/misp-admin.txt")

if [ ! -f .env ]; then
  cp template.env .env
  # pin + identity
  sed -i "s/^CORE_TAG=.*/CORE_TAG=$CORE_TAG/" .env
  sed -i "s|^BASE_URL=.*|BASE_URL=$BASE_URL|" .env
  sed -i "s/^ADMIN_EMAIL=.*/ADMIN_EMAIL=admin@admin.test/" .env
  sed -i "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=$ADMIN_PW/" .env
  sed -i "s/^ADMIN_ORG=.*/ADMIN_ORG=SSOP/" .env
  sed -i "s|^DISABLE_IPV6=.*|DISABLE_IPV6=true|" .env
  grep -q '^DISABLE_IPV6=' .env || echo 'DISABLE_IPV6=true' >> .env
  chmod 0600 .env
fi
echo "  .env: CORE_TAG=$(grep -E '^CORE_TAG=' .env | cut -d= -f2) BASE_URL=$(grep -E '^BASE_URL=' .env | cut -d= -f2)"

echo "=== [5/6] pull images (this takes a while) ==="
sudo docker compose pull -q misp-core misp-nginx misp-modules db redis 2>&1 | tail -3

echo "=== [6/6] bring up (mail DELIBERATELY excluded — no SMTP egress) ==="
sudo docker compose up -d misp-core misp-nginx misp-modules db redis 2>&1 | tail -10
sleep 20
sudo docker compose ps --format '{{.Service}}\t{{.Status}}'

cat <<EOF

=== install staged ===
  admin user : admin@admin.test
  admin pass : stored 0600 at $SECRETS/misp-admin.txt (never in the repo)
  base url   : $BASE_URL
  image tag  : $CORE_TAG
MISP's first boot initialises the DB and can take several minutes before the
web UI answers. Verify TLS from .29 (no CERT_NONE):
  curl --cacert ~/agent-runtime/certs/ca/ca-bundle.crt $BASE_URL/users/login
EOF
