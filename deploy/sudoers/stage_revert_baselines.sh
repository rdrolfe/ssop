#!/bin/bash
# Stage config_revert baselines on a host: copies current versions of the
# canonical revert artifacts into /opt/ssop-backups/ (mode 600, root-owned).
# Run ONCE per host after containment deployment; re-run to refresh.
set -euo pipefail
declare -A CANONICAL=(
  ["sshd_config"]="/etc/ssh/sshd_config"
  ["sshd_config.ssop-baseline"]="/etc/ssh/sshd_config"
  ["hosts"]="/etc/hosts"
  ["crontab"]="/etc/crontab"
  ["sysctl.conf"]="/etc/sysctl.conf"
  ["ssop-containment-network"]="/etc/sudoers.d/ssop-containment-network"
  ["ssop-containment-revert"]="/etc/sudoers.d/ssop-containment-revert"
)
mkdir -p /opt/ssop-backups
chmod 700 /opt/ssop-backups
for art in "${!CANONICAL[@]}"; do
  src="${CANONICAL[$art]}"
  if [ -f "$src" ] && [ ! -L "$src" ]; then
    cp "$src" "/opt/ssop-backups/$art"
    chmod 600 "/opt/ssop-backups/$art"
    echo "staged $art <- $src"
  else
    echo "skip $art (source missing or symlink): $src" >&2
  fi
done
ls -la /opt/ssop-backups/
