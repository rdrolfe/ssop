#!/bin/bash
# SSOP attack-segment router on .13 (network VM).
# Point-to-point /31 links to purple-team targets through THIS host so its
# Suricata (af-packet on ens19) sits in the path and sees unicast both ways.
#   ubuntu-target : 10.10.1.11/31  peer 10.10.1.10 (= this host)
#   c2-sink       : 10.10.1.20/31  peer 10.10.1.21 (= this host)
# Runs as root via ssop-attack-router.service at boot.
set -u
LOG=/var/log/ssop-attack-router.log
exec >>"$LOG" 2>&1
echo "=== $(date) router start ==="
echo "PATH=$PATH"
command -v ip
echo "--- adding 10.10.1.10/31 ---"
ip addr add 10.10.1.10/31 dev ens19
echo "rc=$?"
echo "--- adding 10.10.1.21/31 ---"
ip addr add 10.10.1.21/31 dev ens19
echo "rc=$?"
ip link set ens19 up
echo "--- forwarding ---"
sysctl -w net.ipv4.ip_forward=1
echo "--- iptables ---"
iptables -C FORWARD -i ens19 -j ACCEPT 2>&1 || iptables -I FORWARD -i ens19 -j ACCEPT 2>&1
iptables -C FORWARD -o ens19 -j ACCEPT 2>&1 || iptables -I FORWARD -o ens19 -j ACCEPT 2>&1
echo "=== done ==="
exit 0
