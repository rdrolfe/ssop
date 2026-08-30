#!/bin/bash
# SSOP SPAN mirror: copy attack-plane (vmbr1) traffic to SO's capture NIC.
#
# Linux bridges do NOT deliver known-unicast between two other ports to a
# third port, even if that port is promiscuous. SO's sensor (sec-onion,
# net1 = tap706i1 on vmbr1) therefore only saw broadcast/multicast. This
# mirrors ALL ingress on the attack taps to SO's tap, so its Suricata/Zeek
# see the full purple-team traffic — the same frames .13's Suricata sees.
#
# Runs as root via ssop-span-mirror.service at boot (idempotent).
set -u

SO_TAP=tap706i1
SRC_TAPS="tap902i1 tap903i1 tap904i1 tap705i1"

for tap in $SRC_TAPS; do
    # skip if the tap doesn't exist (VM down)
    [ -e "/sys/class/net/$tap" ] || continue
    # add an ingress qdisc (idempotent-ish: ignore if already present)
    tc qdisc add dev "$tap" ingress 2>/dev/null || true
    # mirror every ingress packet to SO's tap (mirred mirror = copy, not redirect)
    tc filter add dev "$tap" parent ffff: matchall action mirred egress mirror dev "$SO_TAP" 2>/dev/null || true
done

exit 0
