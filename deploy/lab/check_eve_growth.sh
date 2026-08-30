#!/bin/bash
# .13: newest alert events + eve.json growth
timeout 40 ssh -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes rdrolfe@192.168.1.13 '
echo "=== eve.json size + mtime (now) ==="
ls -la --time-style=long-iso /var/log/suricata/eve.json | awk "{print \$5, \$6, \$7}"
date "+%F %T"
echo "=== total lines + newest alert (first of last 12 alerts) ==="
N=$(sudo -n sed -n "$=" /var/log/suricata/eve.json 2>/dev/null)
echo "total lines: $N"
sudo -n sed -n "/\"event_type\":\"alert\"/p" /var/log/suricata/eve.json 2>/dev/null | tail -1 | cut -c1-180
echo "=== newest non-alert event type (is eve even being written now?) ==="
sudo -n tail -3 /var/log/suricata/eve.json 2>/dev/null | cut -c1-120
'
