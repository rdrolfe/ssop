#!/bin/bash
# .13: post-restart capture health — is Suricata still receiving on ens19?
timeout 40 ssh -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes rdrolfe@192.168.1.13 '
echo "=== suricata process + threads ==="
ps -T -p $(pgrep -f "suricata --af-packet" | head -1) -o comm= 2>/dev/null | sort -u | head -8
echo "=== RX counters now ==="
awk "/ens19:/{print \"ens19 RX:\", \$2, \$3}" /proc/net/dev
echo "=== eve.json mtime ==="
ls -la --time-style=long-iso /var/log/suricata/eve.json | awk "{print \$5, \$6, \$7}"
date "+%F %T"
echo "=== any NEW eve lines in last 60s? (count by grep ts) ==="
sudo -n tail -5 /var/log/suricata/eve.json 2>/dev/null | cut -c1-90
'
