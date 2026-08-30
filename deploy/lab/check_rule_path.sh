#!/bin/bash
# .13: ground truth on rule files — what does suricata.yaml include, what's on disk?
timeout 40 ssh -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes rdrolfe@192.168.1.13 '
echo "=== suricata.yaml rule-files block ==="
sudo -n sed -n "/rule-files/,/^[a-z]/p" /etc/suricata/suricata.yaml 2>/dev/null | head -12
echo "=== default-rule-path ==="
sudo -n sed -n "/default-rule-path/p" /etc/suricata/suricata.yaml 2>/dev/null | head -2
echo "=== ssop-drill.rules on disk: 9900002 line ==="
sudo -n sed -n "/9900002/p" /etc/suricata/rules/ssop-drill.rules 2>/dev/null | cut -c1-140
echo "=== any OTHER ssop-drill.rules copies ==="
ls -la /etc/suricata/rules/ssop-drill.rules /var/lib/suricata/rules/ssop-drill.rules /etc/suricata/ssop-drill.rules 2>&1 | head -6
'
