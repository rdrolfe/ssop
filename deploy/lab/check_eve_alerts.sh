#!/bin/bash
# .13: check suricata eve.json for recent alerts (STREAM / anything from the scan)
timeout 40 ssh -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes rdrolfe@192.168.1.13 '
echo "=== suricata active? ==="
sudo -n systemctl is-active suricata
echo "=== last 6 alert events (any sig) ==="
sudo -n sed -n "/\"event_type\":\"alert\"/p" /var/log/suricata/eve.json 2>/dev/null | tail -6 | python3 -c "
import sys, json
for l in sys.stdin:
    try:
        d = json.loads(l)
        a = d.get(\"alert\",{})
        print(d.get(\"timestamp\",\"?\")[:19], \"|\", a.get(\"signature\",\"?\")[:60], \"|\", d.get(\"src_ip\"), \"->\", d.get(\"dest_ip\"), \"|\", a.get(\"signature_id\"))
    except Exception:
        pass
"
echo "=== suricata stats for ens19 (rx) ==="
sudo -n sed -n "/ens19/p" /var/log/suricata/stats.log 2>/dev/null | tail -3
'
