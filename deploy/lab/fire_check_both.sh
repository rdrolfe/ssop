#!/bin/bash
# .13: confirm new restart logged, then fire beacon and check both sids
timeout 40 ssh -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes rdrolfe@192.168.1.13 'sudo -n sed -n "/rule files processed/p" /var/log/suricata/suricata.log 2>/dev/null | tail -3'
echo "=== fire beacon ==="
timeout 40 ssh -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o BatchMode=yes rdrolfe@192.168.1.77 'cd /tmp && DNS_RESOLVER=10.10.1.20 python3 /tmp/beacon_gen.py 2>&1 | tail -1'
sleep 4
echo "=== last 5 alerts on .13 ==="
timeout 40 ssh -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes rdrolfe@192.168.1.13 'sudo -n sed -n "/\"event_type\":\"alert\"/p" /var/log/suricata/eve.json 2>/dev/null | tail -5' > /tmp/last5.jsonl
python3 -c "
import json
for l in open('/tmp/last5.jsonl'):
    try:
        d = json.loads(l); a = d.get('alert',{})
        print(d.get('timestamp','?')[:19], '| sid', a.get('signature_id'), '|', a.get('signature','?')[:55], '|', d.get('src_ip'), '->', d.get('dest_ip'))
    except Exception:
        pass
"
