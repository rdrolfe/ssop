#!/bin/bash
# Full chain: console proxy (.75:5602) -> TLS API (.29:8787) -> cases
echo "=== /cases via proxy ==="
curl -sk https://127.0.0.1:5602/cases 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
cases = d.get('cases') or []
with_dec = [c for c in cases if (c.get('adjudication') or {}).get('decision') or (c.get('supervisory') or {}).get('decision')]
print('cases:', len(cases), '| with decision:', len(with_dec))
for c in with_dec[:3]:
    adj = c.get('adjudication') or {}
    sup = c.get('supervisory') or {}
    dec = adj.get('decision') or sup.get('decision')
    inv = c.get('investigation') or {}
    print(c.get('case_id'), '| decision:', dec, '| sev:', inv.get('severity_label'), '| chain:', len(inv.get('kill_chain') or []))
" 2>&1
echo "=== /tuning via proxy ==="
curl -sk https://127.0.0.1:5602/tuning 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok:', d.get('ok'), 'tuning:', len(d.get('tuning',[])))" 2>&1
echo "=== /tickets via proxy ==="
curl -sk https://127.0.0.1:5602/tickets 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok:', d.get('ok'), 'tickets:', len(d.get('tickets',[])))" 2>&1
