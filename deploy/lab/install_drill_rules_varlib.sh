#!/bin/bash
# Install updated drill rules into the REAL rule path (/var/lib/suricata/rules)
# and reload Suricata.
set -e
echo "=== target: /var/lib/suricata/rules/ssop-drill.rules ==="
sudo -n chown rdrolfe /var/lib/suricata/rules/ssop-drill.rules
cp /tmp/ssop-drill.rules /var/lib/suricata/rules/ssop-drill.rules
sudo -n chown root /var/lib/suricata/rules/ssop-drill.rules
echo "=== 9900002 in target? ==="
sudo -n sed -n '/9900002/p' /var/lib/suricata/rules/ssop-drill.rules | cut -c1-140
sudo -n systemctl restart suricata
sleep 4
echo "=== rule count (should be 52414) ==="
sudo -n sed -n '/rule files processed/p' /var/log/suricata/suricata.log 2>/dev/null | tail -1
sudo -n systemctl is-active suricata
