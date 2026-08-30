#!/bin/bash
# Short /dev/tcp sweep 1-300 + 8080 from ubuntu-target -> c2-sink.
# Reproduces the Suricata STREAM handshake-anomaly signature the full loop
# fired earlier (nc -z is too clean) but finishes fast.
echo "=== /dev/tcp sweep 10.10.1.20 ports 1-300 + 8080 ==="
for p in $(seq 1 300); do
  (echo > /dev/tcp/10.10.1.20/$p) 2>/dev/null && echo "open $p"
done
(echo > /dev/tcp/10.10.1.20/8080) 2>/dev/null && echo "open 8080"
(echo > /dev/tcp/10.10.1.20/80) 2>/dev/null && echo "open 80"
echo "=== sweep done ==="
