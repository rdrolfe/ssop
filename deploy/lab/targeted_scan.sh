#!/bin/bash
# Fast targeted scan from ubuntu-target -> c2-sink open ports (22, 80, 8080 + sweep 1-1024)
# Purpose: trigger Suricata STREAM handshake anomaly alerts fast (full 65535 loop is too slow)
echo "=== targeted scan 10.10.1.20 ports 1-1024 + 8080 (nc if present, else /dev/tcp) ==="
cd /tmp
if command -v nc >/dev/null 2>&1; then
  echo "using nc"
  nc -z -w 1 10.10.1.20 22; nc -z -w 1 10.10.1.20 80; nc -z -w 1 10.10.1.20 8080
  for p in $(seq 1 200); do nc -z -w 1 10.10.1.20 $p >/dev/null 2>&1; done
else
  echo "using bash /dev/tcp on key ports + quick 1-100 sweep"
  for p in 22 80 443 8080 8443 21 25 53 3306 5900; do
    (echo > /dev/tcp/10.10.1.20/$p) 2>/dev/null && echo "open $p"
  done
  for p in $(seq 1 60); do (echo > /dev/tcp/10.10.1.20/$p) 2>/dev/null; done
fi
echo "=== scan done ==="
