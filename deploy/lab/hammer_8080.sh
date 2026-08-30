#!/bin/bash
# Push real HTTP/data at c2-sink 8080 + repeat connects to force stream-state churn.
echo "=== hammer 8080 (data + connects) ==="
for i in 1 2 3 4 5; do
  timeout 3 bash -c 'exec 3<>/dev/tcp/10.10.1.20/8080; printf "GET / HTTP/1.0\r\nHost: x\r\n\r\n" >&3; head -c 100 <&3' 2>/dev/null
done
for i in 1 2 3; do (echo > /dev/tcp/10.10.1.20/8080) 2>/dev/null; done
for i in $(seq 301 500); do (echo > /dev/tcp/10.10.1.20/$i) 2>/dev/null; done
echo "=== done ==="
