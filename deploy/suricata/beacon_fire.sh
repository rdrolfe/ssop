#!/bin/bash
# SSOP drill beacon generator — uses the REAL system resolver so the DNS
# packets on the wire are well-formed and match the Suricata drill rule.
# (getent returns non-zero for NXDOMAIN but the query still hits the wire.)
for i in 1 2 3; do
  timeout 4 getent hosts "beacon-test.ssop.local" >/dev/null 2>&1
  echo "beacon DNS query $i sent (resolver exit $?)"
  sleep 1
done
