#!/bin/bash
# SSOP intel role daily sweep — KEV/NVD ingest -> fleet match -> pack staging
cd /home/rdrolfe/agent-runtime || exit 1
source agent-env/bin/activate
exec python3 -u intel.py
