#!/usr/bin/env python3
"""SSOP drill beacon generator — sends DNS queries to the drill domain."""
import socket
import os

RESOLVER = os.getenv("DNS_RESOLVER", "") or input("DNS resolver IP (your LAN gateway): ")

def build_query(txid: int) -> bytes:
    # DNS query for beacon-test.ssop.local (A record)
    q = bytes([0x12, 0x34 + txid]) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q += b"\x08beacon-test\x04ssop\x02local\x00"  # labels
    q += b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
    return q

def main():
    sent = 0
    for i in range(3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(build_query(i), (RESOLVER, 53))
            try:
                s.recvfrom(512)
            except socket.timeout:
                pass
            sent += 1
        except Exception as e:
            print(f"query {i} failed: {e}")
    print(f"sent {sent} beacon DNS queries")

if __name__ == "__main__":
    main()
