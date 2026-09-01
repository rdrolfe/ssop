#!/usr/bin/env python3
"""Regression test: registry lazy-singleton reentrancy.

A non-reentrant Lock() deadlocks when a lazy singleton's __init__ itself
calls get_client() for another service — the exact wedge that killed the
router for 19h on Aug 30: dispatch_infra -> get_selfheal() -> SelfHeal.__init__
-> get_ssh() re-acquires the held lock and the process sleeps forever.

The regression: build "selfheal" from a fresh registry with a fake RemoteExec
dependency that records whether the nested get_ssh() call completes. Under a
plain Lock() the build never returns (deadlock); under RLock it must return.

Runs WITHOUT touching live stores (registry is injectable via set_client_for_test,
and SelfHeal's SSH dependency is faked). Pure-process, no network.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import registry  # noqa: E402


class _FakeRemote:
    def __init__(self) -> None:
        self.hosts = {"fakehost": "127.0.0.1"}

    def run(self, host, cmd, timeout=None):  # noqa: D401
        return {"ok": True, "stdout": "ok", "stderr": "", "exit": 0}


class _FakeEscalation:
    def escalate(self, *a, **k):
        return {"ticket_id": "fake"}


class _FakeWazuh:
    def list_agents(self):
        return {"data": {"affected_items": []}}


def _main() -> int:
    # Fresh registry: build the selfheal singleton from scratch. Its __init__
    # calls get_ssh() — the nested get_client must not deadlock.
    registry._SINGLETONS = {k: None for k in registry._SINGLETONS}
    registry._clients = {}
    registry.set_client_for_test("ssh", _FakeRemote())
    registry.set_client_for_test("escalation", _FakeEscalation())
    registry.set_client_for_test("wazuh", _FakeWazuh())

    result: dict[str, str] = {}

    def build() -> None:
        try:
            sh = registry.get_selfheal()
            result["status"] = "built"
            result["hosts"] = str(getattr(sh, "hosts", "?"))
        except Exception as e:  # noqa: BLE001
            result["status"] = f"error: {e}"

    t = threading.Thread(target=build, daemon=True)
    t.start()
    t.join(timeout=10)
    if t.is_alive():
        print("FAIL: get_selfheal() deadlocked (nested get_ssh did not return within 10s)")
        return 1
    if result.get("status") != "built":
        print(f"FAIL: get_selfheal() -> {result}")
        return 1
    # Also prove the nested get_ssh() actually returned the SAME singleton.
    ssh = registry.get_ssh()
    if not isinstance(ssh, _FakeRemote):
        print("FAIL: nested get_ssh did not resolve to the registered fake")
        return 1
    print("OK: nested lazy-singleton build completes (RLock, no deadlock)")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
