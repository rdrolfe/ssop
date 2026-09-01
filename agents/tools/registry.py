"""Client registry — lazy singletons for shared service connections.

Every role module creates clients via get_client()/get_<service>() instead of
constructing fresh instances per dispatch. This reuses one connection per
service per process (Qdrant, indexer, escalation, SSH, Wazuh, Proxmox) and
makes tests able to inject fakes via set_client_for_test().

Pattern (module-level, thread-safe for our single-threaded timers):
    from tools.registry import get_analyst, get_cases, ...
"""

from __future__ import annotations

import threading
from typing import Any

# Reentrant lock: lazy singleton builds may themselves trigger nested
# get_client() calls (SelfHeal.__init__ pulls get_ssh()). With a plain
# Lock() that re-acquire deadlocks — this wedged the router for 19h on
# Aug 30 (dispatch_infra -> get_selfheal -> SelfHeal -> get_ssh: same
# thread re-enters the held lock; the process slept on a futex forever).
_lock = threading.RLock()
_clients: dict[str, Any] = {}

# Lazy singletons (built on first access)
_SINGLETONS: dict[str, Any] = {
    "analyst": None,
    "cases": None,
    "escalation": None,
    "hunt": None,
    "selfheal": None,
    "indexer": None,
    "ssh": None,
    "wazuh": None,
    "proxmox": None,
    "intel": None,
    "memory": None,
}


def _build(kind: str) -> None:
    """Lazily construct the singleton for a service kind."""
    if kind == "analyst":
        from tools.analyst_tools import AnalystClient
        _SINGLETONS["analyst"] = AnalystClient()
    elif kind == "cases":
        from tools.case_tools import CaseStore
        _SINGLETONS["cases"] = CaseStore()
    elif kind == "escalation":
        from tools.escalate_tools import EscalationClient
        _SINGLETONS["escalation"] = EscalationClient()
    elif kind == "hunt":
        from tools.hunt_tools import HuntClient
        _SINGLETONS["hunt"] = HuntClient()
    elif kind == "selfheal":
        from tools.self_heal import SelfHeal
        _SINGLETONS["selfheal"] = SelfHeal()
    elif kind == "indexer":
        from tools.indexer_client import IndexerClient
        _SINGLETONS["indexer"] = IndexerClient()
    elif kind == "ssh":
        from tools.ssh_tools import RemoteExec
        _SINGLETONS["ssh"] = RemoteExec()
    elif kind == "wazuh":
        from tools.wazuh_tools import WazuhClient
        _SINGLETONS["wazuh"] = WazuhClient()
    elif kind == "proxmox":
        from tools.proxmox_tools import ProxmoxClient
        _SINGLETONS["proxmox"] = ProxmoxClient()
    elif kind == "memory":
        from tools.qdrant_tools import QdrantMemory
        _SINGLETONS["memory"] = QdrantMemory()
    elif kind == "intel":
        from tools.intel_tools import IntelClient
        _SINGLETONS["intel"] = IntelClient()


def get_client(kind: str) -> Any:
    """Return the singleton for a service kind (lazy, thread-safe)."""
    if kind not in _SINGLETONS:
        raise KeyError(f"unknown client kind: {kind}")
    if _SINGLETONS[kind] is None:
        with _lock:
            if _SINGLETONS[kind] is None:
                _build(kind)
    return _SINGLETONS[kind]


# Convenience accessors
def get_analyst():
    return get_client("analyst")


def get_cases():
    return get_client("cases")


def get_escalation():
    return get_client("escalation")


def get_hunt():
    return get_client("hunt")


def get_intel():
    return get_client("intel")


def get_selfheal():
    return get_client("selfheal")


def get_indexer():
    return get_client("indexer")


def get_ssh():
    return get_client("ssh")


def get_wazuh():
    return get_client("wazuh")


def get_proxmox():
    return get_client("proxmox")


def get_memory():
    return get_client("memory")


def set_client_for_test(kind: str, fake: Any) -> None:
    """Testing hook: inject a fake client."""
    with _lock:
        _SINGLETONS[kind] = fake


def reset() -> None:
    """Testing hook: clear all singletons."""
    with _lock:
        for k in _SINGLETONS:
            _SINGLETONS[k] = None
        _clients.clear()
