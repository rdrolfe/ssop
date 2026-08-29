"""Infra-agent: unified LangGraph agent for SSOP infrastructure management."""

import json
import sys
from typing import TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

load_dotenv()  # entry point — config is loaded here, passed down

from logging_setup import get_logger
from tools.registry import (
    get_escalation,
    get_memory,
    get_proxmox,
    get_selfheal,
    get_ssh,
    get_wazuh,
)

logger = get_logger(__name__)


class AgentState(TypedDict):
    command: str
    target: str | None
    params: dict | None
    result: str
    memory_ref: str | None
    error: str | None


# Shared singletons — one connection set per process (per review)
proxmox = get_proxmox()
wazuh = get_wazuh()
memory = get_memory()
remote = get_ssh()
escalator = get_escalation()
healer = get_selfheal()

# --- Router ---
def router(state: AgentState) -> AgentState:
    state["result"] = "routing..."
    return state

def route_condition(state: AgentState) -> str:
    cmd = state.get("command", "")
    mapping = {
        "proxmox:list": "node_proxmox_list",
        "proxmox:status": "node_proxmox_status",
        "proxmox:start": "node_proxmox_start",
        "proxmox:stop": "node_proxmox_stop",
        "proxmox:snapshot": "node_proxmox_snapshot",
        "wazuh:status": "node_wazuh_status",
        "wazuh:agents": "node_wazuh_agents",
        "wazuh:alerts": "node_wazuh_alerts",
        "wazuh:summary": "node_wazuh_summary",
        "memory:store": "node_memory_store",
        "memory:search": "node_memory_search",
        "memory:recent": "node_memory_recent",
        "ssh:run": "node_ssh_run",
        "ssh:health": "node_ssh_health",
        "self_heal:run": "node_self_heal",
        "escalate": "node_escalate",
    }
    return mapping.get(cmd, "node_unknown")

# --- Unknown ---
def node_unknown(state: AgentState) -> AgentState:
    state["error"] = f"Unknown command: {state.get('command')}"
    state["result"] = state["error"]
    return state

# --- Proxmox Nodes ---
def node_proxmox_list(state: AgentState) -> AgentState:
    try:
        vms = proxmox.list_vms()
        if not vms:
            state["result"] = "No VMs found."
        else:
            lines = [f"VM {v['vmid']:>5}: {v['name']:<20} ({v['status']}) on {v['node']}" for v in vms]
            state["result"] = f"Found {len(vms)} VMs:\n" + "\n".join(lines)
    except Exception as e:
        state["error"] = f"Proxmox list failed: {e}"
        state["result"] = state["error"]
    return state

def node_proxmox_status(state: AgentState) -> AgentState:
    try:
        vmid = int(state.get("target", "0"))
        if vmid == 0: state["result"] = "Usage: target=<VMID>"; return state
        state["result"] = json.dumps(proxmox.vm_status(vmid), indent=2)
    except Exception as e:
        state["error"] = f"Status failed: {e}"; state["result"] = state["error"]
    return state

def node_proxmox_start(state: AgentState) -> AgentState:
    try:
        vmid = int(state.get("target", "0"))
        if vmid == 0: state["result"] = "Usage: target=<VMID>"; return state
        state["result"] = json.dumps(proxmox.start_vm(vmid), indent=2)
    except Exception as e:
        state["error"] = f"Start failed: {e}"; state["result"] = state["error"]
    return state

def node_proxmox_stop(state: AgentState) -> AgentState:
    try:
        vmid = int(state.get("target", "0"))
        if vmid == 0: state["result"] = "Usage: target=<VMID>"; return state
        state["result"] = json.dumps(proxmox.stop_vm(vmid), indent=2)
    except Exception as e:
        state["error"] = f"Stop failed: {e}"; state["result"] = state["error"]
    return state

def node_proxmox_snapshot(state: AgentState) -> AgentState:
    try:
        vmid = int(state.get("target", "0"))
        snapname = (state.get("params") or {}).get("snapname", f"ssop-snap-{vmid}")
        if vmid == 0: state["result"] = "Usage: target=<VMID>"; return state
        state["result"] = json.dumps(proxmox.snapshot_vm(vmid, snapname), indent=2)
    except Exception as e:
        state["error"] = f"Snapshot failed: {e}"; state["result"] = state["error"]
    return state

# --- Wazuh Nodes ---
def node_wazuh_status(state: AgentState) -> AgentState:
    try:
        state["result"] = json.dumps(wazuh.status(), indent=2)
    except Exception as e:
        state["error"] = f"Wazuh status failed: {e}"; state["result"] = state["error"]
    return state

def node_wazuh_agents(state: AgentState) -> AgentState:
    try:
        resp = wazuh.list_agents()
        items = resp.get("data", {}).get("affected_items", [])
        lines = [f"  {a['id']:>5}: {a['name']:<20} ({a['status']}) IP:{a.get('ip','?')}" for a in items]
        state["result"] = f"Wazuh agents ({resp.get('data',{}).get('total_affected_items',0)} total):\n" + "\n".join(lines)
    except Exception as e:
        state["error"] = f"Wazuh agents failed: {e}"; state["result"] = state["error"]
    return state

def node_wazuh_alerts(state: AgentState) -> AgentState:
    try:
        limit = (state.get("params") or {}).get("limit", 10)
        state["result"] = json.dumps(wazuh.last_alerts(limit=limit), indent=2)
    except Exception as e:
        state["error"] = f"Wazuh alerts failed: {e}"; state["result"] = state["error"]
    return state

def node_wazuh_summary(state: AgentState) -> AgentState:
    try:
        state["result"] = json.dumps(wazuh.summary(), indent=2)
    except Exception as e:
        state["error"] = f"Wazuh summary failed: {e}"; state["result"] = state["error"]
    return state

# --- Memory Nodes ---
def node_memory_store(state: AgentState) -> AgentState:
    try:
        collection = state.get("target") or "ltp"
        content = (state.get("params") or {}).get("content", "")
        if not content: state["result"] = "Usage: target=<collection> params.content=<text>"; return state
        meta = dict(state.get("params") or {})
        meta.pop("content", None)
        result = memory.store_memory(collection, content, metadata=meta)
        state["result"] = json.dumps(result, indent=2)
        state["memory_ref"] = result.get("point_id", "")
    except Exception as e:
        state["error"] = f"Store failed: {e}"; state["result"] = state["error"]
    return state

def node_memory_search(state: AgentState) -> AgentState:
    try:
        collection = state.get("target") or "ltp"
        query = (state.get("params") or {}).get("query", "")
        limit = (state.get("params") or {}).get("limit", 5)
        results = memory.search_memory(collection, query, limit=limit)
        if not results:
            state["result"] = f"No memories in '{collection}' matching: {query}"
        else:
            lines = [f"  [{r['timestamp'][:19]}] {r['content'][:100]}" for r in results]
            state["result"] = f"Memories ({len(results)}):\n" + "\n".join(lines)
    except Exception as e:
        state["error"] = f"Search failed: {e}"; state["result"] = state["error"]
    return state

def node_memory_recent(state: AgentState) -> AgentState:
    try:
        collection = state.get("target") or "ltp"
        limit = (state.get("params") or {}).get("limit", 10)
        results = memory.recent_memories(collection, limit=limit)
        if not results:
            state["result"] = f"No memories in '{collection}'"
        else:
            lines = [f"  [{r['timestamp'][:19]}] {r['content'][:100]}" for r in results]
            state["result"] = f"Recent memories ({len(results)}):\n" + "\n".join(lines)
    except Exception as e:
        state["error"] = f"Recent failed: {e}"; state["result"] = state["error"]
    return state

# --- SSH Nodes (sysadmin role) ---
def node_ssh_run(state: AgentState) -> AgentState:
    try:
        host = state.get("target") or list(remote.hosts.keys())[0]
        command = (state.get("params") or {}).get("command", "")
        if not command:
            state["result"] = "Usage: target=<host> params.command=<cmd> [params.sudo=true]"
            return state
        sudo = str((state.get("params") or {}).get("sudo", "false")).lower() in ("true", "1", "yes")
        state["result"] = json.dumps(remote.run(host, command, sudo=sudo), indent=2)
    except Exception as e:
        state["error"] = f"SSH run failed: {e}"; state["result"] = state["error"]
    return state

def node_ssh_health(state: AgentState) -> AgentState:
    try:
        host = state.get("target") or list(remote.hosts.keys())[0]
        state["result"] = json.dumps(remote.health(host), indent=2)
    except Exception as e:
        state["error"] = f"SSH health failed: {e}"; state["result"] = state["error"]
    return state

# --- Self-heal + Escalation Nodes (sysadmin role) ---
def node_self_heal(state: AgentState) -> AgentState:
    try:
        host = state.get("target") or ""
        state["result"] = json.dumps(healer.run(host), indent=2)
    except Exception as e:
        state["error"] = f"Self-heal failed: {e}"; state["result"] = state["error"]
    return state

def node_escalate(state: AgentState) -> AgentState:
    try:
        tier = int((state.get("params") or {}).get("tier", 1))
        title = (state.get("params") or {}).get("title", "Manual escalation")
        detail = dict(state.get("params") or {})
        detail.pop("tier", None); detail.pop("title", None)
        state["result"] = json.dumps(escalator.escalate(tier, title, detail), indent=2)
    except Exception as e:
        state["error"] = f"Escalation failed: {e}"; state["result"] = state["error"]
    return state

# --- Build Graph ---
wf = StateGraph(AgentState)

# Router
wf.add_node("router", router)
wf.set_entry_point("router")

# Condition: route based on command
wf.add_conditional_edges("router", route_condition)

# Execution nodes
for name in [
    "node_proxmox_list", "node_proxmox_status", "node_proxmox_start",
    "node_proxmox_stop", "node_proxmox_snapshot",
    "node_wazuh_status", "node_wazuh_agents", "node_wazuh_alerts", "node_wazuh_summary",
    "node_memory_store", "node_memory_search", "node_memory_recent",
    "node_ssh_run", "node_ssh_health",
    "node_self_heal", "node_escalate",
    "node_unknown",
]:
    wf.add_node(name, globals()[name])
    wf.add_edge(name, END)

compiled = wf.compile()

# --- CLI ---
COMMANDS = [
    "proxmox:list", "proxmox:status", "proxmox:start", "proxmox:stop", "proxmox:snapshot",
    "wazuh:status", "wazuh:agents", "wazuh:alerts", "wazuh:summary",
    "memory:store", "memory:search", "memory:recent",
    "ssh:run", "ssh:health",
    "self_heal:run", "escalate",
]

def run(command, target="", params=None):
    result = compiled.invoke({
        "command": command, "target": target, "params": params or {},
        "result": "", "memory_ref": None, "error": None,
    })
    return result

def cli():
    if len(sys.argv) < 2:
        print("SSOP Infra-Agent CLI\nUsage: python agent.py <command> [target] [key=val ...]\n")
        for c in COMMANDS: print(f"  {c}")
        print("\nExamples:")
        print("  python agent.py proxmox:list")
        print("  python agent.py proxmox:status 100")
        print("  python agent.py wazuh:agents")
        print('  python agent.py memory:store ltp content="Started VM 100"')
        print('  python agent.py ssh:run web command="uptime"')
        print('  python agent.py ssh:run db command="systemctl status docker" sudo=true')
        sys.exit(0)
    cmd = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else ""
    params = {}
    for a in sys.argv[3:]:
        if "=" in a:
            k, v = a.split("=", 1); params[k] = v
    result = run(cmd, target, params)
    if result.get("error"):
        print(f"ERROR: {result['error']}")
    else:
        print(result.get("result", "(no output)"))

if __name__ == "__main__":
    cli()
