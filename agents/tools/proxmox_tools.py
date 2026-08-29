"""Proxmox VE API tool module for infra-agent.

Hygiene: config-driven (config.py), no load_dotenv, imports at top, logging,
specific exception handling (proxmoxer wraps API errors).
"""

from __future__ import annotations

import logging
from typing import Any

from proxmoxer import ProxmoxAPI

from config import settings

logger = logging.getLogger(__name__)


class ProxmoxError(RuntimeError):
    """Raised when the Proxmox API fails."""


class ProxmoxClient:
    """Proxmox VE API client wrapper."""

    def __init__(self) -> None:
        try:
            self.api = ProxmoxAPI(
                host=settings.proxmox_host,
                user=settings.proxmox_user,
                token_name=settings.proxmox_token_id,
                token_value=settings.proxmox_token_secret,
                verify_ssl=settings.proxmox_verify_ssl,
            )
        except Exception as e:
            logger.error("proxmox client init failed: %s", e)
            raise ProxmoxError(f"proxmox client init failed: {e}") from e

    def _nodes(self) -> list[str]:
        try:
            return [n["node"] for n in self.api.nodes.get()]
        except Exception as e:
            logger.error("proxmox nodes fetch failed: %s", e)
            raise ProxmoxError(f"nodes fetch failed: {e}") from e

    def list_vms(self) -> list[dict[str, Any]]:
        """Return list of all VMs across all nodes using cluster resources."""
        vms = []
        try:
            resources = self.api.cluster.resources.get(type="vm")
        except Exception as e:
            logger.error("proxmox vm list failed: %s", e)
            raise ProxmoxError(f"vm list failed: {e}") from e
        for vm in resources:
            if vm.get("type") != "qemu":
                continue
            vms.append({
                "vmid": vm["vmid"],
                "name": vm.get("name", f"VM {vm['vmid']}"),
                "status": vm["status"],
                "node": vm["node"],
                "maxcpu": vm.get("maxcpu", 0),
                "maxmem": vm.get("maxmem", 0),
                "template": vm.get("template", 0),
            })
        return vms

    def list_nodes(self) -> list[dict[str, Any]]:
        """Return list of Proxmox nodes."""
        try:
            return self.api.nodes.get()
        except Exception as e:
            logger.error("proxmox nodes fetch failed: %s", e)
            raise ProxmoxError(f"nodes fetch failed: {e}") from e

    def vm_status(self, vmid: int) -> dict[str, Any]:
        """Get detailed status of a specific VM."""
        for node in self._nodes():
            try:
                status = self.api.nodes(node).qemu(vmid).status.current.get()
                return {
                    "vmid": vmid,
                    "status": status["status"],
                    "uptime": status.get("uptime", 0),
                    "cpu": status.get("cpu", 0),
                    "mem": status.get("mem", 0),
                    "node": node,
                }
            except Exception:  # noqa: BLE001 — try next node
                continue
        return {"error": f"VM {vmid} not found on any node"}

    def _act(self, action: str, vmid: int, node: str | None = None, **kwargs) -> dict[str, Any]:
        """Generic node-scoped action (start/stop/snapshot/clone/config)."""
        targets = [node] if node else self._nodes()
        for n in targets:
            try:
                if action == "start":
                    self.api.nodes(n).qemu(vmid).status.start.post()
                elif action == "stop":
                    self.api.nodes(n).qemu(vmid).status.stop.post()
                elif action == "snapshot":
                    self.api.nodes(n).qemu(vmid).snapshot.post(snapname=kwargs["snapname"])
                elif action == "clone":
                    self.api.nodes(n).qemu(vmid).clone.post(newid=kwargs["newid"], name=kwargs["name"])
                elif action == "config":
                    return {"vmid": vmid, "node": n, "config": self.api.nodes(n).qemu(vmid).config.get()}
                return {"success": True, "action": action, "vmid": vmid, "node": n, **kwargs}
            except Exception as e:  # noqa: BLE001
                logger.warning("proxmox %s %s on %s failed: %s", action, vmid, n, e)
                continue
        return {"error": f"Could not {action} VM {vmid}"}

    def start_vm(self, vmid: int, node: str | None = None) -> dict[str, Any]:
        """Start a VM."""
        return self._act("start", vmid, node)

    def stop_vm(self, vmid: int, node: str | None = None) -> dict[str, Any]:
        """Stop a VM."""
        return self._act("stop", vmid, node)

    def snapshot_vm(self, vmid: int, snapname: str, node: str | None = None) -> dict[str, Any]:
        """Snapshot a VM."""
        return self._act("snapshot", vmid, node, snapname=snapname)

    def clone_vm(self, vmid: int, newid: int, name: str, node: str | None = None) -> dict[str, Any]:
        """Clone a VM (from template or existing VM)."""
        return self._act("clone", vmid, node, newid=newid, name=name)

    def get_vm_config(self, vmid: int, node: str | None = None) -> dict[str, Any]:
        """Get VM configuration."""
        return self._act("config", vmid, node)
