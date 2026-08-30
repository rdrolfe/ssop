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

    def create_vm(
        self,
        vmid: int,
        name: str,
        memory_mb: int = 4096,
        cores: int = 2,
        disk_gb: int = 40,
        storage: str = "local-zfs",
        disk_ctl: str = "scsi0",
        net0: str = "virtio,bridge=vmbr0",
        net1: str | None = None,
        iso: str | None = None,
        iso2: str | None = None,
        ostype: str = "l26",
        node: str | None = None,
        start: bool = False,
        agent: int = 1,
        onboot: int = 0,
        scsihw: str | None = "virtio-scsi-pci",
        **extra,
    ) -> dict[str, Any]:
        """Create a QEMU VM with a disk on the given storage.

        iso / iso2 are storage paths like 'local:iso/<file>.iso' — iso is
        attached as ide2 (primary boot media), iso2 as ide3 (seed/answer
        drive for autoinstall or autounattend). net1, when given, wires a
        second NIC (attack plane) on vmbr1. disk_ctl picks the disk
        attachment (scsi0 default for virtio-scsi; 'ide0' for Windows so no
        virtio drivers are needed during setup; pass net0 with an e1000 NIC
        for the same reason).
        """
        targets = [node] if node else self._nodes()
        for n in targets:
            try:
                boot_first = disk_ctl.split("0")[0] + "0"
                params: dict[str, Any] = {
                    "vmid": vmid,
                    "name": name,
                    "memory": memory_mb,
                    "cores": cores,
                    "sockets": 1,
                    "cpu": "cputype=host",
                    "net0": net0,
                    disk_ctl: f"{storage}:{disk_gb}",
                    "ostype": ostype,
                    "agent": agent,
                    "onboot": onboot,
                    "boot": f"order={boot_first};ide2",
                }
                if net1:
                    params["net1"] = net1
                if scsihw and disk_ctl.startswith("scsi"):
                    params["scsihw"] = scsihw
                if iso:
                    params["ide2"] = f"{iso},media=cdrom"
                if iso2:
                    params["ide3"] = f"{iso2},media=cdrom"
                params.update(extra)
                upid = self.api.nodes(n).qemu.post(**params)
                self._wait_task(n, upid)
                if start:
                    upid = self.api.nodes(n).qemu(vmid).status.start.post()
                    self._wait_task(n, upid)
                return {"success": True, "action": "create", "vmid": vmid, "node": n, "started": start}
            except Exception as e:  # noqa: BLE001
                logger.warning("proxmox create %s on %s failed: %s", vmid, n, e)
                continue
        return {"error": f"Could not create VM {vmid}"}

    def _wait_task(self, node: str, upid: str, timeout_s: int = 120, poll_s: float = 2.0) -> None:
        """Poll a Proxmox task until it stops; raise if it failed.

        qm create / qm start / imgcopy return a UPID immediately and run
        asynchronously — the config/disk/file is NOT ready until the task
        finishes. Reporting success on POST-acceptance races the task (real
        bug: vm902's create task failed with 'volume ... does not exist' but
        the caller saw success).
        """
        import time as _t

        deadline = _t.time() + timeout_s
        while _t.time() < deadline:
            try:
                st = self.api.nodes(node).tasks(upid).status.get()
            except Exception:  # noqa: BLE001 — task may not be queryable yet
                _t.sleep(poll_s)
                continue
            if st.get("status") == "stopped":
                exitstatus = st.get("exitstatus")
                if exitstatus not in (None, "OK"):
                    raise RuntimeError(f"proxmox task {upid} failed: exitstatus={exitstatus}")
                return
            _t.sleep(poll_s)
        raise TimeoutError(f"proxmox task {upid} did not finish in {timeout_s}s")
