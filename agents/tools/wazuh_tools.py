"""Wazuh API tool module for infra-agent.

Hygiene: config-driven (config.py), no load_dotenv, imports at top, logging.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

from config import settings

logger = logging.getLogger(__name__)


class WazuhError(RuntimeError):
    """Raised when the Wazuh manager API fails."""


class WazuhClient:
    """Wazuh Manager API client."""

    def __init__(self) -> None:
        self.host = settings.wazuh_host
        self.port = settings.wazuh_api_port
        self.base_url = f"https://{self.host}:{self.port}"
        self.user = settings.wazuh_api_user
        self.password = settings.wazuh_api_password
        self._token: str | None = None
        try:
            # verify=False: the lab uses self-signed certs on the indexer/API.
            # SSOP OPSEC = zero external calls, so the trusted-CA posture is
            # internal-only. Production must terminate TLS with a trusted CA
            # and set verify=True. Deliberate; not an oversight.
            self._client = httpx.Client(verify=False, timeout=30)  # nosec B501
        except Exception as e:
            logger.error("wazuh client init failed: %s", e)
            raise WazuhError(f"wazuh client init failed: {e}") from e

    def _get_token(self) -> str:
        """Authenticate and get JWT token."""
        if self._token:
            return self._token
        credentials = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        try:
            resp = self._client.post(
                f"{self.base_url}/security/user/authenticate",
                headers={"Authorization": f"Basic {credentials}"},
            )
            resp.raise_for_status()
            token = resp.json()["data"]["token"]
            self._token = str(token)
            return self._token
        except (httpx.HTTPError, KeyError) as e:
            logger.warning("wazuh auth failed: %s", e)
            raise WazuhError(f"wazuh auth failed: {e}") from e

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        try:
            resp = self._client.request(method, f"{self.base_url}{path}",
                                        headers=self._headers(), **kwargs)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("wazuh %s %s failed: %s", method, path, e)
            raise WazuhError(f"wazuh {method} {path} failed: {e}") from e

    def _get(self, path: str, params: dict | None = None) -> dict[str, Any]:
        return self._request("GET", path, params=params)

    def _post(self, path: str, data: dict | None = None) -> dict[str, Any]:
        return self._request("POST", path, json=data)

    def _put(self, path: str, data: dict | None = None) -> dict[str, Any]:
        return self._request("PUT", path, json=data)

    def _delete(self, path: str) -> dict[str, Any]:
        return self._request("DELETE", path)

    # --- Status & Info ---

    def status(self) -> dict[str, Any]:
        """Get Wazuh manager status."""
        return self._get("/manager/status")

    def daemons_status(self) -> dict[str, Any]:
        """Get status of all Wazuh daemons."""
        return self._get("/manager/daemons?status=all")

    # --- Agents ---

    def list_agents(self, status: str | None = None) -> dict[str, Any]:
        """List all agents, optionally filtered by status."""
        params = {}
        if status:
            params["status"] = status
        return self._get("/agents", params=params)

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Get details for a specific agent by ID."""
        return self._get(f"/agents/{agent_id}")

    def add_agent(self, name: str, group: str | None = None) -> dict[str, Any]:
        """Register a new agent and return its key."""
        data = {"name": name}
        if group:
            data["group"] = group
        return self._post("/agents", data=data)

    def delete_agent(self, agent_id: str, purge: bool = False) -> dict[str, Any]:
        """Remove an agent from the manager."""
        params = {"purge": "true" if purge else "false"}
        return self._request("DELETE", f"/agents/{agent_id}", params=params)

    def restart_agent(self, agent_id: str) -> dict[str, Any]:
        """Restart an agent."""
        return self._put(f"/agents/{agent_id}/restart")

    def get_agent_config(self, agent_id: str) -> dict[str, Any]:
        """Get active configuration of an agent."""
        return self._get(f"/agents/{agent_id}/config/active")

    # --- Groups ---

    def list_groups(self) -> dict[str, Any]:
        """List all agent groups."""
        return self._get("/agents/groups")

    def create_group(self, group_name: str) -> dict[str, Any]:
        """Create a new agent group."""
        return self._post(f"/agents/groups/{group_name}")

    # --- Alerts & Events ---

    def last_alerts(self, limit: int = 20) -> dict[str, Any]:
        """Get the most recent alerts."""
        return self._get("/alerts", params={"limit": limit})

    def get_alerts(self, params: dict | None = None) -> dict[str, Any]:
        """Query alerts with filters (time range, level, group, etc.)."""
        return self._get("/alerts", params=params or {})

    def get_agent_alerts(self, agent_id: str, limit: int = 20) -> dict[str, Any]:
        """Get alerts for a specific agent."""
        return self._get(f"/agents/{agent_id}/alerts", params={"limit": limit})

    # --- Syscheck (FIM) ---

    def get_syscheck(self, agent_id: str) -> dict[str, Any]:
        """Get syscheck (file integrity) results for an agent."""
        return self._get(f"/syscheck/{agent_id}")

    def get_syscheck_last_scan(self, agent_id: str) -> dict[str, Any]:
        """Get last syscheck scan info for an agent."""
        return self._get(f"/syscheck/{agent_id}/last_scan")

    # --- Rootcheck ---

    def get_rootcheck(self, agent_id: str) -> dict[str, Any]:
        """Get rootcheck results for an agent."""
        return self._get(f"/rootcheck/{agent_id}")

    # --- Summary / Stats ---

    def summary(self) -> dict[str, Any]:
        """Get agent summary by status."""
        return self._get("/agents/summary/status")

    def stats(self) -> dict[str, Any]:
        """Get Wazuh stats."""
        return self._get("/manager/stats")
