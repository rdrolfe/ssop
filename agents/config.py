"""SSOP central configuration.

Every tunable value in the platform lives here — read from environment once
(at import) with sane defaults, never scattered as constants inside tool
modules. config.py owns the .env bootstrap (see below); tool modules consume
`settings` only.

Rules enforced by review:
- No os.getenv() in tool modules — use settings.<name>
- No load_dotenv() in non-entry files — config owns the single bootstrap,
  everyone else consumes `settings`
- All thresholds/hosts/paths have ONE home: this module
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# config.py owns the env bootstrap: load .env BEFORE Settings freezes at
# import. Without this, any import path that pulls in tools.* (tools/__init__
# re-exports every client) freezes Settings with empty credentials before an
# entry point's own load_dotenv() runs — the source of the intermittent
# "indexer HTTP 401" (AnalystClient worked inline, 401'd from the analyst CLI
# / scripts depending on import order).
load_dotenv()

# ---- env bootstrap (only this module reads raw env) -----------------------


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _env_tuple(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(x.strip() for x in raw.split(",") if x.strip())


def _env_dict(name: str, default: str = "") -> dict[str, int]:
    """Parse `K1=V1,K2=V2` (int values) from env; empty -> {}."""
    raw = os.getenv(name, default)
    out: dict[str, int] = {}
    for part in raw.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        try:
            out[k.strip()] = int(v.strip())
        except (TypeError, ValueError):
            continue
    return out


# ---- runtime paths (the agent-runtime directory) --------------------------

RUNTIME_DIR = Path(_env("SSOP_RUNTIME_DIR", str(Path.home() / "agent-runtime")))


@dataclass(frozen=True)
class Settings:
    """Immutable settings snapshot. Tools read these; never construct clients
    from raw env."""

    # --- indexer (Wazuh/OpenSearch) ---
    # Deployment convention: WAZUH_INDEXER_URL (full URL) + _USERNAME/_PASSWORD.
    # Generic _HOST/_PORT/_USER names also supported as override.
    indexer_url: str = _env("WAZUH_INDEXER_URL", "")
    indexer_host: str = _env("WAZUH_INDEXER_HOST", "localhost")
    indexer_port: str = _env("WAZUH_INDEXER_PORT", "9200")
    indexer_user: str = _env("WAZUH_INDEXER_USER", _env("WAZUH_INDEXER_USERNAME", "admin"))
    indexer_password: str = _env("WAZUH_INDEXER_PASSWORD", "")
    so_indexer_password: str = _env("SO_INDEXER_PASSWORD", "")
    alerts_index: str = _env("WAZUH_ALERTS_INDEX", "wazuh-alerts-4.x-*")

    # --- Hermes escalation API ---
    hermes_api_url: str = _env("HERMES_API_URL", "http://localhost:8642")
    hermes_api_key: str = _env("HERMES_API_KEY", "")
    hermes_model: str = _env("HERMES_MODEL", "hermes-agent")
    escalation_timeout_s: int = _env_int("ESCALATION_TIMEOUT_S", 120)

    # --- Wazuh manager API ---
    wazuh_host: str = _env("WAZUH_HOST", "localhost")
    wazuh_api_port: str = _env("WAZUH_API_PORT", "55000")
    wazuh_api_user: str = _env("WAZUH_API_USER", "wazuh-wui")
    wazuh_api_password: str = _env("WAZUH_API_PASSWORD", "")

    # --- Proxmox ---
    proxmox_host: str = _env("PROXMOX_HOST", "localhost")
    proxmox_user: str = _env("PROXMOX_USER", "root@pam")
    proxmox_token_id: str = _env("PROXMOX_TOKEN_ID", "tokenid")
    proxmox_token_secret: str = _env("PROXMOX_TOKEN_SECRET", "")
    proxmox_verify_ssl: bool = _env_bool("PROXMOX_VERIFY_SSL", False)

    # --- directories ---
    audit_dir: Path = Path(_env("AUDIT_DIR", str(RUNTIME_DIR / "audit")))
    escalation_dir: Path = Path(_env("ESCALATION_DIR", str(RUNTIME_DIR / "tickets")))
    router_state_file: Path = Path(_env("ROUTER_STATE", str(RUNTIME_DIR / "router_state.json")))

    # --- case spine ---
    case_collection: str = _env("CASE_COLLECTION", "cases")

    # --- Qdrant ---
    # Deployment convention: QDRANT_URL (full URL). Generic _HOST/_PORT also supported.
    qdrant_url: str = _env("QDRANT_URL", "")
    qdrant_host: str = _env("QDRANT_HOST", "localhost")
    qdrant_port: str = _env("QDRANT_PORT", "6333")

    # --- analyst severity thresholds (Wazuh levels 0-15) ---
    high_level: int = _env_int("ANALYST_HIGH_LEVEL", 7)
    medium_level: int = _env_int("ANALYST_MEDIUM_LEVEL", 4)
    # categories that escalate at medium severity
    medium_escalate_categories: tuple[str, ...] = ("authentication", "threat")
    # rule ids known to be false-positive classes — never auto-escalate
    # (rootcheck generic signatures at any level; verified empirically)
    fp_rule_ids: frozenset[str] = frozenset(
        _env("ANALYST_FP_RULE_IDS", "510").split(",")
    )

    # --- router ---
    router_interval_s: int = _env_int("ROUTER_INTERVAL_S", 180)
    burst_window_min: int = _env_int("ROUTER_BURST_WINDOW_MIN", 10)
    pattern_rate_minutes: int = _env_int("ROUTER_PATTERN_RATE_MINUTES", 60)
    noise_rules: frozenset[str] = frozenset(_env("ROUTER_NOISE_RULES", "5501,5502,5715").split(","))
    default_category: str = _env("ROUTER_DEFAULT_CATEGORY", "operational")

    # --- strong-TP override policy (config-driven, ops-tunable) ---
    # Categories allowed to lift a human's auto_fp tuning on the severity leg
    # of strong_tp_evidence. Threat-description tokens override regardless of
    # category (the clear-exception path). Tuning this list is an OPS action,
    # not a code change.
    strong_tp_override_categories: tuple[str, ...] = _env_tuple(
        "STRONG_TP_OVERRIDE_CATEGORIES", "threat,authentication,security")
    # Per-category high-level threshold for the severity leg. An integrity
    # checksum at level 7 is routine maintenance, not a strong TP; a threat
    # at level 7 is. Ops can raise the bar per category without code.
    category_high_levels: dict[str, int] = field(default_factory=lambda: _env_dict(
        "CATEGORY_HIGH_LEVELS", "threat=7,authentication=7,security=7,integrity=12,compliance=12,operational=12"))

    # --- data-driven definitions (hunt library + self-heal checks) ---
    hunts_dir: Path = Path(_env("HUNTS_DIR", str(Path(__file__).resolve().parent / "hunts")))
    checks_file: Path = Path(_env("CHECKS_FILE", str(Path(__file__).resolve().parent / "checks.yaml")))
    playbooks_dir: Path = Path(_env("PLAYBOOKS_DIR", str(Path(__file__).resolve().parent / "playbooks")))
    protected_entities: list[str] = field(default_factory=lambda: [
        "192.168.1.29",   # infra-ops (control plane)
        "192.168.1.94",   # kb-vec (Qdrant)
        "192.168.1.75",   # telemetry (Wazuh SIEM)
        "192.168.1.90",   # vault-secrets
        "192.168.1.13",   # network (management iface)
        "127.0.0.1", "localhost",
        "169.254.0.0/16",
    ])

    # --- intel role ---
    kev_url: str = _env("KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    nvd_url: str = _env("NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    hunt_staging_dir: Path = Path(_env("HUNT_STAGING_DIR", str(Path(__file__).resolve().parent / "hunts" / "staging")))
    inventory_index: str = _env("INVENTORY_INDEX", "wazuh-states-inventory-packages-*")
    intel_days: int = _env_int("INTEL_DAYS", 1)

    # --- observable enrichment (adopted SO analyzer concept) ---
    # Provider base URLs + optional community keys (env-driven; empty = keyless).
    greynoise_url: str = _env("GREYNOISE_URL", "https://api.greynoise.io/v3/community/")
    greynoise_key: str = _env("GREYNOISE_KEY", "")
    enrichment_timeout_s: int = _env_int("ENRICHMENT_TIMEOUT_S", 15)

    # --- SOAR responder ---
    approval_expiry_min: int = _env_int("APPROVAL_EXPIRY_MIN", 15)

    # --- self-heal ---
    ssh_hosts: dict[str, str] = field(default_factory=dict)
    ssh_user: str = _env("SSH_USER", "")
    ssh_key_path: str = _env("SSH_KEY_PATH", "~/.ssh/id_ed25519")
    ssh_strict_host_keys: bool = _env_bool("SSH_STRICT_HOST_KEYS", False)
    spire_socket: str = _env("SPIRE_SOCKET", "/tmp/spire-agent/public/api.sock")
    spire_bin: str = _env("SPIRE_BIN", "spire-agent")
    disk_warn_pct: int = _env_int("SELFHEAL_DISK_WARN_PCT", 85)
    disk_crit_pct: int = _env_int("SELFHEAL_DISK_CRIT_PCT", 95)
    timeout_s: int = _env_int("SELFHEAL_TIMEOUT_S", 30)

    def __post_init__(self):
        # parse SSH_HOSTS="web=10.0.0.5,db=10.0.0.6" into dict
        raw = _env("SSH_HOSTS", "")
        hosts: dict[str, str] = {}
        for pair in raw.split(","):
            pair = pair.strip()
            if "=" in pair:
                name, host = pair.split("=", 1)
                hosts[name.strip()] = host.strip()
        object.__setattr__(self, "ssh_hosts", hosts)


# Single shared instance — the source of truth for every module.
settings = Settings()


def ensure_dirs() -> None:
    """Create runtime directories once (idempotent)."""
    settings.audit_dir.mkdir(parents=True, exist_ok=True)
    settings.escalation_dir.mkdir(parents=True, exist_ok=True)
