"""Central verified-TLS context factory (issue #29).

Every management-plane HTTPS client creates its SSL context HERE — no
module builds its own CERT_NONE context anymore. Behavior:

  - Default (SSOP_TLS_VERIFY unset or =1): FULL verification against the
    SSOP internal CA (bundle at ~/.ssop/ca/ca-bundle.crt, override with
    SSOP_CA_BUNDLE). Hostname checking ON. Services present certs signed
    by the internal CA (see deploy/spire/../certs docs) or a publicly
    trusted one; the Wazuh dashboard cert already chains to its own CA.
  - SSOP_TLS_VERIFY=0: explicit test profile — lab scripts against
    throwaway endpoints. Logged loudly on every context creation.
  - Fail behavior: a missing/unreadable CA bundle in verify mode raises —
    a client that cannot verify MUST NOT silently downgrade (issue #29
    acceptance: production rejects verification off).
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

from logging_setup import get_logger

logger = get_logger(__name__)

DEFAULT_CA_BUNDLE = Path.home() / ".ssop" / "ca" / "ca-bundle.crt"


def tls_verify_enabled() -> bool:
    """Production default: verification ON. SSOP_TLS_VERIFY=0 opts out
    (test profile only) — and is loudly logged."""
    raw = os.getenv("SSOP_TLS_VERIFY", "1").strip().lower()
    enabled = raw not in ("0", "false", "no", "off")
    if not enabled:
        logger.warning(
            "SSOP_TLS_VERIFY=0 — TLS verification DISABLED (test profile). "
            "Do not use against production services.")
    return enabled


def ca_bundle_path() -> Path:
    raw = os.getenv("SSOP_CA_BUNDLE", "").strip()
    return Path(raw) if raw else DEFAULT_CA_BUNDLE


def verified_ssl_context() -> ssl.SSLContext:
    """Fully verifying context: internal CA + hostname checks.

    Raises FileNotFoundError (fail-closed) when verification is on but the
    CA bundle is absent — a client that can't verify must not downgrade.
    """
    if not tls_verify_enabled():
        # Explicit test profile: still a distinct context, never ssl's
        # global unverified one (no accidental sharing).
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    bundle = ca_bundle_path()
    if not bundle.is_file():
        raise FileNotFoundError(
            f"TLS verification is ON but the CA bundle is missing: {bundle} "
            f"(install the SSOP internal CA bundle, or set SSOP_CA_BUNDLE, "
            f"or explicitly set SSOP_TLS_VERIFY=0 for a throwaway lab)")
    ctx = ssl.create_default_context(cafile=str(bundle))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
