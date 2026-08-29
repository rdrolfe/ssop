"""Verification core: verdict types, fixture loading, invariant checks.

Mirrors the phase-3-verify pattern adapted to SSOP: the machine-readable
surface is the CASE SPINE (Qdrant + JSONL) + escalation queue + audit trail.
Verdicts: PASS | FAIL | BLOCKED | SKIP. Checks: ok | fail | warn | probe.

BLOCKED (couldn't observe) is distinct from FAIL (observed and wrong).
When in doubt, the runner fails — a false PASS ships bugs.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from config import settings
from logging_setup import get_logger

logger = get_logger(__name__)

VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"
VERDICT_BLOCKED = "BLOCKED"
VERDICT_SKIP = "SKIP"

CHECK_OK = "ok"
CHECK_FAIL = "fail"
CHECK_WARN = "warn"
CHECK_PROBE = "probe"
CHECK_SKIP = "skip"


class VerificationError(RuntimeError):
    """Raised when the verify framework itself is misconfigured."""


def load_fixtures(fixtures_file: Path | None = None) -> List[Dict[str, Any]]:
    """Load verification fixtures from YAML."""
    path = fixtures_file or Path(__file__).resolve().parent / "fixtures.yaml"
    if not path.exists():
        logger.warning("fixtures file %s not found", path)
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        fixtures = data.get("fixtures", []) if isinstance(data, dict) else []
        if not isinstance(fixtures, list):
            raise VerificationError(f"{path}: 'fixtures' must be a list")
        logger.info("loaded %d fixtures from %s", len(fixtures), path.name)
        return fixtures
    except (yaml.YAMLError, OSError) as e:
        logger.error("failed to load fixtures %s: %s", path, e)
        raise VerificationError(f"failed to load fixtures: {e}") from e


class Check:
    """One verification check result."""

    def __init__(self, name: str, status: str, detail: str = "") -> None:
        self.name = name
        self.status = status
        self.detail = detail

    def to_dict(self) -> Dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


class FixtureResult:
    """Result of verifying one fixture against one role."""

    def __init__(self, fixture_id: str, role: str) -> None:
        self.fixture_id = fixture_id
        self.role = role
        self.checks: List[Check] = []
        self.verdict = VERDICT_SKIP
        self.error: Optional[str] = None

    def add_check(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append(Check(name, status, detail))

    def finalize(self) -> None:
        """Compute the verdict from checks (phase-3-verify taxonomy)."""
        statuses = [c.status for c in self.checks]
        if self.error:
            self.verdict = VERDICT_BLOCKED
        elif any(s == CHECK_FAIL for s in statuses):
            self.verdict = VERDICT_FAIL
        elif statuses:
            self.verdict = VERDICT_PASS
        else:
            self.verdict = VERDICT_SKIP

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "role": self.role,
            "verdict": self.verdict,
            "checks": [c.to_dict() for c in self.checks],
            "error": self.error,
        }
