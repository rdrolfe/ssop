"""Shared logging setup for SSOP roles.

One logger per module (logging.getLogger(__name__)), configured once at
import. Under systemd, stdlib logging to stderr lands in journald — no extra
deps. Process-level events (startup, dispatch, connection failures) belong
here; domain events (verdicts, cases) belong in the case spine JSONL.
"""

import logging
import sys

_CONFIGURED = False


def setup_logging(level: int = logging.INFO) -> None:
    """Idempotent root-logger configuration for CLI/daemon entry points."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Get a module logger (ensures config happened for library callers)."""
    setup_logging()
    return logging.getLogger(name)
