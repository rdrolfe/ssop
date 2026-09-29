"""Shared logging setup for SSOP roles.

One logger per module (logging.getLogger(__name__)), configured once at
import. Under systemd, stdlib logging to stderr lands in journald — no extra
deps. Process-level events (startup, dispatch, connection failures) belong
here; domain events (verdicts, cases) belong in the case spine JSONL.
"""

import logging
import os
import sys

_CONFIGURED = False

# Third-party HTTP clients log every request at INFO. Under the roles that
# query the store in a loop (daily_digest's coverage scan, verify.matrix)
# that is tens of thousands of stderr lines per run and it has already cost a
# real unattended run: on 2026-09-27 the daily digest's first attempt died at
# its 120s call timeout on the flood alone (a rerun with stderr suppressed
# completed). Request lines are neither process-level events nor domain
# events — per this module's own doctrine they do not belong in the log.
# Connection FAILURES still surface: the clients report those at WARNING+.
# Set SSOP_LOG_HTTP=1 to get the per-request firehose back when debugging.
_NOISY_HTTP_LOGGERS = ("httpx", "httpcore", "urllib3", "elastic_transport")


def _quiet_http_loggers() -> None:
    if os.getenv("SSOP_LOG_HTTP", "").strip() in ("1", "true", "yes"):
        return
    for name in _NOISY_HTTP_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


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
    _quiet_http_loggers()
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Get a module logger (ensures config happened for library callers)."""
    setup_logging()
    return logging.getLogger(name)
