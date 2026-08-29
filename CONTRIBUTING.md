# Contributing to SSOP

SSOP started velocity-first and is now paying the maintainability tax.
These rules are the contract for every change from here on. They exist
because a code review of the initial codebase found the same class of
issues in every module — this document is the institutional fix.

## Hard rules (review-enforced)

1. **All imports at the top of the module.** No imports inside functions.
   If you need a lazy import (heavy dependency), justify it in a comment —
   and prefer moving it to the module top once the dependency is declared
   in requirements.txt.

2. **No `os.getenv()` in tool modules.** Every tunable value lives in
   `agents/config.py` (`Settings` dataclass, env-read once at import).
   Tool modules consume `settings.<name>`. Thresholds, hosts, ports,
   paths, timeouts, and defaults have ONE home: config.py.

3. **`load_dotenv()` only in entry points.** `agent.py`, `analyst.py`,
   `hunt.py`, `router.py`, `supervisory.py` call it at the top. Tool
   modules and shared libraries NEVER call it — they read `settings`.

4. **No fresh client construction per dispatch.** Use the registry:
   `from tools.registry import get_analyst, get_cases, get_escalation, ...`
   One connection per service per process. Constructors accept optional
   injected dependencies (`def __init__(self, indexer=None)`) so tests
   can pass fakes.

5. **Logging everywhere.** `from logging_setup import get_logger` then
   `logger = get_logger(__name__)`. Process-level events (startup,
   dispatch decisions, connection failures, exceptions) go to the logger
   (which lands in journald under systemd). The JSONL case spine stays
   for DOMAIN events (verdicts, cases) — it's the audit trail, not the
   logger.

6. **Exception discipline.**
   - Catch SPECIFIC exceptions (`OSError`, `json.JSONDecodeError`,
     `urllib.error.HTTPError`), never bare `except Exception` unless the
     failure mode genuinely spans unknown library errors — and then add
     `# noqa: BLE001` with a comment explaining WHY.
   - Use `logger.exception()` (or `logger.warning`) — the traceback goes
     to the log. Don't dump `str(e)` into result dicts as the only record.
   - Structured errors: raise a domain exception (`IndexerError`,
     `QdrantError`, `WazuhError`, `EscalationError`) with context.

7. **No unused imports.** Run a linter (ruff/pyflakes) before committing.
   Dead imports are how modules rot.

8. **No hardcoded values that may change.** Names, IPs, defaults, and
   env-fallback values live in config.py. If you catch yourself writing
   `"/home/rdrolfe/..."` or `"192.168.x.x"` in a module, stop — it goes
   in config.

## Secrets policy (why we use .env, not keyring — a reviewed decision)

Review note: "consider using keyring instead of storing creds in env vars."
Adopted where it fits, deliberately declined for the deployed platform:

- **keyring's default backend needs a desktop session** (D-Bus/SecretService).
  The SSOP roles run as HEADLESS systemd services — no keychain to unlock,
  and a keyrings.alt master password would just live in an env var anyway
  (circular).
- **What we DO instead** (the correct headless pattern):
  - `deploy/.env` is owner-only (`chmod 600`) on every host.
  - Secrets never enter the repo (gitignored) or the tarball; only
    `.env.example` with placeholders ships.
  - The real secrets boundary is the **vault-secrets VM** (isolation), not
    the env file.
  - Service creds load via `load_dotenv()` in entry points only.
- **keyring IS the right tool for the operator's own machine** — interactive
  scripts, dashboard creds, personal keys. A future operator tool can use it.

Decision recorded so the reviewer's point is answered, not ignored.

## Data-driven definitions (hunt library + checks)

Hunts and health checks are DATA, not code:
- `agents/hunts/*.yaml` — one file per hunt; drop a file to add a hunt
  (filename stem = hunt_id). Loaded by `tools/hunt_tools.py:load_hunts()`.
- `agents/checks.yaml` — the self-heal health probes; edit to add a check.
  Loaded by `tools/self_heal.py:load_checks()`.
- Analyzers stay in code (they're logic); the YAML declares query + category.

## Process rules

9. **Every layer is additive.** Refactors and features must not change
   working behavior. Verify after every change: `python3 -m py_compile`
   on changed files, then a live dry-run of the affected role.

10. **TTX before trusting a new path.** Before wiring a new role or
    dispatch path, pick one representative case and walk the code by
    hand — trace what SHOULD happen against what the code DOES. You will
    find missing functions and role gaps on paper, not in production.

11. **Verify with the venv, not just the linter.** Pyright/ruff catch
    style; the runtime catches import cycles and API drift. Always:
    `python3 -c "import <module>"` in the agent venv after refactors.

12. **Run the verification matrix for logic changes.** `python3 -m
    verify.matrix` (deployed on infra-ops). The fixture library is the
    machine-readable contract: synthetic alerts + ground-truth verdicts
    against the case spine, queue, and audit trail. All fixtures must
    PASS before committing role/analyst/router logic. Adding a fixture is
    data (agents/verify/fixtures.yaml), not code. The framework follows
    Anthropic's phase-3-verify pattern: PASS|FAIL|BLOCKED|SKIP taxonomy,
    BLOCKED (couldn't observe) distinct from FAIL (observed and wrong),
    probes that are designed to fail.

## Definition of done

- [ ] Imports at top, no unused
- [ ] No `os.getenv` / `load_dotenv` outside entry points + config.py
- [ ] Clients via registry (or injected deps)
- [ ] Logging on all non-trivial paths
- [ ] Specific exceptions with rationale comments where broad catches remain
- [ ] Tunables in config.py, not inline
- [ ] `python3 -m py_compile` clean on changed files
- [ ] Live dry-run (or role invocation) passes
