"""Case ID spine for SSOP incident lifecycle.

Every security incident gets a case_id minted at first detection. All roles
(analyst, hunter, infra-manager, supervisory) read/write the same incident
record threaded by that ID, so an incident can be reconstructed end-to-end.

DUAL-WRITE CONTRACT:
  - Qdrant collection "cases" = working memory (roles collaborate here)
  - JSONL audit/cases.jsonl = signed, append-only receipt (provable record)
Cross-referencing the two is the supervisory agent's audit-integrity duty.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from config import settings
from logging_setup import get_logger

logger = get_logger(__name__)

CASE_COLLECTION = settings.case_collection


def load_case_template(rule_id: Any) -> str | None:
    """Return the markdown case-template for a rule, if one is mapped.

    Adopted SO concept (case templates per rule -> ontology): the rule map in
    transport.yaml can carry `template: <name>`; the template lives in
    agents/templates/<name>.md. When a case is opened for that rule, the
    checklist is prepopulated into the case so the human (supervisory role)
    sees the investigation steps immediately. Backend-agnostic — the mapping
    is ontology data, not SIEM-specific.
    """
    try:
        tfile = settings.hunts_dir.parent / "transport.yaml"  # agents/transport.yaml
        data = yaml.safe_load(tfile.read_text()) if tfile.exists() else {}
        rules = data.get("rules", {})
        # Rule-map keys parse as ints in YAML; try both forms.
        entry = rules.get(rule_id) or rules.get(str(rule_id))
        tpl_name = (entry or {}).get("template") if isinstance(entry, dict) else None
        if not tpl_name:
            return None
        tpl = settings.hunts_dir.parent / "templates" / f"{tpl_name}.md"
        if tpl.exists():
            return tpl.read_text()
        logger.warning("case template %s not found for rule %s", tpl_name, rule_id)
        return None
    except Exception as e:  # noqa: BLE001 — template lookup must never break case creation
        logger.warning("case template lookup failed for rule %s: %s", rule_id, e)
        return None


class CaseStore:
    """Incident spine backed by Qdrant (working) + JSONL (receipt)."""

    def __init__(self, memory=None) -> None:
        self.audit_dir: Path = settings.audit_dir
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.cases_file = self.audit_dir / "cases.jsonl"
        self._memory = memory  # injected (registry) or None -> lazy

    def _get_memory(self):
        if self._memory is None:
            from tools.qdrant_tools import QdrantMemory

            self._memory = QdrantMemory()
        return self._memory

    # --- core ops ---

    def open_case(self, source: dict[str, Any], title: str, observables: list[dict[str, str]] | None = None,
                  enrichments: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Mint a new incident and write it to both stores.

        `observables` (optional) is the extracted IOC list [{type, value}] —
        a first-class case field per the adopted SO concept (Concept 1 of the
        two-example doctrine). `enrichments` (optional) is the threat-intel
        verdict list from EnrichmentClient (Concept 2). Both ride in the case
        payload — backend-agnostic, not in any SIEM index.
        """
        case = {
            "case_id": "case-" + uuid.uuid4().hex[:10],
            "ts": datetime.now(timezone.utc).isoformat(),
            "title": title,
            "status": "open",
            "source": source,  # original alert/trigger
            "observables": observables or [],  # [{type, value}, ...]
            "enrichments": enrichments or [],  # [{provider, status, raw, ts}, ...]
            "checklist": None,  # case-template markdown (adopted SO concept 5)
            "timeline": [],  # append-only events (verdicts, actions)
            "assignee": None,  # role currently handling it
        }
        # Prepopulate the case checklist from the rule's case-template, if any
        # (adopted SO concept: rule.case_template -> auto-populated checklist).
        try:
            rid = source.get("rule_id") or (source.get("alert_id") and None)
            if rid is not None:
                tpl = load_case_template(rid)
                if tpl:
                    case["checklist"] = tpl
        except Exception as e:  # noqa: BLE001 — template must never break case creation
            logger.warning("case template prepopulate failed: %s", e)
        self._write_both(case, event="case_opened")
        logger.info("case opened: %s (%s) [%d observables, %d enrichments]", case["case_id"], title[:60],
                    len(case["observables"]), len(case["enrichments"]))
        return case

    def append_event(self, case_id: str, role: str, event_type: str, detail: dict[str, Any]) -> dict[str, Any] | None:
        """Append a timeline event to an existing case (by case_id)."""
        case = self.get_case(case_id)
        if not case:
            logger.warning("append_event: case %s not found", case_id)
            return None
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "type": event_type,
            "detail": detail,
        }
        case.setdefault("timeline", []).append(entry)
        case["updated_ts"] = entry["ts"]
        self._write_both(case, event=event_type, role=role)
        return case

    def close_case(self, case_id: str, role: str = "case-spine", reason: str = "") -> dict[str, Any] | None:
        """Close a case (status -> closed) and record the lifecycle event.

        A first-class lifecycle op (not a deletion): the append-only receipt
        preserves the full history; the working Qdrant store marks it closed
        so it stops matching 'recent open' checks and entity-recidivism.
        """
        case = self.get_case(case_id)
        if not case:
            logger.warning("close_case: case %s not found", case_id)
            return None
        case["status"] = "closed"
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "type": "case_closed",
            "detail": {"reason": reason},
        }
        case.setdefault("timeline", []).append(entry)
        case["updated_ts"] = entry["ts"]
        self._write_both(case, event="case_closed", role=role)
        logger.info("case closed: %s (%s)", case_id, reason[:60] if reason else "no reason")
        return case

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        """Fetch case from Qdrant (working store)."""
        try:
            results = self._get_memory().search_memory(CASE_COLLECTION, case_id, limit=1)
            for r in results:
                if case_id in r.get("content", ""):
                    payload = self._parse_content(r.get("content", ""))
                    if payload:
                        return payload
            return None
        except Exception as e:  # noqa: BLE001 — fall back to receipt on any store failure
            logger.warning("qdrant read failed for %s, falling back to receipt: %s", case_id, e)
            return self._get_from_receipt(case_id)

    @staticmethod
    def _parse_content(content: str) -> dict[str, Any] | None:
        if " " not in content:
            return None
        try:
            return json.loads(content.split(" ", 1)[1])
        except (json.JSONDecodeError, IndexError):
            return None

    def _get_from_receipt(self, case_id: str) -> dict[str, Any] | None:
        if not self.cases_file.exists():
            return None
        for line in self.cases_file.read_text().splitlines():
            try:
                rec = json.loads(line)
                if rec.get("case_id") == case_id:
                    return rec
            except json.JSONDecodeError:
                continue
        return None

    # --- dual-write helpers ---

    def _write_both(self, case: dict[str, Any], event: str, role: str = "case-spine") -> None:
        self._write_receipt(case, event=event, role=role)
        self._write_memory(case)

    def _write_receipt(self, case: dict[str, Any], event: str, role: str = "case-spine") -> None:
        """Append a signed receipt line (append-only, provable)."""
        receipt = {
            "case_id": case["case_id"],
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "event": event,
            "status": case.get("status"),
            "title": case.get("title", ""),
            "detail": case.get("timeline", [{}])[-1] if case.get("timeline") else {},
        }
        with open(self.cases_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(receipt) + "\n")

    def _write_memory(self, case: dict[str, Any]) -> None:
        """Upsert canonical case point in Qdrant (stable uuid5 point id).

        Retries transient connection refusals so a brief network blip cannot
        strand a case as receipt-only (the divergence we hit on .94).
        """
        try:
            import uuid as _uuid

            from qdrant_client.models import PointStruct
            from tools.qdrant_tools import _retry_call

            content = f"{case['case_id']} {json.dumps(case)}"
            pid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, case["case_id"]))
            _retry_call(
                self._get_memory().client.upsert,
                collection_name=CASE_COLLECTION,
                points=[PointStruct(
                    id=pid,
                    vector=[0.0] * 384,
                    payload={
                        "content": content,
                        "timestamp": case.get("ts") or case.get("updated_ts", ""),
                        "type": "case",
                        "case_id": case["case_id"],
                        "status": case.get("status", "open"),
                        "title": case.get("title", ""),
                        "observables": case.get("observables", []),  # queryable IOC list
                        "enrichments": case.get("enrichments", []),  # queryable TI verdicts
                    },
                )],
            )
        except Exception as e:
            logger.exception("qdrant write failed for %s", case.get("case_id"))
            raise RuntimeError(f"case memory write failed: {e}") from e

    # --- audit-integrity (supervisory duty) ---

    def recent_hunt_cases(self, hunt_id: str, window_s: int = 86400) -> list[dict[str, Any]]:
        """Find open/recent cases filed by the same HUNT (by hunt_id).

        Hunt-level recidivism: a periodic hunt sweep re-tests the same
        hypothesis, so a persistent finding must ATTACH to the existing hunt
        case (append a recheck event), not mint a new case + re-escalate.

        Scans the Qdrant working store (the receipt spine has no `source` —
        only Qdrant carries source.hunt_id). Iterates case points and keeps
        those with matching hunt_id, status != closed, and a recent ts.
        """
        out: list[dict[str, Any]] = []
        cutoff = datetime.now(timezone.utc).timestamp() - window_s
        try:
            mem = self._get_memory()
            for r in mem.search_memory(CASE_COLLECTION, "case-", limit=1000):
                payload = self._parse_content(r.get("content", ""))
                if not payload:
                    continue
                if payload.get("status") == "closed":
                    continue
                src = payload.get("source", {})
                if str(src.get("hunt_id")) != str(hunt_id):
                    continue
                try:
                    ts = payload.get("ts", "")
                    if datetime.fromisoformat(ts).timestamp() < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
                out.append(payload)
        except Exception as e:  # noqa: BLE001 — recidivism must never break the sweep
            logger.warning("recent_hunt_cases scan failed: %s", e)
        return out

    def recent_entity_cases(self, srcip: str, dstip: str, window_s: int = 3600) -> list[dict[str, Any]]:
        """Find open/recent cases engaged with the same (srcip, dstip) pair.

        Powers the stateful entity-recidivism check: a repeated pair should
        ATTACH to an existing chain, not mint a new case.

        Scans the Qdrant working store (the receipt spine carries no `source`
        — only Qdrant holds source.srcip/src.dstip). Keeps cases with a
        matching entity pair, status != closed, and a recent ts.
        """
        out: list[dict[str, Any]] = []
        cutoff = datetime.now(timezone.utc).timestamp() - window_s
        try:
            mem = self._get_memory()
            for r in mem.search_memory(CASE_COLLECTION, "case-", limit=1000):
                payload = self._parse_content(r.get("content", ""))
                if not payload:
                    continue
                if payload.get("status") == "closed":
                    continue
                src = payload.get("source", {})
                if (str(src.get("srcip")) != str(srcip)
                        or str(src.get("dstip")) != str(dstip)):
                    continue
                try:
                    ts = payload.get("ts", "")
                    if datetime.fromisoformat(ts).timestamp() < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
                out.append(payload)
        except Exception as e:  # noqa: BLE001 — recidivism must never break triage
            logger.warning("recent_entity_cases scan failed: %s", e)
        return out

    def reconcile(self, heal: bool = True) -> dict[str, Any]:
        """Compare Qdrant vs JSONL for each case. Returns mismatches.

        The supervisory agent consumes this as its audit-integrity check.
        With heal=True (default), receipt-only cases are automatically
        re-synced into Qdrant — the JSONL receipt is the provable truth, so a
        working-memory gap is repaired in place rather than left for a human.
        Qdrant-only points are only reported (never deleted automatically: a
        phantom point is safer than a silently dropped case).
        """
        qdrant_ids: set[str] = set()
        try:
            for r in self._get_memory().search_memory(CASE_COLLECTION, "case-", limit=1000):
                cid = (r.get("metadata") or {}).get("case_id") or r.get("content", "").split(" ", 1)[0]
                if cid.startswith("case-"):
                    qdrant_ids.add(cid)
        except Exception as e:  # noqa: BLE001
            logger.warning("reconcile: qdrant scan failed: %s", e)
        receipt_ids: set[str] = set()
        receipts: dict[str, dict[str, Any]] = {}
        if self.cases_file.exists():
            for line in self.cases_file.read_text().splitlines():
                try:
                    rec = json.loads(line)
                    if rec.get("case_id"):
                        receipt_ids.add(rec["case_id"])
                        receipts.setdefault(rec["case_id"], rec)
                except json.JSONDecodeError:
                    continue
        receipt_only = sorted(receipt_ids - qdrant_ids)
        healed: list[str] = []
        heal_failed: list[str] = []
        if heal and receipt_only:
            for cid in receipt_only:
                rec = receipts.get(cid) or self._get_from_receipt(cid)
                if not rec:
                    heal_failed.append(cid)
                    continue
                # Rebuild a minimal canonical case from the receipt record
                # (title/status/timeline) and re-write the Qdrant point.
                try:
                    case = {
                        "case_id": cid,
                        "title": rec.get("title", cid),
                        "status": rec.get("status", "open"),
                        "ts": rec.get("ts"),
                        "updated_ts": rec.get("ts"),
                        "observables": [],
                        "enrichments": [],
                        "timeline": [rec.get("detail")] if rec.get("detail") else [],
                    }
                    self._write_memory(case)
                    healed.append(cid)
                except Exception as e:  # noqa: BLE001 — report, don't die
                    logger.warning("reconcile heal failed for %s: %s", cid, e)
                    heal_failed.append(cid)
            # Refresh the Qdrant id set after healing.
            qdrant_ids.update(healed)
        return {
            "qdrant_only": sorted(qdrant_ids - receipt_ids),
            "receipt_only": sorted(receipt_ids - qdrant_ids),
            "healed": healed,
            "heal_failed": heal_failed,
            "consistent": qdrant_ids == receipt_ids,
            "qdrant_count": len(qdrant_ids),
            "receipt_count": len(receipt_ids),
        }
