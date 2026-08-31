"""Playbook loader — data-driven playbook library.

Playbooks are YAML in agents/playbooks/ (filename stem = id). The loader
discovers them at runtime, matching the hunts/checks pattern: adding a
playbook = dropping a YAML file, no code change.

Schema per docs/wayfinder/tickets/playbook-schema.md:
  name, description, trigger {category, min_level, rule_ids, recommended},
  approval (tier0|tier1|tier2), timeout_s, steps [{step, params}],
  questions [{question, query, expected}]   <- adopted SO Guided Analysis
     (each question carries an executable query; results are returned as
      LIVE EVIDENCE, backend-agnostic via the transport)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from config import settings
from logging_setup import get_logger

logger = get_logger(__name__)


class PlaybookError(RuntimeError):
    """Raised when a playbook is invalid or missing."""


class Playbook:
    """A loaded playbook with trigger matching + validation."""

    def __init__(self, data: Dict[str, Any], path: Path) -> None:
        self.data = data
        self.path = path
        self.name: str = data.get("name", path.stem)
        self.description: str = data.get("description", "")
        self.approval: str = data.get("approval", "tier2")
        self.timeout_s: int = data.get("timeout_s", 120)
        trigger = data.get("trigger", {})
        self.trigger_category: Optional[str] = trigger.get("category")
        self.trigger_min_level: int = trigger.get("min_level", 0)
        self.trigger_rule_ids: List[int] = trigger.get("rule_ids", [])
        self.recommended: bool = trigger.get("recommended", True)
        self.steps: List[Dict[str, Any]] = data.get("steps", [])
        # Adopted SO Guided Analysis: questions carry executable queries.
        self.questions: List[Dict[str, Any]] = data.get("questions", [])

    @property
    def requires_recommendation(self) -> bool:
        """tier1+ playbooks require a role's recommendation to fire."""
        return self.approval in ("tier1", "tier2") and self.recommended

    def run_questions(self, indexer=None) -> List[Dict[str, Any]]:
        """Execute each question's query against the transport, returning live evidence.

        Returns [{question, query, expected, count, results}] where `results`
        is the top hits (small) and `count` is the total match count. This is
        the Guided Analysis pattern — a checklist with answers, not just steps.
        Backend-agnostic: queries run through the transport (Wazuh today, SO
        after the transport flip). A question with no query or a failing query
        degrades to count=-1 (never blocks the playbook).
        """
        if not self.questions:
            return []
        from tools.indexer_client import IndexerTransport
        idx = indexer or IndexerTransport()
        evidence: List[Dict[str, Any]] = []
        for q in self.questions:
            question = q.get("question", "")
            query = q.get("query")
            entry = {
                "question": question,
                "expected": q.get("expected", ""),
                "query": query,
                "count": -1,
                "results": [],
            }
            if not query:
                evidence.append(entry)
                continue
            try:
                body = {"size": 5, "query": query}
                res = idx.search(body)
                hits = res.get("hits", {})
                entry["count"] = int(hits.get("total", {}).get("value", len(hits.get("hits", []))))
                entry["results"] = [h.get("_source", {}) for h in hits.get("hits", [])]
            except Exception as e:  # noqa: BLE001 — evidence must never block
                logger.warning("playbook question %r query failed: %s", question, e)
                entry["count"] = -1
            evidence.append(entry)
        return evidence

    def matches(self, alert: Dict[str, Any]) -> bool:
        """Does this playbook's trigger match the alert?"""
        rule = alert.get("rule", {})
        rule_id = str(rule.get("id", ""))
        level = int(rule.get("level", 0) or 0)
        # exact rule-id override
        if self.trigger_rule_ids:
            return rule_id in {str(r) for r in self.trigger_rule_ids}
        # category + level: category matches the alert's category field if
        # present (router-classified), else any of the rule's groups.
        # trigger.category may be a single ontology category or a list
        # (e.g. the hunt MITRE categories map to multiple containment
        # playbooks).
        if self.trigger_category:
            cats = self.trigger_category if isinstance(self.trigger_category, list) else [self.trigger_category]
            alert_cat = alert.get("category") or ""
            groups = rule.get("groups", [])
            if alert_cat not in cats and not any(c in groups for c in cats):
                return False
        return level >= self.trigger_min_level

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "approval": self.approval,
                "description": self.description, "steps": len(self.steps)}


def load_playbooks(playbooks_dir: Path | None = None) -> Dict[str, Playbook]:
    """Discover and load all playbooks from the playbooks directory."""
    d = playbooks_dir or settings.playbooks_dir
    out: Dict[str, Playbook] = {}
    if not d.exists():
        logger.warning("playbooks dir %s missing", d)
        return out
    for f in sorted(d.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text())
            if not data or not isinstance(data, dict):
                continue
            pb = Playbook(data, f)
            out[pb.name] = pb
        except (yaml.YAMLError, OSError) as e:
            logger.error("bad playbook %s: %s", f.name, e)
    logger.info("loaded %d playbooks from %s", len(out), d)
    return out
