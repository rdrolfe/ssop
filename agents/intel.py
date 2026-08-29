"""SSOP Intel role — dedicated state machine.

The intel role is proactive intelligence: it reads advisories (CISA KEV +
NVD), matches them against fleet inventory (Wazuh syscollector), and
generates hunt packs into a staging area for human/supervisory review.

Flow: INGEST -> MATCH -> GENERATE -> STAGE -> (PROMOTE after review)
Per the wayfinder hunt-pack-schema decision: environment match + dedupe +
staging-review are the quality gate. Separation of duties: intel generates,
it does NOT promote (review is human/supervisory's).

Hygiene: config-driven, registry singletons, logging, exceptions, dotenv
only in __main__ (entry point).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional, TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

from logging_setup import get_logger
from tools.intel_tools import IntelClient
from tools.registry import get_intel

logger = get_logger(__name__)


class IntelState(TypedDict, total=False):
    """State threaded through the intel state machine."""
    days: int
    dry_run: bool
    report: Dict[str, Any]
    error: Optional[str]


def node_ingest(state: IntelState) -> IntelState:
    """Fetch advisories (KEV + NVD)."""
    client: IntelClient = get_intel()
    report = state.get("report") or {}
    try:
        report["fetched_kev"] = len(client.fetch_kev())
        report["fetched_nvd"] = len(client.fetch_nvd_since(days=state.get("days", 1)))
    except Exception as e:  # noqa: BLE001 — node boundary; record + fail fast
        logger.exception("intel ingest failed")
        return {**state, "error": str(e)}
    return {**state, "report": report}


def node_match(state: IntelState) -> IntelState:
    """Match advisories against fleet inventory (environment filter)."""
    client: IntelClient = get_intel()
    report = state.get("report") or {}
    try:
        kev = client.fetch_kev()
        inventory = client.inventory_products()
        matched = client.match_kev_to_inventory(kev, inventory)
        report["matched"] = len(matched)
        report["matched_entries"] = matched
    except Exception as e:  # noqa: BLE001 — node boundary
        logger.exception("intel match failed")
        return {**state, "error": str(e)}
    return {**state, "report": report}


def node_generate_stage(state: IntelState) -> IntelState:
    """Generate hunt packs from matched entries and stage them (dedupe)."""
    client: IntelClient = get_intel()
    report = state.get("report") or {}
    entries = report.get("matched_entries") or []
    staged, deduped, packs = 0, 0, []
    for entry in entries:
        pack = client.generate_pack(entry)
        if state.get("dry_run"):
            packs.append({"cve": entry.get("cveID"), "pack": pack["name"]})
            staged += 1
        else:
            path = client.stage_pack(pack)
            if path:
                staged += 1
                packs.append({"cve": entry.get("cveID"), "path": str(path)})
            else:
                deduped += 1
    report["staged"] = staged
    report["deduped"] = deduped
    report["packs"] = packs
    report["summary"] = (
        f"kev={report.get('fetched_kev', 0)} nvd={report.get('fetched_nvd', 0)} "
        f"matched={len(entries)} staged={staged} deduped={deduped}"
    )
    logger.info("intel run: %s", report["summary"])
    return {**state, "report": report}


def build_graph() -> StateGraph:
    """Build the intel LangGraph state machine."""
    g = StateGraph(IntelState)
    g.add_node("ingest", node_ingest)
    g.add_node("match", node_match)
    g.add_node("generate_stage", node_generate_stage)
    g.set_entry_point("ingest")
    g.add_edge("ingest", "match")
    g.add_edge("match", "generate_stage")
    g.add_edge("generate_stage", END)
    return g


def run(days: int = 1, dry_run: bool = False) -> Dict[str, Any]:
    """Run the intel role end-to-end."""
    graph = build_graph().compile()
    result = graph.invoke({"days": days, "dry_run": dry_run})
    if result.get("error"):
        logger.error("intel run error: %s", result["error"])
    return result.get("report") or {"error": result.get("error")}


def cli() -> None:
    load_dotenv()  # entry point — config is loaded here, passed down
    dry_run = "--dry-run" in sys.argv
    report = run(days=1, dry_run=dry_run)
    out = json.dumps(report, indent=2)
    print(out[:4000] if len(out) > 4000 else out)
    if report.get("error"):
        sys.exit(1)


if __name__ == "__main__":
    cli()
