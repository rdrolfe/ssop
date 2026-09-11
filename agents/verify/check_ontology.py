#!/usr/bin/env python3
"""Phase-2 ontology consistency gate — HermiT proves the authority invariants.

Design (operator-approved 2026-09-11, scope = schema only, no live instances):

1. MODEL CONSISTENCY: the generated docs/ontology/ssop.ttl must be internally
   consistent under an open-world reasoner. A broken axiom set fails here.
2. NEGATIVE PROBE (non-vacuity): an individual Tier2 Decision approved by an
   individual of class Router MUST be derived inconsistent. This is the
   machine-proof of the operator policy "router never authorizes tier2"
   (Tier2 ⊑ ∀approvedBy.Supervisory + Supervisory ⊥ Router). If anyone
   weakens the axioms, this probe stops failing and the gate goes RED.
3. POSITIVE CONTROL: the same decision approved by a Supervisory individual
   MUST stay consistent — proves the axioms are not trivially contradictory
   (a probe suite where everything fails proves nothing).

Runs as a SUBPROCESS from verify/matrix.py / the offline suite: owlready2
boots an embedded JVM (HermiT) per run and must not touch the suite's own
singletons.

HERMETIC: no secrets, no network, no stores — the TTL is parsed in-memory
(via rdflib round-trip to NT because owlready2's loader wants its own
format), scenarios live in separate owlready2 Worlds, and the temp TTL
artifacts are written to a private tempfile dir.

PUNNING GOTCHA (found in smoke tests, worth the comment): the probe filler
must be a NAMED INDIVIDUAL declared `a :Router`. Using the CLASS IRI
`:Router` itself as the approvedBy value punns it as an individual, and
HermiT does NOT apply class disjointness to the punned node — the negative
probe silently passes. Any future probe in this file must use individuals.

Usage: python3 agents/verify/check_ontology.py   (exit 0/1)
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "agents"))

FAILS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


def _scenario(ttl_text: str, tmpdir: Path, name: str) -> str:
    """Load a TTL string into a fresh World and run HermiT.

    Returns "consistent" | "inconsistent" | "error:<msg>".
    Separate World per scenario — an inconsistency poisons the whole world,
    so the negative probe must never share one with the positive control.
    """
    from rdflib import Graph
    from owlready2 import World, sync_reasoner

    nt = Graph().parse(data=ttl_text, format="turtle").serialize(format="nt")
    p = tmpdir / f"{name}.nt"
    p.write_text(nt)
    world = World()
    onto = world.get_ontology(f"file://{p}").load()
    try:
        sync_reasoner(onto, debug=0)
        return "consistent"
    except Exception as e:  # noqa: BLE001 — owlready2 signals inconsistency by exception
        if type(e).__name__ == "OwlReadyInconsistentOntologyError":
            return "inconsistent"
        return f"error:{type(e).__name__}: {e}"


def main() -> int:
    # Load ontology_export by FILE PATH, not package import: agents/tools/
    # __init__ pulls proxmoxer/paramiko/qdrant-client (runtime-only deps).
    # The gate must run hermetic in the CI venv, which has none of those.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "ontology_export", REPO / "agents" / "tools" / "ontology_export.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    base = mod.render()
    IND = "\n"  # individuals appended after the base model

    with tempfile.TemporaryDirectory(prefix="ssop-ontology-") as td:
        tmp = Path(td)

        # 1. The model itself must be consistent (axioms don't self-contradict).
        r = _scenario(base, tmp, "model")
        check("model consistency (HermiT)", r == "consistent", f"got {r}")

        # 2. NEGATIVE PROBE: Tier2 decision approved by a Router individual
        #    must be INCONSISTENT. Punning note: the filler is an individual
        #    of class Router, not the class IRI (see module docstring).
        probe = (
            IND +
            ":probe-bad a :Tier2 , :Decision ;\n"
            "    :approvedBy :router-agent-x .\n"
            ":router-agent-x a :Router .\n"
        )
        r = _scenario(base + probe, tmp, "negative")
        check(
            "negative probe: router-approved tier2 is INCONSISTENT",
            r == "inconsistent",
            f"got {r} — axioms no longer prove router-never-tier2",
        )

        # 3. POSITIVE CONTROL: Supervisory-approved tier2 stays consistent.
        probe = (
            IND +
            ":probe-good a :Tier2 , :Decision ;\n"
            "    :approvedBy :sup-agent-x .\n"
            ":sup-agent-x a :Supervisory .\n"
        )
        r = _scenario(base + probe, tmp, "positive")
        check(
            "positive control: supervisory-approved tier2 is CONSISTENT",
            r == "consistent",
            f"got {r} — axioms are trivially contradictory; they prove nothing",
        )

        # 4. Non-vacuity of the whole gate: if the base model ALONE were
        #    inconsistent, probes 2 and 3 would pass/fail for the wrong
        #    reason — covered by check 1. Here we additionally require the
        #    reasoner to have actually RUN (error: results mean a broken
        #    JVM/owlready2 env, which must be BLOCKED, not skipped).
        for label, res in (("model", _scenario(base, tmp, "recheck-model")),):
            check(f"reasoner executed cleanly ({label})", not res.startswith("error"), res)

    print("\nONTOLOGY GATE: PASS" if FAILS == 0 else f"\nONTOLOGY GATE: FAIL ({FAILS})")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
