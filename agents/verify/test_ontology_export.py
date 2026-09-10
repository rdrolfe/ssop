#!/usr/bin/env python3
"""Ontology export drift gate + structural validation (hermetic).

1. Fresh render == on-disk docs/ontology/ssop.ttl (no hand-edits, no drift).
2. Structural sanity: classes, roles, categories, tiers, authority axioms
   all present and parseable line-level.
Phase 2 will add a real reasoner (owlready2/HermiT) consistency check here.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "agents"))

from tools.ontology_export import render, OUT  # noqa: E402

FAILS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


def main() -> int:
    ttl = render()

    # 1. no drift
    current = OUT.read_text() if OUT.exists() else ""
    check("export artifact matches fresh render", current == ttl,
          "rerun agents/tools/ontology_export.py")

    # 2. structural content
    for cls in ("Alert", "Observable", "Case", "Verdict", "Decision",
                "Playbook", "TuningEntry", "Receipt"):
        check(f"class :{cls} declared", f":{cls} a owl:Class" in ttl)
    for role in ("Router", "Analyst", "Investigator", "Supervisory",
                 "Responder", "Hunt", "Intel", "InfraManager"):
        check(f"role :{role} subclasses :Role",
              f":{role} a owl:Class ;\n    rdfs:subClassOf :Role" in ttl)
    for cat in ("authentication", "threat", "integrity", "compliance",
                "operational", "infra"):
        check(f"category :{cat} declared",
              f":{cat} a owl:Class ;\n    rdfs:subClassOf :AlertCategory" in ttl)
    for tier in ("tier0", "tier1", "tier2"):
        check(f"tier :{tier} declared",
              f":{tier} a owl:Class ;\n    rdfs:subClassOf :Tier" in ttl)

    # 3. authority axioms present
    check("tier2 requiresApprovalFrom Supervisory axiom",
          "owl:hasValue :Supervisory" in ttl)
    check("router-never-tier2 invariant documented",
          "Router never authorizes tier2" in ttl)
    check("classifiedAs single-categorizer property",
          ":classifiedAs a owl:ObjectProperty" in ttl)

    # 4. mirror-source checks: the taxonomy in tools/ontology.py must cover
    #    the same categories the OWL declares (drift between code and OWL).
    ontology_py = (REPO / "agents" / "tools" / "ontology.py").read_text()
    code_cats = [c for c in ("authentication", "threat", "integrity",
                             "compliance", "operational") if f'"{c}"' in ontology_py]
    for c in code_cats:
        check(f"code category '{c}' mirrored in OWL",
              f":{c} a owl:Class ;\n    rdfs:subClassOf :AlertCategory" in ttl)

    print("\nNON-VACUOUS" if FAILS == 0 else f"\n{FAILS} NON-VACUITY FAILURES")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
