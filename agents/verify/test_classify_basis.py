"""classify() must name WHY it decided, on every path.

The router's decision is a hard (category, role) pair. Before basis, a
signed tuning entry, a hand-written rule map line, and the ontology
fallback were indistinguishable at the call site — which made the
unadjudicated share of live decisions unmeasurable.

Two properties are asserted here, and the second is the one that matters:

  1. Every return path attributes a REAL basis. No default, no silent
     fallthrough attributed to a source that never ran.
  2. A guard that RAISES produces Basis.DEGRADED, not an ordinary basis.
     Property 1 alone would pass happily while a swallowed tuning-ledger
     failure was still being reported as a clean ontology decision — the
     silent-fallthrough class that made the ADR-008 stage-2 gap invisible
     for a week. So the degraded path is forced here by making the guard
     throw, and asserted to be reachable. A DEGRADED branch that no test
     can reach is a vacuous gate.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

# The tuning ledger is the authority surface classify() consults. Without a
# Qdrant key it raises, which marks EVERY classification DEGRADED — correct
# behaviour, and exactly what the offline suite's SSOP_ALLOW_NO_QDRANT_KEY=1
# exists to prevent. Establish the hermetic profile before importing router
# so these tests measure basis attribution, not the missing key.
os.environ.setdefault("SSOP_ALLOW_NO_QDRANT_KEY", "1")
os.environ.setdefault("SSOP_OFFLINE", "1")

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from router import Basis, Classification, classify  # noqa: E402


def _alert(rid, groups=None, level=5, desc="test", agent="vault-secrets"):
    return {
        "rule": {"id": rid, "level": level, "groups": groups or [], "description": desc},
        "agent": {"id": "003", "name": agent},
        "timestamp": "2026-09-28T12:00:00.000Z",
    }


# Rule ids that exist ONLY in router.RULE_MAP. 510/52002/5710 are deliberately
# NOT used: those also appear in transport.yaml's `rules:` block, and the
# transport map WINS by design (backend-specific overrides beat the default),
# so they would report TRANSPORT_RULE and the test would be asserting against
# the wrong source. 553 (syscheck/FIM) is in the Python map alone.
_PY_ONLY_RULE = "553"
# A rule present in NEITHER map, so the group heuristic is the only path.
_NO_RULE_ID = "99999"


class TestClassificationShape(unittest.TestCase):
    def test_returns_namedtuple_with_four_fields(self):
        c = classify(_alert(_PY_ONLY_RULE, ["syscheck"]))
        self.assertIsInstance(c, Classification)
        self.assertEqual(len(c), 4)
        self.assertIsInstance(c.basis, Basis)

    def test_index_access_still_works(self):
        """callers that used classify(a)[0] must keep working."""
        c = classify(_alert(_PY_ONLY_RULE, ["syscheck"]))
        self.assertEqual(c[0], c.category)
        self.assertEqual(c[1], c.role)

    def test_two_name_unpack_is_a_loud_error_not_a_silent_drop(self):
        """A stale 2-tuple unpack must FAIL, never quietly discard basis.

        This is the guard on the guard: if a future edit added a default
        basis or shrank the tuple, a call site could silently lose the
        provenance and every other check would still pass.
        """
        c = classify(_alert(_PY_ONLY_RULE, ["syscheck"]))
        with self.assertRaises(ValueError):
            category, role = c  # noqa: F841 — the point is that it raises

    def test_basis_is_json_safe_string(self):
        """basis must serialise into the dispatch report and the spine."""
        c = classify(_alert(_PY_ONLY_RULE, ["syscheck"]))
        self.assertIsInstance(c.basis.value, str)
        self.assertEqual(c.basis.value, str(Basis(c.basis.value).value))


class TestBasisAttribution(unittest.TestCase):
    def test_rulemap_rule_reports_rulemap(self):
        c = classify(_alert(_PY_ONLY_RULE, ["syscheck"]))
        self.assertEqual(c.basis, Basis.RULE_MAP)
        self.assertEqual(c.basis_detail, _PY_ONLY_RULE)

    def test_group_heuristic_reports_the_group(self):
        c = classify(_alert(_NO_RULE_ID, ["apparmor", "ossec"]))
        self.assertEqual(c.basis, Basis.GROUP_HEURISTIC)
        self.assertIn("apparmor", c.basis_detail)

    def test_heuristic_basis_is_not_the_default_fallthrough(self):
        """A group-heuristic hit must not read as UNCLASSIFIED.

        These are the two that would otherwise blur: both can end at
        DEFAULT_CATEGORY, so only the basis separates 'we decided' from
        'we gave up'.
        """
        c = classify(_alert(_NO_RULE_ID, ["apparmor"]))
        self.assertNotEqual(c.basis, Basis.UNCLASSIFIED)

    def test_basis_detail_is_populated_on_every_path(self):
        for rid, groups in [(_PY_ONLY_RULE, ["syscheck"]), (_NO_RULE_ID, ["apparmor"]),
                            (_NO_RULE_ID, ["authentication_failed"])]:
            with self.subTest(rid=rid, groups=groups):
                self.assertTrue(classify(_alert(rid, groups)).basis_detail)


class TestDegradedBasisIsReachable(unittest.TestCase):
    """A guard that raises must NOT be laundered as a clean decision.

    These two are the substance of the change. Pre-basis, both of these
    fell through to the next heuristic and the only trace was a log line
    nobody read — the router could route an alert the tuning ledger would
    have suppressed, and nothing downstream could tell.
    """

    def test_tuning_lookup_failure_reaches_the_decision(self):
        """TuningLedger() raising must surface, not vanish."""
        import tools.tuning_tools as tt

        real_ledger = tt.TuningLedger

        class Boom:
            def __init__(self, *a, **k):
                raise RuntimeError("ledger unavailable")

        with mock.patch.object(tt, "TuningLedger", Boom):
            # 61004 is untuned and reaches the syscheck group heuristic, so
            # the fallthrough has somewhere real to go.
            c = classify(_alert(_NO_RULE_ID, ["syscheck"], level=7,
                                desc="New dpkg (Debian Package) installed."))
        self.assertTrue(real_ledger is not None)  # sanity: the patch was scoped
        self.assertEqual(c.basis, Basis.DEGRADED)
        self.assertIn("tuning_lookup", c.basis_detail)

    def test_drill_gate_failure_reaches_the_decision(self):
        """is_drill_replay() raising must surface, not vanish."""
        import tools.ontology as onto

        def boom(_alert):
            raise RuntimeError("ontology unavailable")

        with mock.patch.object(onto, "is_drill_replay", boom):
            c = classify(_alert(_NO_RULE_ID, ["apparmor"]))
        self.assertEqual(c.basis, Basis.DEGRADED)
        self.assertIn("drill_gate", c.basis_detail)

    def test_degraded_does_not_change_the_verdict(self):
        """Provenance is metadata: the dispatch decision must be identical.

        If this fails, basis has leaked into authority — which is exactly
        what ADR-008 forbids. A degraded router still dispatches what it
        always dispatched; it merely says out loud that it is guessing.
        """
        import tools.tuning_tools as tt

        clean = classify(_alert(_NO_RULE_ID, ["syscheck"], level=7,
                                desc="New dpkg (Debian Package) installed."))

        class Boom:
            def __init__(self, *a, **k):
                raise RuntimeError("ledger unavailable")

        with mock.patch.object(tt, "TuningLedger", Boom):
            degraded = classify(_alert(_NO_RULE_ID, ["syscheck"], level=7,
                                       desc="New dpkg (Debian Package) installed."))
        self.assertEqual(clean.category, degraded.category)
        self.assertEqual(clean.role, degraded.role)
        self.assertNotEqual(clean.basis, degraded.basis)

    def test_rulemap_hit_ignores_degraded_flag_but_still_decides(self):
        """A degraded flag must not flip a definite decision into degraded.

        RULE_MAP is a static table — if the rule is in it, the basis is
        rule_map regardless of what an earlier guard did. Marking a known
        rule as DEGRADED would be a false alarm.
        """
        import tools.tuning_tools as tt

        class Boom:
            def __init__(self, *a, **k):
                raise RuntimeError("ledger unavailable")

        with mock.patch.object(tt, "TuningLedger", Boom):
            c = classify(_alert(_PY_ONLY_RULE, ["syscheck"]))
        self.assertEqual(c.basis, Basis.RULE_MAP)
        self.assertEqual(c.category, "security")


class TestDispatchCarriesBasis(unittest.TestCase):
    def test_dispatch_result_exposes_basis_fields(self):
        """The basis must reach the run report, not stop inside classify().

        The downstream role is stubbed: this asserts dispatch()'s result
        ASSEMBLY, and a real dispatch_security() would try to build an
        indexer client (and fail on a missing CA bundle in a hermetic run),
        which is a different test wearing this one's clothes.
        """
        from router import dispatch

        with mock.patch("router.dispatch_security",
                        return_value={"action": "dispatched_to_analyst"}):
            r = dispatch(_alert(_PY_ONLY_RULE, ["syscheck"]), burst_count=1)
        self.assertIn("basis", r)
        self.assertIn("basis_detail", r)
        self.assertEqual(r["basis"], Basis.RULE_MAP.value)
        self.assertEqual(r["dispatch"]["action"], "dispatched_to_analyst")

    def test_classification_defaults_detail_to_empty(self):
        c = Classification("operational", None, Basis.NOISE_RULE)
        self.assertEqual(c.basis_detail, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
