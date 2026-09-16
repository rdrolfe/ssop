#!/usr/bin/env python3
"""Non-vacuity test for fingerprint-based tuning (thread #2).

The ledger records the DECISION-RELEVANT signature of the alert a human
tuned (rule_id/groups/level/category/threat-desc). Identical signatures
suppress; only a MATERIAL delta lifts the tuning for re-adjudication.

This test proves the decision helper is non-vacuous:
  - identical fingerprint              -> suppress
  - benign drift (different package
    name, lower level)                 -> suppress (still the tuned class)
  - MATERIAL delta: new attack group   -> override
  - MATERIAL delta: threat-desc token  -> override
  - MATERIAL delta: category -> attack -> override
  - MATERIAL delta: level rose         -> override
  - legacy entry WITHOUT a fingerprint -> falls back to the strong-TP gate
    (config-driven: integrity at lvl 7 suppresses, threat-desc overrides)

Uses TuningLedger directly but monkeypatches the client upsert/retrieve to
an in-memory dict — no Qdrant, hermetic.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.tuning_tools import TuningLedger, tuned_rule_suppresses  # noqa: E402


class _FakePoint:
    def __init__(self, payload):
        self.payload = payload


class _FakeClient:
    def __init__(self, store):
        self._store = store

    def retrieve(self, collection_name, ids, with_payload=True):
        return [_FakePoint(self._store[i]) for i in ids if i in self._store]

    def upsert(self, collection_name, points):
        for p in points:
            self._store[str(p.id)] = p.payload
        return None


class _FakeMemory:
    """In-memory stand-in for QdrantMemory (retrieve/upsert/ensure_collection)."""

    def __init__(self):
        self.store: dict[str, dict] = {}
        self.collections: set[str] = set()
        self.client = _FakeClient(self.store)

    def ensure_collection(self, name: str):
        self.collections.add(name)

    def scroll(self, *a, **k):
        return []


def _mk(rule_id, level, desc, groups):
    return {"rule": {"id": rule_id, "level": level, "description": desc, "groups": groups}}


def main() -> int:
    fails = 0
    fake = _FakeMemory()
    led = TuningLedger.__new__(TuningLedger)
    led._memory = fake  # type: ignore[assignment]

    # Baseline tuning for rule 2902 (dpkg install), the flood case.
    seed = _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck"])
    led.write("2902", "auto_fp", "human: routine package mgmt", source="human",
              fingerprint=None)  # legacy, no fingerprint
    tuning = led.lookup("2902")
    assert tuning is not None
    legacy_suppress, _ = tuned_rule_suppresses(tuning, seed, category="integrity")
    print(f"legacy (no fp) dpkg lvl7 integrity: suppress={legacy_suppress} (want True)")
    if not legacy_suppress:
        fails += 1

    # Re-tune WITH a fingerprint (the thread-#2 path).
    from tools.ontology import fingerprint_from_verdict
    seed_v = {"rule_id": "2902", "groups": ["syscheck"], "level": 7,
              "category": "integrity", "description": "New dpkg (Debian Package) installed."}
    led.write("2902", "auto_fp", "human: routine package mgmt", source="human",
              fingerprint=fingerprint_from_verdict(seed_v))
    tuning = led.lookup("2902")
    assert tuning is not None and tuning.get("fingerprint"), "fingerprint not stored"

    # 1. identical alert -> suppress
    same = _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck"])
    s, reason = tuned_rule_suppresses(tuning, same, category="integrity")
    print(f"identical dpkg: suppress={s} (want True) — {reason[:60]}")
    if not s:
        fails += 1

    # 2. benign drift: different package name, same groups/level -> suppress
    drift = _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck"])
    drift["rule"]["description"] = "New dpkg (Debian Package) install: libfoo 1.2.3"
    s, _ = tuned_rule_suppresses(tuning, drift, category="integrity")
    print(f"benign drift (pkg name): suppress={s} (want True)")
    if not s:
        fails += 1

    # 3. MATERIAL: new attack group
    newgrp = _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck", "suricata"])
    s, _ = tuned_rule_suppresses(tuning, newgrp, category="threat")
    print(f"new attack group (suricata): suppress={s} (want False)")
    if s:
        fails += 1

    # 4. MATERIAL: threat-desc token appeared
    threat = _mk("2902", 7, "ET MALWARE Sality (dpkg)", ["syscheck"])
    s, _ = tuned_rule_suppresses(tuning, threat, category="threat")
    print(f"threat-desc token: suppress={s} (want False)")
    if s:
        fails += 1

    # 5. MATERIAL: category became attack (authentication group added)
    auth = _mk("2902", 7, "sshd brute-force failure", ["syscheck", "authentication_failed"])
    s, _ = tuned_rule_suppresses(tuning, auth, category="authentication")
    print(f"category->authentication: suppress={s} (want False)")
    if s:
        fails += 1

    # 6. MATERIAL: level rose
    high = _mk("2902", 12, "New dpkg (Debian Package) installed.", ["syscheck"])
    s, _ = tuned_rule_suppresses(tuning, high, category="integrity")
    print(f"level rose 7->12: suppress={s} (want False)")
    if s:
        fails += 1

    # 7. legacy strong-TP gate still works for entries without a fingerprint:
    #    a tuned integrity rule at lvl 7 with a threat-desc token -> override
    led.write("550", "auto_fp", "human: integrity drift", source="human", fingerprint=None)
    t550 = led.lookup("550")
    assert t550 is not None, "550 tuning lookup failed"
    mal = _mk("550", 7, "ET C2 beacon (checksum)", ["syscheck", "fim"])
    s, _ = tuned_rule_suppresses(t550, mal, category="integrity")
    print(f"legacy gate threat-desc: suppress={s} (want False)")
    if s:
        fails += 1

    # 8. HOST-SCOPED EXCEPTION (option-C): a tuning with exclude_hosts must
    #    NEVER suppress an alert from an excluded host — even an IDENTICAL
    #    fingerprint — while other hosts still suppress.
    led.write("2901", "auto_fp", "user option-C: dpkg noise, keep secrets host",
              source="human", fingerprint=fingerprint_from_verdict(
                  {"rule_id": "2901", "groups": ["dpkg", "syslog"], "level": 3,
                   "category": "security", "description": "New dpkg (Debian Package) requested to install."}))
    t2901 = led.lookup("2901")
    assert t2901 is not None
    t2901["exclude_hosts"] = ["vault-secrets"]
    on_secrets = _mk("2901", 3, "New dpkg (Debian Package) requested to install.", ["dpkg", "syslog"])
    on_secrets["agent"] = {"name": "vault-secrets"}
    s, reason = tuned_rule_suppresses(t2901, on_secrets, category="security")
    print(f"excluded host vault-secrets: suppress={s} (want False) — {reason[:55]}")
    if s:
        fails += 1
    on_other = _mk("2901", 3, "New dpkg (Debian Package) requested to install.", ["dpkg", "syslog"])
    on_other["agent"] = {"name": "ubuntu-target"}
    s, _ = tuned_rule_suppresses(t2901, on_other, category="security")
    print(f"non-excluded host: suppress={s} (want True)")
    if not s:
        fails += 1

    # 9. ENTITY-SCOPED tuning (thread #4): a deny on one ENTITY must not
    #    silence the rule globally. Same rule + same entity -> suppress;
    #    same rule + DIFFERENT entity -> override (re-triage).
    from tools.ontology import fingerprint_from_alert, entity_scope_from_alert

    # network rule: tuned on the noisy pair 10.0.0.9 > 192.168.250.100
    net_fp = {"rule_id": "87101", "groups": ["suricata"], "level": 3,
              "category": "threat", "description": "ET SCAN check.",
              "entity_scope": "pair:10.0.0.9>192.168.250.100"}
    led.write("87101", "auto_fp", "deny: noisy scanner tuple", source="human",
              fingerprint=net_fp)
    t87101 = led.lookup("87101")
    assert t87101 is not None

    same_tuple = {"rule": {"id": "87101", "level": 3,
                           "description": "ET SCAN check.", "groups": ["suricata"]},
                  "srcip": "10.0.0.9", "dstip": "192.168.250.100"}
    s, reason = tuned_rule_suppresses(t87101, same_tuple, category="threat")
    print(f"same tuple: suppress={s} (want True) — {reason[:55]}")
    if not s:
        fails += 1

    other_tuple = {"rule": {"id": "87101", "level": 3,
                            "description": "ET SCAN check.", "groups": ["suricata"]},
                   "srcip": "10.0.0.9", "dstip": "192.168.1.77"}
    s, reason = tuned_rule_suppresses(t87101, other_tuple, category="threat")
    print(f"DIFFERENT tuple: suppress={s} (want False) — {reason[:55]}")
    if s:
        fails += 1

    # host rule (sysmon-style, no pair): tuned on one host, fires on another
    host_fp = {"rule_id": "991053", "groups": ["drill"], "level": 7,
               "category": "operational", "description": "Drill beacon.",
               "entity_scope": "host:we8105desk"}
    led.write("991053", "auto_fp", "deny: drill host", source="human",
              fingerprint=host_fp)
    t991053 = led.lookup("991053")
    assert t991053 is not None

    same_host = {"rule": {"id": "991053", "level": 7,
                          "description": "Drill beacon.", "groups": ["drill"]},
                 "agent": {"name": "we8105desk"}}
    s, _ = tuned_rule_suppresses(t991053, same_host, category="operational")
    print(f"same host: suppress={s} (want True)")
    if not s:
        fails += 1

    other_host = {"rule": {"id": "991053", "level": 7,
                           "description": "Drill beacon.", "groups": ["drill"]},
                  "agent": {"name": "vault-secrets"}}
    s, reason = tuned_rule_suppresses(t991053, other_host, category="operational")
    print(f"DIFFERENT host: suppress={s} (want False) — {reason[:55]}")
    if s:
        fails += 1

    # PROFILE SCOPING (ADR-008 narrowing, 2026-09-15). A tuning whose evidence
    # was a set of stock AppArmor profiles must not silence a denial on ANOTHER
    # profile. Measured before this existed: a level-12 deny on a profile the
    # adjudication never saw suppressed silently — the whole apparmor channel
    # was off, and denials are how a container escape surfaces.
    prof_fp = {"rule_id": "52002", "groups": ["apparmor", "ossec"], "level": 5,
               "category": "operational",
               "profiles": ["snap-confine", "fusermount3", "unprivileged_userns"]}
    led.write("52002", "auto_fp", "snapd stock noise (profiles adjudicated)",
              source="human", tuned_by="rdrolfe", fingerprint=prof_fp)
    t52002 = led.lookup("52002")
    assert t52002 is not None

    def _aa(profile=None, level=5, via_data=False):
        a = {"rule": {"id": "52002", "level": level, "groups": ["apparmor", "ossec"],
                      "description": "Apparmor DENIED"},
             "agent": {"name": "infra-ops"}}
        if profile and via_data:
            a["data"] = {"apparmor": {"profile": profile}}
        elif profile:
            a["full_log"] = ('type=AVC msg=audit(1.2:3): apparmor="DENIED" '
                             f'operation="open" profile="{profile}" name="/run/gdm3" '
                             'comm="snapd"')
        return a

    s, _ = tuned_rule_suppresses(t52002, _aa("snap-confine"), category="operational")
    print(f"adjudicated profile: suppress={s} (want True)")
    if not s:
        fails += 1

    s, reason = tuned_rule_suppresses(t52002, _aa("nginx-worker"), category="operational")
    print(f"UNSTUDIED profile: suppress={s} (want False) — {reason[:52]}")
    if s:
        fails += 1

    s, reason = tuned_rule_suppresses(t52002, _aa("docker-default", level=12),
                                      category="operational")
    print(f"UNSTUDIED profile, level 12: suppress={s} (want False) — {reason[:52]}")
    if s:
        fails += 1

    # Full-path profile form: this is what REAL alerts carry. Basename
    # normalisation is what keeps the allowlist from overriding everything.
    aa_path = {"rule": {"id": "52002", "level": 5, "groups": ["apparmor", "ossec"],
                        "description": "Apparmor DENIED"},
               "agent": {"name": "infra-ops"},
               "full_log": ('apparmor="DENIED" operation="capable" '
                            'profile="/snap/snapd/27710/usr/lib/snapd/snap-confine" '
                            'name="capable" comm="snap-confine"')}
    s, _ = tuned_rule_suppresses(t52002, aa_path, category="operational")
    print(f"full-path stock profile: suppress={s} (want True — basename matched)")
    if not s:
        fails += 1

    aa_path_other = {"rule": {"id": "52002", "level": 5, "groups": ["apparmor", "ossec"],
                              "description": "Apparmor DENIED"},
                     "agent": {"name": "infra-ops"},
                     "full_log": ('apparmor="DENIED" profile="/usr/sbin/nginx-worker" '
                                  'comm="nginx"')}
    s, _ = tuned_rule_suppresses(t52002, aa_path_other, category="operational")
    print(f"full-path unknown profile: suppress={s} (want False)")
    if s:
        fails += 1

    s, _ = tuned_rule_suppresses(t52002, _aa("docker-default", via_data=True),
                                 category="operational")
    print(f"data.apparmor.profile honoured: suppress={s} (want False)")
    if s:
        fails += 1

    # Documented limitation, asserted so it cannot drift silently: an alert
    # whose profile is NOT readable is not treated as out-of-scope. Same
    # decoder withholds full_log on some variants; overriding there would flood
    # the analyst with the noise class the human already adjudicated.
    s, _ = tuned_rule_suppresses(t52002, _aa(), category="operational")
    print(f"profile unreadable: suppress={s} (want True — falls through, not out-of-scope)")
    if not s:
        fails += 1

    # An entry with NO allowlist keeps the old behaviour (a plain rule tuning):
    led.write("52999", "auto_fp", "untuned profiles — rule-wide on purpose",
              source="human", tuned_by="rdrolfe",
              fingerprint={"rule_id": "52999", "groups": ["apparmor", "ossec"],
                           "level": 5, "category": "operational"})
    t_rw = led.lookup("52999")
    assert t_rw is not None
    wide = {"rule": {"id": "52999", "level": 5, "groups": ["apparmor", "ossec"],
                     "description": "Apparmor DENIED"},
            "agent": {"name": "infra-ops"},
            "full_log": 'apparmor="DENIED" profile="whatever-else" comm="x"'}
    s, _ = tuned_rule_suppresses(t_rw, wide, category="operational")
    print(f"no allowlist (rule-wide entry): suppress={s} (want True — unchanged)")
    if not s:
        fails += 1

    # scope helpers behave
    if entity_scope_from_alert(same_tuple) != "pair:10.0.0.9>192.168.250.100":
        fails += 1
    if entity_scope_from_alert(same_host) != "host:we8105desk":
        fails += 1
    if entity_scope_from_alert({}) != "":
        fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
