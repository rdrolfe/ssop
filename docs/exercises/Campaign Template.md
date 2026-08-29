# Campaign Template

> Copy this file for each orchestrator campaign. Name it `YYYY-MM-DD - Campaign Name.md`.

---

## Campaign: {{NAME}}

**Date:** {{YYYY-MM-DD}}

**MITRE Technique:** {{T1003.001}} — {{LSASS Memory}}

**Orchestrator Model:** {{model name}}

---

### Setup

- **Target VM:** {{vmid, name, OS}}
- **Cloned from template:** {{template name or snapshot}}
- **Wazuh agent deployed:** {{yes/no, agent ID}}
- **Heartbeat confirmed:** {{yes/no, timestamp}}

---

### Attack

- **Test:** {{Atomic Red Team test ID or custom payload description}}
- **Command executed:** ```{{command}}```
- **Execution time:** {{timestamp}}

---

### Detection

| Metric | Value |
|--------|-------|
| Expected Wazuh rule ID | {{rule ID}} |
| Did Wazuh fire? | {{yes/no/partial}} |
| Time from attack to alert | {{seconds}} |
| Rule match quality | {{exact/close/miss}} |
| False positives generated | {{count}} |

---

### Verdict

**Detection status:** {{pass | fail | partial}}

**Notes:** {{what happened? what was unexpected?}}

---

### Gap Report (if fail/partial)

**What should have been detected:**
{{description}}

**Why it wasn't:**
{{root cause — missing rule, log source not enabled, agent version mismatch, etc.}}

**Recommended fix:**
{{action item}}

---

### Teardown

- **VM destroyed:** {{yes/no}}
- **Cleanup verified:** {{yes/no}}
- **Duration from clone to teardown:** {{minutes}}

---

### Related

- [[SSOP/exercises/]]
- [[SSOP/architecture/Agent Tiers]]
