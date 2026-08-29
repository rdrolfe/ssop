# Rootcheck Drift Investigation — case checklist

> Auto-attached by the SSOP case spine when a rootcheck drift alert escalates
> (rule 510). Follow this checklist to close the case.

## 1. Confirm the drift
- [ ] Verify the flagged file/registry key against the current syscheck baseline
- [ ] Confirm the change is NOT a known-good deployment (patch, config push)
- [ ] Note the `diff` of what changed (before vs after)

## 2. Classify intent
- [ ] Authorized change (deployment/maintenance) -> close as benign
- [ ] Unauthorized change -> treat as potential tampering (T1547.001-style)
- [ ] Unknown -> escalate to supervisory with the diff attached

## 3. Scope
- [ ] Single host or fleet-wide?
- [ ] Correlate with auth events (who touched it, when)
- [ ] Check for other integrity alerts on the same host

## 4. Respond
- [ ] Benign: note the baseline update for next scan
- [ ] Tampering: contain the host (quarantine), preserve the diff as evidence
- [ ] Revert via the config-revert step if a known-good baseline exists

## 5. Close
- [ ] Record the decision + rationale in the case
- [ ] Update the tuning ledger if this was a systemic false positive
