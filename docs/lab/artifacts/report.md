# Incident Report — [HUNT] DEFENSE-EVASION finding in AppArmor denials

- **Case**: `case-2d9c6106e3`
- **Status**: closed
- **Opened**: 2026-08-19 19:42:06

## Summary

**CLOSED** case for hunt `apparmor-denials` finding. Decision: **DENY** — Nth recurrence of the chronic apparmor-denials hunt FP (rule 52002, volume-only threshold, query size-capped at 100 - '100' is the cap, not reality). Fresh indexer pull (rule.id=52002, 7d): TOTAL 2949 vs hunt's capped 100. BY PROFILE all known-benign stock-Ubuntu families - fusermount3 200 / snap-update-ns.firmware-updater 97 / snap-confine rev27710 95 / unprivileged_userns 85 / firmware-notifier 17 / cupsd 6; zero unknown profiles. BY COMM all known-benign (fusermount3, snap-confine, snap-update-ns, (ubuntu-insigh), systemd-detect-, firmware-notifi, cupsd) - (ubuntu-insigh)/systemd-detect- is the documented unprivileged_userns family. Discriminators all zero: class=exec 0, load_profile 0, unload 0, change_profile 0 - nothing blocked from executing, no evasion signal. Ticket split 38/38/24 is the capped sample vs real population: infra-ops 318 / vault-secrets 98 / kb-vec 84. Host spot-check: kernel.apparmor_restrict_unprivileged_userns=1 and fusermount3 dac_override/setuid caps commented out - stock enforcement by design. Newest tail 06:15:51Z infra-ops fusermount3/unprivileged_userns = session-start FUSE burst. Enforcement noise, not evasion. Tuning signal: whitelist stock profiles (fusermount3 / unprivileged_userns / snap-* / cupsd) + per-agent threshold..

## 2. Trigger

- Hunt: `apparmor-denials`

## 3. Decision Chain

- **2026-08-19 19:48:37** — Pattern finding  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 54, 'kb-vec': 3, 'network': 43}
- **2026-08-19 19:56:22** — Supervisor verdict  
  verdict **false_positive**  
  Nth recurrence of the apparmor-denials hunt wave (router over-mint; 15+ prior supervisory denies this wave 19:41-19:54Z: case-eccec2022b, case-0438d44de4, case-9147e6c443, case-9010dffd73, case-9c4eda5bcc, case-ac4215f239, case-56125cc215, case-28ee8395d0, case-21f1ab0b6f, case-0207859bdc, case-2d9c6106e3, case-c86069019d, case-cf46b88895, case-6cf460b177, case-3b76d3523b, case-7d4af80cdd, case-77ebe5b21e). Identical payload: same 100 denials (infra-ops 54 / network 43 / kb-vec 3), same Aug 18 18:21:18-51Z burst, same sample logs. Fresh indexer pull this review (7d window, rule 52002): 1976 events, profile distribution = fusermount3 1092, unprivileged_userns 524, snap-update-ns.firmware-updater 175, snap-confine 175, cupsd 8, firmware-notifier 2. ZERO unknown/custom profiles, ZERO class=exec denials (ops: capable 1268 / open 356 / mount 178 / getattr 174). All stock Ubuntu 24.04 profiles enforcing policy by design: fusermount3 cap denials (dac_override/setuid = FUSE mount-helper), unprivileged_userns (kernel.apparmor_restrict_unprivileged_userns=1; ubuntu-insights sys_admin probe + systemd-detect-virt disconnected-path getattr bug). by_day: 681 Aug 18 / 1285 Aug 19 = chronic noise, not a burst. Hunt undercounts (reported 100/3 agents; indexer shows 1976/4 agents incl. vault-secrets). 43 network denials trace to sanctioned Aug 16 purple-team beacon (case-02a740873a). Enforcement, not evasion. Tuning signal (volume-only threshold; whitelist stock profiles) already on spine.
- **2026-08-31 06:15:20** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 38, 'kb-vec': 38, 'infra-ops': 24}
- **2026-08-31 06:15:20** — Hunt escalation  
  finding **suspicious**
- **2026-08-31 06:16:45** — Supervisor verdict  
  verdict **false_positive**  
  Nth recurrence of the chronic apparmor-denials hunt FP (rule 52002, volume-only threshold, query size-capped at 100 - '100' is the cap, not reality). Fresh indexer pull (rule.id=52002, 7d): TOTAL 2949 vs hunt's capped 100. BY PROFILE all known-benign stock-Ubuntu families - fusermount3 200 / snap-update-ns.firmware-updater 97 / snap-confine rev27710 95 / unprivileged_userns 85 / firmware-notifier 17 / cupsd 6; zero unknown profiles. BY COMM all known-benign (fusermount3, snap-confine, snap-update-ns, (ubuntu-insigh), systemd-detect-, firmware-notifi, cupsd) - (ubuntu-insigh)/systemd-detect- is the documented unprivileged_userns family. Discriminators all zero: class=exec 0, load_profile 0, unload 0, change_profile 0 - nothing blocked from executing, no evasion signal. Ticket split 38/38/24 is the capped sample vs real population: infra-ops 318 / vault-secrets 98 / kb-vec 84. Host spot-check: kernel.apparmor_restrict_unprivileged_userns=1 and fusermount3 dac_override/setuid caps commented out - stock enforcement by design. Newest tail 06:15:51Z infra-ops fusermount3/unprivileged_userns = session-start FUSE burst. Enforcement noise, not evasion. Tuning signal: whitelist stock profiles (fusermount3 / unprivileged_userns / snap-* / cupsd) + per-agent threshold.
- **2026-08-31 06:16:45** — supervisory/case_closed  
  {"reason": "Nth recurrence of the chronic apparmor-denials hunt FP (rule 52002, volume-only threshold, query size-capped at 100 - '100' is the cap, not reality)
- **2026-08-31 06:45:30** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 25, 'kb-vec': 26, 'infra-ops': 49}
- **2026-08-31 07:00:31** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 25, 'kb-vec': 19, 'infra-ops': 56}
- **2026-08-31 07:15:27** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 21, 'kb-vec': 19, 'infra-ops': 60}
- **2026-08-31 07:30:38** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 21, 'kb-vec': 19, 'infra-ops': 60}
- **2026-08-31 07:45:20** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 21, 'kb-vec': 19, 'infra-ops': 60}
- **2026-08-31 08:00:32** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 21, 'kb-vec': 19, 'infra-ops': 60}
- **2026-08-31 08:15:26** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 21, 'kb-vec': 19, 'infra-ops': 60}
- **2026-08-31 08:30:28** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 35, 'kb-vec': 32, 'infra-ops': 33}
- **2026-08-31 08:45:31** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 35, 'kb-vec': 32, 'infra-ops': 33}
- **2026-08-31 09:00:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 34, 'kb-vec': 28, 'infra-ops': 38}
- **2026-08-31 09:15:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 34, 'kb-vec': 28, 'infra-ops': 38}
- **2026-08-31 09:30:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 34, 'kb-vec': 28, 'infra-ops': 38}
- **2026-08-31 09:45:26** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 30, 'kb-vec': 24, 'infra-ops': 46}
- **2026-08-31 10:00:17** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 21, 'kb-vec': 19, 'infra-ops': 60}
- **2026-08-31 10:15:36** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 17, 'kb-vec': 15, 'infra-ops': 68}
- **2026-08-31 10:30:32** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 30, 'kb-vec': 28, 'infra-ops': 42}
- **2026-08-31 10:45:11** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 37, 'kb-vec': 24, 'infra-ops': 39}
- **2026-08-31 11:00:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 37, 'kb-vec': 24, 'infra-ops': 39}
- **2026-08-31 11:15:26** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 26, 'kb-vec': 15, 'infra-ops': 59}
- **2026-08-31 11:30:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 24, 'kb-vec': 15, 'infra-ops': 61}
- **2026-08-31 11:45:12** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 24, 'kb-vec': 15, 'infra-ops': 61}
- **2026-08-31 12:00:35** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 24, 'kb-vec': 15, 'infra-ops': 61}
- **2026-08-31 12:15:33** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 24, 'kb-vec': 15, 'infra-ops': 61}
- **2026-08-31 12:30:16** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 24, 'kb-vec': 15, 'infra-ops': 61}
- **2026-08-31 12:45:33** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 30, 'kb-vec': 28, 'infra-ops': 42}
- **2026-08-31 13:00:32** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 29, 'kb-vec': 21, 'infra-ops': 50}
- **2026-08-31 13:15:09** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 27, 'kb-vec': 29, 'infra-ops': 44}
- **2026-08-31 13:30:35** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 27, 'kb-vec': 29, 'infra-ops': 44}
- **2026-08-31 13:45:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 20, 'kb-vec': 24, 'infra-ops': 56}
- **2026-08-31 14:00:33** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 15, 'kb-vec': 20, 'infra-ops': 65}
- **2026-08-31 14:15:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 14:30:34** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 14:45:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 15:00:24** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 15:15:38** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 15:30:16** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 15:36:43** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 15:38:48** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 15:40:48** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 15:45:21** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 16:00:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 14, 'kb-vec': 20, 'infra-ops': 66}
- **2026-08-31 16:15:09** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 29, 'kb-vec': 21, 'infra-ops': 50}
- **2026-08-31 16:30:30** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 29, 'kb-vec': 20, 'infra-ops': 51}
- **2026-08-31 17:00:15** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 7, 'infra-ops': 83}
- **2026-08-31 17:15:38** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 7, 'infra-ops': 83}
- **2026-08-31 17:30:31** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 7, 'infra-ops': 83}
- **2026-08-31 17:45:17** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 7, 'infra-ops': 83}
- **2026-08-31 18:00:28** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 7, 'infra-ops': 83}
- **2026-08-31 18:15:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 7, 'infra-ops': 83}
- **2026-08-31 18:30:19** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 7, 'infra-ops': 83}
- **2026-08-31 18:45:26** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 7, 'infra-ops': 83}
- **2026-08-31 19:00:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 10, 'kb-vec': 5, 'infra-ops': 85}
- **2026-08-31 19:15:15** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 24, 'kb-vec': 17, 'infra-ops': 59}
- **2026-08-31 19:30:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 24, 'kb-vec': 17, 'infra-ops': 59}
- **2026-08-31 19:45:18** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 18, 'kb-vec': 12, 'infra-ops': 70}
- **2026-08-31 20:00:12** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 15, 'kb-vec': 8, 'infra-ops': 77}
- **2026-08-31 20:30:22** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 5, 'kb-vec': 3, 'infra-ops': 92}
- **2026-08-31 20:45:18** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 5, 'kb-vec': 3, 'infra-ops': 92}
- **2026-08-31 21:00:13** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 5, 'kb-vec': 3, 'infra-ops': 92}
- **2026-08-31 21:15:38** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 5, 'kb-vec': 3, 'infra-ops': 92}
- **2026-08-31 21:30:04** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 5, 'kb-vec': 3, 'infra-ops': 92}
- **2026-08-31 21:45:07** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 5, 'kb-vec': 3, 'infra-ops': 92}
- **2026-08-31 22:00:12** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'vault-secrets': 5, 'kb-vec': 3, 'infra-ops': 92}
- **2026-08-31 22:15:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 92, 'vault-secrets': 4, 'kb-vec': 4}
- **2026-08-31 22:30:46** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 92, 'vault-secrets': 4, 'kb-vec': 4}
- **2026-08-31 22:45:32** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 100}
- **2026-08-31 23:00:25** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 66, 'vault-secrets': 19, 'kb-vec': 15}
- **2026-08-31 23:15:35** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 66, 'vault-secrets': 19, 'kb-vec': 15}
- **2026-08-31 23:30:27** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 68, 'vault-secrets': 19, 'kb-vec': 13}
- **2026-08-31 23:45:36** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 78, 'vault-secrets': 15, 'kb-vec': 7}
- **2026-09-01 00:00:19** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 00:15:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 00:30:28** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 00:45:40** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 01:00:08** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 01:15:12** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 01:30:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 01:45:47** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 02:00:19** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 02:15:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 02:30:40** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 02:45:38** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 03:00:15** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 03:15:32** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 03:30:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 03:45:27** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 04:00:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 04:15:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 04:30:21** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 04:36:12** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 41, 'kb-vec': 26, 'infra-ops': 33}
- **2026-09-01 04:42:07** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'kb-vec': 27, 'infra-ops': 33}
- **2026-09-01 04:45:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 05:00:07** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 05:15:31** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 05:30:48** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 05:45:18** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 06:00:18** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 06:15:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 06:21:09** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 39, 'infra-ops': 33, 'kb-vec': 28}
- **2026-09-01 06:30:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 06:45:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 07:00:17** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 07:03:17** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 43, 'infra-ops': 30, 'kb-vec': 27}
- **2026-09-01 07:15:07** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 07:30:22** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 07:45:41** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 08:00:33** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 08:15:26** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 08:30:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 08:45:05** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 43, 'infra-ops': 30, 'kb-vec': 27}
- **2026-09-01 08:45:28** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 09:00:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 09:15:10** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 09:30:20** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 09:45:27** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 10:00:15** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 10:03:17** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'infra-ops': 31, 'kb-vec': 29}
- **2026-09-01 10:15:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 10:30:05** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'infra-ops': 31, 'kb-vec': 29}
- **2026-09-01 10:30:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 10:33:13** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'infra-ops': 31, 'kb-vec': 29}
- **2026-09-01 10:45:33** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 11:00:32** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 11:15:12** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 11:18:18** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'infra-ops': 31, 'kb-vec': 29}
- **2026-09-01 11:21:07** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'infra-ops': 31, 'kb-vec': 29}
- **2026-09-01 11:30:17** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 11:45:34** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 12:00:19** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 12:06:16** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'infra-ops': 31, 'kb-vec': 29}
- **2026-09-01 12:15:33** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 12:27:46** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'infra-ops': 31, 'kb-vec': 29}
- **2026-09-01 12:30:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 12:45:17** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'vault-secrets': 40, 'infra-ops': 31, 'kb-vec': 29}
- **2026-09-01 12:45:30** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 13:00:30** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 13:06:16** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 34, 'vault-secrets': 39, 'kb-vec': 27}
- **2026-09-01 13:09:08** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 34, 'vault-secrets': 39, 'kb-vec': 27}
- **2026-09-01 13:15:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 13:30:12** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 13:42:06** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 34, 'vault-secrets': 39, 'kb-vec': 27}
- **2026-09-01 13:45:20** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 13:57:05** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 34, 'vault-secrets': 39, 'kb-vec': 27}
- **2026-09-01 14:00:22** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 14:15:45** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 14:30:33** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 14:39:25** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 34, 'vault-secrets': 39, 'kb-vec': 27}
- **2026-09-01 14:45:31** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 15:00:34** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 15:15:30** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 15:30:21** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 15:33:34** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 34, 'vault-secrets': 39, 'kb-vec': 27}
- **2026-09-01 15:42:16** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 34, 'vault-secrets': 39, 'kb-vec': 27}
- **2026-09-01 15:45:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 16:00:32** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 16:03:12** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 32, 'vault-secrets': 38, 'kb-vec': 30}
- **2026-09-01 16:15:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 16:30:16** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 16:45:14** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 17:00:35** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 17:12:26** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 32, 'vault-secrets': 38, 'kb-vec': 30}
- **2026-09-01 17:15:07** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 32, 'vault-secrets': 38, 'kb-vec': 30}
- **2026-09-01 17:15:12** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 17:30:19** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 17:45:07** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 32, 'vault-secrets': 38, 'kb-vec': 30}
- **2026-09-01 17:45:31** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 18:00:07** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 18:09:12** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 32, 'vault-secrets': 38, 'kb-vec': 30}
- **2026-09-01 18:15:47** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 18:30:24** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 18:45:21** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 18:54:06** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 32, 'vault-secrets': 38, 'kb-vec': 30}
- **2026-09-01 19:00:35** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 19:06:16** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 31, 'vault-secrets': 40, 'kb-vec': 29}
- **2026-09-01 19:09:07** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 31, 'vault-secrets': 40, 'kb-vec': 29}
- **2026-09-01 19:15:38** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 19:30:39** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 19:33:18** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 31, 'vault-secrets': 40, 'kb-vec': 29}
- **2026-09-01 19:45:12** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 20:00:17** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 31, 'vault-secrets': 40, 'kb-vec': 29}
- **2026-09-01 20:00:32** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 20:15:35** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 20:30:41** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 20:45:37** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 20:57:07** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 31, 'vault-secrets': 40, 'kb-vec': 29}
- **2026-09-01 21:00:31** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 21:12:06** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'infra-ops': 31, 'vault-secrets': 40, 'kb-vec': 29}
- **2026-09-01 21:15:35** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 21:30:38** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 21:45:23** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 22:00:38** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 22:09:13** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'kb-vec': 31, 'infra-ops': 29, 'vault-secrets': 40}
- **2026-09-01 22:12:10** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'kb-vec': 31, 'infra-ops': 29, 'vault-secrets': 40}
- **2026-09-01 22:15:19** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 22:30:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 22:45:06** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 23:00:45** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 23:15:26** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 23:30:29** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 97, 'vault-secrets': 3}
- **2026-09-01 23:45:18** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 94, 'vault-secrets': 6}
- **2026-09-02 00:00:44** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 94, 'vault-secrets': 6}
- **2026-09-02 00:15:18** — Pattern recheck (repeat signal)  
  finding **suspicious** (confidence ?)  
  100 AppArmor denials across {'kb-vec': 31, 'infra-ops': 29, 'vault-secrets': 40}
- **2026-09-02 00:15:23** — Hunt recheck (repeat signal)  
  finding **suspicious** (confidence medium)  
  100 AppArmor denials across {'infra-ops': 94, 'vault-secrets': 6}

## 5. Decision

**DENY** — 2026-08-31 06:16:45

Nth recurrence of the chronic apparmor-denials hunt FP (rule 52002, volume-only threshold, query size-capped at 100 - '100' is the cap, not reality). Fresh indexer pull (rule.id=52002, 7d): TOTAL 2949 vs hunt's capped 100. BY PROFILE all known-benign stock-Ubuntu families - fusermount3 200 / snap-update-ns.firmware-updater 97 / snap-confine rev27710 95 / unprivileged_userns 85 / firmware-notifier 17 / cupsd 6; zero unknown profiles. BY COMM all known-benign (fusermount3, snap-confine, snap-update-ns, (ubuntu-insigh), systemd-detect-, firmware-notifi, cupsd) - (ubuntu-insigh)/systemd-detect- is the documented unprivileged_userns family. Discriminators all zero: class=exec 0, load_profile 0, unload 0, change_profile 0 - nothing blocked from executing, no evasion signal. Ticket split 38/38/24 is the capped sample vs real population: infra-ops 318 / vault-secrets 98 / kb-vec 84. Host spot-check: kernel.apparmor_restrict_unprivileged_userns=1 and fusermount3 dac_override/setuid caps commented out - stock enforcement by design. Newest tail 06:15:51Z infra-ops fusermount3/unprivileged_userns = session-start FUSE burst. Enforcement noise, not evasion. Tuning signal: whitelist stock profiles (fusermount3 / unprivileged_userns / snap-* / cupsd) + per-agent threshold.

## 6. Disposition

Adjudicated as: **false_positive**

---
*Generated by the SSOP investigation framework · case `case-2d9c6106e3`*