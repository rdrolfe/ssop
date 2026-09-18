# Security policy

SSOP accepts coordinated vulnerability reports. This file also defines the security boundaries and invariants used when reviewing this repository.

## Supported versions

SSOP is currently a reference implementation without stable release branches.

| Version | Supported |
| --- | --- |
| Current `main` branch | Yes |
| Earlier commits, forks, and modified deployments | No |

Security fixes may be made only on the current `main` branch. Reporters should identify the commit they tested and any deployment changes that affect reachability or impact.

## Reporting a vulnerability

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/rdrolfe/ssop/security/advisories/new). Do not open a public issue, discussion, or pull request containing vulnerability details.

If private vulnerability reporting is unavailable, open a public issue that asks the maintainers to provide a private reporting channel. Include no technical details, affected endpoints, credentials, logs, screenshots, exploit code, or other sensitive information in that issue.

A useful private report includes:

- the affected commit and deployment configuration;
- a concise description of the broken security property and realistic impact;
- minimal reproduction steps that avoid destructive actions and access to other people's data;
- relevant logs or proof with credentials, tokens, personal data, and unrelated incident data removed;
- any proposed mitigation or fix, if known.

Allow the maintainers time to confirm the issue, prepare a fix, and coordinate disclosure. Do not access data beyond what is necessary to demonstrate the issue, disrupt a live service, retain sensitive data, or publish details before the maintainers release a fix or advisory.

## System and scope

SSOP is a self-hosted, single-tenant security operations platform. It ingests security telemetry, creates and adjudicates incident cases, recommends response playbooks, and can run commands that change services, files, firewalls, and monitored hosts.

This policy covers all maintained source, configuration, deployment files, scripts, user interfaces, templates, tests, and documentation in this repository. Lab and replay tooling remains in scope when it can reach real services, use real credentials, alter a host, or influence a supported deployment. Security claims in documentation are also in scope when they could cause an operator to deploy an unsafe configuration.

Important assets include:

- credentials, API keys, SSH keys, workload identities, and signing material;
- security telemetry, observables, case history, tuning decisions, and reports;
- approval state, playbook definitions, resolved action parameters, and action results;
- audit records and the identity attributed to each decision or action;
- SSOP control-plane services and the hosts and networks SSOP can administer.

Treat every listener as reachable by an untrusted party unless the checked-in deployment enforces a narrower boundary. A private network, VPN, reverse proxy, source IP, hostname, or claimed role is not authentication by itself.

## Threat model and trust boundaries

Potential attackers include unauthenticated network clients, compromised monitored hosts, malicious insiders without approval authority, compromised service accounts, and attackers who can influence telemetry or content rendered in an operator interface.

Treat these inputs as attacker-controlled until the receiving boundary validates them:

- SIEM events, alert fields, observables, case and ticket metadata, and indexed documents;
- HTTP requests, query parameters, headers, browser origins, and integration callbacks;
- data returned by Wazuh, Security Onion, IRIS, Qdrant, Proxmox, enrichment providers, and other remote services;
- strings used in HTML, Markdown, logs, queries, file paths, hostnames, IP addresses, service names, or command arguments;
- CLI arguments and runtime files writable by a less-trusted principal.

Repository configuration, environment variables, hunt definitions, and playbook YAML are privileged administrative inputs. Validate their schema and values before use. If a less-trusted principal can change them, treat them as attacker-controlled and report the missing integrity boundary.

Only an authenticated principal with explicit authorization for the exact operation is trusted to read sensitive case data, change tuning, approve an action, or administer a target. Source control maintainers, deployment secret administrators, and host root are administrative trust anchors, but their authority does not extend to unrelated systems or silently replace required separation of duties.

## Security invariants

### Authentication and authorization

- Authenticate every non-public API and user interface before returning operational data or accepting a mutation. Authorize each operation and case separately.
- Bind human and service decisions to a verified principal. Do not infer identity or authority from caller-supplied actor fields, role names, rationale text, network location, or possession of a case identifier.
- Deny access when identity, authorization policy, case state, or a required dependency is missing, malformed, unavailable, or ambiguous.
- Use least-privilege service identities and credentials. Do not share an administrative credential across roles merely to preserve attribution in application data.
- Prevent cross-origin and cross-site request abuse. Use an explicit origin allowlist and CSRF protection when browsers authenticate with ambient credentials.

### Approval and action execution

- A recommendation is never an approval. The recommending, approving, executing, and verifying roles must remain distinct where the configured tier requires separation of duties.
- Tier 0 automation is limited to explicitly allowlisted, narrow, reversible operations with validated targets and arguments. Read-only verification is preferred. A generic shell or arbitrary-command path is never Tier 0.
- Tier 1 mutations require one authenticated principal with explicit approval authority who is independent of the recommending or executing role.
- Tier 2 mutations require two independent authenticated approvals, including an authorized human approval. Both approvals must cover the same immutable action payload.
- Bind every approval to the case, playbook version, fully resolved parameters, target, run identifier, tier, and expiration. Approval is single-use. A denial, false-positive decision, missing or expired approval, mismatched run, modified payload, or lookup failure must execute zero action steps.
- Validate all playbook steps and resolve all templates before guard checks or approval. Reject unknown fields, unresolved templates, invalid types, unsafe paths, malformed addresses, unapproved services, and shell metacharacters.
- Do not construct shell commands from untrusted strings. Use fixed executables and structured argument lists. The remote account and operating-system policy must independently restrict the allowed command and arguments.
- Never target SSOP control-plane systems, identity services, audit stores, approval services, or protected management interfaces unless a distinct break-glass policy explicitly authorizes the exact action.
- Stop on the first failed step. Record partial completion, do not mark the run successful, and make retries idempotent so they cannot repeat a mutation.

### Case, audit, and state integrity

- Preserve complete, ordered case history under concurrent writers, retries, crashes, and store outages. Use stable event identifiers, revisions, and conflict detection. Never reconstruct authoritative state from an arbitrary first match or incomplete receipt.
- Do not checkpoint or discard an alert until every required downstream write or dispatch has succeeded. Retried intake must not create duplicate cases or actions.
- Treat approvals, tuning, case assignment, and action state as security-sensitive mutations. They require the same authentication, authorization, concurrency, and audit guarantees as command execution.
- A privileged mutation must produce a durable audit record with the verified actor, exact request, decision, target, result, event identifier, timestamp, and integrity metadata. If required audit persistence fails, block the privileged mutation.
- Audit verification must detect record modification, deletion, reordering, duplication, and forged attribution. The verifier must be independent of the role that writes or executes the action.
- A value labeled `unverified`, a caller-supplied SPIFFE ID, an append-only file handle, or matching identifiers in two mutable stores does not prove identity or record integrity.
- Reconciliation and repair must preserve the latest complete case state. Never overwrite richer state with an older or partial record, and never silently heal through an integrity conflict.

### Network, transport, and secrets

- Use authenticated encryption for every connection carrying credentials, case data, approvals, telemetry, or commands. Verify certificate names and chains and verify SSH host keys. Fail closed on verification errors.
- Bind administrative services to loopback or a dedicated management network by default, enforce host firewall policy, and require application-layer authentication even on private networks.
- Do not ship default or placeholder credentials in a runnable deployment. Reject empty secrets where authentication is required. Keep secrets out of source, logs, tickets, reports, URLs, and exception responses.
- Qdrant, SIEM, adjudication, dashboard, and integration endpoints must not be exposed without authentication and least-privilege authorization.
- Restrict outbound connections to an explicit allowlist. Make enrichment and model-provider egress opt-in, bounded by time and response size, and clear to the operator.
- Apply timeouts, pagination, rate limits, and input-size bounds so attacker-controlled work cannot block alert intake, approval handling, or response.

### Parsing and presentation

- Parse JSON, YAML, XML, templates, and remote responses with safe parsers and strict schemas. Bound nesting, collection sizes, and numeric ranges.
- Escape untrusted content for its destination. This includes HTML, JavaScript, Markdown, logs, search queries, and generated reports. Do not trust content because it came through a SIEM or case store.
- Restrict file access to configured roots. Resolve and validate paths before use, reject traversal and symlink escapes, and use safe temporary-file permissions.
- Do not evaluate repository data, telemetry, templates, or model output as code or policy instructions.

## Reportable findings and severity context

A finding is reportable when maintained code or a checked-in deployment path violates an invariant above and a realistic attacker, compromised monitored host, or unauthorized insider can reach it. A lab default does not make a reachable weakness non-reportable.

Treat these as Critical or High when realistically reachable:

- bypassing an approval or protected-target guard to cause a privileged action;
- unauthenticated or unauthorized adjudication, tuning, case mutation, or command execution;
- command, query, template, or path injection that crosses into a more privileged service or managed host;
- credential theft, sensitive incident-data disclosure, or impersonation of an approving actor;
- forged, deleted, reordered, or overwritten security records that can hide or authorize an action;
- loss or suppression of alerts, cases, or decisions that materially prevents detection or response;
- stored script execution in an operator or administrator interface.

Use Medium or Low only when the missing defense has limited reachability and cannot plausibly change a security decision, expose sensitive data, cross a privilege boundary, hide an action, or impair security processing. Security documentation, tests, comments, or intended architecture do not lower severity unless the deployed control is present and independently enforced.

## Out of scope, exclusions, and accepted risk

No security finding class is accepted or excluded for maintained SSOP code or checked-in deployment paths.

The following distinctions prevent noise without suppressing a real SSOP finding:

- The mere presence of malicious indicators, attack commands, or replay data in clearly marked fixtures is not a vulnerability. Escape from the fixture boundary, unsafe interpolation, unintended execution, or targeting a real system remains reportable.
- A defect solely inside an unmodified third-party dependency should be reported to that dependency. An exploitable dependency version, unsafe integration, insecure configuration, or failure to constrain the dependency in a supported SSOP deployment remains reportable here.
- Local virtual environments, caches, and generated artifacts are not maintained source. Findings caused by SSOP loading, publishing, trusting, or exposing those files remain reportable.
- Requiring existing administrative access does not automatically make a finding out of scope. Report it when SSOP expands that access, breaks separation of duties, crosses into another target, or defeats an audit or approval guarantee.

## Known limitations and compensating controls

The following are unresolved limitations, not accepted risks or reasons to suppress a finding:

- The checked-in adjudication service can bind to all interfaces, lacks request authentication and per-operation authorization, and permits wildcard browser origins. Keep it disabled or isolated behind an authenticated boundary until the application enforces identity and authorization.
- Current responder decision lookup and approval handling do not establish fail-closed execution for every unavailable, false-positive, expired, resumed, or mismatched state. Do not rely on the current responder for unattended privileged execution.
- JSONL receipts are unsigned, action records can carry an `unverified` identity, and reconciliation compares store membership rather than complete ordered content. Current audit data is useful operational evidence but is not cryptographic proof.
- Several lab defaults disable certificate or SSH host verification, use self-signed server TLS without client authentication, publish service ports broadly, or start data services without application authentication. These defaults are not suitable for an untrusted or production network.
- Case updates and recovery do not yet provide a demonstrated concurrency-safe, complete event history. Dual writes alone are not a compensating control for lost or overwritten state.
- External enrichment endpoints may receive observables unless operators disable or restrict egress. A sovereign or isolated deployment must use an explicit no-egress policy.

Until these limitations are fixed and verified in the deployed environment, network isolation, host firewalls, least-privilege service accounts, and disabled automatic actions reduce exposure. They do not make violations of this policy non-reportable.
