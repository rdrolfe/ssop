# Use case 3 — Security Onion single-node without leaking egress

**Status:** Live and proven. This is the case where the deployment being small
and rebuildable is the feature rather than a limitation.

---

## The situation

You want Security Onion — it's the best free answer to "full SOC stack I don't
have to assemble myself." Then you install it and find the thing nobody warns
you about: **Security Onion is built to phone home.**

Not maliciously. Legitimately. It syncs Suricata rules, Elasticsearch mappings,
Zeek intel feeds, and vendor configuration. That's what makes it good, and it's
also a fleet of outbound connections from a host that holds your raw packet
capture.

So you land in a bad spot, and both horns are bad:

- **Block the egress** and the stack quietly stops getting updated. You find out
  months later when detection coverage has rotted and you have no idea why.
- **Allow it** and you have a box that talks to a dozen vendors, on a network
  you've told yourself is sovereign, and no inventory of what it's said.

The lazy resolution — "it's just update traffic" — is the one that will hurt
you. Because the moment you add a feed *you* chose, that host has an outbound
path that runs on its own schedule, and now the allow-list has an entry whose
purpose nobody recorded.

## The specific trap: the boundary that isn't there

The instance from this project's own deployment, and it's worth stating plainly
because it's the kind of gap that looks closed.

MISP was deployed as a dedicated VM specifically so its feed-sync workers would
run somewhere isolated. The reasoning was good: a dedicated VM doesn't share a
trust or failure domain with the SIEM or the case record.

Then the boundary question arrived, and the answer was uncomfortable: **MISP's
own feed-sync workers run on the MISP host, outside the runtime egress gate's
reach.** The gate inspects the SSOP runtime's code. MISP is another machine
running another product's cron jobs. Declaring it in the project's own registry
would have been *documentation*, not control — the file would have said "MISP's
egress is scoped" while MISP's config remained the only thing scoping MISP.

That's the general lesson and it's the reason this use case exists:

> **A service's own configuration is not a boundary. If the only thing scoping
> egress is a file on the box that wants the egress, you have documented a
> decision rather than enforced one.**

## What SSOP does about it

Two layers, because one of them is structurally incapable of being the control.

### Layer 1 — Declaration (in the runtime, enforced at build time)

Every external destination the runtime may contact must be declared in
`agents/transport.yaml` under `external_calls`, with a class and a description
of what data goes out. The gate (`agents/verify/check_egress.py`) scans the
agent code for URL literals and **fails the build** on anything external that
isn't declared.

The classes are the interesting part:

| Class | Meaning | Default |
|---|---|---|
| `lookup` | Sends indicator values (hash/domain/url/ip), receives reputation. Value-only. | allowed when declared |
| `submit` | Uploads artifacts. **A disclosure event.** | requires explicit operator approval, per entry |

The current registry is three `lookup` entries — GreyNoise, VirusTotal, OTX —
all pointing at one enrichment module. **There is deliberately no `submit` entry.**

And the doctrine is stated in the file itself, in a line worth quoting because it
prevents a common misreading:

> *"the sovereignty claim covers AI INFERENCE (no cloud provider owns our
> decisions) — it does NOT forbid external data-plane calls; it requires them
> DECLARED."*

That's the distinction most "sovereign" setups get wrong in the direction of
paralysis. The requirement isn't zero egress. It's that every egress has someone
who decided it.

**The absence of a `submit` entry is a control, not a gap.** The MISP client is
read-only, and the test suite fails the build if a write endpoint ever appears in
it. Contributing your own observables back to a shared feed is publishing your
detections to everyone who reads that feed.

### Layer 2 — Enforcement at the boundary (where the traffic actually leaves)

For infrastructure egress the gate can't see, enforcement lives on the host
itself. The MISP host runs a **default-deny allow-list** in `nft`, with hooks on
both output and forward, listing only the hosts it's permitted to sync from.

The procedure is deliberately tedious: add the feed host to the list, re-apply,
verify, then persist the *verified live table*. Verifying before persisting is the
step that matters — persisting the intended table would mean writing down a
policy you haven't confirmed is the policy in force.

Note the classification here is different from layer 1, and the difference is
load-bearing: this is declared as `direction: inbound-sync`, `data_sent: none`.
The platform **pulls** feeds; it's a data sink. That framing is what lets the
entry be honestly `lookup` while a dozen vendors are involved.

## How you'd know it worked

- **The build fails when you add an undeclared endpoint.** That's the whole test,
  and it's worth confirming deliberately: add a URL to an agent module and confirm
  red. A boundary nobody has ever seen reject anything is an assumption.
- **The allow-list is default-deny, and you can show the denied traffic.** Add
  a host that isn't permitted and confirm it's dropped. Same principle: prove the
  control works by using it.
- **Every entry has a named `used_by`.** Three `lookup` entries all point at one
  module. If an entry can't name its caller, the declaration is decorative.
- **The `submit` class stays empty unless you approved it individually.** If you
  find a `submit` entry you don't remember approving, stop and read it.

## How you'd know it failed

- **An update silently stopped and nobody noticed for months.** The characteristic
  failure of over-tight egress. The mitigation is boring: treat "no feed updates
  in N days" as an alertable condition, because otherwise the block reads as
  working.
- **A declared entry becomes load-bearing for something undeclared.** The classic
  shape: you allow a host for feed sync, then someone points an enrichment call
  at the same host because it happens to be reachable. Same path, new purpose, no
  new decision.
- **The registry and the live table diverge.** A YAML file describing a policy
  that isn't the policy in force is worse than no file, because it's trusted. This
  is why the live table is verified before it's persisted.
- **A service's own config is treated as the boundary.** The original trap. If the
  only enforcement is inside the thing that wants the traffic, there is no
  boundary.

## Extending it

Adding a lookup is a YAML edit plus a module reference — and the build will
remind you if you forget the declaration. Adding anything in the `submit` class
is a decision, not a task: it should be an explicit record of what you're
publishing, to whom, and why that's acceptable. The absence of those entries is
the most valuable thing in the file.

**On running single-node:** this project runs Security Onion with
`number_of_replicas: 0` on purpose. Single-node is the right shape for a lab you
rebuild from script. It also means the cluster is not a distributed-systems
problem you've solved, and shouldn't be presented as one.

---

**Related:** [`ADR-007 — MISP Feed Platform`](../decisions/ADR-007 - MISP Feed Platform.md) ·
[`agents/transport.yaml`](../../agents/transport.yaml) ·
[`agents/verify/check_egress.py`](../../agents/verify/check_egress.py) ·
[`docs/feeds-and-licensing.md`](../feeds-and-licensing.md)