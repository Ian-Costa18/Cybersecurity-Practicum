---
id: PUB-2
title: "Proxy Bypass"
stride: ["Elevation of Privilege"]
attack: [T1078]
capability: [L2]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: critical
bucket: 1
related: [CORE-1, CORE-2, IDENT-5, PUB-3, HOST-5]
tests:
  - tests/service_types/one_time/test_reconcile.py::test_out_of_band_publish_raises_an_alert
  - tests/service_types/one_time/test_reconcile.py::test_the_alert_notifies_approvers_and_admin
  - tests/service_types/one_time/test_reconcile.py::test_the_alert_is_recorded_in_the_audit_trail
  - tests/service_types/one_time/test_reconcile.py::test_a_release_the_proxy_published_raises_no_alert
---

# PUB-2 — Proxy Bypass

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L2 — possession of one out-of-band publish credential: a retained PyPI maintainer/Owner credential, a stale pre-adoption API token still in CI, or control of the organization account's recovery path (the recovery flow itself is [PUB-3](PUB-3-external-account-recovery-bypass.md)'s surface — inherited there, because the baseline has it too; what PUB-2 owns is the credential the recovery yields being *unmediated*). |
| **What the attacker gains** | A publish to PyPI that never touches the proxy: no request, no votes, no audit trail. The proxy cannot observe it, let alone mediate it. An unauthorized artifact reaches PyPI unobserved — complete mission failure, and the strongest bypass in the catalog. |
| **What they cannot do** | Touch the proxy's own state — but they do not need to. The honest content of this row is the conditionality statement: **the proxy's guarantee is conditional on credential exclusivity** — m-of-n approval governs a publish only if no credential outside the proxy can perform one (complete mediation, Saltzer & Schroeder). |
| **Current defenses** | **Out-of-band publish reconciliation (detect + alert)** — [#124](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/124). A scheduled reconciler (`service_types/one_time/reconcile.py`) fetches the project's public release list from PyPI's JSON API and subtracts the proxy's publish log (the versions of its `approved` one-time requests); any release the proxy never performed raises a `publish.out_of_band_detected` alert — recorded in the audit trail (durable evidence) and emailed to approvers + admin (`test_out_of_band_publish_raises_an_alert`, `test_the_alert_notifies_approvers_and_admin`, `test_the_alert_is_recorded_in_the_audit_trail`; a release the proxy *did* publish raises nothing — `test_a_release_the_proxy_published_raises_no_alert`). This is **detection, not prevention** (bucket ① detection tier): it bounds the exposure window and makes an exclusivity violation observable, but cannot un-ship an artifact that already reached the index. The preventive control remains operator credential-topology hygiene (below). |
| **Operator configuration** | At onboarding: revoke **all** pre-existing project API tokens; demote maintainer accounts to non-upload roles; put the sole upload credential in the proxy. Protect the organization account's recovery path and enforce 2FA on it. Periodically audit project collaborators and tokens; treat any credential able to publish without the proxy as a policy violation. |

**The abstract threat is incomplete mediation** — an unmediated path to the protected
action exists. For the package-publishing use case (the practicum's scope), the primary
instance is the out-of-band publish credential described above. In a general-purpose
forward-auth deployment (future vision,
[#109](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/109)) the same threat
generalizes to a backend reachable around the proxy — ATT&CK's T1599, *Network Boundary
Bridging*: the attacker circumvents a network segmentation control to reach what it
protects — with reverse-proxy middleware integration
([#24](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/24)) as the tracked
mechanism idea there.

**Delta.** Introduced — with a subtlety worth stating. In the baseline world *every*
publish path is unmediated; that is precisely the baseline that
[CORE-1](CORE-1-single-approver-account-compromise.md) and [CORE-2](CORE-2-api-token-theft.md) measure
their improvements against (one stolen credential = unilateral publish). Adopting the proxy
shrinks the unmediated set from "every credential" to "whatever onboarding misses" — and
that reduction is the credential-consolidation improvement, **counted once, under CORE-1 and
CORE-2**. What this threat uniquely names is the *completeness condition* those improvements
rest on: a missed credential is a credential the consolidation never reached, and for it
the improvement simply did not happen. A mediation-completeness gap can only exist where
mediation is claimed — the baseline claims none — so the threat is introduced, not
improved. Delta classifies mechanism ownership, not outcome size.

**Ratings.** Likelihood residual `medium` is a justified deviation from the L2 default
(`high`): the documented onboarding hygiene is supposed to *empty* the out-of-band
credential population, so the precondition is "find a credential that was missed," not
commodity theft of a credential known to exist. It is not `low`, because nothing *prevents*
a violation — reconciliation ([#124](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/124))
detects one after the fact but does not stop the credential from publishing, and a missed
credential stays live until an operator revokes it. Severity residual `critical`: an
unauthorized artifact reaches PyPI directly — detection is **post-hoc**, so the artifact is
still shipped; the reconciler bounds how long it goes unobserved, not whether it ships. Both
ratings are therefore unchanged by the promotion: detection raises the **bucket** (what is
demonstrable today), not the residual risk (what the attacker still achieves).

**ATT&CK mapping.** T1078 — *Valid Accounts*: the attacker uses legitimate, valid
credentials instead of exploiting a vulnerability — here, a genuine PyPI credential the
proxy never mediated.

## Detection and its boundary

Reconciliation ([#124](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/124))
is the proxy watching its own complete-mediation assumption: on a schedule it fetches the
project's release list from PyPI's public JSON API and compares it against its publish log
(the versions of `approved` one-time requests). A release present on the index but absent
from the log never routed through the proxy — an exclusivity violation — and raises the
alert. The alert is emitted **blind** (ADR 0005) as a `publish.out_of_band_detected` event,
so the audit subscriber records it (the durable oracle) and the notification subscriber
emails the alert audience (all admins + the service's approvers).

The honesty boundary is explicit, and the ratings above hold to it: this is
**detection, not prevention**. It cannot un-ship an artifact that reached the index, and
**automated remediation is blocked upstream** — PyPI exposes no delete/yank API (web-UI
only), and yank ([PEP 592](https://peps.python.org/pep-0592/)) does not remove
already-pinned installs anyway. The response is therefore an **operator runbook**: manually
yank/delete the release via the PyPI web UI, rotate the project's credentials, and audit the
collaborator/token list for whatever credential published without the proxy. Detection
**bounds the exposure window**; the preventive control stays the onboarding hygiene above
(the same detect-not-prevent tier as [HOST-2](HOST-2-database-write-compromise.md)'s
tamper-evidence).
