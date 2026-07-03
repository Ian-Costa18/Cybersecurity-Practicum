---
id: CODE-2
title: "Supply Chain Attack on the Proxy Itself"
stride: ["Tampering", "Elevation of Privilege"]
attack: [T1195.001]
capability: [external]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: low
severity_baseline: N/A
severity_residual: critical
bucket: 4
related: [HOST-1, CODE-1]
---

# CODE-2 — Supply Chain Attack on the Proxy Itself

| | |
|---|---|
| **Category** | Tampering, Elevation of Privilege |
| **Capability** | `external` — the attacker operates entirely outside the deployment's trust boundary, compromising an upstream Python dependency of the proxy. No L-rung applies. |
| **What the attacker gains** | Malicious code running inside the proxy's own process: exfiltrate credentials, approval data, or key material; silently approve requests; backdoor the host. Everything [HOST-1](HOST-1-proxy-host-compromise.md) concedes, reached from outside. This is the same attack class the proxy exists to stop in downstream packages, pointed back at us. |
| **What they cannot do** | Forge historical Ed25519 approval signatures already stored in the database — prior records remain independently verifiable (tamper-evidence of the past survives, same as HOST-1). |
| **Current defenses** | `uv.lock` pins the full transitive dependency tree with **549 `sha256` hashes** — nothing installs that does not match a recorded hash, so a poisoned release cannot enter the tree until a human updates the lockfile. CI audits the locked tree on every run (`uv audit`, [.github/workflows/ci.yml](../../.github/workflows/ci.yml)), failing the build on known-vulnerable pinned dependencies. Dependabot vulnerability alerts are enabled on the repository (verified 2026-07-02). |
| **Operator configuration** | Only install the proxy from a trusted source. Use a private package-index mirror where possible rather than pulling from PyPI at deploy time. Audit third-party dependencies in the lock file. Run the proxy in a container with a minimal base image to limit the blast radius. These are likelihood reducers around an accepted core — none survives a successful poisoning. |

**Delta.** Introduced: the baseline maintainer publishes directly to PyPI — there is no
self-hosted dependency tree sitting between them and PyPI to poison. The proxy's own
software stack is surface that exists only because the proxy exists.

**Scope.** Python-dependency poisoning is the primary instance, not the extent: the same
acceptance covers any upstream code entering the proxy's trusted computing base — the
container base image, the build/CI toolchain, the install source. The operator row's items
are the per-channel likelihood reducers for exactly those instances.

**Why bucket ④.** The shared discriminator with HOST-1: *if the operator cannot completely
defend or prevent it, we own it — accepted limitation.* A compromised dependency executes
in-process — in-process code **is** the proxy; no configuration survives it. Pinning,
auditing, and alerting reduce the likelihood of a poisoned version being adopted; they do
not retract the acceptance. Release signing and reproducible builds have been considered
and are deliberately **not tracked** — named here as explicit non-commitments, not planned
work.

**Ratings.** `capability: external` carries no default likelihood, so the body must
justify its own: residual `low`, because the precondition is a *chain* — compromise an
upstream package **and** get the poisoned version adopted. Hash-pinning means nothing new
enters the tree until the lockfile is deliberately updated, so the attacker needs either a
compromise already inside the pinned set or a compromise timed to a lockfile-update window.
That is a demanding precondition, not a commodity attack. Severity residual `critical`:
in-process malicious code reaches the live publishing token — publish-at-will, the top
rung of the mission ladder.

**ATT&CK mapping.** T1195.001 — *Supply Chain Compromise: Compromise Software Dependencies
and Development Tools*: the attacker poisons a library or tool the victim builds with, so
the victim installs malicious code through a trusted channel. Exactly this threat.
