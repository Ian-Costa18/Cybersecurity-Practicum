<!-- LTeX: enabled=false -->
# Trusted Publishing (OIDC) — row 2

**Axis:** Authentication (scoped, short-lived credential)
**Verdicts:** Stolen credential `✓` · Trusted insider `✗` · Compromised CI `✗` · Direct publish `~`

Scenario names and verdicts are fixed by [evaluation-plan.md §1, Move 1](../../../../docs/evaluation-plan.md).

## Primary sources
- PyPI Docs, "Trusted Publishers" — https://docs.pypi.org/trusted-publishers/ (accessed 2026-07-15) → `pypi-trusted-publishing`
- PyPI blog, "Introducing Trusted Publishers" — https://blog.pypi.org/posts/2023-04-20-introducing-trusted-publishers/ (accessed 2026-07-15) → `pypi-trusted-publishers-intro`
- npm Docs, "Trusted publishing for npm packages" — https://docs.npmjs.com/trusted-publishers/ (accessed 2026-07-15) → `npm-trusted-publishing`
- PyPI blog, "Supply-chain attack analysis: Ultralytics" — https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/ (accessed 2026-07-15) → `pypi-ultralytics-analysis`
- Snyk, "TanStack npm Packages Hit by Mini Shai-Hulud" — https://snyk.io/blog/tanstack-npm-packages-compromised/ (accessed 2026-07-17) → `shai-hulud-tanstack-snyk` *(the May 2026 Shai-Hulud wave that abused OIDC/Trusted Publishing directly; see [incident-shai-hulud.md](../sources/incident-shai-hulud.md))*

## What it actually gates
Trusted Publishing changes **how a publish authenticates**. Instead of a long-lived stored token,
a pre-registered CI workflow presents an OpenID Connect identity that PyPI/npm exchange for a
**short-lived, project-scoped credential**, mintable only from inside that workflow. So it gates
*which credential the upload presents* — not *who the human is* and not *whether this artifact
should ship*. Two consequences fall straight out of the axis. Because trust is delegated to the CI
workflow's identity, **whatever that workflow builds publishes authentically** — a subverted build
is a validly-signed publish. And because both registries offer Trusted Publishing as *complementary
to*, not a *replacement for*, API tokens, it removes the *stored* credential but not the registry's
*acceptance of token uploads* — so a maintainer who still holds a token can publish straight to the
registry, off the CI path entirely.

## Documented behavior (anchored)
> "'Trusted publishing' is our term for using the OpenID Connect (OIDC) standard to exchange
> short-lived identity tokens between a trusted third-party service and PyPI." The minted token is
> "only valid for 15 minutes from time of creation" and "behaves exactly like a normal
> project-scoped API token." OIDC publishing is introduced as **"complementing API tokens."**
— *Trusted Publishers* (docs.pypi.org) and *Introducing Trusted Publishers* (blog.pypi.org). The
2023 post adds that these tokens "never need to be stored or shared, rotate automatically by
expiring quickly, and provide a verifiable link between a published package and its source."

> "Each publish uses short-lived, cryptographically-signed tokens that are specific to your workflow
> and cannot be extracted or reused." "When you configure a trusted publisher for your package, npm
> will accept publishes from the specific workflow you've authorized." "The npm CLI automatically
> detects OIDC environments and uses them for authentication **before falling back to traditional
> tokens**."
— *Trusted publishing for npm packages* (docs.npmjs.com)

> "The first set of injected packages were published through the existing GitHub Actions workflow."
> "The second round of malicious releases came from the attacker using an unrevoked PyPI API token
> that was still available to the GitHub Actions workflow."
— *Supply-chain attack analysis: Ultralytics* (blog.pypi.org, 2024-12-11). The Ultralytics project
was using Trusted Publishing at the time.

## Per-column analysis

| Scenario | Verdict | Catches / Misses | Source |
|---|:--:|---|---|
| Stolen credential | `✓` | No standing long-lived token exists to harvest — the credential is short-lived and mintable only inside the CI workflow, so the Shai-Hulud token-harvest finds nothing to grab. | `pypi-trusted-publishers-intro`, `npm-trusted-publishing` |
| Trusted insider | `✗` | OIDC proves the *workflow's* identity, not the human's *intent*; the insider triggers the legitimate workflow and publishes. | axis argument |
| Compromised CI | `✗` | Trusted Publishing trusts the CI workflow by design, so a subverted build gets an authentic OIDC-minted publish. Realized in Ultralytics: versions 8.3.41/8.3.42 "were published through the existing GitHub Actions workflow." Realized again, against Trusted Publishing *directly*, in the May 2026 Shai-Hulud/TanStack wave: after CI cache-poisoning, "attacker-controlled binaries … extracted the OIDC token from runner memory … then POST directly to `registry.npmjs.org` authenticated as the legitimate TanStack release workflow" — 42 `@tanstack/*` packages published through OIDC before the real publish step ran. | `pypi-ultralytics-analysis`, `shai-hulud-tanstack-snyk` |
| Direct publish | `~` | **Catches** under a TP-*exclusive* setup (every API token removed): no credential to carry to a laptop, every publish must originate from the registered CI workflow. **Misses** by default: TP *complements* tokens rather than disabling them, so a token-holding maintainer publishes straight to the registry — exactly the Ultralytics second round, an "unrevoked PyPI API token." ⚠ | `pypi-trusted-publishing`, `npm-trusted-publishing`, `pypi-ultralytics-analysis` |

> ⚠ **Caveat (Direct publish).** The `~` is contingent on **operator configuration, not on the
> control**: coverage exists only if every API token has been removed so Trusted Publishing is the
> exclusive publisher. This is the same kind of operator-enforced precondition the proxy carries in
> its own Direct-publish column — the difference is the proxy *detects* a bypass (out-of-band
> publish reconciliation), whereas an orphaned publish token here is silent until it is used.

## How the proxy beats this row
Trusted Publishing hardens **authentication** — a short-lived, scoped, CI-bound credential — but
never authorizes *which artifact ships*. Ultralytics is the clean demonstration: Trusted Publishing
was active, and the poisoned build still published authentically because the subversion happened
*upstream of* the credential exchange. The proxy operates one layer up, at **authorization time**:
it requires **m-of-n independent, re-authenticated approvals bound to the exact artifact by hash**
before the publish credential is ever used. An OIDC token minted for a compromised build, or a
maintainer's own token publishing off-path, both reach the registry unchallenged under this row;
under the proxy, approvers see an artifact-bound request for a version they never sanctioned — and
deny it.
