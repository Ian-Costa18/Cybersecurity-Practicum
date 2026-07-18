<!-- LTeX: enabled=false -->
# Build provenance (Sigstore / SLSA / PEP 740) — row 3

**Axis:** Origin/integrity attestation (detective, not preventive)
**Verdicts:** Stolen credential `✗` · Trusted insider `✗` · Compromised CI `✗` · Direct publish `✗`

Scenario names and verdicts are fixed by [evaluation-plan.md §1, Move 1](../../../../docs/evaluation-plan.md).

## Primary sources
- PyPI Docs, "Attestations" — https://docs.pypi.org/attestations/ (accessed 2026-07-15) → `pypi-attestations` *(primary: what an attestation certifies)*
- SLSA v1.0, "What SLSA doesn't cover" — https://slsa.dev/spec/v1.0/about (accessed 2026-07-15) → `slsa`
- PEP 740, "Index support for digital attestations" — https://peps.python.org/pep-0740/ (accessed 2026-07-15) → `pep740` *(normative anchor for the non-mandate fact only)*
- npm Docs, "Generating provenance statements" — https://docs.npmjs.com/generating-provenance-statements/ (accessed 2026-07-15) → `npm-provenance`
- Sigstore Docs, "Overview" — https://docs.sigstore.dev/about/overview/ (accessed 2026-07-15) → `sigstore`
- PyPI blog, "Supply-chain attack analysis: Ultralytics" — https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/ (accessed 2026-07-15) → `pypi-ultralytics-analysis` *(already tracked, row 2)*
- Snyk, "TanStack npm Packages Hit by Mini Shai-Hulud" — https://snyk.io/blog/tanstack-npm-packages-compromised/ (accessed 2026-07-17) → `shai-hulud-tanstack-snyk` *(the first documented case of valid SLSA-L3 provenance minted for malware; see [incident-shai-hulud.md](../sources/incident-shai-hulud.md))*

## What it actually gates
Build provenance attaches a **signed statement about an artifact's origin**: SLSA provenance and PEP 740
attestations, signed through Sigstore, certify *from which source repository, at which commit, and via
which build workflow* a distribution was produced. This is the only row in the matrix that **gates no
decision at all**. Every other row at least gates *something* — 2FA gates *login*, Trusted Publishing
gates *which credential* the upload presents — whereas provenance gates nothing: it annotates the
artifact with verifiable evidence and leaves the ship/no-ship call to whoever consumes that evidence,
if anyone does. It certifies *where a build came from*, never *what its code does*, and it is not a
publish gate. Two facts fall straight out. SLSA states plainly that it "does not address organizations
that intentionally produce malicious software" and "does not tell you whether the developers writing the
source code followed secure coding practices" — so an authentically-built malicious artifact earns a
*genuine* attestation. And per PEP 740 the index makes "no policy recommendation around mandatory
digital attestations … or their subsequent verification," so registries **display and record**
provenance without requiring it, leaving it detective rather than preventive.

Provenance is not worthless here: it is the strongest available defense against **origin substitution**
— an artifact never built from the claimed source — and it makes the build→artifact link tamper-evident.
Its four `✗`'s are because that defense is *detective and unenforced* (PEP 740 declines to mandate
verification), and because none of these columns *is* an origin-substitution attack: those live on the
consumer-side axis this evaluation deliberately excludes (dependency confusion, [evaluation-plan.md §1,
Move 2](../../../../docs/evaluation-plan.md) scope boundary).

## Documented behavior (anchored)
> "**Code quality**: SLSA does not tell you whether the developers writing the source code followed
> secure coding practices." "SLSA does not address organizations that intentionally produce malicious
> software, but it can reduce insider risks within an organization you trust."
— *What SLSA doesn't cover* (slsa.dev, v1.0)

> An attestation gives "publicly verifiable proof that a package was published via a specific Trusted
> Publisher," or "more general SLSA Provenance attesting to a package's original source location,"
> "allowing both PyPI and downstream users to verify that a particular package was attested to by a
> particular identity."
— *Attestations* (docs.pypi.org, "Quick background")

> "This PEP does not make a policy recommendation around mandatory digital attestations on release
> uploads or their subsequent verification by installing clients."
— *PEP 740* (peps.python.org) — the normative statement that attestation and its verification are
**not required**, so provenance stays detective rather than a publish gate.

> "This allows developers to verify **where and how** your package was built before they download it."
> "npm provenance provides a verifiable link to the package's source code and build instructions, which
> developers can then audit and determine whether to trust it or not."
— *Generating provenance statements* (docs.npmjs.com)

> A Sigstore-signed artifact is "**Signed**" with Cosign, "**Associated** with an identity through our
> certificate authority (Fulcio)," and "**Witnessed** … in a permanent transparency log (Rekor)." It
> proves *who signed*, not that the contents are safe.
— *Overview* (docs.sigstore.dev)

> "The first set of injected packages were published through the existing GitHub Actions workflow."
— *Supply-chain attack analysis: Ultralytics* (blog.pypi.org, 2024-12-11): an authentically-built,
pipeline-published poisoned artifact — exactly the input provenance attests as genuine.

## Per-column analysis

| Scenario | Verdict | Catches / Misses | Source |
|---|:--:|---|---|
| Stolen credential | `✗` | Provenance is not a publish gate — registries display attestations but do not mandate them (PEP 740 declines to). A stolen-token republish through the legitimate workflow even *earns* valid provenance; a hand-built upload simply lacks it and is still accepted. Detective at best, never preventive. | `pypi-attestations`, `pep740`, `npm-provenance` |
| Trusted insider | `✗` | SLSA "does not address organizations that intentionally produce malicious software." The insider builds through the real pipeline; provenance attests the malicious build as authentic (the XZ shape). | `slsa` |
| Compromised CI | `✗` | The sharpest failure: a subverted build produces a *genuine* attestation. Provenance certifies *from which source / how* a build ran, not *what the code does*. Realized in Ultralytics — the poisoned versions shipped "through the existing GitHub Actions workflow," so provenance marks them authentic. Confirmed at the limit by the May 2026 Shai-Hulud/TanStack wave, which "produced validly-attested SLSA Build Level 3 provenance for malicious packages — the first documented case of this kind": the highest common provenance tier certified malware as authentically built. | `slsa`, `pypi-ultralytics-analysis`, `shai-hulud-tanstack-snyk` |
| Direct publish | `✗` | Provenance never gates the publish decision; PyPI/npm accept unprovenanced uploads (PEP 740 does not mandate verification). A maintainer publishing straight to the registry is unaffected. | `pep740` |

*(No `~` cell in this row — no caveat box. Every verdict follows directly from the axis: an
attestation that gates no decision cannot stop any of the four publish-authorization attacks.)*

## How the proxy beats this row
Provenance answers *"where did this come from?"*; the proxy answers *"should this ship?"* The proxy
operates at **authorization time**, requiring **m-of-n independent, re-authenticated approvals bound to
the exact artifact by hash** before the publish credential is ever used. A poisoned-but-authentically-
attested build (Ultralytics, XZ) carries a *genuine* provenance statement and would be waved through by
any origin check; under the proxy it reaches approvers who deny an artifact-bound request for a version
they never sanctioned.

**Complementary, not competing (future work).** Provenance is "detective, not preventive" only because
nothing forces verification; the proxy is a mandatory chokepoint holding the sole publish credential.
Make provenance verification a **precondition of authorization** — the proxy checks that a *signed*
attestation binds the request's exact digest to the authorized CI build identity (right repository,
right workflow) before the artifact reaches the quorum — and provenance becomes preventive, with the
proxy supplying the enforcement point it always lacked (the sibling of feeding scan verdicts to
approvers, [#108](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/108)). This closes
origin substitution automatically, so humans need not audit build provenance by hand. It does **not**
extend to the insider or compromised-CI columns: a poisoned-but-authentically-built artifact carries
valid provenance and a matching digest, so the automated check passes and the human quorum remains the
only barrier — which is exactly why the two layers compose instead of duplicating.
