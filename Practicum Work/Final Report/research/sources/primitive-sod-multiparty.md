---
bucket: P2
title: Multi-party authorization as an established primitive (and the scope boundary)
report_home:
  - "§2 — Intro thesis anchor (m-of-n human authorization is a recognized, NIST-codified primitive)"
  - "§4 — Positioning: the primitive is recognized, not novel; the gap is deployment in registries"
  - "§4 — Scope-boundary paragraph (attacks the proxy deliberately does NOT address)"
proxy_grounding:
  - docs/adr/0001-credential-backed-approval.md
  - docs/evaluation-plan.md
related_notes:
  - primitive-multiparty-approval.md
bib_keys:
  - nist-sp-800-53r5
  - clark-wilson-integrity
  - birsan-dependency-confusion
  - ladisa-sok-supply-chain
  - cisa-esf-developers
status: vetted
---

<!-- LTeX: enabled=false -->

## Why the report needs this

The Intro thesis is *m-of-n human authorization is an under-used general primitive.* The headline
finding here is sharper than "under-deployed": the standards that do recognize multi-person approval
recognize it only in its **narrowest possible form — exactly two people.** NIST SP 800-53 Rev. 5
codifies the mechanism as **AC-3(2) Dual Authorization**, whose control text requires "the approval
of *two* authorized individuals" — not "two or more," not a quorum, not m-of-n. The broader principle
it rests on, **AC-5 Separation of Duties**, is about *dividing* duties across roles, not about a
configurable approval threshold; and the formal lineage (**Clark–Wilson**, 1987) is likewise
dual-control. So the richest form of multi-party approval anyone standardized is the **degenerate
m = 2 case** of the actual idea. The general primitive — a configurable m-of-n quorum over the whole
set of owners, where the required number of approvers scales to the consequence of the action — is
neither standardized nor deployed.

That absence *is* the argument. This proxy implements the general case (configurable m-of-n; ADR
0001); "two-person control" is the special case the field mistook for the whole idea. The critique
the report makes — an author's analytical claim, marked as synthesis, anchored to what the control
literally says — is that had the standard written two more words ("or more"), it would have prompted
organizations toward general m-of-n security controls; it didn't, and that failure of imagination is
why the primitive isn't recognized as a first-class solution. The platform-siloed adoption note
([[primitive-multiparty-approval]]) corroborates from the other direction: even the hyperscalers'
*general* privileged-access product (Azure Entra PIM) resolves on the **first** approver — no quorum
at all — so in practice the ceiling is often below even two.

This note also anchors the §4 **scope boundary**: dependency confusion is the named attack class the
proxy deliberately does not address, and the CISA/NSA developer guidance is the adjacent,
non-authorization control set the proxy sits alongside.

## Sources (vetted this session)

- NIST SP 800-53 Rev. 5, *Security and Privacy Controls for Information Systems and Organizations* —
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final (accessed 2026-07-18) → `nist-sp-800-53r5`
  · anchors AC-3(2) Dual Authorization + AC-5 Separation of Duties · [primary]
- Clark & Wilson, *A Comparison of Commercial and Military Computer Security Policies*, IEEE S&P 1987 —
  https://doi.org/10.1109/SP.1987.10001 (accessed 2026-07-18) → `clark-wilson-integrity`
  · formal lineage of SoD as an integrity-enforcement rule · [formal]
- Birsan, *Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies*
  (2021) — Medium (accessed 2026-07-18) → `birsan-dependency-confusion` · scope-boundary attack
  class, primary disclosure · [primary]
- Ladisa, Plate, Martinez & Barais, *SoK: Taxonomy of Attacks on Open-Source Software Supply Chains*,
  IEEE S&P 2023 — https://oaklandsok.github.io/papers/ladisa2023.pdf (accessed 2026-07-18) →
  `ladisa-sok-supply-chain` · peer-reviewed classification placing dependency confusion · [formal]
- Enduring Security Framework (NSA/CISA/ODNI), *Securing the Software Supply Chain: Recommended
  Practices for Developers* (2022) — CISA (accessed 2026-07-18) → `cisa-esf-developers` · adjacent,
  non-authorization control set · [primary]

## Key facts (anchored)

### The codified control stops at *two* — AC-3(2) (the headline finding)

> "Enforce dual authorization for [Assignment: organization-defined privileged commands and/or other
> actions]."

> "Dual authorization, also known as two-person control, reduces risk related to insider threats.
> Dual authorization mechanisms require the approval of **two authorized individuals** to execute. To
> reduce the risk of collusion, organizations consider rotating dual authorization duties…"
— NIST SP 800-53 Rev. 5, control AC-3(2) Dual Authorization (statement + discussion; emphasis added)

This is the load-bearing quote of the whole note. The flagship federal control catalog's only
codification of multi-person approval is **hard-wired to exactly two** — "two authorized
individuals," not "two or more," not an m-of-n quorum — and there is no AC control anywhere in
800-53 that generalizes it. *Author's critique (synthesis, not a sourced claim):* standards bodies
choose words deliberately, so "two" rather than "two or more" is a choice, and the omission is the
failure — two words would have opened the door to general m-of-n controls. The report poses the
question to the reader ("why only two?") rather than asserting NIST *forbids* more; the anchored fact
is only what AC-3(2) literally says. Scope note: AC-3(2) is also confined to "privileged commands /
actions" — the proxy's contribution is both *generalizing the count* (m-of-n, not two) and *placing
it* on the package-publish action.

### NIST also codifies the broader principle — AC-5 Separation of Duties
> "Separation of duties addresses the potential for abuse of authorized privileges and helps to
> reduce the risk of malevolent activity without collusion."
— NIST SP 800-53 Rev. 5, control AC-5 Separation of Duties (discussion)

Backs the thesis framing that SoD is an established, catalog-level principle. The "without collusion"
phrase is the honest limit that also grounds §7: the proxy raises the bar against a lone actor but,
like SoD generally, does not defeat a colluding quorum (the XZ / CORE-3 limitation).

### The formal lineage predates the catalog — Clark–Wilson (1987)
The separation-of-duty enforcement rule is not a modern compliance artifact: it is one of the
enforcement rules of the Clark–Wilson integrity model, published at the 1987 IEEE Symposium on
Security and Privacy as the commercial-integrity counterpart to the military/Bell–LaPadula lattice
model. *(Lineage pointer — cited for provenance of the principle, not for a verbatim quote; the
load-bearing anchors above are the NIST controls.)*

### Dependency confusion is the named scope-boundary attack — Birsan (2021)
The primary disclosure that coined "dependency confusion": packages published under unclaimed
*internal* names on public indexes (npm, PyPI, RubyGems) at high version numbers were pulled in
preference to the private originals, yielding remote code execution across 35+ organizations
including Apple, Microsoft, PayPal, and Netflix. Ladisa et al.'s peer-reviewed taxonomy (IEEE S&P
2023, built from 107 attack vectors) places it within the open-source supply-chain attack space.

Backs the §4 scope-boundary line: dependency confusion is a *name-resolution / registry-configuration*
attack, not an *authorized-but-malicious-publish* attack — so it sits outside what an approval gate
on the publish action addresses. The report names it as deliberately out of scope.

### The adjacent, non-authorization control set — CISA/NSA ESF (2022)
The NSA/CISA/ODNI *Securing the Software Supply Chain: Recommended Practices for Developers* (Part I
of three) is the developer-facing guidance whose recommendations — threat modeling, code signing,
provenance/attestation, hermetic reproducible builds, SBOM delivery — are the *other half* of the
scope-boundary line: the ecosystem-recognized controls the proxy complements rather than replaces.
None of them is a human m-of-n authorization gate, which is the specific gap the proxy fills.

## How the proxy relates

One honest point, two moves. The security field endorses multi-person approval only in its narrowest
codified form — NIST AC-3(2)'s *two* authorized individuals, lineage Clark–Wilson. The proxy (a)
**generalizes the count** from a fixed two to a configurable m-of-n quorum over the owner set, and (b)
**places it** on a control plane where it is missing entirely — the package-publish action. It does
**not** claim to invent multi-party approval (dual control is decades old), and it does **not** address
the attacks that guidance/provenance controls (CISA ESF) or registry configuration (dependency
confusion) already own. Its contribution is *generalization + placement*, not a new cryptographic
primitive.

## Source decisions

- **SSDF (SP 800-218) / EO 14028 are outside scope.** They govern *process compliance* (SBOMs,
  signing attestations), not the *multi-party-authorization primitive*, so they cannot reinforce the
  "under-deployed primitive" thesis and would invite scope questions (why the proxy does not map to
  SSDF tasks). The stronger §3 framing comes from the marquee incidents and the landscape note.
- **AC-3(2) is the headline, not AC-5.** AC-3(2) Dual Authorization is the exact two-person mechanism
  the proxy implements; AC-5 is the broader principle cited in support. The thesis leads with the
  specific codified mechanism because it is the harder claim to dismiss.
