<!-- LTeX: enabled=false -->
---
bucket: I1
title: Shai-Hulud npm worm (2025–2026)
report_home:
  - "§3 — Background case study (marquee, stolen-credential)"
  - "§4 — Stolen-credential column anchor; the auth-layer-vs-authorization-layer argument"
proxy_grounding:
  - docs/threat-model/CORE-2-api-token-theft.md
  - docs/threat-model/operator-checklist.md   # PUB-2: sole upload credential lives in the proxy
  - research/controls-matrix/ctrl-mandatory-2fa.md
related_notes:
  - controls-matrix/ctrl-mandatory-2fa.md
  - controls-matrix/ctrl-trusted-publishing.md
  - controls-matrix/ctrl-build-provenance.md
bib_keys: [shai-hulud-cisa, shai-hulud-unit42, shai-hulud-github, shai-hulud-reversinglabs, shai-hulud-2-wiz, shai-hulud-tanstack-snyk]
status: vetted
---

## Why the report needs this

Shai-Hulud is the report's marquee **stolen-credential** case study (§3) and the anchor for that
column of the §4 positioning matrix. It is the clean, real-world realization of threat
[CORE-2 — API Token Theft](../../../../docs/threat-model/CORE-2-api-token-theft.md): a single
harvested npm token, which **bypasses 2FA entirely**, publishes malicious versions under the
legitimate maintainer's identity — with no second party in the loop. Its **recurrence** is itself
the argument: the ecosystem answered the September 2025 original with layer-appropriate fixes
(FIDO 2FA, short-lived tokens, Trusted Publishing/OIDC, provenance), and by May 2026 attackers were
publishing through the very Trusted-Publishing endpoint and minting *validly-attested SLSA Build L3
provenance for malware*. Every fix landed at the **authentication / integrity** layer; none of them
authorizes *whether this particular artifact should ship*. That missing layer — authorization — is
the proxy's thesis. (Synthesis; the anchors are below.)

## Sources (vetted this session)

- CISA, "Widespread Supply Chain Compromise Impacting the npm Ecosystem" (2025-09-23) → `shai-hulud-cisa`
  · US-gov primary advisory for the September original · [primary]
- Unit 42, "'Shai-Hulud' Worm Compromises npm Ecosystem in Supply Chain Attack" (accessed 2026-07-17)
  → `shai-hulud-unit42` · token→auto-republish mechanism (already cited in the 2FA control note) · [formal]
- GitHub Blog, "Our plan for a more secure npm supply chain" (2025-09-23) → `shai-hulud-github`
  · **operator-primary**: registry operator's own disclosure + remediation; the "response = more
  authentication" anchor for §4 · [primary]
- ReversingLabs, "Shai-Hulud … what you need to know" (accessed 2026-07-17) → `shai-hulud-reversinglabs`
  · first-detection incident research: Patient Zero timeline, TruffleHog, exfil mechanics · [formal]
- Wiz, "Sha1-Hulud 2.0 — Ongoing Supply Chain Attack" (accessed 2026-07-17) → `shai-hulud-2-wiz`
  · scope anchor for the November 2025 second wave (recurrence tail) · [context]
- Snyk, "TanStack npm Packages Hit by Mini Shai-Hulud" (accessed 2026-07-17) → `shai-hulud-tanstack-snyk`
  · the May 2026 wave: OIDC/Trusted-Publishing abuse + SLSA-L3-attested malware (the decisive
  §4 anchor) · [formal]

## Key facts (anchored)

### Patient Zero and the timeline of the September original
> "The malicious version 0.0.3 of *rxnt-authentication* was published on September 14 at 17:58:50
> UTC, making npm maintainer *techsupportrxnt* 'Patient Zero for this campaign.'"
— ReversingLabs, *Shai-Hulud … what you need to know*

> "On September 14, 2025, we were notified of the Shai-Hulud attack, a self-replicating worm that
> infiltrated the npm ecosystem via compromised maintainer accounts by injecting malicious
> post-install scripts into popular JavaScript packages." … GitHub "removed over 500 compromised
> packages and blocked uploads containing malware indicators."
— GitHub Blog, *Our plan for a more secure npm supply chain* (2025-09-23)

Backs the §3 opening: a dated, operator-confirmed incident, ~500 packages, initial vector =
maintainer-account compromise + post-install script.

### The token harvest bypasses 2FA (the CORE-2 realization)
> "Using the stolen npm token, the malware authenticates to the npm registry as the compromised
> developer. It then identifies other packages maintained by that developer, injects malicious code
> into them, and publishes the new, compromised versions to the registry." The harvested credentials
> were npm tokens read from `.npmrc` — the token path that bypasses 2FA.
— Unit 42, *'Shai-Hulud' Worm Compromises npm Ecosystem* (via
[ctrl-mandatory-2fa.md](../controls-matrix/ctrl-mandatory-2fa.md))

> The worm "installs TruffleHog, a popular open-source tool that can detect more than 800 different
> types of secrets." A function named *updatePackage* "adds a *postinstall* script to the
> *package.json* file that adds the *bundle.js* file to the package archive," enabling automatic
> republishing by compromised accounts. Stolen secrets were "exfiltrated to newly created GitHub
> repositories … The created repository has the name 'Shai-Hulud' … Exfiltrated data is double
> Base64-encoded and uploaded to a file named *data.json*."
— ReversingLabs, *Shai-Hulud … what you need to know*

This is the load-bearing fact for the stolen-credential column: the publish leg needs **only a
token**, and the token carries no TOTP step. `@ctrl/tinycolor` (2.2M weekly downloads) was among the
compromised packages — the blast radius of one token.

### npm's response was entirely at the authentication layer
> GitHub is restructuring npm publication to require: local publishing with mandatory 2FA; granular
> tokens limited to seven-day lifespans; Trusted Publishing without token management. Further:
> "Phasing out legacy classic tokens; Replacing TOTP 2FA with FIDO-based authentication; …
> Defaulting publishing access to disallow tokens, promoting trusted publishers; Eliminating 2FA
> bypass options for local publishing; Expanding trusted publishing provider eligibility."
— GitHub Blog, *Our plan for a more secure npm supply chain* (2025-09-23)

Every measure strengthens *who authenticates* or *how the token is scoped/attested* — the
authentication and integrity layers. None asks *whether this specific artifact should ship*. This is
the §4 hinge, in the registry operator's own words.

### Recurrence, and the auth-layer fixes getting walked around
> The "Shai-Hulud 2.0 / Second Coming" campaign began around November 21–23, 2025 (earliest leaked-
> secret repos at 01:22 UTC 11/24). Approximately 700 malicious npm packages; "25,000+ malicious
> repos across ~500 GitHub users," accelerating at ~1,000 new repos every 30 minutes. Trojanized
> namespaces included Zapier, PostHog, Postman, ENS Domains, and AsyncAPI.
— Wiz, *Sha1-Hulud 2.0 — Ongoing Supply Chain Attack*

> The May 2026 TanStack wave's malicious packages "were published via **OIDC trusted publishing
> after cache poisoning**, not by stealing credentials directly." Attacker-controlled binaries
> "extracted the OIDC token from runner memory … then POST directly to `registry.npmjs.org`
> authenticated as the legitimate TanStack release workflow." The attack "produced validly-attested
> SLSA Build Level 3 provenance for malicious packages — the first documented case of this kind."
> 84 malicious artifacts across 42 `@tanstack/*` packages (incl. `@tanstack/react-router`,
> 12.7M weekly downloads); May 11, 2026, 19:20–19:26 UTC.
— Snyk, *TanStack npm Packages Hit by Mini Shai-Hulud*

The decisive §4 evidence: the ecosystem's post-Shai-Hulud fixes are **Trusted Publishing (OIDC)** and
**SLSA provenance** — the exact controls the §4 matrix scores — and within eight months attackers had
published through OIDC and attested malware at SLSA L3. The controls did what they promise (prove
*who* published, prove *how* it was built); the attacker satisfied both while shipping malware,
because neither authorizes the *decision to ship*.

## How the proxy relates

**What it beats.** Shai-Hulud's engine is *auto-republish under the legitimate identity*: harvested
token → new malicious version live in the registry, no human in the loop. The proxy breaks exactly
that leg. Under the target deployment the operator has already **revoked all pre-existing project
tokens so the sole upload credential lives inside the proxy** (operator-checklist PUB-2 item); the
developer's machine and CI hold only a **proxy request-token**. When TruffleHog harvests that
machine, the npm/PyPI upload credential simply is not there — the stolen token opens a
**hash-bound, m-of-n-gated *request***, never a *publish* (CORE-2: "the token opens a *request*, not
an *outcome*"). The worm's exponential step stalls: it cannot mint a new version under the victim's
identity, because that identity's credential no longer publishes anything by itself. This is the
result the §4 matrix turns on.

**Network isolation compounds it.** The proxy should be reachable only from the audiences that need
it (internal network / VPN), not internet-facing — so even *using* a harvested proxy request-token
requires network position the worm running on a random developer box does not have. (This is now an
operator-checklist item; see *Open threads*.)

**What it does *not* beat (the honest line).** The proxy defends the **publish surface**, not the
developer's whole secret store. TruffleHog still harvests the machine's *other* secrets — AWS/GCP
keys, `GITHUB_TOKEN` — and self-propagation via stolen **GitHub** tokens (repo writes, workflow
injection, the exfil repos) is outside the proxy's registry-publish remit. The proxy makes the
*token harvest ineffective for publishing*; it does not make the machine unharvestable.

*Caveat on that residual (synthesis).* This residual assumes those other secrets are still sitting
on the developer's machine — which, ideally, they should not be. The move the proxy makes for the
publish credential (take the standing secret off every laptop and CI runner, custody it inside one
hardened, network-isolated party that only ever hands out deny-able requests) is the *general*
custody principle, not a package-publishing quirk. An organization that applies it broadly — no
standing AWS/GCP keys or long-lived GitHub tokens on dev boxes, only short-lived workload identity
brokered by a hardened custodian — shrinks this residual toward nothing, because TruffleHog on a
compromised box finds nothing worth harvesting anywhere. The proxy *demonstrates* that pattern for
the one credential in its remit; it is not itself the custodian for the rest. So the honest framing
is not "the proxy can't stop the harvest" but "the proxy stops it for the publish credential, and the
same principle — applied by the operator to the other secrets — is what closes the remainder." The
CORE-2 residual is contained operationally today (secrets manager, egress filtering, `is_active`
kill-switch); the caveat is that the ceiling is set by how far the operator carries the
custody principle, not by the proxy.

**One approver is enough to stop *this* attack — but multi-party is the thesis.** *(Synthesis.)*
The generalizable argument the report makes is **m-of-n human authorization**. But it is worth saying
that "multi-party authorization" does not require multiple *individual* approvers: an approver stack
of **one** — publish, then confirm via an out-of-band re-auth the attacker does not also control —
already defeats Shai-Hulud, because the attacker now needs the token *and* the second channel *and*
to monitor it, all far harder than reading `.npmrc`. That single-approver mode is *not* generalizable
(you would not gate shared-account login on yourself alone), which is why the thesis stays multi-party;
but for package publishing it shows the mechanism's floor is low and the friction it adds is already
enough to break the worm.

## Open threads / to verify

- **Operator-checklist item — landed in this change.** The checklist now carries a *Network &
  Deployment* item making the proxy internal/VPN-gated rather than internet-facing (tied to
  CORE-2 / CODE-1 / PUB-2), alongside the pre-existing database-binding item. Fork B's network-reach
  premise is spec-backed; no remaining gap.
- **Lowering the minimum quorum to 1 — filed for later grill.** Shai-Hulud shows a single
  out-of-band approval already breaks this attack, but the code hard-enforces `quorum >= 2`
  ([config.py](../../../../src/msig_proxy/core/config.py), constraints.md §3). Whether to allow a
  1-approver quorum for maximum operator flexibility is a genuine design reversal — filed as
  [#172](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/172) (needs-triage) citing
  this source, not settled here.
- The "approver-stack-of-one adds friction" framing is a §4/§7 positioning point, not a Shai-Hulud
  fact — confirm with the §7 draft that it reads as *mechanism floor*, not as diluting the
  multi-party thesis.

## Source decisions

- **September original is the case study; 2.0 (Nov 2025) and Mini/TeamPCP (May–Jul 2026) are the
  recurrence tail.** All load-bearing narrative facts (Patient Zero, mechanism, npm's response) are
  anchored to the September event so numbers do not drift; the later waves are cited only as
  *recurrence evidence* — the point they carry is "the gap persisted through every auth-layer fix,"
  culminating in the SLSA-L3-attested-malware anchor, which is why the May 2026 Snyk source is
  load-bearing despite not being the marquee incident.
- **Kept both Unit 42 and ReversingLabs** for the original: they anchor different facts (Unit 42 the
  token→republish quote already load-bearing in the 2FA note; ReversingLabs the Patient-Zero timeline
  and exfil mechanics). GitHub Blog was *added*, not substituted — it is the only operator-primary
  source and the only one that states the remediation verbatim.
