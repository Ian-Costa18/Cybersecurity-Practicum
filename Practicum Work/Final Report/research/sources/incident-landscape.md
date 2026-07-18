<!-- LTeX: enabled=false -->
---
bucket: I3
title: Supply-chain incident landscape (the recurring single-actor-publish pattern)
report_home:
  - "§3 — Background framing: the cost of the gap beyond the two marquee cases"
  - "§4 — Positioning evidence: the gap is systemic, not two anomalies"
proxy_grounding:
  - docs/threat-model/CORE-2-api-token-theft.md
  - research/controls-matrix/ctrl-mandatory-2fa.md
  - research/controls-matrix/ctrl-the-proxy.md   # Caveat 2: review-surviving payload (the SolarWinds/XZ boundary)
related_notes:
  - sources/incident-shai-hulud.md   # the marquee stolen-credential case this landscape generalizes
  - controls-matrix/ctrl-the-proxy.md
bib_keys: [event-stream-incident, ctx-pypi-incident, backstabbers-knife, cncf-supply-chain-catalog, mitre-c0024-solarwinds]
status: draft
---

## Why the report needs this

The two marquee case studies (Shai-Hulud, XZ) prove the gap exists in vivid detail; this note proves
it is a **pattern, not a pair of anomalies**. It carries the §3 "cost of the gap" framing beyond the
marquee cases and hands §4 its breadth evidence: the *publish/release* action in the major package
ecosystems is a **single-actor capability**, and a recurring class of real, damaging incidents
succeeded for exactly that reason — one compromised or socially-engineered identity could unilaterally
ship. event-stream (npm, 2018) and ctx (PyPI, 2022) are the two anchor incidents; the
`backstabbers-knife` dataset and the CNCF catalog supply the **taxonomy framing** that turns two
stories into "this is a documented category, at scale." SolarWinds appears once, deliberately, as the
**scope boundary** — the class the proxy does *not* claim. (Synthesis; anchors below.)

## Sources (vetted this session)

- **event-stream / flatmap-stream GitHub issue #116** — github.com/dominictarr/event-stream/issues/116
  (accessed 2026-07-18) → `event-stream-incident` · the primary disclosure thread; maintainer handoff
  to `right9ctrl`, the `flatmap-stream` injection, the Copay/crypto target · [primary]
- **"Account Takeover and Malicious Replacement of ctx Project"** — python-security.readthedocs.io
  (accessed 2026-07-18) → `ctx-pypi-incident` · dormant-maintainer account takeover via an *expired
  email domain*, env-var/AWS-key exfil, no MFA on the account · [primary]
- **Ohm, Plate, Sykosch & Meier, "Backstabber's Knife Collection"** — DIMVA 2020, arXiv 2005.09535
  (accessed 2026-07-18) → `backstabbers-knife` · the 174-package dataset + two attack trees; the
  taxonomy/quantification anchor · [formal]
- **CNCF TAG Security, "Catalog of Supply Chain Compromises"** — tag-security.cncf.io (accessed
  2026-07-18) → `cncf-supply-chain-catalog` · the living attack-vector taxonomy (Malicious Maintainer,
  Publishing Infrastructure, …); the "understand the patterns" framing · [context]
- **MITRE ATT&CK Campaign C0024, "SolarWinds Compromise"** — attack.mitre.org/campaigns/C0024
  (accessed 2026-07-18) → `mitre-c0024-solarwinds` · the scope-boundary anchor: build-process
  compromise, legitimately signed, distributed as a normal update · [primary]

## Key facts (anchored)

### event-stream (npm, 2018): earned-then-abused unilateral publish
> The issue questions why "@right9ctrl" was given access to the event-stream repository … the new
> maintainer added `flatmap-stream`, described as "entirely an injection targeting ps-tree" … the
> "target seems to have been identified as copay related libraries." Users could identify exposure by
> checking: "If you see `flatmap-stream@0.1.1` after running `npm ls event-stream flatmap-stream`, you
> are most likely affected." The compromise affected "millions of weekly installs."
— event-stream GitHub issue #116 (opened by FallingSnow, 2018-11-20)

Backs the §3 pattern claim: a maintainer who *earned* publish trust through legitimate contribution
could then ship a malicious dependency **alone**. No second human was in the release loop; the added
dependency is exactly what a co-approver would have questioned. (Weekly-download precision varies by
source — the primary issue's own phrasing, "millions of weekly installs," is what is anchored here.)

### ctx (PyPI, 2022): account takeover of a dormant maintainer
> A new domain was registered on "2022-05-14T18:40:05Z," followed by a successful password reset just
> 12 minutes later … the compromised versions … sent captured data as "a base64 encoded query
> parameter to a heroku application." The project "was registered and uploaded to PyPI in 2014" …
> "we estimate that 27,000 malicious versions of this project were downloaded." … "No mechanism for
> multi factor authentication was enabled for the owner user account."
— *Account Takeover and Malicious Replacement of ctx Project* (PyPI security writeup)

Backs the second pattern variant: an attacker who never earned trust simply **took the account** — a
$5 expired-domain re-registration and a password reset against an ~8-year-dormant project — and then
published. Still a single actor, still unilateral. This is the account-takeover leg that a per-account
control (even MFA, absent here) addresses at the *authentication* layer; the missing layer is *who
authorizes the release*.

### The taxonomy: this is a documented category, quantified
> "a dataset of 174 malicious software packages that were used in real-world attacks on open source
> software supply chains" (npm **62.6%**, PyPI **16.1%**, RubyGems **21.3%**), November 2015 to
> November 2019. "most packages (56%) trigger their malicious behavior on installation … More than
> half of the packages (61%) leverage typosquatting." 55% aimed at data exfiltration.
— Ohm et al., *Backstabber's Knife Collection* (DIMVA 2020)

> The catalog's goal is "not to catalog every known supply chain attack, but rather to capture many
> examples of different kinds of attack, so that we can better understand the patterns."
— CNCF TAG Security, *Catalog of Supply Chain Compromises*

These two convert the anecdotes into evidence of a **class**. Backstabber's Knife quantifies it (174
packages, three ecosystems, a majority triggering on install and exfiltrating); the CNCF catalog is
the living taxonomy whose very first vector is "Malicious Maintainer." The report cites them so §3/§4
can assert "recurring pattern" without hand-waving.

### The scope boundary: SolarWinds is a *different* class
> "APT29 used customized malware to inject malicious code into the SolarWinds Orion software build
> process that was later distributed through a normal software update" … the group "was able to get
> SUNBURST signed by SolarWinds code signing certificates by injecting the malware into the SolarWinds
> Orion software lifecycle." (~18,000 customers; Aug 2019 – Jan 2021.)
— MITRE ATT&CK Campaign C0024, *SolarWinds Compromise*

This is **not** the single-actor-publish pattern. The compromise was in the *build infrastructure*;
the shipped artifact was a legitimately-signed compiled binary, and the payload was obfuscated and
dormant. It backs the §3/§4 **boundary** sentence — "not all supply-chain compromise is
single-actor-publish" — not the pattern.

## How the proxy relates

**What it beats — the pattern.** event-stream and ctx share one leg with the marquee Shai-Hulud case:
a single identity (earned trust, stolen token, or hijacked account) can turn a compromise into a live
malicious release **with no second human in the loop**. The m-of-n publish gate breaks exactly that
leg — the malicious version now needs an *independent* approver, and a suspicious added dependency
(event-stream) or a dormant package suddenly publishing (ctx) is precisely what that approver is
positioned to catch. The proxy also works **one layer above the payload**: Backstabber's Knife shows a
majority of packages act on install and exfiltrate, but the proxy never has to *detect* the malicious
code — it gates the *release event*, which an attacker holding only stolen credentials cannot obtain.
The 56%-trigger-on-install / 55%-exfiltrate figures are why: whatever the payload does, it does nothing
if the version never ships.

**What it does not beat — the boundary (the honest line).** SolarWinds is build-*infrastructure*
compromise producing a legitimately-signed, compiled, dormant artifact. Publish-time **human review
does not reliably catch** that (you cannot eyeball a swapped source file in a compiled DLL, and the
payload was engineered to survive scrutiny) — so the proxy does not claim this class. It pairs with the
XZ marquee caveat and [ctrl-the-proxy.md](../controls-matrix/ctrl-the-proxy.md) Caveat 2
(review-surviving payload): XZ bounds "review-surviving *source* payload in the tarball," SolarWinds
bounds "compromised *build pipeline*." Naming the boundary is the honest scoping the report wants, not
a weakness to hide.

## Open threads / to verify

- **Two companion stubs were not full-text-retrieved this session** (both bot-block/paywall `WebFetch`),
  so neither is `% RESEARCHED`-tagged yet:
  - `event-stream-analysis` (Arvanitis et al., *A Systematic Analysis of the Event-Stream Incident*,
    EuroSec 2022) — the DOI resolves to the ACM page but the text is paywalled. It is the **formal
    academic corroboration** of the event-stream facts already anchored to the primary GitHub issue;
    retrieve via institutional access if §3 wants the formal cite alongside the primary.
  - `solarwinds-sunburst-cisa` (CISA ED 21-01) — the CISA site returns 403 to `WebFetch`. The
    SolarWinds boundary is anchored to MITRE C0024 (verified) instead; ED 21-01 is the contemporaneous
    US-gov directive and can be added as secondary color if retrieved through a non-blocking path.
- **event-stream download/dependents precision** — the "~1.5–2M weekly downloads / ~1,600 dependents"
  figures common in secondary write-ups vary by source; the note deliberately anchors only the primary
  issue's own "millions of weekly installs." Tighten only if a primary npm figure is retrieved.

## Source decisions

- **SolarWinds is a one-line boundary, not pattern evidence — by decision.** It is the most famous
  incident of the era, so a "cost of the gap" landscape that omitted it would read as a hole in
  awareness; but used as *pattern* evidence it is a liability, because it is build-infrastructure
  compromise the proxy does not beat, and the "three parallel cross-checking build environments" in
  SolarWinds' own remediation is *machine verification*, not *human authorization* — leaning on it as an
  m-of-n analog would muddy the human-approval thesis. Demoting it to the scope boundary turns the
  awkwardness into honest scoping. (Settled in the grill for this note.)
- **event-stream is anchored to the primary GitHub issue, not the ACM analysis paper.** The primary
  disclosure is reachable and quotable; the formal EuroSec analysis is paywalled. The paper is kept as
  a *formal companion* (see Open threads), not the load-bearing anchor — so the fact stands on a source
  actually retrieved this session.
