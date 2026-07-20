<!-- LTeX: enabled=false -->
# Final Presentation — Script Beats (LEGACY / superseded)

> **This document is legacy — do not treat it as current.** The live spoken
> content is the `SCRIPT` blocks inside
> [final_presentation_deck.md](final_presentation_deck.md), which is now the
> single source of truth for both slides and script. The beats below capture the
> original arc and rationale, but they are **no longer kept in sync** with the
> deck (the deck has diverged, e.g. the Gap/matrix reframe). Read this only for
> historical intent; edit the deck, not this file.

Spoken-script drafting for the final-presentation deck, built beat-by-beat via `writing-beats`.
Finished beats fold into the deck's `SCRIPT` blocks ([final_presentation_deck.md](final_presentation_deck.md)).
Source of truth for structure: [presentation-spec.md](presentation-spec.md). **Full spoken arc
drafted** (Opening → Close).

**Settled structure (front of talk):**

- **Opening (pre-hook):** minimal identity + the conviction (multi-party authz is underused) +
  "general proxy, shown in more than one use case" + narrow to package publishing. Plants the
  advocacy bookend's front post; does **not** reveal that m-of-n is the answer to *this* worm.
- **Hook:** Shai-Hulud as pure menace — damage + recurrence drumbeat. No diagnosis of *why* the
  fixes failed (that's the Gap's reveal). The worm is a through-line into the Gap.
- **Prerequisites (audience walks in knowing):** package registries / publishing; supply-chain
  attacks as a category; credentials/tokens/2FA; common security controls (FIDO 2FA, Trusted
  Publishing/OIDC, SLSA provenance, CI gates, scanning) — the Gap shows them *fail*, doesn't define
  them. Introduced by beats: what Shai-Hulud is; authn-vs-authz; m-of-n as the answer.

---

## Opening · pre-hook on-ramp

> I'm Ian Barish. Multi-party authorization — requiring more than one person to approve something
> before it goes through — is an underused security control. You see it in a few specialized places:
> a multisig crypto wallet needs several keys before it will move any funds. But almost everywhere
> else, it's rare. So I built a proxy that lets you put that requirement in front of many different
> actions, and I'll make the case today that it belongs in more than one place. My headline use case
> is package publishing.

*Grounds:* the conviction (bookend front post); multi-party = more-than-one-person-approves;
general proxy + the "belongs in more than one place" claim (softened from "I'll show it in more than
one use case" — the talk demos only package publishing and *makes the case* for breadth in future
work rather than showing a second demo; the Beat-7 advocacy callback pays this exact wording off); the
package-publishing narrowing. Hands off at the lip of the Shai-Hulud scene.

---

## Hook 1 · the incident (Patient Zero → engine → blast radius)

> On September 14th, 2025, an npm maintainer unknowingly ships a new version of their package with
> malware buried inside — and it spends the next day tearing through the npm registry. Here's how it
> moves: when that infected package lands on another developer's machine, it steals the tokens that
> developer uses to publish their *own* packages, and quietly republishes itself into every one of
> them. Each new victim becomes a carrier. In about a day, a single infection became roughly 500
> compromised packages — including one downloaded more than two million times a week.

*Grounds:* the incident is real and dated; the self-propagation engine (stolen publish token →
republish, no human in the loop); "one credential" as the load-bearing unit (quietly seeds the
thesis); the blast radius. Menace only — no diagnosis of why later fixes failed. Package name kept
vague on purpose. *Leaves the reader at:* "and then it was over, right?" → the recurrence turn.

---

## Hook 2 · the recurrence turn (names it, drumbeat, hands to the Gap)

> The ecosystem scrambled to clean it up. Two months later, it came back — bigger. And again. And
> again — the most recent wave just weeks ago. They named it Shai-Hulud, after the sandworms in
> *Dune* — because every time we put a defense in its way, it slips back under the sand and surfaces
> somewhere else. So what controls did we put in place — and why couldn't any of them stop it?

**Slide direction:** on the *Dune* line, cut to an image of the sandworm surfacing / chasing the
protagonist — the visual makes "slips back under the sand and surfaces somewhere else" land. (Need a
usable image: a licensed/fair-use still or an illustrative render, not just a grabbed film frame.)

*Grounds:* the name (Shai-Hulud + the *Dune* recurrence metaphor); the recurrence drumbeat; the
hand-off question that opens the Gap. Still menace, not diagnosis — "locked things down harder" /
"put a defense in its way" stays abstract; the Gap names the controls and shows why each misses.
*Ends the hook on the gap-as-setup pivot:* the audience now feels "why can't we stop it?" and Beat 2
answers it.

*Recurrence timeline (verified):* original Sept 14 2025 → 2.0 "Second Coming" Nov 2025 ("two months
later") → Mini/TeamPCP wave spring 2026 (TanStack) → resurfaced June 1 2026 (Red Hat) → **AsyncAPI release-
pipeline compromise July 14 2026** — one week before the July 21 submission, which anchors "the most
recent wave just weeks ago." The July-2026 facts are newer than the vetted research note; fold them
into #119 / [incident-shai-hulud.md](../Final%20Report/research/sources/incident-shai-hulud.md)
when that lands.

---

## Gap 1 · walk the controls, land the diagnosis (fast sweep → the turn)

> So the industry threw the whole playbook at it. Hardware 2FA — the worm is already holding a valid
> publish token, so it publishes right past it. Trusted Publishing, where a machine identity replaces the
> token — it just rides that instead.
> CI gates, scanners — they wave through a trusted maintainer shipping a normal-looking update.
> We tried signed provenance and SLSA attestations, but in a later wave, the malware shipped with *valid* SLSA Level 3 provenance,
> the first documented case of its kind. It was signed because it came straight out of the real pipeline. Every
> one of these is asking the same kind of question: *are you who you say you are, and is this artifact
> intact?* And every time, the answer was yes. Because none of them ask the one question that actually
> mattered: *should this release be going out at all?*

**Slide direction:** the comparative matrix (report Table I), competitor columns only — each control
a row, all failing the same compromised-maintainer column. Rows tick past as they're named; the
"should this go out?" question is the empty column the proxy fills at Beat 3. (Artifact waits
on #113.)

*Grounds:* the shared failure mode (every deployed control authenticates identity or verifies the
artifact — none re-checks the *decision to publish*); **authn/integrity vs. authz** as the axis the
whole talk turns on. *Requires (already grounded):* the controls themselves (prerequisite — named,
not defined); the self-propagation engine from Hook 1 (the worm holds a *valid* credential, which is
why identity checks pass). *Leaves the reader at:* "then who should be answering that question?" →
the thesis (m-of-n human authorization, Beat 3).

*Pace note:* deliberately brisk — one clause per control, no definitions. The beat's weight is on the
final turn, not the walk. The SLSA line is the one sanctioned exception: it gets a beat of weight
because "even the newest control failed" is the strongest single piece of gap evidence. Keeps Beat 2
under its ~2 min budget and front-loads time for the demo.

*Accuracy anchor (the SLSA claim):* attribute to the **May 2026 Mini Shai-Hulud / TanStack wave**,
not the September original — malicious `@tanstack/*` packages published via **OIDC Trusted Publishing
after cache poisoning**, POSTing as the legitimate TanStack release workflow, which "produced
validly-attested **SLSA Build Level 3 provenance for malicious packages — the first documented case of
this kind**." Source: Snyk, *TanStack npm Packages Hit by Mini Shai-Hulud* (`shai-hulud-tanstack-snyk`),
anchored in [incident-shai-hulud.md](../Final%20Report/research/sources/incident-shai-hulud.md) §4.
Script says "a later wave" — do **not** imply the original worm defeated provenance.

---

## Thesis 1 · name the missing layer, land m-of-n (the payoff row)

> The owners should decide — that part's obvious. The problem is that nothing gave them a way to.
> Every control we just walked lives at one layer: proving identity, proving the artifact is intact.
> What's missing is a layer *above* that — authorization. Not *are you who you say you are*, but *did
> the people responsible for this package actually decide to ship it?* That's the layer I built: a
> proxy that holds a release until more than one owner signs off on it. Put that row in the matrix,
> and it's the only one that stops a compromised maintainer — because a stolen credential is still
> just one owner, and one owner is no longer enough.

**Slide direction:** the payoff — drop the **proxy row** into the matrix (the row swaps in beneath the
failed controls) and light up the compromised-maintainer column: every control above it fails that
column, the proxy row is the only pass. The visual *is* "the missing layer, added." (Same matrix as
Beat 2; artifact waits on #113.)

*Grounds:* the **authorization layer** as a named thing distinct from authn/integrity (this is B's
core move — the layer, not just the answer); **m-of-n human authorization** as the instance that fills
it; the payoff that a stolen credential is *one* owner and m-of-n makes one insufficient. *Requires
(already grounded):* authn-vs-authz axis (Gap); "one credential" as the load-bearing unit (Hook 1 —
the callback lands here: the thing the whole worm rides on is exactly what m-of-n neutralizes).
*Leaves the reader at:* "does this actually work / where else does it belong?" → advocacy one-liner +
XZ proof-of-pattern, then the mechanism.

*Note on the "who":* deliberately does **not** dwell on who decides (owners — obvious). The reveal is
the *layer that gives them the power to require a deliberate decision*, which is the security control
the project contributes. Per the user: "what security control gives them the power to do that is
really what my project is solving."

*Cut here (decided):* the advocacy plant and XZ do **not** appear in this movement. Generality lives
only at the two ends of the talk (Opening front post + Close payoff) — a mid-talk return to it makes
the concrete spine oscillate general↔concrete. XZ is out of the presentation entirely (time; and
Shai-Hulud alone carries the case study). The report-side XZ pair (Background §3) is a separate,
still-open call — not decided here. **Close obligation:** the future-work beat must call back to the
Opening's "underused / general" line so the two-post bookend closes without a mid-post.

---

## Mechanism 1 · the flow, taught before the demo (request → quorum → publish)

> So how does that actually work? A maintainer goes to publish — but instead of hitting the registry,
> the request hits the proxy first. The proxy takes a fingerprint of exactly what's being published
> and binds the request to it, so every approval that follows is approving *this* artifact, not
> something swapped in later. Then it notifies the other owners. Each one re-authenticates — proves
> it's really them, right now — and signs their approval. Nothing ships until enough of them have:
> that's the quorum. Only when the threshold is met does the proxy release the publish to the
> registry. You're about to watch this happen twice.

**Slide direction:** the report's architecture figure (Fig 1) as the backdrop; the five steps light up
in sequence as narrated — request → hash-bind → per-vote reauth + sign → quorum met → publish. Reuse
the report figure verbatim (US10). No new artifact.

*Grounds:* the mechanism as a concrete pipeline — **hash-binding** (approvals are pinned to one exact
artifact, so a later swap is rejected), **per-vote reauthentication** (each approver proves liveness,
not a stored token), **per-vote signing**, and **quorum threshold** as the gate. *Requires (already
grounded):* m-of-n (Thesis); "one owner is no longer enough" (the quorum is the enforcement of that).
*Leaves the reader at:* "show me" → the demo (Beat 5) is now *evidence*, not instruction — the flow is
already taught, so the recording confirms it rather than introducing it.

*Sets up the demo's two acts:* "watch this happen twice" = Act 1 (legit publish reaches quorum →
ships) and Act 2 (malicious publish freezes at 2/3 → caught → denied). The beat deliberately ends on
that hand-off so the demo doesn't need its own setup narration.

*Pace note:* ~1.5 min budget. Teach-before-demo is the whole point of putting mechanism here (US9) —
resist adding detail the demo will show anyway (e.g. TOTP specifics, key-at-rest encryption); those
are the demo's to reveal.

---

## Threat Delta 1 · the honest accounting (no control is free → the three themes)

> Here's the thing, though: no security control is free. Every one you add to stop one attack opens
> up something new to defend. And this one is not a cheap control — it adds real friction, and it
> adds its own attack surface. The most obvious cost is the one you might already be thinking:
> I just took the release decision for a whole ecosystem's worth of packages and funneled it through
> a single proxy. That's one very juicy target. And that's the honest worst case — this is a
> proof of concept, not a hardened production service, and concentrating the authority concentrates
> the risk. This is the full threat model for the system — every threat I mapped. Some of these the
> proxy actually improves on, and a few it just inherits from any registry setup. But the ones it
> newly introduces are the honest cost, and they cluster into three themes. One: concentration — the
> proxy itself becomes worth attacking. Two: the human factor — the approvers are now in the loop, so
> fatigue, coercion, and getting tricked into signing all become live. And three: availability — I
> just put a gate in front of publishing, so if the gate jams, nobody ships. The reassuring part is that none of these are new *kinds* of problem, and the
> structural fix for the worst of them is the same: fold this into the registry itself, so there's no
> separate juicy target to knock over.

**Slide direction:** the **full threat model on screen** — all **33 threats** (24 introduced · 5
improved · 4 inherited), grouped, as a dense "here's the whole accounting" backdrop. On "this is the
full threat model," the whole wall is up. Show the improved/inherited threats in a distinct, quieter
register (e.g. green/muted) so the eye reads "the proxy also fixes and inherits some" without a word
spent on them. Then the **three themes highlight in sequence** over the **introduced** subset as
narrated: concentration cluster lights → human-factor cluster lights → availability cluster lights.
The unlit introduced remainder (INFO / PUB) stays visible but unhighlighted — shown, not claimed away.
The wall reads "comprehensive"; the highlights carry the three points (US20, overriding the earlier
"table off the slides" call). Keep the upper-right clear for the talking-head overlay; render the set
legibly-as-rigor, not for row-by-row reading. Artifact source: `uv run tools/threat_model.py` renders
the catalog — build the grouped/highlightable version from that so it can't drift. (Waits on the same
matrix/figure tooling as #113.)

*Grounds:* the honest-accounting frame (every control introduces threats — applied, not left
abstract); the **three-theme distillation** (concentration · human-factor · availability) as the
*headline* spoken over the full introduced set; **native-registry integration** planted as the
structural cure for the concentration theme. Source: presentation-spec US19–20. The on-screen artifact
is the **whole threat model** (33 threats: 24 introduced · 5 improved · 4 inherited) with the three
themes highlighting over the *introduced* subset — **overrides** the earlier US20 "distillation-only,
table off the slides" call (decision below). The
three themes are the *spoken* structure, **not** the threat catalog's numeric `bucket` field (that's
mitigation *posture* ①–④; the 24 introduced threats span all four). Word is "themes," never
"buckets," to avoid colliding with that field.

*Accuracy note (the three themes are NOT a partition):* the catalog organizes the 24 introduced
threats into **8 STRIDE families** (VOTE 5 · DOS 4 · HOST 4 · IDENT 5 · CODE 2 · CRYPTO 1 · INFO 1 ·
PUB 2). Most map onto the three themes, but at least **INFO-1** (information disclosure / quorum-status
— confidentiality) and **PUB-1** (payload substitution — integrity of the in-flight artifact) do
**not** sit cleanly in concentration/human-factor/availability. So the script must **not** claim the
delta *is* three themes — it says the threats "worth your attention here cluster into three themes"
and points to the report for the full net-delta table (US20). Do not "tighten" this back to "it all
falls into three themes"; that over-claim fails a Q&A challenge (e.g. "what about disclosure?"). *Requires (already grounded):* the proxy as a distinct interposed service
(Mechanism); the demo just watched (Beat 5) — "one juicy target" lands because the audience just saw
every release routed through the one box. *Leaves the reader at:* "so what would you actually need to
deploy this, and where does it stop?" → Discussion (Beat 7: deployment · limitations · future work).

*Framing note (decided):* opens on the **general principle** ("no control is free") but pays it off
in one breath by applying it to *this* control — the friction + own-attack-surface admission — then
straight to the concrete "one juicy target." This is the sanctioned exception to the no-oscillation
rule: the abstraction is a one-clause on-ramp to a concrete concession, not a return to generality.
Per the user: lead with "no control is free," stress that *this* one in particular adds a lot of
friction and its own attack surface, weave the "one juicy target" line back in, then apply to the
proxy. Naming the strongest objection before the audience can is the credibility move (US17–18).

*Pace note:* ~2 min budget. The three themes are named, not enumerated exhaustively — the net-delta
table is the report's job (US20). Resist re-opening the mechanism; this beat is accounting, not
re-teaching. Ends on the native-registry plant so future-work (Beat 7) has its callback.

---

## Discussion 1 · deployment reality (it only works if you deploy it right)

> There's an honest caveat with all of this: it only helps if you deploy it right — and two things
> matter most. The first is really a consequence of where we are today: multi-party approval isn't a
> first-class feature in any package registry, so the registry underneath will still accept a direct
> publish from any valid token. That means you have to revoke every publishing token that already
> exists — leave one live, and an attacker just walks around the proxy with it. Second, the quorum is
> only as strong as the people in it — choose co-owners who won't collude, and set the threshold with
> some care: too low, and a single stolen credential is still enough to ship; too high, and one
> maintainer on vacation can stall every release. Everything else is in the operator checklist.

**Slide direction:** the operator checklist, with the **two load-bearing items highlighted** — revoke
pre-existing tokens; set quorum / pick non-colluding co-owners — the rest of the checklist visible but
dimmed with a "full checklist →" pointer. Keep upper-right clear for the overlay. No new artifact:
excerpt the existing operator checklist (same source the report cites).

*Grounds:* the **deploy-reality frame** (the control is conditional on correct deployment — stated,
not hidden); **revoke-pre-existing-tokens** (PUB-2 / proxy bypass) as the single most important
operator action — framed as a *consequence of multi-party auth not being a native registry feature*
(the registry still accepts direct publishes, so the proxy only helps if it is the *sole* path). This
deliberately reuses the native-registry theme from Threat Delta and pre-echoes the future-work payoff
(US27): the friction exists *because* it isn't first-class, which is exactly what going native fixes.
Framing chosen over "the one people miss" — nobody has deployed this yet, so a field-wisdom claim
would be false. **Quorum configuration** is the second (CORE-3 non-collusion · DOS-3/4 threshold), with
the too-low/too-high tension made concrete (the availability theme from Threat Delta, now an operator
dial). *Requires (already
grounded):* the proxy as the interposed publish path + the quorum (Mechanism); the concentration &
availability themes (Threat Delta — this beat turns "availability is a risk" into "here's the dial you
set"). *Leaves the reader at:* "fine — but what did you *not* test or claim?" → limitations (Beat 7
part 2).

*Divides labor with Threat Delta (US24):* Threat Delta = the new attack surface the *design* owns;
this beat = what the *operator* must do to make the design hold. No re-listing of introduced threats
here — PUB-2 and CORE-3/DOS appear as **operator actions**, not as threats re-narrated.

*Pace note:* ~45–50s (Discussion's ~2.5 min splits deployment → limitations → future work). Exactly
two prerequisites spoken; the rest is a checklist pointer (US22). Resist expanding to the full
checklist — legibility-as-rigor on the slide, two items in the voice.

---

## Discussion 2 · limitations (the two boundaries — collusion, and the bolt-on)

> Even chosen well, a quorum has one hard limit — collusion. If everyone who has to sign off is
> already in on it, requiring more signatures changes nothing; that's a boundary I chose, not one I
> missed. The other limit is structural: this is a proxy bolted in front of a registry it doesn't
> own, so it inherits that registry's weaknesses — seize the account through its *own* recovery flow,
> and you've skipped the proxy entirely. Neither is a patch away. Both are why the real endgame isn't
> bolting this on in front of the registry — it's building it *in*.

**Slide direction:** two labeled boundaries, side by side — "Colluding quorum (by design)" and
"Inherited: it's a bolt-on." Keep it spare; the talking-head carries this beat. Optional callback:
re-dim the Threat-Delta threat-model wall and light **CORE-3** + the **inherited** row(s) (PUB-3 et
al.) instead of a fresh graphic — but only if it doesn't over-reuse the wall; a clean two-box slide is
the safer default. Upper-right clear for the overlay.

*Bridge (subtle, no meta):* opens on **"Even chosen well…"** — a light callback to deployment's "pick
co-owners who won't collude" knob. The audience *feels* the connection (you chose them well, but even
so…) without being told "I planted this earlier." Replaced the earlier "I planted something worth
making explicit" opener (telegraphed the seam; cringe). Collusion is now ~2 sentences total across
both beats (deployment: the 5-word knob; here: the boundary), down from 5–6.

*Grounds:* the two **scope boundaries** — (1) **insider collusion** (CORE-3; delta `improved`,
bucket ④ residual) as the deliberate non-goal, *elevated* from deployment's "pick non-colluding
owners" knob to a stated boundary (bridge, not repeat); (2) the **inherited-surface** limit — the
proxy is a **bolt-on** in front of a registry it doesn't own, so it inherits that registry's threats
(exemplar: **PUB-3** external account-recovery bypass; also CRYPTO-2/3, IDENT-3, all catalogued
`inherited` = scope statements, not proxy weaknesses). Both **pivot to native integration**, handing
to future work (US25/27). *Requires (already grounded):* deployment's collusion knob (the bridge);
the proxy as an interposed bolt-on (Mechanism); the native-registry theme (Threat Delta plant).
*Leaves the reader at:* "so where does this actually go?" → future work (Beat 7 part 3).

*Divides labor with deployment (US24):* deployment = operator **dials** (what you set); limitations =
**boundaries** (what the design chose not to solve + what it inherits). Collusion appears in both but
at different altitudes — knob vs. non-goal — so it's a segue, not a restatement.

*Cut (decided):* performance and human-subjects usability are **not** named here. Per the user: not
honest-debt worth runtime, and there's no measured data to report — naming unmeasured dimensions with
nothing to say about them is filler. The two boundaries above are real, catalog-grounded, and both
feed the native-registry payoff; that's the whole beat. (US23 updated to match.)

*Pace note:* ~35s. Two boundaries, each one move; end on "building it *in*" so future work opens on the
native-registry productization path already pointed at three times (Threat Delta plant · deployment
framing · here).

---

## Discussion 3 · future work (native registry → advocacy payoff, the bookend closes)

> So where does this go? The limitations keep pointing at one answer: stop bolting this on, and build
> it into the registry itself. And that's not a fantasy — Trusted Publishing already proved a registry
> will bake a brand-new control straight into the publish path. It just baked in another *identity*
> check, when the missing piece was *authorization*. Put multi-party approval in that same native
> slot, and the biggest risk I introduced — the proxy as one juicy target — simply dissolves: there's
> no separate box to attack, it's the registry you already had to trust. And packages are only where I
> started. I opened by calling multi-party authorization underused and general — and that's the real
> headline. The same core already extends past publishing to guarding a shared account, and it fits
> anywhere one stolen credential can trigger something you can't take back — a production deploy,
> sensitive data, a joint account.

**Slide direction:** two moves, two light visuals. First, native integration — the architecture
figure with the proxy *collapsing into* the registry box (the bolt-on becomes native); optional small
"Trusted Publishing" tag on the registry as the precedent. Second, on the advocacy widen, a short list
of real domains grounded in the use-case docs (shared accounts · deployments · sensitive data) — one
line, not a new framework. Upper-right clear for the overlay.

*Grounds:* **native-registry integration** as the productization path (US27), with **Trusted
Publishing reframed as precedent** — proof registries will host a native control, not proof the
control worked (it was identity; the missing layer was authorization). This deliberately *reuses* the
authn-vs-authz axis (Gap) so the precedent reinforces the thesis instead of contradicting the Gap beat
where Trusted Publishing *failed*. Then the **advocacy payoff** (US25): m-of-n belongs anywhere one
compromised credential triggers a high-consequence action — **grounded in the real use-case docs**,
kept concise (per the user: match the earlier tight version, don't expand). The spoken examples:
**shared account** = the *designed second shape* ([docs/use-cases/02-shared-account-management.md] —
same approval core, `forward-auth` grant vs. a `one-time` publish); **production deploy · sensitive
data** = the *documented future* set ([docs/use-cases/00-overview.md] §Future). **Money is NOT a
future example** — it's the already-solved case (multisig wallets, the Opening's own anchor). The
richer separated-parents / child's-savings detail lives in the doc if a longer cut ever needs it — cut
here for length. *Requires (already grounded):* the
native-registry theme (pointed at 3× before — Threat Delta plant · deployment · limitations); "one
juicy target" (Threat Delta); authn-vs-authz (Gap); **the Opening's "underused / general" plant** —
this is the callback that closes the two-post bookend (US26). *Leaves the reader at:* the single-line
Close (Beat 8) — everything is now said; the Close only punctuates.

*Bookend close (US26):* "I opened by calling multi-party authorization underused and general" is the
explicit callback to the Opening front post. The bookend now closes with **no mid-post** — generality
appeared only at the two ends (Opening · here), never mid-talk, exactly as decided in the Thesis beat.

*Resolved — Opening reconciled:* the Opening used to say *"I'll show it in more than one use case
today,"* but the talk demos only package publishing. Softened the Opening to *"I'll make the case it
belongs in more than one place"* (per the user) — a claim this beat pays off exactly, since it *names*
the designed shared-account shape and the broader domains rather than promising a second demo. The
bookend's "underused / general" callback now lands against a promise the talk actually keeps.

*Pace note:* ~50–60s (the largest slice of Discussion's ~2.5 min). Two moves only — native slot, then
widen. Advocacy is one breath (US26: one sentence in Thesis, one here), not a re-argument. Ends on the
domain list (deploy · sensitive data · joint account) — deliberately does **not** land on Shai-Hulud
(cut, per the user; re-centering the worm here steps on the conviction) so the one-line Close delivers
the payoff clean.

---

## Close 1 · the one line (land the conviction)

> One stolen credential should never be enough — and multi-party approval belongs in more places than
> you might first think.

**Slide direction:** the closing card — the single line on screen, nothing else. Talking-head holds,
then end. No recap slide, no "thank you / questions" bullet clutter.

*Grounds:* nothing new — the Close only **punctuates**. Lands the **conviction** (one credential must
not be load-bearing) and the **generality** ("more places than you might first think"), closing the
bookend the Opening opened ("underused / general"). *Requires (already grounded):* the whole talk —
especially the advocacy widen (Beat 7) that just named the domains. *Ends the talk.*

*Note on the phrasing (decided):* lands on the conviction, **not** on Shai-Hulud (per the user — the
worm was the vehicle, not the point). "More places than you might first think" is the user's wording,
chosen over "almost everywhere" — which over-claims; the honest claim is that it's *underused*, i.e.
it belongs in more places than it currently sits, not literally everywhere. Single line, no recap
(US28).

*Pace note:* ~8–10s. One sentence, then stop. The last beat of the talk; resist any coda after it.
