<!-- LTeX: enabled=false -->
# Final Report — Fragments

> This is the **first-class quarry** that [draft-report-section](../../.agents/skills/draft-report-section/SKILL.md)
> mines for **every** section, not just the hard rhetorical bits — sentences, analogies, and
> framings in Ian's own voice, alongside the spec lines that no rewrite improves on.
> Fragments are flat and unordered; each carries its provenance and a `Candidate use:` pointer.
> See [outline.md](outline.md) for the spine.
>
> **Selection rule (decided 2026-07-23):** a fragment earns a slot only if it says the thing
> *better than the governing doc already says it* — sharper, shorter, or in a register the spec
> cannot reach. `draft-report-section` already reads the specs, so a fragment that merely
> restates one adds nothing. Voice is the dominant way to win that test.
>
> **Caveats travel with their claim.** Where a fragment has an honest limit, that limit lives
> inside the same fragment so a claim cannot be lifted without it. ⚠ marks a guardrail: material
> whose obvious use is wrong.
>
> **Register (decided 2026-07-23).** Much of this quarry is transcribed from the final
> presentation, which is spoken first-person — right for a conference talk, wrong for a report.
> Per [How to write a technical paper](How%20to%20write%20a%20technical%20paper%20or%20a%20research%20paper.htm):
> *"First person is rarely appropriate in technical writing"*, and is reserved for **describing
> something the author did manually** — a design decision made, a threat model authored, an
> approach rejected. It is **not** for narrating the system's behavior or addressing the reader
> as *you*. Where a spoken fragment is first- or second-person, the verbatim line is kept as the
> source of the phrasing and a **`Report voice:`** rendering sits beneath it. Draft from the
> `Report voice:` line; the fragment above it is there so the cadence is not lost in translation.
> Fragments marked **`First person is correct here`** keep it — those describe Ian's own choices
> and converting them would obscure who acted, which is the thing passive voice is condemned for.

<!-- WHERE THE SPINE ACTUALLY LIVES. outline.md gives section order and the page budget, but
     the *internal* structure of the evaluated sections is fixed by docs/evaluation-plan.md,
     which outline.md cites as each section's claim source. Read it before placing a §4/§5/§6
     fragment — §4 in particular runs three named moves:
       Move 1 — the gap is real (the comparative positioning matrix; verdicts are FIXED there)
       Move 2 — the gap is costly to leave open (the Shai-Hulud / XZ case studies)
       Move 3 — the gap is live industry territory, still unfilled at the registry-publish point
                (hyperscaler multi-party approval, siloed per control plane)
     Every note under research/ also carries a `report_home:` field naming its section. Where a
     fragment's provenance is design-time research (docs/research/) and the report-facing corpus
     later scoped it differently, the corpus wins — those fragments carry a ⚠ guardrail inline. -->

<!-- Fragments accumulate below, separated by --- . -->

The proxy doesn't make approver compromise less likely — it makes it matter less.

Delta story for [CORE-1](../../docs/threat-model/CORE-1-single-approver-account-compromise.md) (single approver account compromise), the threat model's flagship "improved" threat — from the #107 Phase C grill, 2026-07-02. On the rated axes: in the direct-publish baseline, stealing the one maintainer's PyPI credential is likelihood-high / severity-critical (unilateral publish). Under the proxy, stealing one approver's credential pair is *still* likelihood-high — the proxy can't stop credential theft, and [IDENT-5](../../docs/threat-model/IDENT-5-no-anti-automation-on-authentication-endpoints.md)'s missing rate-limiting means the TOTP second factor doesn't buy the rating down — but severity drops to high: the attacker gets one vote, and m−1 independent approvals still stand between them and PyPI. The improvement lives entirely on the severity axis.

Candidate use: the final report's §1 value proposition / security-evaluation narrative.

---

Multi-party authorization — requiring more than one person to approve an action before it goes through — is an underused security control.

*(final_presentation_deck.md:61)* Thesis and definition in one sentence, no jargon in front of it.

Candidate use: §1 opener. Also the abstract's first move.

---

It's not that nobody does it. AWS, Google, and Azure all gate a few of their most sensitive operations behind multiple approvers. But it's only just a few.

*(final_presentation_deck.md:61)* This is the honest form of "underused" — breadth-with-siloing, not a false universal negative. It discharges in three sentences the epistemic care that `Broad Literature Review.md:188` needed a paragraph for ("all surveyed multi-party-approval systems are resource-specific"). Keep the hedge; the claim is that adoption is *siloed*, never that nobody has built it.

Candidate use: §1, immediately after the thesis — the "underused" half, made defensible before §4 has to argue it.

---

So I built a proxy that is generalizable — you can use it for many different use cases, basically anywhere that a single stolen credential allows for an outsized amount of damage. My headline is package publishing, as I think it shows it off best.

**Report voice:** This work presents a general-purpose multi-party authorization proxy, applicable wherever a single stolen credential can trigger disproportionate damage. Package publishing is the use case it is instantiated and evaluated against, chosen because it exercises the primitive most sharply.

*(final_presentation_deck.md:61)* The general→concrete bookend's front post, stated plainly. The outline calls this the framing hardest to get from the specs, and this is it already said out loud.

Candidate use: §1 thesis paragraph. Opens the bookend that §7 Future Work closes.

---

The open-source model's greatest strength — distributed contribution — is also, under the current authorization model, its greatest security liability.

*(docs/mvp-prd.md:15)* The paradox framing. Earns its slot despite being spec prose: nothing in the corpus states the problem's *shape* better, and the qualifier "under the current authorization model" is what keeps it from being a complaint about open source.

Candidate use: §1 problem statement.

---

Today, *adding a maintainer* means *handing out unilateral publish rights*.

*(docs/mvp-prd.md:15)* The permission model's defect in nine words. Pairs directly with the concrete platform evidence — PyPI has no role that allows project membership without upload rights *(PyPi Use Case Research.md:47)*.

Candidate use: §1, or §4 where the registry permission gap is evidenced.

---

The breach notifications repeat the same shape: one account, one unilateral publish, thousands of victims.

*(docs/mvp-prd.md:11)* Kept over the looser `PR4.tex:80` variant ("Recent incidents have followed the same attack shape…") — the tricolon is tighter and the cadence carries.

Candidate use: §1, and it is the sentence the §3 incident pair exists to substantiate.

---

The deeper problem is not that accounts get stolen. It is that the package ecosystem has no concept of multi-party authorization for a publish.

*(docs/mvp-prd.md:13)* Frames the problem by naming what is *absent*. Distinct from the §4 gap sentence, which frames it by naming the *question nobody asks* — this one belongs in §1 (here is the missing concept), that one in §4 (here is why every control misses it). Both can live; they are not redundant.

Candidate use: §1 problem statement, the pivot into the contribution.

---

None of them distribute the decision to publish itself.

*(PR4.tex:82)* The whole thesis in eight words. Kept over `mvp-prd.md:13`'s three-line version of the same argument.

Candidate use: §1. Also usable as the closing line of §4's matrix reading.

---

The novel contribution is the approval layer, not the auth primitives.

*(docs/adr/0006-build-proxy-from-scratch.md:51)* The tightest scoping sentence in the project. Says what the contribution *is* and pre-empts the "did you invent crypto?" question in the same breath.

Candidate use: §1 contribution statement. Guardrail for the whole report — the proxy does **not** implement threshold signatures; the shipped scheme is credential-backed (Ed25519, PBKDF2, AES-256-GCM, bcrypt), and the FROST/MuSig2/GG20 survey is background the project deliberately did not adopt.

---

Now, it won't fit everywhere, and it shouldn't be on by default — but it belongs anywhere a single stolen credential allows for an outsized amount of damage: a production deploy, a root cloud account, a wire transfer.

*(final_presentation_deck.md:621)* The calibrated advocacy, and the strongest version of it in the corpus. The hedge is what makes it credible — "it shouldn't be on by default" is the clause that turns a pitch into a position. This is the bookend's back post.

Candidate use: §7 Future Work & Generalizability, the thesis payoff. Framing/advocacy only — never one of the three evaluated claims (#109).

---

For anything you can't take back, one stolen credential shouldn't be enough — and with multi-party authorization, it doesn't have to be.

*(final_presentation_deck.md:645, the closing slide)* The best sentence in the corpus. Thesis, contribution, and advocacy in one line, and it generalizes past package publishing without over-claiming anything. The leading phrase is **"anything you can't take back"** — it names the class of action the primitive belongs to better than "high-consequence action" does, and it can carry the generality argument anywhere in the report without the word "generality."

**Register — a deliberate exception to the third-person rule (decided 2026-07-23).** *"Anything you can't take back"* is a generic *you*, not the reader addressed as a participant, and it is the phrase the whole bookend hangs on. The line **keeps the generic *you* and the contraction** in both §1 and §8: a paper is allowed one closing sentence with a pulse, and the strict conversion — *"For anything that cannot be taken back, one stolen credential should not be enough"* — is noticeably flatter, because the contraction and the second person are most of what makes it land. Use the converted form only if the line ever needs to appear in the abstract, where the plainer register fits. This is the single sanctioned exception; everything else follows the `Report voice:` renderings.

Candidate use: **bookended, split** (decided 2026-07-23). §1 opens on the problem half alone — *"For anything you can't take back, one stolen credential shouldn't be enough"* — stated as the motivating conviction and left unresolved. §8 Conclusion closes on the whole sentence, resolution clause included. The reader hears "and it doesn't have to be" exactly once, at the end, so the repetition is the §1↔§8 bookend structure rather than a refrain. The abstract does **not** use it — the abstract closes on the "underused security control" fragment instead, because an abstract wants the claim, not the flourish.

---

On September 14, 2025, an npm maintainer unknowingly ships a new version of their package with a piece of malware buried inside, and it spends the next day tearing through the npm registry.

*(final_presentation_deck.md:108)* Dated cold open with no security vocabulary in it. "Unknowingly" is the word doing the work — the maintainer is a victim, not a failure point, which is the posture the whole report needs toward maintainers.

Candidate use: §3 lead sentence.

---

Each new victim becomes a carrier.

*(final_presentation_deck.md:108)* The worm's propagation engine in five words.

Candidate use: §3, Shai-Hulud mechanics. The citable version of the same mechanic, for the sentence that needs a footnote: *"Using the stolen npm token, the malware authenticates to the npm registry as the compromised developer. It then identifies other packages maintained by that developer, injects malicious code into them, and publishes the new, compromised versions to the registry."* — Unit 42, `shai-hulud-unit42` *(incident-shai-hulud.md:72-75)*. The harvested credential was an npm token read from `.npmrc` — the path that bypasses 2FA entirely.

---

In about a day, a single infection became roughly 500 compromised packages, including one that was downloaded more than two million times a week.

*(final_presentation_deck.md:108)* Scale as a sentence rather than a statistic. The 500 figure is operator-confirmed and citable: GitHub "removed over 500 compromised packages and blocked uploads containing malware indicators" — GitHub Blog, 2025-09-23, `shai-hulud-github` *(incident-shai-hulud.md:63-66)*.

Candidate use: §3.

---

Shai-Hulud's engine is auto-republish under the legitimate identity — harvested token, new malicious version live in the registry, no human in the loop. That is exactly the leg a quorum gate severs.

*(incident-shai-hulud.md:143-145, tightened)* The clean statement of why this incident is the proxy's best case.

Caveat that must travel with it: the proxy "defends the **publish surface**, not the developer's whole secret store … it makes the *token harvest ineffective for publishing*; it does not make the machine unharvestable" *(incident-shai-hulud.md:159-163)*. The worm still steals the secrets; it just cannot spend them on a release.

Candidate use: §3 close / §4 hinge.

---

The ecosystem scrambled. npm and GitHub revamped their security — mandatory 2FA on local publishing, granular tokens with seven-day lifespans, Trusted Publishing, hardware keys replacing TOTP. All very serious and good changes. But two months later it came back, and bigger.

*(final_presentation_deck.md:151; the response list is verbatim from GitHub Blog, "Our plan for a more secure npm supply chain", 2025-09-23, `shai-hulud-github`, via incident-shai-hulud.md:91-97)*

"All very serious and good changes" is load-bearing. Conceding the controls are competent *before* showing they were walked around is what makes §4 read as analysis rather than as a strawman. Do not cut it for space.

Candidate use: §3, the recurrence turn — and the setup §4 needs.

---

Every fix hardened *who publishes* — and it kept surfacing.

*(final_presentation_deck.md:138)* The §3→§4 hinge in eight words. This is the sentence that converts the incident narrative into the positioning argument: every measure strengthened who authenticates or how the token is scoped, and none of them asked whether the artifact should ship.

Candidate use: §3 closing line, or §4 opening line. It is the seam.

---

Every time the ecosystem buries it with a defense, it surfaces somewhere else.

*(final_presentation_deck.md:151)* The sandworm metaphor, earned rather than decorative.

**Accuracy caveat — do not write this as etymology.** The name comes from the worm stamping the literal string `Shai-Hulud` on the public GitHub repos it auto-creates to exfiltrate stolen secrets, after the sandworm in *Dune*; researchers adopted it *(incident-shai-hulud.md:82-84)*. The recurrence is a coincidence the metaphor leans on, not the reason for the name.

Recurrence evidence, all cited: Nov 2025 "Second Coming" — ~700 packages, 25,000+ repos across ~500 GitHub users, ~1,000 new repos every 30 minutes (`shai-hulud-2-wiz`); Spring 2026 TanStack (`shai-hulud-tanstack-snyk`); Jun 2026 Red Hat, 32 packages; Jul 2026 AsyncAPI (`shai-hulud-landscape-unit42`).

Candidate use: §3. Use once, and only if the metaphor is going to be paid off — otherwise cut it and keep the timeline.

---

On July 14, 2026, attackers pushed commits to unprotected pre-production branches of four AsyncAPI repositories that **"bypassed all human review,"** triggering GitHub Actions to publish five trojanized `@asyncapi` packages.

*(incident-shai-hulud.md:127-132)* — Unit 42, *The npm Threat Landscape*, updated 2026-07-15, `shai-hulud-landscape-unit42`.

The sharpest single datum in the corpus: an automated pipeline that "bypassed all human review" is precisely the leg an m-of-n *human* gate re-inserts. It is also the most recent, which makes the problem present-tense rather than historical.

Candidate use: §3 recurrence, or §4 as the closing evidence that the gap is still open.

---

The May 2026 TanStack wave's malicious packages "were published via **OIDC trusted publishing** after cache poisoning, not by stealing credentials directly," and "produced validly-attested **SLSA Build Level 3** provenance for malicious packages — the first documented case of this kind."

*(incident-shai-hulud.md:110-114)* — Snyk, `shai-hulud-tanstack-snyk`. 84 artifacts across 42 `@tanstack/*` packages.

Does double duty: in §3 it is the recurrence walking around the newest control, and in §4 it is the empirical kill-shot for the provenance row — attackers published *through* the OIDC endpoint and minted valid attestations for malware.

Candidate use: §3 and §4. Cite once, reference twice.

---

Over a period of more than two years, an attacker using the name "Jia Tan" worked as a diligent, effective contributor to the xz compression library, eventually being granted commit access and maintainership.

*(incident-xz-backdoor.md:54-57)* — Russ Cox, *Timeline of the xz open source attack*, `xz-timeline-swtch`.

By every mechanical test, the attacker was a legitimate maintainer by ship time: first innocuous patch 2021-10-29, first release tagged by Jia Tan 2023-03-18 *(:61-63)*.

Candidate use: §3 second case.

---

Every control that should have stopped XZ was satisfied — the committer authenticated, the release was signed by the legitimate process, the build was authentically the project's own — because the malice originated *inside* the trust boundary.

*(incident-xz-backdoor.md:32-34)* The §3 second-case lead, and the sentence that makes XZ worth its page space: it is the case where every column of the §4 matrix reads green and the outcome is still CVSS 10.0.

Compresses to the same point from the spec side: *"XZ Utils is the proof: that was a trusted maintainer, and no amount of authentication would have stopped them."* *(docs/mvp-prd.md:13)*

Candidate use: §3, and referenced again in §4 and §7.

---

"That line is *not* in the upstream source of build-to-host, nor is build-to-host used by xz in git. However, it is present in the tarballs released upstream."

*(incident-xz-backdoor.md:95-97)* — Andres Freund, oss-security disclosure, `openwall-xz-backdoor`.

The decisive fact: the malice lived in binary test fixtures and the release tarball's build machinery, not in the human-readable git source. Caught by accident via a ~0.5 s SSH login slowdown *(:105-108)*, not by any control. CVSS 10.0, versions 5.6.0–5.6.1, `cve-2024-3094`.

The "caught only because someone investigated half a second of latency" clause is quotable on its own and is the strongest available argument that detection was not the thing that worked here.

Candidate use: §3.

---

A genuine quorum approves genuine-looking bytes, and that is a legitimate approval by construction. The proxy binds the decision to the right bytes and puts them in front of humans; it is **not a detector of malice** and never claims to be.

*(incident-xz-backdoor.md:138-143)* The honest ceiling on the entire contribution, and the reason the evaluation is credible. Must travel with any XZ discussion.

What the proxy *does* still add against this case: a review-surviving payload that passes quorum "leaves m permanent, provable co-signatures on the exact bytes … a signed record of who authorized these bytes" *(:147-152)* — residual deterrence through non-repudiation, explicitly not prevention. Or, from the threat model: *"This is deterrence, not prevention … it prices participation: each member's involvement is permanent and provable."* *(CORE-3-insider-collusion.md:24)*

Candidate use: §3 (stated where XZ is introduced), §4 (where the matrix scores it), §7 (limitations). State it once properly and cross-reference.

---

event-stream and ctx share one leg with the marquee Shai-Hulud case: a single identity — earned trust, stolen token, or hijacked account — can turn a compromise into a live malicious release with no second human in the loop. The m-of-n publish gate breaks exactly that leg.

*(incident-landscape.md:145-148)* The unifying pattern sentence: it lets the report claim a *class* from three incidents without narrating three incidents.

Supporting breadth, if there is room for a clause each: ctx — a domain registered 2022-05-14T18:40:05Z, a password reset "just 12 minutes later," 27,000 malicious versions downloaded, no MFA on the owner account, an ~8-year-dormant project hijacked via a $5 expired-domain re-registration (`ctx-pypi-incident`, *incident-landscape.md:93-96*). Backstabber's Knife Collection — 174 real malicious packages, 56% trigger on installation, 61% typosquatting (`backstabbers-knife`, DIMVA 2020, *:107-110*).

Candidate use: §1 or §3. The 12-minutes-and-$5 detail is the most vivid single fact in the corpus.

---

The proxy never has to *detect* the malicious code — it gates the *release event*, which an attacker holding only stolen credentials cannot obtain. Whatever the payload does, it does nothing if the version never ships.

*(incident-landscape.md:150-154)* Connects the "56% trigger on install" base rate to the design decision: gate the event, not the artifact. It is also the cleanest pre-emption of "but how do you know the code is bad?" — the answer is that the proxy does not need to know.

Candidate use: §4 or §5. Pairs with the XZ honest-limit fragment above, which bounds exactly this claim.

---

They all miss for the same reason: every one ensures *you are who you say you are* and *that the artifact is intact*. Not one asks the question that actually decides a supply-chain attack — should this release be going out at all?

*(final_presentation_deck.md:238)* The best statement of the gap in the corpus. It beats `mvp-prd.md:13` ("no concept of multi-party authorization for a publish") because it names the two layers that *do* exist and the question neither one asks, so the missing layer is defined by its job rather than by its absence — which is what makes it a positioning argument instead of a complaint.

Candidate use: **§4 thesis sentence.** Everything else in the section is evidence for this.

---

So who should be answering that question? The package's owners. The problem is that nothing ever gave them the ability to.

*(final_presentation_deck.md:295, lightly tightened from the spoken "The human owners, obviously!")* The pivot from gap to contribution. "Nothing ever gave them the ability to" reframes the whole project as *supplying a missing capability* rather than *adding another control* — the more defensible and more interesting claim, and the one that makes §7's advocacy follow naturally.

Candidate use: §4, immediately after the thesis sentence.

---

What is missing is a layer *above* them — authorization. Not *are you who you say you are*, but *did the people responsible for this package actually decide to ship it?*

*(final_presentation_deck.md:295)* The authentication/authorization distinction as a question pair. Clearer than every spec version of the same point, because a reader can hold two questions in mind more easily than two abstract nouns.

Candidate use: §4, the "authorization layer vs. authentication layer" beat the outline opens on.

---

Every control the industry built to stop a poisoned release, against every way a release gets poisoned.

*(final_presentation_deck.md:207)* States Table I's *method* in one line: it is a cross-product, not a survey. Tells the reader how to read the table before they read it.

Candidate use: **Table I caption**, or the sentence that introduces it.

---

No existing control enforces m-of-n human authorization of a registry publish bound to the exact artifact. The proxy fills that gap.

*(controls-matrix/README.md:6-8)* The matrix thesis — the claim Table I exists to support. Note the four qualifiers are all load-bearing: *m-of-n*, *human*, *registry publish*, *bound to the exact artifact*. Drop any one and a competitor row satisfies it.

**Scope caveat that must travel with the matrix:** each cell is *argued and cited, not empirically tested* — "the evidence is the control's *own documented behavior* plus real incidents where it was in place and failed" *(README.md:72-74)*. State this where the matrix is introduced, not in a footnote. It is the honest description of what Claim 1 rests on, and stating it plainly is stronger than letting a reader discover it.

The four scenarios every control is stressed against: **stolen credential** (Shai-Hulud), **trusted insider** (XZ), **compromised CI**, **direct publish** *(README.md:16-20)*.

Candidate use: §4, introducing Table I.

---

The proxy operates one layer up, at **authorization time**: it requires m-of-n independent, re-authenticated approvals bound to the exact artifact by hash, before the publish credential is ever used.

*(ctrl-mandatory-2fa.md:63-66; also ctrl-trusted-publishing.md:69-71, ctrl-build-provenance.md:85-86)* The anchoring transition. It appears verbatim across three control notes — **use it once in the report, not per-control**, or it reads as a refrain.

Candidate use: §4, once, as the hinge between the competitor rows and the proxy row.

---

Provenance answers *"where did this come from?"*; the proxy answers *"should this ship?"*

*(ctrl-build-provenance.md:84)* The integrity-vs-authorization pivot in one line.

Candidate use: §4, provenance row.

---

Per-control gap explanations — the matrix cells, argued. Each compresses a whole `ctrl-*.md` note; the spoken one-liner and the cited version are given together so the report can use whichever the sentence needs.

**2FA / MFA** *(axis: authentication)*
> 2FA gates *who logs in*, and only optionally — and bypassably — gates the publish action itself. It never authorizes *which artifact* ships. *(ctrl-mandatory-2fa.md:21-22)*
Spoken: *"Publish tokens don't use MFA, so it only protects password theft."* *(deck:235)*
Citable: a bypass-2FA token "will bypass all 2FA requirements at all times, regardless of account-level or package-level 2FA settings" — npm Docs, `npm-2fa-publish` *(:38-40)*. Caveat for the `~` verdict: 2FA stops a stolen *password*, not a stolen *token* *(:57-59)* — which is exactly the credential Shai-Hulud harvested from `.npmrc`.

**Trusted Publishing / OIDC** *(axis: authentication, scoped short-lived credential)*
> Because trust is delegated to the CI workflow's identity, **whatever that workflow builds publishes authentically** — a subverted build is a validly-signed publish. *(ctrl-trusted-publishing.md:22-24)*
Spoken: *"Trusted Publishing shuts down a stolen static token, but pretty much nothing else."* *(deck:235)*
Citable: Ultralytics — "The second round of malicious releases came from the attacker using an unrevoked PyPI API token that was still available to the GitHub Actions workflow," in a project *using* Trusted Publishing at the time — blog.pypi.org, `pypi-ultralytics-analysis` *(:44-46)*. Caveat: coverage is "contingent on **operator configuration, not on the control**" *(:59-63)*. Note this is the same shape as the proxy's own PUB-2 precondition — worth conceding the symmetry rather than having a reader find it.

**Build provenance / SLSA / Sigstore / PEP 740** *(axis: integrity attestation, detective)*
> This is the only row in the matrix that **gates no decision at all** … it certifies *where a build came from*, never *what its code does*. *(ctrl-build-provenance.md:22-25)*
Spoken: *"Provenance attests the build, but a poisoned pipeline produces a perfectly valid attestation."* *(deck:236)*
Citable, and normative: "SLSA does not address organizations that intentionally produce malicious software" (`slsa`); "This PEP does not make a policy recommendation around mandatory digital attestations on release uploads or their subsequent verification by installing clients" (PEP 740, `pep740`) *(:42-44, 52-53)*. Confirmed empirically at the limit by TanStack's validly-attested SLSA-L3 malware. Future-work complementarity — flag, do not assert as shipped: make provenance verification "a **precondition of authorization**" and it "becomes preventive" *(:94-97)*.

**GitHub required reviews / branch protection** *(axis: repo merge decision)*
> It governs the repo's *merge* decision … a compromised CI pipeline runs *after* the merge the gate protects, and a direct registry publish never opens a pull request at all. *(ctrl-github-branch-protection.md:15-16)*
Citable: "By default, the restrictions of a branch protection rule don't apply to people with admin permissions … People and apps with admin permissions … are always able to push to a protected branch" — docs.github.com, `gh-about-protected-branches` *(:19)*. Caveat worth stating: the XZ pattern (payload in binary test fixtures no reviewer decodes) is **shared** with the proxy *(:41-42)*.

**CI/CD deployment-approval gates** *(axis: pipeline deploy-job gate, platform-bound)*
> The gate is **platform-bound** … and its approval is bound to *a deployment*, not to the artifact by hash, so an authentically-built poisoned artifact passes review. *(ctrl-cicd-deployment-gates.md:15)*
Citable, and the sharpest single quote in this cluster: GitHub environments — "Only one of the required reviewers needs to approve the job for it to proceed" (`gh-environments-deployment`, *:18*). That is 1-of-n, not m-of-n, in the control that looks most like the proxy. Caveat: "if the compromise lives *in* the gated deploy runner, the gate is already satisfied" *(:40)*.

**Artifact-repo staging/promotion (Artifactory / Nexus)** — flagged as the **closest competitor**
> Separation-of-duties over an artifact move … but promotion is bound to the artifact's **SHA1**, which proves the promoted bytes equal the built bytes — *identity*, not *authorization*. *(ctrl-artifact-repo-promotion.md:15)*
Citable: Nexus separates "Staging: Deployer" from "Staging: Promoter" as distinct roles (`sonatype-nexus-staging`, *:21*).
**Honest boundary, keep attached:** "for **enterprise-internal distribution** … promotion *is* effectively the publish gate and the proxy adds little; the proxy's value is sharpest where promotion cannot follow — publishing to a third-party registry the org does not own" *(:43)*. Conceding this is what makes the rest of the matrix credible.

Spoken summary for the remaining rows: *"Review, deploy, and internal gates each catch a slice and miss the rest."* *(deck:237)*

Candidate use: §4, the matrix walk. Prose per row, not a bulleted list — the outline wants §4 to engage the literature as evidence, not survey it.

---

Not one of these controls completely covers more than one or two columns.

*(final_presentation_deck.md:238)* How to read the matrix, stated so the reader does not have to derive it.

Candidate use: §4, closing the competitor rows.

---

The proxy's decision sits *at the publish point itself*. It holds the sole publish credential and will not release it until m independent, re-authenticated approvals, each Ed25519-bound to the artifact's SHA-256, are cast — *may these exact bytes be published*, decided by m humans who each inspected them.

*(ctrl-the-proxy.md:16)* Table I's row 7, the only all-covered row.

**The two honest limits that must travel with any proxy ✓:**

1. Sole-credential precondition — "the trust model depends on the proxy being the **only** holder of the upstream upload credential … an **operator-enforced operational precondition**, not something the proxy can verify" *(:25-26)*. Detection is post-hoc; "prevention stays operator credential-topology hygiene" *(:37)*. This is the `✓*` on the Direct-publish column.
2. Colluding / review-surviving quorum — the ✓ buys "*no unilateral action* plus *a human gate on the exact artifact* — **not immunity**" *(:39)*.

Candidate use: §4, the proxy row. The limits belong here, where the matrix scores it — not deferred entirely to §7.

---

A single stolen credential can now only **request** to publish, not actually publish.

*(final_presentation_deck.md:296)* Sharper than "yields at most one vote," because naming what the attacker *does* still get is what makes the boundary credible.

Candidate use: §4, reading the proxy row against the Shai-Hulud column. The companion for the other three columns, also spoken: a trusted insider must have their artifact reviewed and it is now attributable to them; compromised CI produces an artifact that does not match what an owner could build themselves; and with the proxy holding the only credential, no individual owner can skip the review stages *(deck:296-299)*.

---

"Requiring multi-party approval for this operation helps ensure that no single individual can unilaterally establish or change the root of trust."

*(primitive-multiparty-approval.md:64-66, 78-80)* — AWS, *What is Multi-party approval?*, `aws-mpa`.

The cleanest external statement of the proxy's own value proposition — written by AWS, about AWS. Worth quoting precisely because it is not the author's sentence.

Candidate use: §4, the pedigree move. Establishes the primitive is real and respected before arguing it is siloed.

---

"Requests are resolved by the first approver who approves or denies."

*(primitive-multiparty-approval.md:125-126)* — Microsoft, *Approve requests for Azure resource roles in PIM*, `azure-pim-approval`.

The sharpest "underused" datum in the corpus: the one *general-purpose* privileged-access product on the market is **1-of-n, not a quorum**. Everything else in the pedigree move is about scope; this one is about the count itself.

Candidate use: §4, pedigree. Pairs with the GitHub environments "only one of the required reviewers needs to approve" quote — two independent vendors, both stopping at one.

---

All three giants have reached for the primitive; not one offers it as a general, cross-platform capability. None can authorize "publish version X of package Y to PyPI, bound to this exact artifact hash."

*(primitive-multiparty-approval.md:165-171)* The payoff for the "underused general primitive" argument, and the evidence behind the deck's opening claim. Each implementation is fused to the platform that ships it.

The one point of cross-vendor convergence worth noting: *backup-vault* protection — AWS Backup MPA ≈ Azure Backup MUA *(:29-31)*. Where two vendors independently reached the same conclusion, they reached it about the same narrow resource.

Candidate use: §4, pedigree close.

---

The security field endorses multi-person approval only in its narrowest codified form. The proxy (a) **generalizes the count** from a fixed two to a configurable m-of-n quorum, and (b) **places it** on a control plane where it is missing entirely — the package-publish action.

*(primitive-sod-multiparty.md:129-133)* "Generalization and placement, not a new primitive" — the precise, defensible statement of the contribution. Consistent with `adr/0006:51` ("the novel contribution is the approval layer, not the auth primitives").

Grounding, citable: NIST SP 800-53r5 — "Dual authorization … require[s] the approval of **two authorized individuals** to execute"; "Separation of duties … helps to reduce the risk of malevolent activity **without collusion**" (AC-3(2), AC-5, `nist-sp-800-53r5`, *:78-79, 95-96*). The flagship federal catalog codifies multi-person approval only as a fixed *two*, confined to "privileged commands." The "without collusion" phrase is the honest limit and should be kept attached — it is NIST conceding the same boundary the proxy concedes at CORE-3. Lineage traces to Clark–Wilson (1987 IEEE S&P, `clark-wilson-integrity`, *:104-107*).

Candidate use: §4, pedigree — the move that turns "someone already does this" from an objection into evidence.

---

Existing web auth proxies implement multi-*factor* authentication for a *single* user — something you know plus something you have — not multi-*person* authentication across several cooperating users.

*(Broad Literature Review.md:17)* The cleanest sentence in the corpus for the factor-vs-person distinction, which is a genuinely useful piece of vocabulary.

**⚠ Guardrail — do not use this as the §4 novelty claim.** The report-facing corpus explicitly rules it out: *"Authelia is not the multi-party primitive. It is single-user forward-auth SSO and therefore does not support this note's §4 argument"* *(primitive-multiparty-approval.md:200)*. `Broad Literature Review.md:9` calls the Authelia/Authentik/Duo/Okta comparison "the project's strongest contribution"; that is **design-time research the report-facing corpus has superseded**. §4's adoption argument is Move 3 — hyperscaler multi-party approval, siloed per control plane — and auth proxies are not part of it. Naming Okta as a defeated competitor invites the correct objection that it was never trying to do this.

Candidate use: the *distinction* is reusable anywhere the report needs to separate multi-factor from multi-person — most naturally §1, one clause. The *competitive claim* built on it: **do not use.**

---

Every deployed multi-party-approval system is bound to a single resource type — a vault, a backup operation, a blockchain transaction, an account-recovery flow. That is the precise opening this project fills.

*(Broad Literature Review.md:56)* The gap in two sentences, and the best available closer for the Related Work work that §4 is absorbing.

Concrete comparators, each with its differentiator: **AWS MPA** — "Sessions expire 24 hours … Expired sessions and non-responses from approvers count as rejections," gating one backup-recovery operation *(:51)*. **SLSA Level 4** — two-party review "governs source review, not a runtime access decision" *(:43)*.

Two more that make the siloing vivid *(evaluation-plan.md §1 Move 3)*: Google offers the primitive twice over (Cloud PAM multi-approver grants, Workspace admin-setting approval), and the AWS↔Azure convergence is on **backup vaults specifically** — two independent clouds picking the same narrow resource is a sharper illustration of boundedness than either one alone *(primitive-multiparty-approval.md:29-31, 194-196)*.

**⚠ Vault does not belong here.** *"Vault → C1, not P1. Shamir unseal is key custody, often auto-unsealed; citing it as industry human-approval adoption would overclaim"* *(primitive-multiparty-approval.md:197-199)*. Its real home is the **Appendix crypto rationale**, as lineage: threshold m-of-n is the shipped default of a mainstream secrets manager, and HashiCorp recommends auto-unseal for most users — a shipped m-of-n so operationally heavy the vendor recommends turning it off, which is precisely the usability argument for the credential-backed variant *(ADR 0001 §4)*.

Candidate use: §4 Move 3 close — the "every adoption is welded to one control plane" payoff.

---

There is no role that allows project membership without upload rights. A legitimate maintainer can always publish a new release unilaterally. PyPI's permission model provides no mechanism for separation of duties between project association and publish capability.

*(PyPi Use Case Research.md:47)* The concrete platform gap, precisely stated — the evidence under "adding a maintainer means handing out unilateral publish rights."

Generalized, and citable as a systemic claim: "No major public package registry (PyPI, npm, RubyGems, crates.io, Docker Hub) natively supports multi-party publish authorization. This is a systemic supply chain security gap, not a PyPI-specific issue." *(:217)*

Candidate use: §4. This is the sentence that earns the report the right to build a proxy rather than file a feature request.

---

For PyPI, the natural analogy is GitHub's branch protection rules — a developer can push code, but it will not merge without required reviewers.

*(PyPi Use Case Research.md:230)* The most intuitive analogy in the corpus for a reader who is not a supply-chain specialist. It borrows an intuition the audience already has and moves it one layer down the pipeline.

Candidate use: §4 or §1. Use it early — it makes everything after it cheaper to explain.

---

Dependency confusion — "yielding remote code execution across 35+ organizations including Apple, Microsoft, PayPal, and Netflix" — is a name-resolution attack, not an authorized-but-malicious publish, so it sits outside an approval gate.

*(primitive-sod-multiparty.md:110-114)* — `birsan-dependency-confusion`; taxonomy via Ladisa et al., *SoK*, IEEE S&P 2023, `ladisa-sok-supply-chain`.

A scope boundary stated with its most impressive-sounding counterexample, which is the right way to do it: naming the attack the proxy does *not* address, at its most famous, costs nothing and buys precision. Same shape as: "there is no victim publish event to authorize, so the proxy has nothing to gate" *(docs/evaluation-plan.md:84)*.

Candidate use: §4 scope boundary, or §7.

---

The proxy shows the pattern is technically achievable today, even within existing platform constraints. That makes the case that native platform support is a matter of prioritization, not feasibility.

*(PyPi Use Case Research.md:221)* The advocacy thesis in two sentences, and the bridge from §4's gap to §7's native-integration future work. Pairs with *"Trusted Publishing is proof the community will change the publish path when the case is strong"* *(deck:611)*.

Candidate use: §4 close or §7 Future Work.

---

An upload is **held, not published**, until the package's owners authorize the exact artifact.

*(final_presentation_deck.md:326)* **Leading phrase.** The entire mechanism in three words, and reusable everywhere in the report — it is what the proxy *does*, stated so a reader never has to hold the architecture in mind to follow an argument about it.

Candidate use: §5 opening. Also §1's "Solution in Brief."

---

From this moment the thing under review is that one specific set of bytes.

*(final_presentation_deck.md:341)* Hash binding explained without the word "hash." The best available gloss for a reader who does not yet know why binding matters — it makes the property intuitive before the mechanism arrives.

Candidate use: §5, the hash-bind stage.

---

The re-check immediately before publishing — not the upload-time hash alone — is what guarantees the artifact cannot be silently swapped between approval and publication.

*(docs/use-cases/01-package-publishing.md:78)* Locates the guarantee at the *right* place. Most readers will assume the upload-time hash does the work; it does not. The executor re-verifies `SHA-256(held artifact) == action_hash` immediately before publishing and refuses on mismatch — a property that holds "even against full write access to the artifact store" *(PUB-1)*.

Spoken version: *"the release that goes out is byte-for-byte identical to the one they signed off on"* *(deck:344)*. Corollary: *"Approvers cannot approve a 'future upload.'"* *(docs/constraints.md:45)*

**Keep the claim narrow.** The on-slide line is *"The owners approve one exact artifact — and that's the artifact that ships"* — deliberately narrowed from an earlier draft that said "even if the proxy is compromised." A fully compromised proxy holds the PyPI token and can publish directly, so hash-binding does **not** prevent that. What survives proxy compromise is *detection*: forged approvals fail Ed25519 verification in the signed audit trail.

Candidate use: §5. The narrowing note is a guardrail, not prose.

---

It publishes only when m-of-n owners have approved, and any single denial kills it.

*(final_presentation_deck.md:343)* The quorum rule and the denial rule in one sentence.

Candidate use: §5.

---

The deny path is deliberately never throttled — a deny forges no approval and is the one action that halts an attack, so throttling it would only let an attacker exhaust the budget to suppress a legitimate denial.

*(docs/approver-authentication.md:79)* The best asymmetric-design argument in the project: it reasons from *what an attacker could do with the rate limit* rather than from a uniform policy. Small, concrete, and it shows the threat model actually drove the implementation — exactly the kind of detail that makes §5 credible on 1.5 pages.

Candidate use: §5. High value per word; keep it even under budget pressure.

---

Approval links are deliberately not secrets — the request id is guessable by design, and security rests on per-vote authentication. The single-use TOTP burn already *is* a server-enforced nonce per `(user, time-step)`.

*(VOTE-2:44-50; simpler form at CONTEXT.md:84 — "The link itself is not secret; security comes from the re-authentication step.")* The "TOTP burn *is* the nonce" reframing is the sharp part: a property the system already had, recognized rather than added.

Candidate use: §5, or the Appendix.

---

Both use cases run through the **same approval core** and differ only in what happens *after* quorum.

*(docs/use-cases/00-overview.md:6)* The cleanest statement of the architectural thesis, and the design-level evidence for the generality argument §7 makes.

Companion: *"The Approval Request owns the vote. Its whole life is the m-of-n decision; it reaches a terminal state and does no post-approval work itself."* *(:9)*

**⚠ Scope guardrail (#109).** Generality is **framing and advocacy, never an evaluated claim.** The shared-account / forward-auth second use case is cited as *designed-for evidence*, and the corpus is candid about why it stays in scope: *"It is the better narrative but the weaker security case, retained for relatability and to demonstrate generality"* *(:49)*. The practicum has narrowed to package publishing as the evaluated use case.

Candidate use: §5 (one line, architecture), §7 (generality, labeled unevaluated).

---

A policy change on a live vote is exactly the attack we are denying.

**Report voice:** A policy change applied to a live vote is exactly the attack the design denies.

*(docs/adr/0008:39)* The security case for snapshotting the approver set and threshold at request creation, in one sentence. The spec's "we" here means the designers, which the style guide rules out for a paper.

The threat it closes: "If configuration changes applied to live requests, a compromised admin could lower the threshold or swap in a colluding approver *while a malicious request is pending*" *(:26)*. The resulting property: "The request carries a fixed, signed statement of exactly what it required ('2-of-{Alice, Bob, Charlie}'). A rule that mutates mid-vote is unauditable" *(:25)*.

Paired design tension, resolved: "Append-only supersession keeps both properties — **non-repudiation** (every decision, including a reversal, is signed and never erased) and **flexibility** (the effective vote can change until the request leaves `pending`)" *(adr/0009:8)*.

Candidate use: §5 or §6. This is the kind of detail that shows the design was threat-driven rather than feature-driven.

---

A tempting single fix — give the server its own signing key and sign everything with it — was rejected at the approval layer: it would make the **host** a signing authority over approvals, so a host compromise could manufacture approvals wholesale.

*(docs/adr/0015:31)* The design story worth telling if §5 has room for exactly one.

The resolution: "Approval integrity must **not** rest on a server-held key … But the audit trail has *no approver in the loop* to sign its system-emitted rows, so it *needs* a server-side mechanism. The two surfaces therefore resolve to **two different trust roots**." *(:35)*

The asymmetry, stated honestly: the audit trail's "best available root against a *database-write* attacker is a key the host holds; that is strictly weaker … but strictly better than the nothing it replaces" *(:86)*. And the ceiling: "The only mechanism that beats a host attacker is an **external append-only sink** (e.g. S3 Object Lock)" *(:108)* — which is HOST-1's honest limit and a §7 future-work item.

Slogan for the key separation: *"One operator secret, two non-interchangeable keys."* *(:80)*

Candidate use: §5 or §6. Probably too long for §5's 1.5 pages — a strong Appendix candidate with a one-line pointer in the body.

---

Each primitive has exactly one role. These are not conventions — they are invariants; violating any one of them collapses the security argument of the entire scheme.

*(docs/cryptography.md:26)* The flagship crypto-design sentence.

The triad it introduces: "The bcrypt output is never used as key material. The PBKDF2 output is never stored. The Ed25519 private key is never written to disk in plaintext." And the reason the password is the hinge: it is "load-bearing three ways — the bcrypt login verifier, the PBKDF2 input that wraps the user's Ed25519 signing key, and the PBKDF2 input that wraps the TOTP secret" *(docs/account-management.md:132)*.

Honesty about scope, from the same doc: *"What is cryptographically signed is precise; over-claiming it would itself be a false security statement."* *(:290)*

Candidate use: §5 one line ("the crypto is inherited-secure, not a novel claim"), full development in the Appendix — that is exactly what `primitive-crypto-choices.md`'s `report_home` specifies.

---

Notifications are a best-effort subscriber to an event stream, never a step the approval flow waits on.

*(docs/adr/0005-decoupled-notification-system.md:68)* One line, and it pre-empts "what if email is down?" — an availability question a reader will otherwise raise against a system whose whole flow appears to run on email.

Candidate use: §5.

---

The demo is legible; the suite is worst-case-rigorous.

*(docs/evaluation-plan.md:102, condensed)* The division of evidentiary labor, and the answer to "why is your headline evidence a video?" Pairs with *"A green test log is rigorous but illegible on video"* *(docs/evaluation-demo.md:9)*.

The strict boundary case — t = m−1, two fully-compromised seats plus one honest deny, race-free — is carried by the **pytest adversarial suite**, not the demo. Say this explicitly; it is what keeps the demo from looking like the whole evaluation.

Candidate use: §5, introducing the evidence.

---

The request freezes at 2/3 and waits — the proxy will not publish without quorum, no matter who is awake.

*(docs/evaluation-plan.md:102)* "No matter who is awake" is the vivid clause, and it is the single sentence that makes the 2 a.m. scenario land.

The narrative device, articulated: "the cheerful heads-up here becomes conspicuous silence in Act 2 — nobody announces the 2 a.m. publish, which is exactly the anomaly the diligent co-owner notices" *(docs/evaluation-demo.md:16)*. The differentiator in four words: **"denies on human context — no code review"** *(:17)*. Spoken: *"She reaches out to Charles out of band"* *(deck:410)*; *"Because Ada denied, the package doesn't go through, no matter how many approval votes there are"* *(deck:412)*.

What it dramatizes, per the plan: "two differentiators at once — enforced friction/latency (time to think) and human-context anomaly detection (no security expertise required)" *(evaluation-plan.md:102)*. Note the second one is the stronger claim: the honest co-owner needed *no security expertise*, only context.

Also useful — approval fatigue shown rather than asserted: *"Being late in the night, Grace approves without much thought"* *(deck:408)*, which is VOTE-4 dramatized, and it is the same threat §6 has to concede.

Candidate use: §5 evidence, and the Fig 2 "2 a.m. timeline" if it survives. It is *illustrative*, not the rigorous t = m−1 test — keep that distinction visible.

---

So let me ask the question you might already be asking: doesn't this add new risks? Yes, it honestly does.

**Report voice:** Does interposing a proxy add new risks? It does. This section accounts for all of them.

*(final_presentation_deck.md:469)* The §6 opener. The rhetorical question survives the register change — what has to go is *"let me ask"* and *"you might already be asking,"* which address the reader directly. Asking and answering in the report's own voice keeps the concession-first structure without the podium. Voicing the objection in the reader's own words and conceding it flatly, before enumerating anything, is what makes the net-delta model read as an audit rather than a defense.

Candidate use: **§6 opening move.**

---

I took the risk that used to be spread across every maintainer's laptop and put it behind one gate. So did I just build one big juicy target? Yes — compromise the proxy's host, its database, or its admin account, and you've defeated it.

**Report voice:** The design moves risk that was distributed across every maintainer's workstation and concentrates it behind a single gate. That gate is a correspondingly attractive target: compromising the proxy's host, its database, or its administrator account defeats the control entirely.

*(final_presentation_deck.md:470)* The best statement of concentration-of-risk in the corpus, and nothing in the threat model says it this plainly. The plainness is the point: it is the project's worst residual risk, stated in one breath with no hedge, which is what buys credibility for the 32 threats that follow. It also sets up §7's native-integration payoff, where this specific risk dissolves.

Candidate use: §6, the Introduced class — lead with it.

---

The whole design relies on people — which means it also inherits how people fail.

*(final_presentation_deck.md:471)* The human-factor family's thesis: it explains *why* VOTE-1..5 exist as a group rather than listing them. The named exemplars: approval fatigue (VOTE-4), a coerced click (VOTE-3), a replayed credential (VOTE-2).

Candidate use: §6.

---

I turned publishing into a gate, which adds friction. And a gate is something you can target.

**Report voice:** Turning publishing into a gate adds friction — and a gate is something an attacker can target.

*(final_presentation_deck.md:472)* Availability in two sentences; the friction/target duality is the whole DOS family. The two shapes: *"Flood it, or just have one approver sit on every request and simply never vote"* — one external, one internal.

**Pair it with the other half of the friction argument:** *"The friction is the point, not a defect. A publish is a rare, high-stakes event. Trading minutes-to-hours of approval latency for 'no single point of compromise' is a good deal for this operation."* *(docs/mvp-prd.md:32)*

Together they are the honest both-sides: friction is the mechanism *and* the attack surface. Putting them adjacent is stronger than either alone, and it pre-empts the reader who thinks they have spotted a flaw.

Candidate use: §6, Availability.

---

The security claim is a net delta, not an absolute. Rather than claim the proxy "resists everything in its threat model," the evaluation measures the *change* the proxy makes relative to the direct-publish baseline.

*(docs/evaluation-plan.md:19)* The framing move the whole of §6 depends on. Use this live version, not the disabled `PR4.tex` draft of the same idea.

Candidate use: §6 methodology, stated before any counts.

---

The honest headline: the proxy closes a large pre-existing gap (Improved) at the price of a bounded, enumerated new attack surface (Introduced), while explicitly not addressing an orthogonal authentication layer (Inherited).

*(docs/evaluation-plan.md:24)* The three-class model in one citable line. If §6 has one sentence a reader remembers, this is the candidate.

The counts, tool-verified: **24 introduced · 5 improved · 4 inherited = 33**; the proxy **owns** improved + introduced, **29 of 33**, and reports its four-bucket classification over exactly those. The 4 inherited carry `bucket: N/A` and are reported as a scope statement, not defended threat-by-threat *(threat-model/00-overview.md:40-48)*.

Candidate use: §6, and a compressed form in the abstract.

---

Every owned threat is assigned one evaluation bucket — the honesty axis of the model, answering *how do we know the defense holds?*

**Report voice:** …the honesty axis of the model, answering *how is the defense known to hold?*

*(threat-model/00-overview.md:52-53)* The best one-line gloss of the bucket axis, and it names the axis's *purpose* rather than its values, which is what a reader needs. Only the "how do we know" needs converting; the rest carries over unchanged.

Related precision, worth keeping: "delta classifies **mechanism ownership, not outcome size**. Severity comparison *illustrates* delta; it does not *define* it." *(evaluation-plan.md:190)*

Candidate use: §6, introducing Table II.

---

The (likelihood, severity) pair — a cell in a qualitative matrix — *is* the risk statement. Arithmetic over ordinal scales, DREAD-style multiplication or averaging, has no defensible semantics and is explicitly rejected.

*(docs/evaluation-plan.md:166; taxonomies.md:145-147)* A genuine methodological stance, and one of the few places the report can show judgment rather than execution.

Two citable authorities, both from DREAD's own side: co-author David LeBlanc called its scoring an **"obvious malfunction"**, and wrote *"If we're going to have big error bars, let's simplify matters and drop back to high, medium and low"* (`dread-leblanc`, *taxonomies.md:147-149; method-threat-modeling.md:94-95*). Citing the author against his own framework is stronger than asserting the objection.

Companion three-token precision: **"tamper-evident ≠ tamper-proof"** *(threat-model/CONTRIBUTING.md:209)* — states exactly what the integrity tier claims, and nothing more.

Candidate use: §6 methodology. Worth the space — it is a defensible choice a reviewer might otherwise assume was an omission.

---

That argument is only credible if "pre-existing" is anchored to a recognized, real-world taxonomy rather than asserted. Mapping each threat to its ATT&CK technique(s) provides that anchor.

*(threat-model/taxonomies.md:62-66)* Why ATT&CK is in the model at all — it is what keeps "inherited" from being a convenient label the author assigned himself.

The two-lens split, tightest form: "STRIDE — *which property is violated?* … MITRE ATT&CK — *which real-world behavior is this?*" *(:119-120)*. Neither is claimed as a completeness proof; keep that caveat attached.

Candidate use: §6 methodology.

---

Ratings and buckets must be allowed to produce non-flattering answers, or they are worthless as evidence.

*(threat-model/CONTRIBUTING.md:214-218)* The honest-audit guarantee, stated as a rule the author bound himself to in advance — which is far more persuasive than claiming impartiality after the fact. Companion: *"Current defenses is an audit, not an aspiration."* *(:274)*

Candidate use: §6 methodology, or §7 limitations.

---

This number is only as trustworthy as the threat list itself, which I, working with AI, authored. This self-enumerated model could risk introducing blind spots that I would never think to test or attack.

**First person is correct here.** This describes something the author did manually — authored a threat list, working with AI — and it is precisely the case the style guide reserves first person for. Converting it to "the threat model was authored" would hide the actor, which is the whole reason the admission carries weight.

*(PR3.tex:128 — live prose, in your own voice; prefer this over the disabled PR4 block)* The strongest honesty beat in the corpus. It names the limit of a self-authored threat model and the words "self-grading" appear two lines later.

The candid raw version, if a sharper form is wanted: *"I built the threat model in a week. Most companies and most projects continually update a threat model for a long time. And so I'm not confident that all of the threats that this project faces is in the threat model."* *(PR4.tex:191, raw notes)*

Candidate use: §7 limitations. This is the fragment that most makes the evaluation believable — a reader who finds this weakness themselves discounts everything; a reader who is handed it trusts the rest.

---

This plan does not depend on any other person using the system. Every result is either an automated test outcome or a cited analytical argument. No survey, interview, or satisfaction score is fabricated to stand in for real users.

*(docs/evaluation-plan.md:29)* Directly answers the single-operator / no-human-subjects concern, and the third sentence is the one that matters — it forecloses the suspicion rather than hoping it does not arise.

Companion, the strict binary oracle: *"Pass = zero unauthorized publishes across all trials; any single bypass = fail."* *(docs/mvp-prd.md:89)*

Candidate use: §6 methodology or §7.

---

Any override one person can pull is a backdoor around quorum, and reintroduces exactly the single point of failure the system exists to remove.

*(docs/mvp-prd.md:96)* The anti-break-glass argument in one sentence. Pre-empts the most common practitioner objection ("what if you need to ship urgently?") by showing the objection asks for the vulnerability back.

Candidate use: §5, §6, or §7. Wherever the reader is most likely to be forming the objection.

---

The proxy's guarantees rest on a few steps it **can't enforce for you**.

**Report voice:** The proxy's guarantees rest on several deployment steps it cannot enforce for itself.

*(final_presentation_deck.md:522)* The cleanest framing of the operator-precondition class, and better than the catalog's "operator-enforced" because it says *whose problem it is* and *why* in the same clause.

Candidate use: §7, opening the deployment-precondition beat.

---

Leave an old maintainer token live and an attacker doesn't have to beat the quorum — they just **publish around it**.

**Report voice:** If any pre-existing maintainer token remains live, an attacker need not beat the quorum at all — they publish around it.

*(final_presentation_deck.md:532)* PUB-2 in one sentence, and **"publish around it"** is a leading phrase: it makes the bypass concrete in a way "proxy bypass" never does.

The precondition it rests on: "Revoke all pre-existing project API tokens … so the sole upload credential lives in the proxy (PUB-2)" *(operator-checklist.md:59)*. This is also the precondition behind Table I's `✓*` on the Direct-publish column, so §4 and §7 are describing the same fact from two directions — worth making that link explicit rather than letting it read as two separate caveats.

Honest current state: a bypass is now *detected* at bucket ① by out-of-band publish reconciliation, but *prevention* stays operator credential-topology hygiene — detection bounds the exposure window, it does not stop the unmediated credential from publishing *(evaluation-plan.md:66)*.

Candidate use: §7, the first of the two weighted operator preconditions.

---

Set the quorum high enough to mean something, low enough that losing one approver can't freeze a release.

**Report voice:** The threshold must be high enough to mean something and low enough that losing a single approver cannot freeze a release.

*(final_presentation_deck.md:526)* The quorum trade-off, and it beats the spec version *(CONTEXT.md:35)* because it names both failure modes symmetrically, one clause each, with no jargon.

Grounding: "Set quorum thresholds accounting for approver availability (losing one approver must not block operations) (DOS-3, DOS-4)" *(operator-checklist.md:48)*. The co-owner-selection half is the CORE-3 knob, which §7 then elevates into a stated non-goal — a knob becoming a limitation is a clean transition, not a repetition.

Candidate use: §7, the second weighted precondition, handing directly to the collusion limitation.

---

Raising the bar from one person to several was never a promise to survive everyone you trusted turning at once.

**Report voice:** Raising the bar from one person to several was never a promise to survive every trusted party defecting at once.

*(final_presentation_deck.md:562)* The best CORE-3 sentence in the corpus. The rendering costs almost nothing here — only *"everyone you trusted"* has to go, and *"every trusted party"* keeps the cadence. It converts the collusion limitation from an *admission* into a *statement of what was actually promised* — which is both more honest and more defensible, because it shows the boundary was designed rather than discovered.

The catalog's own framing, if a more formal register is needed: "Bucket ④, and deliberately so: at L9, multi-party authorization is definitionally defeated — no mechanism inside the proxy can tell a corrupt consensus from a real one … stated rather than papered over" *(CORE-3:46)*; "m genuine votes from m genuine accounts is a legitimate approval by construction" *(:22)*; "The quorum requirement protects against a single compromised identity — not against coordinated betrayal by a majority" *(docs/constraints.md:55)*.

What remains: "This is deterrence, not prevention … it prices participation: each member's involvement is permanent and provable" *(:24)*.

**Note the delta subtlety.** CORE-3 is `delta: improved`, `bucket: ④` — the proxy *improves* on the single-maintainer baseline (m colluders now required, not one) while the fully-colluding quorum stays an accepted limitation. Writing it as flatly "out of scope" understates the project's own result.

Candidate use: §7 limitations, lead. XZ Utils is its worked example.

---

The proxy sits in front of a registry it does not own, so it inherits that registry's weaknesses. If an attacker takes over the PyPI account through its recovery flow, they publish without ever touching the proxy. **I can't fix that from the outside.**

**Report voice:** The proxy sits in front of a registry it does not own, and so inherits that registry's weaknesses. An attacker who takes over the PyPI account through its recovery flow publishes without touching the proxy at all. No bolt-on control can close that from the outside.

*(final_presentation_deck.md:567, 574)* PUB-3, `delta: inherited`. "From the outside" is the clause that earns it: it names the limitation as *architectural*, which is what makes the native-integration pivot follow as a conclusion rather than land as a deflection.

The operator can mitigate (enforce PyPI 2FA, use a group recovery inbox — *operator-checklist.md:61-62*) but the surface itself is inherited and stays inherited.

Candidate use: §7 limitations, second boundary — and the hand-off into future work.

---

Build this gate into the registry itself. The biggest risk the proxy introduces dissolves: the gate **becomes** the registry, which was already the juiciest target in the ecosystem.

*(final_presentation_deck.md:620)* The native-integration payoff, and the reason §6's concentration concession is safe to make. **"Dissolves" is the right verb** — the risk is not mitigated or accepted, it stops existing as a *new* risk, because no additional juicy target is created.

Note the honest scope of the pivot: native integration dissolves **concentration (§6)** and **bypass (PUB-2)** and **PUB-3**. It does **not** fix CORE-3 — a colluding quorum authorizes the release whether the check lives in a bolt-on proxy or inside the registry. Do not let the future-work section imply otherwise; the deck's own grounding note flags exactly this trap.

Feasibility precedent: *"Trusted Publishing is proof the community will change the publish path when the case is strong"* *(deck:611)*, which pairs with *"native platform support is a matter of prioritization, not feasibility"* *(PyPi Use Case Research.md:221)*.

Candidate use: §7 Future Work, the productization path.

---

Instead of one administrator resetting a user's password or second factor, independent recovery approvers would review and authorize the reset.

*(outline.md §7 — quorum-gated credential recovery)* An unevaluated future scenario, and a good one: it applies the primitive to the exact flow that defeats the proxy from the outside (PUB-3 is a registry *account-recovery* takeover), which makes the generality argument land as a solution to a problem the report already showed rather than as a list of places the idea might also fit.

Current state, for honesty: the proxy uses admin-mediated, out-of-band credential recovery.

Candidate use: §7 Future Work & Generalizability. Label unevaluated.

---

Two axes are excluded, with justifications. Performance is human-bound — the system waits on human reaction and approval times, which dwarf any optimization the program itself could make. Formal human-subjects usability is excluded because the system is a proof of concept.

*(PR4.tex:270, tightened)* A ready-to-use scoping paragraph, and the performance argument is genuinely good rather than merely defensive: it explains why the measurement would be *uninformative*, not merely why it was not done.

Related exclusions available if §7 wants to show the boundary was drawn deliberately: **CVSS v4** — "outside this report-facing bucket because it scores vulnerabilities, not baseline-relative design-time threats" *(research-process.md:264)*; **SSDF / EO 14028** — they "govern *process compliance* (SBOMs, signing attestations), not the multi-party-authorization primitive" *(research-process.md:342)*. Keep the "exclusion, not endorsement" framing attached to both.

Candidate use: §7 limitations.

---

APT29 injected malicious code into the SolarWinds Orion *build process* and got SUNBURST signed by SolarWinds' own code-signing certificates. This is **not** the single-actor-publish pattern — the compromise was in the build infrastructure, and the shipped artifact was a legitimately-signed compiled binary.

*(incident-landscape.md:124-141)* — MITRE ATT&CK C0024 (`mitre-c0024-solarwinds`), CISA ED 21-01 (`solarwinds-sunburst-cisa`).

A scope boundary named with its most famous possible counterexample, which costs nothing and buys precision. It pairs with the XZ caveat to bound the claim from both sides: **XZ** bounds "review-surviving source payload," **SolarWinds** bounds "compromised build pipeline."

Worth noting the honest complication: SolarWinds' own remediation added "three separate build environments with separate credentials and cross-checking" *(Broad Literature Review.md:37)* — an operational analog of multi-party verification. The incident is outside the proxy's remit, but the *remedy* the industry reached for was multi-party. That is a gift to §7's advocacy and should not be buried.

Candidate use: §7 scope boundary.

---

A future formal model could state scoped properties of the artifact-bound quorum protocol — requiring distinct valid approvals before publication, or preventing a vote from being replayed. It would **not** prove that people review artifacts well, that a quorum cannot collude, or that the full deployment is flaw-free.

*(method-evaluation-frameworks.md:29-34; Tamarin precedent, `tamarin-prover`)* The "would not prove" clause is load-bearing and must be kept — it is what stops a formal-methods future-work item from sounding like a promise to eliminate the limitations §7 just conceded.

Candidate use: §7 Future Work, one short paragraph.

---

These are not bugs — they are documented trade-offs made to keep the MVP tightly scoped.

*(docs/mvp.md:172; echoed at constraints.md:3)* The proof-of-concept posture in one sentence.

The fuller ambition statement, in your own voice: "my research and deliverables serve more as a proof-of-concept … built to show that this functionality is possible and should be a first-class authentication mechanism in package repositories" *(PR1.tex:122)*. And the candid integration admission from the same passage: *"The solution I found is a bit of a hack."*

Two precision boundaries worth keeping nearby, because both name something the mechanism genuinely does not reach: "the multi-party property protects the *grant event*, not the *session*" *(Broad Literature Review.md:77)*, and "The signature scheme authenticates the password-holder, not the human" *(IDENT-4:49)* — the latter paired with the model naming its own undefended surface: *"In-app capture prevention: none — that is this threat's point."*

Candidate use: §7 limitations.

---

My primary use of AI has been through iterative, adversarial dialog — "grilling" — in which I stress-test my ideas or a design against the AI.

**First person is correct here** — and mandatory. An AI-usage disclosure is a first-person statement about what the author did; there is no third-person rendering that is both honest and readable. Same for the crypto-pivot admission (*"I did not want to implement these schemes blindly just because I had sunk time and effort into researching them"*) and the PoC candour (*"The solution I found is a bit of a hack"*).

*(PR4.tex:297)* Accurate, specific, and it describes a method rather than a disclaimer.

The integrity statement: "The meaning and thought behind the words are always my own, and I type every word in the body of these reports to ensure nothing is written without my full understanding, though I may borrow language and sentence structure from the AI-generated draft." *(PR4.tex:299)*

Process detail, if the report discusses method at all: "These phases were organized as vertical slices, backed by executable tests, which made it easy for the AI to implement. I then reviewed each implementation in its own pull request to ensure the code aligned to the spec." *(PR3.tex:90)* And the sunk-cost honesty on the crypto pivot: *"I did not want to implement these schemes blindly just because I had sunk time and effort into researching them."* *(PR2.tex:126)*

Candidate use: Appendix — AI Usage Disclosure, carried from the progress reports.

---

Threshold signatures don't solve the multi-identity compromise case either; they just shift the attack from "compromise one approver's password" to "compromise one approver's key" — not a meaningful improvement, given the constraint that approvers should not manage keys.

*(docs/adr/0001-credential-backed-approval.md:37)* The crisp "shifts, doesn't solve" rebuttal, and the core of the Appendix's cryptographic-choice rationale.

The deciding factor is **usability, not a security gap**: threshold signatures are stronger on exactly one axis (approvers never trust the proxy to record their approval), but against the proxy's actual adversary — a single compromised identity — both models collapse to "compromise one identity." The give-up is bounded and named: the proxy must be trusted to record honestly, but "a compromised proxy *before* approval can approve anything; a compromised proxy *after* approval cannot forge approvals retroactively (they are cryptographically tied to past auth events)" *(:51)*.

The origin three-reason rationale, in your own voice: multi-signature schemes "often require communication between users," would "require every user to create and manage cryptographic keys, which is not ideal for non-technical users," and are "overly complex when some of the security of the system would still rely on the security of the proxy server" *(PR2.tex:97)*. Design constraint behind it: "Approvers should not need to manage or store additional cryptographic secrets beyond their regular authentication credentials" *(CONTEXT.md:106)*.

Lineage that makes the choice legible rather than defensive: threshold m-of-n is not exotic — it is the shipped default of a mainstream secrets manager (HashiCorp Vault, 3-of-5), operationally heavy enough that HashiCorp recommends auto-unseal for most users. That a shipped m-of-n is burdensome enough for its vendor to recommend turning it off *is* the usability argument for the credential-backed variant.

Candidate use: Appendix — Cryptographic-choice rationale. Keep only if the page budget allows; deranked from the body deliberately.
