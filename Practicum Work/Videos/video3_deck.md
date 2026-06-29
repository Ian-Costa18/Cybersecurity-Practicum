---
marp: false
theme: midnight
paginate: true
footer: "Multi-Party Authorization Proxy · CS 6727"
---

<!-- _class: title -->
<!-- _paginate: false -->
<!-- _footer: "" -->

# Multi-Party Authorization Proxy

### Progress Update 3 — CS 6727 Practicum

<div class="meta">Ian Barish</div>
<div class="ai">AI use: Deck drafted with AI assistance — all design and project decisions are my own.</div>

<!-- SCRIPT (~10s):
     • "Hi — this is my third progress update on the multi-party authorization
       proxy."
     • "Last cycle I finished the written design; this cycle I actually built
       it." Then move straight on. -->

---

## The Project So Far

A proxy that requires **multiple approvers** to sign off before a sensitive action runs — its headline case is publishing a package to PyPI.

- Researched the problem: one compromised maintainer can ship to everyone
- Wrote the full design — specifications, ADRs, and a threat model
- Renamed the project from "Multi-Signature" to "Multi-Party"

<!-- SCRIPT (~30s, HARD CAP):
     • "Quick recap for anyone who missed a video: this is a proxy that requires
       multiple people to approve a sensitive action before it runs, and the
       headline case is publishing a package to PyPI."
     • "The first cycle was research — I showed how one compromised maintainer can
       ship to everyone."
     • "The second was the full written design: the specifications, the ADRs, and
       a threat model. I also renamed it from Multi-Signature to Multi-Party."
     • Don't retell the story — just set the baseline so this cycle lands. -->

---

## Completed Tasks

Shifted from writing specs to building — the MVP now runs end-to-end with roughly 12,700 lines of code and tests and 29 reviewed pull requests this cycle.

- **Intercept:** uploads are held and bound to a SHA-256 hash
- **Approve:** a quorum of signed votes in an append-only log
- **Publish:** the hash is re-verified, then forwarded to PyPI
- **Around it:** email alerts, an audit trail, portals, Docker

<!-- SCRIPT (~90s):
     • "This cycle I shifted from writing specs to building — the MVP now runs
       end-to-end, and it comes to about 12,700 lines of code and tests across 29
       reviewed pull requests this cycle."
     • "The flow is three steps. First, intercept: a developer uploads with their
       normal tooling, the proxy catches the upload, holds the file, and
       fingerprints it with a SHA-256 hash."
     • "Second, approve: the configured approvers each cast a signed yes-or-no
       vote, and every vote is appended to a log that nobody can edit after the
       fact — and it waits until a quorum agrees."
     • "Third, publish: right before sending, the proxy re-verifies that
       fingerprint so the file can't have been swapped underneath it, and only
       then forwards it on to PyPI."
     • "Around all of that is the supporting machinery — email alerts, an audit
       trail, the approver and admin portals, and Docker packaging."
     • "And to show the design is general and not PyPI-specific, the same approval
       engine already drives a second use case — granting temporary web access."
     -->

---

## Next Steps

<div class="cards">
<div><h4>Threat model</h4>Finish it and map every threat to an industry framework</div>
<div><h4>Evaluation suite</h4>Build it from the threats and user stories</div>
<div><h4>Results & outline</h4>Run the suite, gather results, start the report</div>
</div>

<!-- SCRIPT (~60s):
     • "Next steps, in order. The security results hinge on the threat model, so
       that comes first — I'll finish enumerating the threats and map each one to
       a public industry framework."
     • "Then I build the evaluation suite out of those threats and the user
       stories: each threat becomes something I can check — a passing test, an
       argued design property, an operator setting, or an accepted limitation —
       and I'll reuse the tests I've already written rather than start over."
     • "Finally I run the suite, gather the numbers, and start outlining the final
       report. The order matters: I can't score the system before I know what I'm
       scoring it against." -->

---

<!-- _class: ask -->

## Feedback Request

<div class="context">
<span class="label">Background</span>
My final result is a <strong>security score</strong> — I grade the proxy against a list of threats. But I wrote that threat list myself, so the score grades its own homework.
</div>

<div class="q">
Should I anchor it to a public framework — <strong>MITRE ATT&amp;CK</strong>, or supply-chain-specific <strong>SLSA / CNCF Catalog</strong> — and does that actually close the blind-spot?
</div>

<!-- SCRIPT (~40s): the video ENDS here — protected slot, do not rush.
     • "Last thing — a question for the group. My final deliverable is a security
       score: I grade the proxy against a list of threats, and the score is really
       just how many threats fall into each bucket."
     • "The problem is I wrote that threat list myself, with AI, so the score is
       grading its own homework — if I missed a threat, I also miss it in the
       grade."
     • "To avoid that blind spot I want to anchor the list to a public taxonomy.
       MITRE ATT&CK is broad and I already know it; SLSA and the CNCF catalog are
       narrower but supply-chain-specific."
     • "So: which should I anchor to, and does grounding it in a public framework
       actually close the self-grading blind spot?"
     -->
