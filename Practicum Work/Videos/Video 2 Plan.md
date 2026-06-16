<!-- LTeX: enabled=false -->
# Video 2 Plan — Progress Report 2 Update

Working plan for the ~3–5 minute Video 2 update. Captures the design decisions reached so the work survives context compaction. This is an outline/spec, not a script.

## Constraints (from Assignment.md)

A ~3–5 minute video that: (1) summarizes the last two weeks, (2) sketches ideas for the week ahead, (3) ends by highlighting specific areas where I want feedback. Hard ceiling: under 5 minutes.

## Core problem this plan solves

PR2 was almost entirely **documentation** (~5,800 lines / 32 commits: research, ADRs, specs, threat model, PRD, consistency audit) — not a demoable feature. The challenge: make documentation work engaging **without PowerPoint**. Reading bullets off slides is the failure mode to avoid.

## Decisions locked

### Spine: the pivot
The whole video hangs on one story: *"I spent two weeks researching cutting-edge multi-sig crypto — FROST, MuSig2, GG20, DKLS — and then deliberately threw it away for a credential-backed scheme. Here's why."* Honest, dramatic, and it sets up the feedback ask.

### Medium: marimo as repo-native slides (no widgets)
Use marimo's slides layout as a clean, markdown-driven deck. **No interactive widgets** — a pivot is an argument, not something you poke; a quorum slider or crypto/credentials toggle would be decoration. marimo's one honest justification here is *not* interactivity: it lives in the repo and renders the **actual artifacts** (ADR-0001, real diagrams) inline. The medium reinforces the message — *"I don't make slides, I make versioned artifacts."* marimo renders mermaid natively, so embedding existing diagrams is cheap.

### The thesis to land
Two claims, the second is the differentiator:
- **Velocity:** AI makes coding fast, so front-loading specs pays off. (Everyone already knows this.)
- **Focus / anti-scope-creep (the real point):** *because* coding is cheap now, the bottleneck moved upstream — knowing exactly what to build. A tight, deeply-scoped spec lets you dive in and prove one thing, instead of sprawling and bolting on features that don't serve the original point (the "research paper that wanders into tangents" analogy). Reframes "I wrote zero code" from a weakness into a deliberate bet: spend the cheap-coding dividend on depth and focus, not sprawl.
- **Key line:** I built this documentation *before committing to any code*.

**Guardrail:** Do NOT name or characterize any peer/classmate (the forum "rescoping" post inspired this point, but classmates will watch the video). Frame it only as a general observation about AI-era development.

### Five-beat arc
1. **The seduction** — multi-sig crypto, like crypto wallets; the cool idea.
2. **The wall** — three reasons it doesn't fit: (a) every user must manage keys, (b) schemes need inter-party communication, (c) security still rests on the proxy anyway.
3. **The turn** — killed it, chose credential-backed approval, then committed to fully specifying + stress-testing the system on paper before any code.
4. **The proof (breadth beat)** — see below.
5. **Week ahead + feedback ask (merged)** — see below.

### The "proof" / breadth beat
Fast, almost overwhelming rattle through what got built — does three jobs at once: shows volume of work, demonstrates docs-first discipline, and lands the *scope* on the viewer (scope feedback keys off breadth, not detail).
- **Show the Phase 0 PyPI flow as the visual centerpiece** (the slice I'll actually build first): upload → hash-bind → notify approvers → quorum via emailed link → publish to mocked PyPI.
- **Plain language only.** No internal jargon — e.g. never say "approval core"; say what it does.
- Then flash the rest of the v1 in plain language as "everything else I've specified."

### Feedback ask: forward-looking
*"I've specced a full v1. For my six weeks I'm building the PyPI publish flow end-to-end first and layering the rest (shared-account, portals, second factor) only if time allows. Is that the right first slice — or have I over-scoped the MVP?"* Answerable by the whole group (all doing AI-assisted builds now), and it's the thing I'm genuinely unsure about. Replaces the backward-looking "was docs-first the right bet" framing and demotes the pivot-soundness question to a quick secondary mention.

## Diagram / artifact sources for embedding
- **Component topology** (mermaid): `docs/architecture.md`
- **Request/approval state machines** (ASCII; may redraw as mermaid): `docs/request-lifecycle.md`
- **End-to-end flows** (sequence diagrams): `docs/use-cases/01-package-publishing.md` (PyPI — the headline), `docs/use-cases/02-shared-account-management.md`
- **The pivot artifact:** `docs/adr/0001-credential-backed-approval.md`
- **Scope + build order:** `docs/mvp.md` (now includes a "Build Sequence" section)

## Related project decision (already actioned)
The scope realization led to a **build-sequencing** decision now recorded in `docs/mvp.md` → "Build Sequence": the spec is the full v1 vision; the build goes *thinnest-thesis-first* (Phase 0 PyPI tracer bullet → Phase 1 forward-auth → Phase 2 hardening/portals/TOTP/tokens). Nothing cut, only ordered. Fine-grained vertical slices will be generated into the issue tracker via the `to-issues` skill when implementation begins.

### Build the real marimo deck (locked)
Author an actual marimo slides deck with the five beats laid out, embedding the real ADR and mermaid diagrams — not a narrated walk-through of the raw docs. Rationale: the only honest justification for marimo over PowerPoint is that the medium *is* the message ("I make versioned artifacts that live in the repo and render the real thing"). A narrated file tour throws that away and reads as less polished than the PowerPoint it's meant to beat. Cost is ~1–2 hours since the beats are mostly markdown + diagrams that already exist.

### Recording: screen capture + talking-head overlay (locked)
Record the live deck (`marimo run`) as a screen capture with a **talking-head webcam overlay in the upper-right corner** — instructors are grading a person's progress and want to see a face. **Authoring constraint: every slide must keep its upper-right corner clear of content** so the webcam feed never covers anything. Narration is still scripted per beat so individual beats can be re-recorded against the 5-minute ceiling.

### Beat timing budget (provisional — verify when recording)
Target ~4:30 with ~30s headroom under the 5:00 hard ceiling. Beat 4 is the heart (most evidence) so it gets the most room; going over 5:00 is the one unforced error to avoid.

- Beat 1 — Seduction: ~40s
- Beat 2 — The wall (three reasons): ~50s (densest explainer beat, earns the length)
- Beat 3 — The turn (+ "spec before code"): ~40s
- Beat 4 — Proof / breadth (Phase 0 PyPI flow + fast rattle): ~90s
- Beat 5 — Week ahead + feedback ask: ~50s

### AI-use disclosure (locked)
TA feedback on Video 1 (Emad) requires noting **where and how** any AI tool was used — the course allows AI use but it must be acknowledged. A footnote on the **title slide** discloses that the deck and much of the documentation were drafted/organized/copy-edited with AI (Claude), while research direction, the pivot, architecture, and scope decisions are the author's own. Being specific reinforces the deck's own thesis (AI makes coding cheap → work moves upstream). Belt-and-suspenders: also drop the same note in the **private assignment submission comments** (Emad offered slide *or* comments — do both).

### Diagrams: no redraws needed (locked)
The beat-4 centerpiece — the PyPI publish workflow in `docs/use-cases/01-package-publishing.md` — is already a `mermaid` block, so it renders natively in marimo with zero work. The ASCII state machines in `docs/request-lifecycle.md` stay **out of the video**: a state machine is a detail artifact that competes with the PyPI sequence diagram and slows the breadth beat; viewers who want that depth follow the repo link. Redrawing them as mermaid would be repo hygiene, not video work — out of scope for this plan.
