---
name: video-deck
description: >-
  Build a short (~3-5 min) video progress-update presentation as a Marp
  markdown slide deck. Use when the user wants to make a course video update,
  turn a progress report into a slide deck, or create slides for a CS 6727
  practicum video. Produces co-editable markdown + a tuned theme; does NOT
  cover recording or post-processing.
---

# Video Progress-Update Deck (Marp)

Build a sub-5-minute video-update deck as a **Marp markdown slide deck**: one
`.md` file you and the user both edit freely, a theme CSS tuned once so it looks
sharp, exported to PDF/PPTX. The structure is **conventional and fixed** — it
maps 1:1 to the assignment's three required parts. That is deliberate (see
"Why this shape" below).

**Scope: this skill builds the deck, full stop.** Recording (OBS), MKV→MP4
transcode, and Whisper subtitles are a separate concern — a future
`video-postprocess` skill. When the deck is done, hand off: "Deck's built —
record it in OBS, then run video-postprocess." Do not build a recording or
posting checklist here.

## Why this shape (read before "improving" the structure)

This deck format exists because of direct TA feedback across two videos:

- **Video 1** was a PowerPoint. TA: "met the assignment expectations," slides
  "looked sharp." It worked. The *only* ask was to disclose AI use.
- **Video 2** was a marimo deck built as a dramatic five-beat *narrative* (a
  pivot story, with the conventional structure deliberately merged/demoted).
  TA: slide format fine, but **"the main area to improve is structure"** — the
  introduction ran long; next steps and the feedback ask got compressed at the
  end. He explicitly asked for clear slide titles: **"Completed Tasks," "Next
  Steps," "Feedback Request."**

So: **no storytelling spine, no merged beats.** Conventional titles, the
feedback ask as a protected first-class slide, a hard-bounded recap. If you feel
tempted to make it a narrative again, that is the exact mistake this skill was
written to stop.

## Workflow (three steps, in order)

1. **Read the source of truth.** The latest report in
   `Practicum Work/Progress Reports/` is "what I did." Also read
   `Practicum Work/Videos/Assignment.md` for the exact requirements. (No
   grill-with-docs phase — this is a routine biweekly update, not a design
   review. If a genuinely unsettled decision needs a feedback ask, the user can
   invoke `grilling` separately.)
2. **Copy the template and fill it.** Copy `assets/template.md` →
   `Practicum Work/Videos/video<N>_deck.md` and the theme(s) from
   `assets/themes/` alongside it. Fill the five slides from the report. Draft
   **rough speaker notes** the user will edit (see below).
3. **Add one visual, export, hand off.** Render one diagram to PNG, embed it,
   export PDF/PPTX, hand the deck to the user for editing + recording.

## The fixed five-slide skeleton

Use these exact slides and titles every time:

| # | Slide | Maps to | Budget | Notes |
|---|-------|---------|--------|-------|
| 1 | **Title** | — | ~10s | Project name, "Progress Update · Week N," author, AI-use note. |
| 2 | **The Project So Far** (recap) | context | ~30s | One plain sentence on what the project is + 2-3 cumulative bullets. **Hard-bounded** — never a narrative. For peers who skipped a video. |
| 3 | **Completed Tasks** | assignment part 1 | ~90s | The substance. The last two weeks. May spill to a 2nd slide on a heavy cycle. |
| 4 | **Next Steps** | assignment part 2 | ~60s | Card row or short bullets. |
| 5 | **Feedback Request** | assignment part 3 | ~40s | One sharp question in a callout. **The video ends here** — never buried. |

Total ~3:50, leaving headroom under the 5:00 ceiling. Completed Tasks gets the
most time; Feedback Request gets a protected slot so it can never again be the
rushed afterthought.

The "one visual" (see Diagrams) usually rides as its own slide between
Completed Tasks and Next Steps, or replaces a Completed bullet wall.

## Content rules

- **≤4 bullets per slide, ≤~12 words each.** Keeps slides scannable and stops
  you reading them aloud.
- **Plain language only — say what a thing *does*, never its codename**
  (e.g. not "approval core"; say "the approval check").
- **Never name or characterize a classmate** — peers watch the video.
- **AI-use note on the title slide** (TA requirement: note *where and how* AI was
  used). Same note also goes in the private assignment submission comments — but
  that's a posting step, out of this skill's scope; just put it on the slide.
- **Keep every slide's upper-right corner clear** for the talking-head overlay.
  The themes cap titles at ~70% width to enforce this.

## Speaker notes & subtitles

- **Write rough speaker notes per slide as a first draft for the user to edit** —
  not a finished script. Put them in the `.md` as HTML comments:
  `<!-- Speaker notes: ... -->`. They show in Marp's presenter view while
  recording.
- **Do NOT generate an `.srt` from the notes.** The user transcribes the actual
  recording locally with **Whisper** (so subtitles match even when they go off
  script). Subtitles are a post-recording step, not a deck artifact.

## Marp mechanics (hard-won — verified, don't relearn)

- **`---` separates slides.** Front-matter block at the top: `marp: true`,
  `theme: midnight`, `paginate: true`, `footer: "..."`.
- **Per-slide directives** are HTML comments: `<!-- _class: title -->`,
  `<!-- _class: ask -->`, `<!-- _paginate: false -->`, `<!-- _footer: "" -->`
  (the leading underscore = "this slide only").
- **The footer must be positioned by the theme CSS** (`position: absolute;
  bottom: ...`). Marp's `footer:` directive alone floats it inline — that was
  the V1 "footer won't stick to the bottom" bug. The shipped themes already pin
  it; keep that CSS if you fork a theme.
- **Cards / columns:** a `<div class="cards">` with child `<div>`s renders a
  clean triptych (the themes style it). Better than a bullet wall for Next Steps.
- **Theme selection:** set `theme: <name>` in front-matter AND pass
  `--theme assets/themes/<name>.css` on the CLI (the front-matter name must
  match the `/* @theme <name> */` line in the CSS).

## Diagrams — one strong visual per video

Marp does **not** render mermaid inline. Pre-render to PNG, then embed:

1. Write/lift a mermaid source (the repo's `docs/` diagrams are reusable),
   e.g. `flow.mmd`.
2. Render: `npx @mermaid-js/mermaid-cli -i flow.mmd -o flow.png -c assets/themes/<theme>.mermaid.json -b transparent -s 2`
   — the per-theme config recolors the diagram to match and sets
   `mirrorActors:false` (drops the duplicated bottom actor row, which otherwise
   collides with the footer).
3. Embed with a width hint: `![w:1120](flow.png)`.
4. **Export with `--allow-local-files`** or the image silently drops from the
   PDF/PNG (Marp blocks local files by default).

One visual per video, not one per slide.

## Run, export, share

- **Author with live preview:** the **Marp for VS Code** extension (side-by-side
  preview, no build loop) is the easy path. CLI watch alternative:
  `npx @marp-team/marp-cli <deck>.md --theme assets/themes/<theme>.css --watch`
- **PDF:** `npx @marp-team/marp-cli <deck>.md --theme assets/themes/<theme>.css --allow-local-files --pdf`
- **PPTX (editable escape hatch):** same with `--pptx`.
- **PNG per slide (for review):** add `--images png --image-scale 1.4`.
- **GitHub viewing:** commit the **PDF** — GitHub renders PDFs inline (same as
  the old marimo exports). `.html` shows as raw source.

All of the above are verified working on this machine (Node + `npx`, no global
install needed).

## Themes (assets/themes/)

- **`midnight.css` — default.** Modern dark deck: deep navy gradient title,
  electric-teal accents, Inter sans. Closest to the "sharp" Video 1 look.
- **`charter.css` — alternate.** Echoes the LaTeX progress report: Charter
  serif, black ink, thin rules, no color. Use when the deck should read as a
  sibling of the written report. Switch by changing `theme:` in front-matter
  and the `--theme` path.
- Each theme has a matching `<theme>.mermaid.json` so embedded diagrams recolor
  to the theme automatically.

## Assets

- `assets/template.md` — the five-slide skeleton with placeholders, rough
  speaker-note stubs, time-budget comments, and a commented diagram-slide
  example.
- `assets/themes/midnight.css` (+ `.mermaid.json`) — default dark theme.
- `assets/themes/charter.css` (+ `.mermaid.json`) — report-matched serif theme.

Copy `template.md` → `video<N>_deck.md` and the chosen theme(s) into
`Practicum Work/Videos/`, then fill the beats.
