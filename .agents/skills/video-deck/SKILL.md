---
name: video-deck
description: >-
  Build a short (~3–5 min) video progress-update presentation as a marimo
  slides deck instead of PowerPoint. Use when the user wants to make a course
  video update, turn a progress report into a slide deck, or create a marimo
  presentation for a video. Tailored to the CS 6727 practicum video assignment.
---

# Video Progress-Update Deck (marimo)

Build a sub-5-minute video-update deck as a **marimo slides presentation** that
renders the project's *real* artifacts (ADRs, mermaid diagrams) inline. The
medium is the message.

## Workflow (three phases, in order)

1. **Grill-with-docs first.** Invoke the `grill-with-docs` skill to stress-test
   the plan/decisions and update the domain docs (`CONTEXT.md`, ADRs) *before*
   designing the deck. The deck is only as sharp as the thinking behind it.
   Ask open-ended, conversational questions — never multiple-choice menus.
2. **Mine the progress report.** Read the latest report in
   `Practicum Work/Progress Reports/` — that is the source of truth for "what I
   did the last two weeks." Also read `Practicum Work/Videos/Assignment.md` for
   the current assignment's exact requirements.
3. **Build the deck.** Copy the templates from `assets/` (below) into
   `Practicum Work/Videos/`, then fill in the beats. Keep the deck and the
   stylesheet as separate files.

## Assignment constraints (verify against Assignment.md each time)

- **~3–5 minutes; hard ceiling 5:00; target ~4:30** with ~30s headroom.
- Must (1) summarize the last two weeks, (2) sketch ideas for the week ahead,
  (3) **end** with specific areas where feedback is wanted.
- **AI-use disclaimer is mandatory** (TA requirement): note *where and how* AI
  was used, not just that it was. Put a quiet footnote on the **title slide**
  *and* paste the same note into the private assignment submission comments.
- **Talking-head overlay sits in the UPPER-RIGHT corner.** Keep that corner of
  every slide clear of content.

## Narrative design (what makes a docs-heavy update engaging)

Documentation work is hard to show. Don't read bullets off slides. Instead:

- **Find the single most dramatic true story and make it the spine** (e.g. a
  pivot: "I researched cutting-edge X for two weeks, then deliberately threw it
  away — here's why"). A pivot is an argument; it carries a whole video.
- **Five-beat arc:** seduction (the cool idea) → wall (why it failed, ~3 crisp
  reasons) → turn (the decision + the meta-move, e.g. "spec before code") →
  proof/breadth (fast rattle through what got built; lands *scope* on the
  viewer) → week-ahead + feedback ask (merged).
- **Plain language only on slides.** No internal jargon — say what a thing
  *does*, never its codename (e.g. not "approval core").
- **Make the feedback ask forward-looking** (e.g. "is this the right first
  slice, or have I over-scoped?") — answerable by the whole class.
- **Never name or characterize a peer/classmate** — classmates watch the video.

## marimo technical conventions (hard-won — don't relearn these)

**Always check the marimo docs before guessing at config or layout.** Guessing
here burns iterations.

- **One cell per slide.** Use `@app.cell(hide_code=True)` and `mo.md(...)`.
  A cell with a **display output becomes a slide**; a cell that only returns
  values (like the import cell) does **not**.
- **Theme via an external stylesheet + a skip cell.** `css_file=` on
  `marimo.App(...)` does **not** reliably apply. Instead keep
  `video_deck_style.css` next to the deck, read it with
  `mo.notebook_dir()`, and inject it as a `<style>` tag from a dedicated cell:
  `mo.Html(f"<style>{(mo.notebook_dir() / 'video_deck_style.css').read_text()}</style>")`.
  Use **unscoped `!important`** selectors (marimo's DOM has no stable `.marimo`
  wrapper). Mark that cell **`{"type": "skip"}`** in the layout JSON so it
  styles every slide without rendering as a blank one.
  (WASM note: `mo.notebook_dir()` is None under WASM — for html-wasm builds put
  the CSS in a `public/` dir and use `mo.notebook_location()`.)
- **Slides layout JSON** (`layouts/<deck>.slides.json`): a positional `cells`
  array. Per-cell `type` values: `slide`, `sub-slide` (grouped under the slide
  above, reached with the down-arrow), `fragment`, `skip` (not shown), `notes`.
  Group a detail diagram as a `sub-slide` under its intro slide.
- **Reorder cells in the marimo UI (the slide minimap), NOT by editing the .py
  text.** Text reorders desync the positional layout JSON — `skip`/`sub-slide`
  attributes end up on the wrong cells (e.g. the title gets hidden).
- **Cards / columns:** `mo.hstack([mo.callout(mo.md(...), kind="neutral"), ...],
  widths="equal", gap=1)` turns a dense beat into a visual triptych.
- **Shrink a tall mermaid sequence diagram** with an init directive on the first
  line: `%%{init: {'sequence': {'messageMargin':16,'boxMargin':6,'noteMargin':6,'mirrorActors':false}}}%%`
  (`mirrorActors:false` drops the duplicated bottom actor row).
- **`marimo.App(width=..., app_title="...", layout_file="layouts/<deck>.slides.json")`** —
  set `app_title` for the browser tab.
- **PEP 723 header** (`# /// script ... # ///`) declaring `marimo` (and for PDF
  export `nbconvert`, `nbformat`, `playwright`) so `uv run` self-resolves deps.

## Run, export, and share

- **Author:** `uv run marimo edit --watch "<deck>.py"`
- **PDF (slides):** `uv run marimo export pdf "<deck>.py" -o <deck>.pdf --as=slides --raster-server=live`
- **GitHub viewing gotcha:** GitHub renders committed **PDFs** inline but shows
  committed **.html** as raw source. So PDF is the easiest "view it in the repo"
  format; HTML needs hosting.
- **PDF export is broken on Windows** — marimo sets `WindowsSelectorEventLoopPolicy`,
  which can't spawn Playwright's subprocess (marimo issue #8700:
  `NotImplementedError` at `subprocess_exec`). Build the PDF on **Linux/WSL** or
  in **CI** (`ubuntu-latest`). For an interactive URL instead, use
  `marimo export html-wasm "<deck>.py" -o site --mode run` (no Playwright) and
  publish to GitHub Pages (add an empty `.nojekyll`).

## Assets (copy these, then customize)

- `assets/deck_template.py` — five-beat deck skeleton with the skip style cell,
  `app_title`, PEP 723 header, a cards beat, and a mermaid beat.
- `assets/video_deck_style.css` — the deck theme (light "designed slide" look;
  colored title bars, callout cards, footer). Recolor via the `:root` variables.
- `assets/layouts/deck_template.slides.json` — matching slides layout (style cell
  `skip`, the mermaid as a `sub-slide`).

Copy `deck_template.py` → `<deck>.py`, `video_deck_style.css` alongside it, and
`layouts/deck_template.slides.json` → `layouts/<deck>.slides.json`. Point the
deck's `layout_file=` at the renamed layout.
