# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "marimo",
#     "nbconvert",
#     "nbformat",
#     "playwright",
# ]
# ///

# Video deck template — Progress Update. Slides layout; each cell is one slide.
# Run:     uv run marimo edit --watch "<deck>.py"
# Share:   uv run marimo export pdf "<deck>.py" -o <deck>.pdf --as=slides --raster-server=live
# Keep every slide's upper-right corner clear — the talking-head overlay sits there.

import marimo

app = marimo.App(
    width="medium",
    app_title="Project Name — Progress Update N",
    layout_file="layouts/deck_template.slides.json",
)


@app.cell
def _():
    import marimo as mo

    return (mo,)


@app.cell(hide_code=True)
def _(mo):
    # DECK THEME — read the external stylesheet and inject it as a <style> tag.
    # Marked "skip" in the slides layout so it styles every slide without being
    # one. (css_file= on marimo.App did not apply.)
    _css = (mo.notebook_dir() / "video_deck_style.css").read_text(encoding="utf-8")
    mo.Html(f"<style>{_css}</style>")
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 0 — Title
    # AI-use disclosure is mandatory: note *where and how* AI was used. Keep it a
    # quiet footnote, clear of the upper-right webcam overlay.
    mo.md(r"""
    # Project Name
    ### Progress Update N — Your Name

    *One-line hook — the dramatic spine of the update.*

    <br>

    ---

    <small>**AI use disclaimer:** This deck was created with AI assistance.
    The content, direction, and storyline ideas are all my own.</small>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 1 — BEAT 1: The seduction (~40s) — the cool idea / the setup.
    mo.md(r"""
    ## The idea that seemed perfect

    Set up the appealing approach you started with.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 2 — BEAT 2: The wall (~50s) — ~3 crisp reasons, as side-by-side cards.
    _reasons = mo.hstack(
        [
            mo.callout(mo.md("**1 · First reason.**\n\nWhy it failed."), kind="neutral"),
            mo.callout(mo.md("**2 · Second reason.**\n\nWhy it failed."), kind="neutral"),
            mo.callout(mo.md("**3 · Third reason.**\n\nWhy it failed."), kind="neutral"),
        ],
        widths="equal",
        gap=1,
    )
    mo.vstack([mo.md("## Why it didn't fit"), _reasons])
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 3 — BEAT 3: The turn (~40s) — the decision + the meta-move.
    # Quote a REAL artifact (e.g. an ADR) so the deck renders versioned truth.
    mo.md(r"""
    ## So I changed course — and documented it first

    State the decision you made.

    > **Decision: <quote the real ADR decision here>.**
    > *key reasons, kept short*

    The meta-move: I made this decision **before committing to code.**
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 4 — BEAT 4a: The proof — the headline flow, in plain language.
    mo.md(r"""
    ## What it actually does

    One plain-language sentence describing the headline flow.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 4 (cont.) — embed a REAL diagram. Mark this cell "sub-slide" in the
    # layout so it groups under the slide above. The init directive shrinks tall
    # sequence diagrams (drop mirrored bottom actors, tighten spacing).
    mo.mermaid(
        """
        %%{init: {'sequence': {'messageMargin': 16, 'boxMargin': 6, 'noteMargin': 6, 'mirrorActors': false}}}%%
        sequenceDiagram
            actor U as User
            participant S as System
            U->>S: request
            S-->>U: response
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 5 — BEAT 5: Week ahead + the feedback ask (~50s), merged.
    mo.md(r"""
    ## The week ahead — and where I want your read

    What you'll build next, and what's optional.

    ### The feedback I'm after
    > **A forward-looking question the whole group can answer.**
    """)
    return


if __name__ == "__main__":
    app.run()
