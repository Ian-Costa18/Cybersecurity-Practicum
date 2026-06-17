# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "marimo",
#     "nbconvert",
#     "nbformat",
#     "playwright",
# ]
# ///

# Video 2 deck — Progress Report 2 update. Slides layout; each cell is one slide.
# Run:     uv run marimo edit --watch "video2_deck.py"
# Share:   uv run marimo export pdf "video2_deck.py" -o video2_deck.pdf --as=slides --raster-server=live
# Keep every slide's upper-right corner clear — the talking-head overlay sits there.

import marimo

__generated_with = "0.23.9"
app = marimo.App(
    width="medium",
    app_title="Multi-Sig Auth Web Proxy — Progress Update 2",
    layout_file="layouts/video2_deck.slides.json",
)


@app.cell
def _():
    import marimo as mo

    return (mo,)


@app.cell(hide_code=True)
def _(mo):
    # DECK THEME — read the external stylesheet and inject it as a <style> tag.
    # This cell is marked "skip" in the slides layout so it styles every slide
    # without rendering as one. (css_file= on marimo.App did not apply.)
    _css = (mo.notebook_dir() / "video_deck_style.css").read_text(encoding="utf-8")
    mo.Html(f"<style>{_css}</style>")
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 0 — Title
    # AI-use disclosure (per TA feedback on Video 1): note *where and how* AI was
    # used, not just that it was. Kept as a quiet footnote, clear of the
    # upper-right webcam overlay.
    mo.md(r"""
    # Multi-Signature Authentication Web Proxy
    ### Progress Update 2 — Ian Barish

    *The week I spent researching cryptography —*
    *and why I threw half of it away.*

    <br>

    ---

    <small>**AI use disclaimer:** This deck was created with AI assistance.
    The content, direction, and storyline ideas are all my own.</small>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 1 — BEAT 1: The seduction (~40s)
    mo.md(r"""
    ## The idea that seemed perfect

    Require **several people to approve** before a sensitive action runs —
    the same *m-of-n* guarantee that protects a crypto wallet.

    The obvious way to build it: **threshold signature cryptography.**

    - FROST · MuSig2 · GG20 · DKLS
    - Each approver holds a key; their shares combine into one signature
    - No approver ever trusts a server with their secret

    Cutting-edge, mathematically elegant, and exactly what the crypto world uses.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 2 — BEAT 2: The wall (~50s) — three side-by-side cards
    _reasons = mo.hstack(
        [
            mo.callout(
                mo.md(
                    "**1 · Every approver becomes a key manager.**\n\n"
                    "Lost keys, backups, secure storage — for approvers who aren't "
                    "cryptographers."
                ),
                kind="neutral",
            ),
            mo.callout(
                mo.md(
                    "**2 · The parties have to talk to each other.**\n\n"
                    "Network round trips and synchronization — when approvers are spread "
                    "across the world and approve hours apart."
                ),
                kind="neutral",
            ),
            mo.callout(
                mo.md(
                    "**3 · Security still rests on the server.**\n\n"
                    'Threshold signatures just trade *"compromise a password"* for '
                    '*"compromise a key"* — no real gain, given approvers shouldn\'t '
                    "manage keys."
                ),
                kind="neutral",
            ),
        ],
        widths="equal",
        gap=1,
    )
    mo.vstack([mo.md("## Three reasons it didn't fit"), _reasons])
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 3 — BEAT 3: The turn (~40s) — embeds the real ADR-0001
    mo.md(r"""
    ## So I set it aside — on paper, before any code

    Chosen instead: **credential-backed approval.** Approvers sign in with a
    password + a one-time code; each approval is cryptographically tied to that
    login, signed, and tamper-evident. Simpler for people, and strong where it
    counts.

    It's written up as a versioned decision in the repo — **ADR 0001**:

    > **Decision: Credential-Backed Approval.**
    > *No key-management burden · supports distributed, async approvers ·
    > simpler to implement and audit · adequate for the single-compromise threat
    > model · leaves a clear upgrade path.*

    The call was cheaper to make **on paper than in a codebase** — so I made it first.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 4 — BEAT 4a: The proof — the headline flow (the slice I build first)
    mo.md(r"""
    ## What it actually does — package publishing

    Upload a package → **locked to its fingerprint** → approvers sign off →
    only then is it **published**. It can't be swapped after approval.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 4 (cont.) — the REAL sequence diagram from docs/use-cases/01-package-publishing.md
    mo.mermaid(
        """
        %%{init: {'sequence': {'messageMargin': 16, 'boxMargin': 6, 'noteMargin': 6, 'mirrorActors': false}}}%%
        sequenceDiagram
            actor U as Requester via Twine
            participant P as Proxy
            participant AS as Artifact holding
            actor A as Approvers
            participant X as Executor
            participant PyPI as PyPI

            U->>P: POST /pypi/legacy/ with API token
            P->>P: authenticate token, validate metadata
            P->>AS: store artifact
            P->>P: compute SHA-256, create Approval Request bound to hash (pending)
            P-->>U: 200, Twine exits, pending-approval email sent
            P->>A: notify with Approval Links, best-effort
            A->>P: re-auth and signed Vote (approve, deny, or withdraw)
            Note over P: effective votes drive quorum and the single-denial rule
            P->>P: quorum reached, Approval Request approved
            P-->>X: emit request.approved, Action queued
            X->>AS: read held artifact
            X->>X: re-verify SHA-256(held artifact) == action_hash, refuse on mismatch
            X->>PyPI: publish (idempotent: no double-publish)
            PyPI-->>X: success or permanent rejection
            X->>AS: delete artifact (terminal — on every path)
            X-->>U: email outcome, succeeded or failed
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 5 — BEAT 4b: The breadth rattle — everything else specced (plain language)
    mo.md(r"""
    ## The rest of the system is specified, too

    Two weeks · **~5,800 lines · 32 commits** — all specification, no app code yet:

    - **What the system is made of** and how the pieces talk
    - **Every state** a request can move through
    - **The exact cryptography**, down to the parameters
    - **A threat model** — who attacks it, and how it holds
    - **Who uses it and why** — personas, real user stories
    - **Shared-account access, self-service portals, second-factor login**
    - A **consistency audit** across the whole document set

    *The aim was depth on the parts that matter, rather than a wide pile of
    half-built features.*
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    # SLIDE 6 — BEAT 5: Week ahead + the feedback ask (~50s)
    mo.md(r"""
    ## The week ahead — and where I want your read

    **Now I build.** First slice, end-to-end: the **package-publishing flow**
    above. Shared accounts, portals, and second-factor login layer on **only if
    time allows.**

    ### The feedback I'm after
    I've specified a full v1. I'm building the publishing flow end-to-end first
    and treating everything else as optional.

    > **Is that the right first slice — or have I over/under-scoped the MVP?**
    """)
    return


if __name__ == "__main__":
    app.run()
