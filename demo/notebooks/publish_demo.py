"""Evaluation demo — Act 0: the admin's chair (setup prologue). Issue #143, epic #142.

A marimo notebook that drives the **live `compose.publish.yaml` stack** — nothing
mocked. Act 0 stands up a 3-of-3 publishing service and introduces the team of three
co-owners: one (`ada`) is shown coming to life via a live enrollment (account →
credentials → Ed25519 keypair → private key + TOTP secret encrypted at rest), the
other two are born enrolled (Mode-B). The credential state shown is read from **real
DB rows**; the flow + crypto live in the tested `demo_lib` beside this file (backing
check: `tests/demo/`), so this notebook only *sequences and draws*.

Run it two ways (the compose stack uses `run`):

    uv run marimo run  demo/notebooks/publish_demo.py    # clean web app — the default for recording
    uv run marimo edit demo/notebooks/publish_demo.py    # code visible — proves the HTTP/DB is real

The board is a light-mode, Maltego-style graph driven by a `step` state variable.
DEGRADATION LADDER (documented so the render cell can be swapped without touching the
flow logic): custom SVG (`render_board_svg`, default) → `mo.mermaid()`
(`render_board_mermaid`) → capability checklist (`render_capability_checklist`) →
this notebook's own markdown runbook. Swap only the one board-render cell.

Acts 1 (#112) and 2 (#114) extend the same notebook + board node-set; Act 0 builds the
scaffold they reuse.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium", app_title="MPA Proxy — Demo Act 0")


with app.setup:
    import os
    import sys
    from pathlib import Path

    import marimo as mo

    # demo_lib (the tested flow/board logic) sits next to this notebook; put it on the
    # path and import it. It imports msig_proxy, so `marimo run` must run in the project
    # environment (compose uses `uv run`), where the package is installed.
    _here = Path(__file__).resolve().parent
    if str(_here) not in sys.path:
        sys.path.insert(0, str(_here))
    import demo_lib


@app.cell
def _():
    mo.md(
        f"""
        # Act 0 — the admin's chair

        From zero, an **admin** stands up a **3-of-3** publishing service for the team
        that co-owns **`{demo_lib.PACKAGE_NAME}`**, and introduces the three co-owners.
        Everything below runs against the **live proxy stack** — the rows are real, the
        Ed25519 keys are really generated, and the private keys + TOTP secrets are really
        encrypted at rest.
        """
    )
    return


@app.cell
def _():
    # Honesty legend + degradation ladder — one scroll away in `run` mode (an accordion),
    # always here in `edit` mode / the markdown. The demo never fakes a system action.
    mo.accordion(
        {
            "ℹ️ Honesty legend & fallbacks (open me)": mo.md(
                """
                **What is real vs. staged.** Three categories, honestly labelled:

                - **Proxy-emitted mail** — approval / outcome notifications the proxy really sends (Acts 1/2).
                - **Human-authored mail** — the team thread + the Act 2 verification exchange: *also* real
                  Mailpit email, just written by people. The proxy has **no** chat/SMS feature; humans just
                  happen to use the same email server.
                - **Pure staging** — narrative devices only (the Act 2 2 a.m.→9 a.m. time-jump). Act 0 has none.

                **In Act 0 the only compression is the ceremony**: one enrollment is *shown*, two are
                *asserted* — but all three produce the same real, encrypted rows (see the crypto beat below).

                **Degradation ladder** (if the polished board fights the presenter, scale back without
                touching the flow logic — swap only the board-render cell):
                custom SVG → `mo.mermaid()` → capability checklist → this markdown runbook.

                **Credentials are throwaway & demo-only** (`demo_lib.DEMO_TEAM`, `demo/seed/users.demo.yaml`):
                planted on purpose so Act 2's simulated compromise uses a *known* stolen secret. No real key
                material is committed.
                """
            )
        }
    )
    return


@app.cell
def _():
    # Stand up the stack + provision the team. Idempotent (create-if-absent), so it runs
    # on load and is safe to re-run; the live stack points MSIG_DATABASE_URL at the
    # proxy's shared SQLite so these are the very rows Acts 1/2 vote on.
    sessions = demo_lib.demo_sessionmaker()
    with sessions() as _provision_session:
        provisioning = demo_lib.provision_demo_team(_provision_session)
        _provision_session.commit()

    _db = os.environ.get("MSIG_DATABASE_URL", demo_lib.DEFAULT_DEMO_DATABASE_URL)
    _source = "committed users.demo.yaml" if provisioning.mode_b_from_file else "regenerated bundle"
    mo.md(
        f"""
        **Service stood up:** `{demo_lib.SERVICE_NAME}` — one-time PyPI publish, quorum
        **{len(demo_lib.CO_OWNERS)}-of-{len(demo_lib.CO_OWNERS)}**.
        **Team provisioned** into `{_db}` (Mode-B source: {_source}).
        """
    )
    return provisioning, sessions


@app.cell
def _():
    # The `step` state variable: buttons advance it; the board + detail cells read it.
    get_step, set_step = mo.state(0)
    return get_step, set_step


@app.cell
def _(set_step):
    _last = len(demo_lib.ACT0_STEPS) - 1
    back_button = mo.ui.button(
        label="◀ Back", on_click=lambda _value: set_step(lambda s: max(s - 1, 0))
    )
    next_button = mo.ui.button(
        label="Next ▶", on_click=lambda _value: set_step(lambda s: min(s + 1, _last))
    )
    reset_button = mo.ui.button(label="⟲ Restart Act 0", on_click=lambda _value: set_step(0))
    mo.hstack([back_button, next_button, reset_button], justify="start")
    return


@app.cell
def _(get_step, provisioning, sessions):
    # Live data painted onto the board: read the shown co-owner's REAL rows and derive a
    # public-key fingerprint + at-rest markers. Nothing here is fabricated.
    step_index = get_step()
    step_obj = demo_lib.ACT0_STEPS[step_index]

    shown = provisioning.shown_person
    with sessions() as _s:
        _state = demo_lib.read_credential_state(_s, shown.username, password=shown.password)

    overlays: dict[str, str] = {}
    if "ada" in step_obj.active_nodes:
        overlays["ada"] = f"ed25519:{_state.public_key_hex[:8]}"
    if {"bruno", "carol"} & step_obj.active_nodes:
        overlays["bruno"] = "born enrolled"
        overlays["carol"] = "born enrolled"

    mo.md(f"### Step {step_index + 1}/{len(demo_lib.ACT0_STEPS)} — {step_obj.title}")
    return overlays, shown, step_index, step_obj


@app.cell
def _(overlays, step_obj):
    # THE degradation-ladder cell. Swap this one line for the fallback of your choice;
    # the flow logic (step advancement, live data) above is untouched:
    #   mo.Html(demo_lib.render_board_svg(step_obj, overlays=overlays))   # 1. custom SVG (default)
    #   mo.mermaid(demo_lib.render_board_mermaid(step_obj))               # 2. mermaid
    #   mo.md(demo_lib.render_capability_checklist())                     # 3. checklist only
    #   (this notebook's markdown)                                        # 4. runbook
    mo.Html(demo_lib.render_board_svg(step_obj, overlays=overlays))
    return


@app.cell
def _(sessions, shown, step_obj):
    # The crypto beat, read from REAL rows: a readable public key next to ciphertext
    # private key + ciphertext TOTP secret. Shown when the enrollment beat is on screen.
    if "ada" not in step_obj.active_nodes:
        _out = mo.md("")
    else:
        with sessions() as _s:
            state = demo_lib.read_credential_state(_s, shown.username, password=shown.password)
        _priv = state.encrypted_private_key or b""
        _totp = state.totp_secret_ciphertext or b""
        _out = mo.md(
            f"""
            #### {shown.display_name}'s account — read from the database, right now

            | field | at rest | value |
            |---|---|---|
            | `UserKey.public_key` | **readable** | `ed25519:{state.public_key_hex[:24]}…` |
            | `UserKey.encrypted_private_key` | **ciphertext** (AES-256-GCM / PBKDF2) | `{_priv[:16].hex()}…` ({len(_priv)} B) |
            | `User.totp_secret` | **ciphertext** (AES-GCM wrap, #122) | `{_totp[:16].hex()}…` ({len(_totp)} B) |

            The private key and TOTP secret decrypt **only** under {shown.display_name.split()[0]}'s
            password — a database read alone yields ciphertext. TOTP codes are computed live from these
            rows at vote time, so single-use TOTP (#73) never breaks a re-run.
            """
        )
    _out
    return


@app.cell
def _():
    # Capability checklist (degradation-ladder fallback 3): every capability Act 0 shows,
    # traced to the passing backing test in `tests/demo/`.
    mo.md("#### Capability checklist (each row backed by a passing test)\n\n" +
          demo_lib.render_capability_checklist())
    return


if __name__ == "__main__":
    app.run()
