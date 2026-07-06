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

    import httpx

    import demo_flow
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

    # The step->overlay mapping is tested flow logic in demo_lib (not glue in here); we
    # only feed it the shown co-owner's real public-key fingerprint read above.
    overlays = demo_lib.overlays_for_step(step_obj, shown_fingerprint=_state.public_key_hex[:8])

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
    if shown.key not in step_obj.active_nodes:
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
def _(sessions):
    # The live-stack driver + the human channel. Everything below drives the REAL proxy
    # over HTTP (twine upload, the approve page, the User Portal), reads Mailpit's REST
    # API, and checks the pypiserver index — nothing mocked. Endpoints default to the
    # compose service names; a presenter on the host overrides them via the environment.
    demo_stack = demo_flow.DemoStack.from_env()
    _proxy_client = httpx.Client(base_url=demo_stack.proxy_url, timeout=30)
    driver = demo_flow.ProxyDriver(client=_proxy_client, sessions=sessions)
    mo.md(
        f"""
        ---
        # Acts 1 & 2 — the workflow on the live stack

        Proxy `{demo_stack.proxy_url}` · Mailpit `{demo_stack.mailpit_url}` ·
        pypiserver `{demo_stack.pypiserver_url}`. Each button fires **real** HTTP calls
        and paints the result onto the same board. The backing checks in `tests/demo/`
        drive this exact flow code against an in-process proxy.
        """
    )
    return demo_stack, driver


@app.cell
def _():
    mo.md("## Act 1 — the happy path (all light)")
    return


@app.cell
def _():
    # Act 1 progress: a `beat` pointer into ACT1_STEPS plus the real values read back from
    # the stack (the bound hash, the tally, the published/installable facts).
    a1_get, a1_set = mo.state({"beat": 0})
    return a1_get, a1_set


@app.cell
def _(a1_get, a1_set, demo_stack, driver):
    # Each button performs one live beat and records its real result. The board cell below
    # reads that state and paints it; no value is fabricated for a beat that has not run.
    def _announce(_value):
        delivered = demo_flow.act1_announce(demo_stack)
        a1_set(lambda s: {**s, "beat": 0, "announced": delivered})

    def _submit(_value):
        cookie, token = demo_flow.act1_prepare_requester(driver)
        draft_id, request_id, artifact = demo_flow.act1_submit_with_self_cancel(
            driver, cookie, token
        )
        a1_set(
            lambda s: {
                **s,
                "beat": 2,
                "draft_id": draft_id,
                "request_id": request_id,
                "sha256": artifact.sha256,
            }
        )

    def _inspect(_value):
        request_id = a1_get()["request_id"]
        matches = demo_flow.act1_inspect_and_vote(driver, request_id, demo_flow.benign_release())
        approvals, quorum = driver.tally(request_id)
        a1_set(
            lambda s: {
                **s,
                "beat": 3,
                "inspected": matches,
                "approvals": approvals,
                "quorum": quorum,
            }
        )

    def _self_votes(_value):
        request_id = a1_get()["request_id"]
        demo_flow.act1_self_driven_votes(driver, request_id, base_offset=2)
        approvals, quorum = driver.tally(request_id)
        a1_set(
            lambda s: {
                **s,
                "beat": 5,
                "approvals": approvals,
                "quorum": quorum,
                "state": driver.state(request_id),
            }
        )

    def _install(_value):
        files = demo_flow.index_files(demo_stack)
        a1_set(
            lambda s: {**s, "beat": 6, "installable": demo_flow.index_has_version(files, "1.0.0")}
        )

    _shown = demo_lib.person(demo_lib.ACT1_SHOWN_VOTER).given_name
    mo.hstack(
        [
            mo.ui.button(label="① Announce", on_click=_announce),
            mo.ui.button(label="② Submit 1.0.0 (self-cancel a draft first)", on_click=_submit),
            mo.ui.button(label=f"③ {_shown} inspects & votes", on_click=_inspect),
            mo.ui.button(label="④ Self-driven votes → quorum", on_click=_self_votes),
            mo.ui.button(label="⑤ pip install check", on_click=_install),
        ],
        justify="start",
        wrap=True,
    )
    return


@app.cell
def _(a1_get):
    _s = a1_get()
    _beat = _s.get("beat", 0)
    _step = demo_lib.ACT1_STEPS[_beat]
    _overlays = demo_lib.act1_overlays(
        _step,
        artifact_sha256=_s.get("sha256"),
        approvals=_s.get("approvals"),
        quorum=_s.get("quorum"),
        published_version="1.0.0" if _beat >= 5 else None,
        installable=_s.get("installable"),
    )
    _shown = demo_lib.person(demo_lib.ACT1_SHOWN_VOTER).given_name
    _lines: list[str] = []
    if "announced" in _s:
        _lines.append(
            f"- Team thread: **{_s['announced']}** heads-up email(s) sent (real, in Mailpit)."
        )
    if "request_id" in _s:
        _lines.append(f"- Draft self-cancelled; clean request `{_s['request_id']}` is pending.")
        _lines.append(f"- Hash-bound at intake: `sha256:{(_s.get('sha256') or '')[:16]}…`")
    if "inspected" in _s:
        _mark = "matched the bound hash ✓" if _s["inspected"] else "MISMATCH ✗"
        _lines.append(f"- {_shown} downloaded the exact artifact ({_mark}) and voted approve.")
    if "state" in _s:
        _lines.append(
            f"- Tally **{_s.get('approvals')}/{_s.get('quorum')}**, request **{_s['state']}** "
            "→ published to pypiserver, audited, outcome emailed."
        )
    if "installable" in _s:
        _ok = "succeeds ✓" if _s["installable"] else "not found ✗"
        _lines.append(
            f"- `pip install {demo_lib.PACKAGE_NAME}==1.0.0` {_ok} against the local index."
        )
    mo.vstack(
        [
            mo.md(f"**Act 1 · beat {_beat + 1}/{len(demo_lib.ACT1_STEPS)} — {_step.title}**"),
            mo.Html(demo_lib.render_board_svg(_step, overlays=_overlays)),
            mo.md("\n".join(_lines) or "_Press ① to begin Act 1._"),
        ]
    )
    return


@app.cell
def _():
    mo.md("## Act 2 — the compromise (the dark turn)")
    return


@app.cell
def _():
    a2_get, a2_set = mo.state({"beat": 0})
    return a2_get, a2_set


@app.cell
def _(a2_get, a2_set, demo_stack, driver):
    # The stolen seat is a *planted, throwaway* credential (demo_lib.DEMO_TEAM) — no real
    # theft. Only the proxy credential is "stolen"; the owner's mailbox stays intact, which
    # is why the out-of-band reply below is trustworthy.
    def _two_am(_value):
        with driver.sessions() as _session:
            _stolen, request_id, artifact = demo_flow.act2_submit_from_stolen_seat(driver, _session)
        approvals, quorum = driver.tally(request_id)
        a2_set(
            lambda s: {
                **s,
                "beat": 0,
                "request_id": request_id,
                "sha256": artifact.sha256,
                "approvals": approvals,
                "quorum": quorum,
            }
        )

    def _careless(_value):
        request_id = a2_get()["request_id"]
        demo_flow.act2_careless_rubber_stamp(driver, request_id)
        approvals, quorum = driver.tally(request_id)
        a2_set(lambda s: {**s, "beat": 1, "approvals": approvals, "quorum": quorum})

    def _frozen(_value):
        request_id = a2_get()["request_id"]
        approvals, quorum = driver.tally(request_id)
        a2_set(lambda s: {**s, "beat": 2, "approvals": approvals, "quorum": quorum})

    def _verify(_value):
        question_sent, reply_sent = demo_flow.act2_verify_out_of_band(demo_stack)
        try:  # render the real exchange from Mailpit; decorative, never blocks the deny
            thread = demo_flow.fetch_thread(demo_stack, subject_contains="acme-widgets 1.0.1")
            thread_html = demo_flow.render_thread_html(thread)
        except Exception:
            thread_html = ""
        a2_set(
            lambda s: {
                **s,
                "beat": 3,
                "verify_sent": question_sent,
                "reply_sent": reply_sent,
                "thread_html": thread_html,
            }
        )

    def _deny(_value):
        request_id = a2_get()["request_id"]
        demo_flow.act2_diligent_deny(driver, request_id)
        a2_set(lambda s: {**s, "beat": 4, "state": driver.state(request_id)})

    def _blocked(_value):
        files = demo_flow.index_files(demo_stack)
        a2_set(
            lambda s: {**s, "beat": 5, "absent": not demo_flow.index_has_version(files, "1.0.1")}
        )

    def _reveal(_value):
        setup_py = demo_flow.extract_text_member(demo_flow.malicious_release().content, "setup.py")
        a2_set(lambda s: {**s, "beat": 6, "payload": setup_py})

    mo.hstack(
        [
            mo.ui.button(label="① 2 a.m. malicious 1.0.1 + self-approve", on_click=_two_am),
            mo.ui.button(label="② Careless rubber-stamp", on_click=_careless),
            mo.ui.button(label="③ Frozen at 2/3", on_click=_frozen),
            mo.ui.button(label="④ 9 a.m. verify out-of-band", on_click=_verify),
            mo.ui.button(label="⑤ Diligent deny", on_click=_deny),
            mo.ui.button(label="⑥ Index blocked", on_click=_blocked),
            mo.ui.button(label="⑦ Reveal payload", on_click=_reveal),
        ],
        justify="start",
        wrap=True,
    )
    return


@app.cell
def _(a2_get):
    _s = a2_get()
    _beat = _s.get("beat", 0)
    _step = demo_lib.ACT2_STEPS[_beat]
    _overlays = demo_lib.act2_overlays(
        _step,
        approvals=_s.get("approvals"),
        quorum=_s.get("quorum"),
        state=_s.get("state"),
        blocked_version="1.0.1" if _beat >= 5 else None,
    )
    _owner = demo_lib.person(demo_lib.ACT2_STOLEN_SEAT).given_name
    _diligent = demo_lib.person(demo_lib.ACT2_DILIGENT).given_name
    _lines: list[str] = []
    if "request_id" in _s:
        _lines.append(
            f"- 2 a.m.: request `{_s['request_id']}` from {_owner}'s seat — **no** team-thread heads-up."
        )
    if _s.get("beat", 0) >= 2 and "approvals" in _s:
        _lines.append(
            f"- Frozen at **{_s.get('approvals')}/{_s.get('quorum')}** — the proxy will not publish without quorum."
        )
    if "verify_sent" in _s:
        _lines.append(
            f"- {_diligent} emailed {_owner} out-of-band (sent: {_s['verify_sent']}); "
            f'{_owner} replied *"I was asleep"* (reply: {_s["reply_sent"]}) — a channel the attacker never held.'
        )
    if "state" in _s:
        _lines.append(
            f"- Denied on human context — request state **{_s['state']}**; no code review needed."
        )
    if "absent" in _s:
        _ok = "absent ✓ (`pip install …==1.0.1` fails)" if _s["absent"] else "PRESENT ✗"
        _lines.append(f"- Registry reality: 1.0.1 is {_ok} from the pypiserver index.")
    _body = [
        mo.md(f"**Act 2 · beat {_beat + 1}/{len(demo_lib.ACT2_STEPS)} — {_step.title}**"),
        mo.Html(demo_lib.render_board_svg(_step, overlays=_overlays)),
        mo.md("\n".join(_lines) or "_Press ① to begin Act 2._"),
    ]
    if _s.get("thread_html"):
        # The out-of-band exchange, rendered from Mailpit's REST API (real email, not overlay).
        _body.append(mo.md("**Out-of-band verification (live from Mailpit):**"))
        _body.append(mo.Html(_s["thread_html"]))
    if _s.get("payload"):
        # Corroboration revealed AFTER the deny — the install-time payload, from the real bytes.
        _body.append(mo.md("**Only now — the payload (from the uploaded `setup.py`):**"))
        _body.append(mo.md(f"```python\n{_s['payload']}\n```"))
    mo.vstack(_body)
    return


@app.cell
def _():
    mo.md("## Reset between recording takes")
    return


@app.cell
def _():
    reset_get, reset_set = mo.state(None)
    return reset_get, reset_set


@app.cell
def _(demo_stack, driver, reset_set):
    def _reset(_value):
        reset_set(demo_flow.reset_demo(driver, demo_stack))

    mo.ui.button(label="⟲ Reset demo (clear rows + drop the package)", on_click=_reset)
    return


@app.cell
def _(reset_get):
    _summary = reset_get()
    if _summary is None:
        _out = mo.md(
            "_Clears the demo's requests / staged artifacts / votes / tokens and drops "
            "`acme-widgets` from the index, so a take re-runs in seconds (US31). Team "
            "accounts are kept; a full cold start is `docker compose … down -v`._"
        )
    else:
        _out = mo.md(
            f"Reset: **{_summary.requests_deleted}** requests and **{_summary.tokens_deleted}** "
            f"tokens cleared; index removal attempted: **{_summary.index_removed}**."
        )
    _out
    return


@app.cell
def _():
    # Capability checklist (degradation-ladder fallback 3): every capability the demo shows
    # across Acts 0–2, each traced to a passing backing test.
    mo.md(
        "#### Capability checklist (each row backed by a passing test)\n\n"
        + demo_lib.render_capability_checklist()
    )
    return


if __name__ == "__main__":
    app.run()
