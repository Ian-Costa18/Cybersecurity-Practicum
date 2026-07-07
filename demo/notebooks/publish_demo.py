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
        # Act 0 — Setting up the team

        A team of three co-owns **`{demo_lib.PACKAGE_NAME}`**. Before anyone can ship a new
        release, an administrator sets one rule: **every release needs all three owners to
        approve it** — so no single account, stolen or not, can publish on its own.

        Then watch a new teammate, **{demo_lib.SHOWN_PERSON.display_name}**, come aboard and get
        the personal signing key she'll use to approve releases.
        """
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

    mo.md(
        f"""
        **The service is set up.** Publishing **`{demo_lib.PACKAGE_NAME}`** now takes all
        **{len(demo_lib.CO_OWNERS)}** owners' approval.
        """
    )
    return provisioning, sessions


@app.cell
def _():
    # The `step` state variable: buttons advance it; the board + detail cells read it.
    get_step, set_step = mo.state(0)
    return get_step, set_step


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
    mo.Html(
        demo_lib.render_board_svg(
            step_obj,
            overlays=overlays,
            locked_nodes=demo_lib.locked_nodes_for_step(step_obj),
        )
    )
    return


@app.cell
def _(set_step):
    # Nav sits under the board (above the crypto card) so a click and the board it advances
    # stay close together, matching Acts 1 & 2. Buttons are bound to variables to stay live.
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
def _(sessions, shown, step_obj):
    # The keypair beat, read from Ada's REAL rows: her readable public key, and — once
    # sealed — her private key as ciphertext. Shown only on her keypair/sealed beats
    # (progressive reveal), so the crypto lands where the story is about it.
    _first = shown.display_name.split()[0]
    if step_obj.key == demo_lib.ADA_KEYPAIR_BEAT:
        with sessions() as _s:
            _state = demo_lib.read_credential_state(_s, shown.username, password=shown.password)
        _out = mo.md(
            f"""
            #### {shown.display_name}'s new key pair

            | key | kept | value |
            |---|---|---|
            | **Public key** | readable — safe to share | `ed25519:{_state.public_key_hex[:24]}…` |

            The **public key** is the half anyone can see. It's used to *verify* {_first}'s
            approvals and detect tampering, so it never has to be kept secret.
            """
        )
    elif step_obj.key == demo_lib.ADA_SEALED_BEAT:
        with sessions() as _s:
            _state = demo_lib.read_credential_state(_s, shown.username, password=shown.password)
        _priv = _state.encrypted_private_key or b""
        _out = mo.md(
            f"""
            #### {shown.display_name}'s key pair — private half sealed 🔒

            | key | kept | value |
            |---|---|---|
            | **Public key** | readable — safe to share | `ed25519:{_state.public_key_hex[:24]}…` |
            | **Private key** | 🔒 sealed under {_first}'s password | `{_priv[:16].hex()}…` ({len(_priv)} bytes of ciphertext) |

            {_first}'s **private key is what signs each approval** — a valid signature proves it
            was really her. It's stored **encrypted**, and unlocked only in memory, only when
            {_first} enters her password, for the instant it takes to sign. Read the database
            without her password and all you get is ciphertext.
            """
        )
    else:
        _out = mo.md("")
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
        """
        ---
        # The team puts the service to work

        **Act 1** is a normal release — the team ships a new version the right way.
        **Act 2** is the night one owner's account is stolen, and what stops the attacker
        from shipping malware in the team's name.
        """
    )
    return demo_stack, driver


@app.cell
def _():
    # A presenter-facing action cue rendered under a beat's narration: an imperative line
    # ("open Ada's inbox", "check the internal PyPI") that is still viewer-friendly, with
    # an optional click-out link that opens in a NEW tab so the notebook tab stays put.
    def presenter_cue(text: str, *, url: str | None = None, link_text: str = "open ↗") -> str:
        link = (
            f' &nbsp;<a href="{url}" target="_blank" rel="noopener"><b>{link_text}</b></a>'
            if url
            else ""
        )
        return (
            '<div style="margin:8px 0;padding:8px 12px;border-left:3px solid #3b6ea5;'
            'background:#eef4fb;border-radius:6px;font:14px system-ui,sans-serif;color:#2a2a3a">'
            f"▶ {text}{link}</div>"
        )

    return (presenter_cue,)


@app.cell
def _():
    mo.md("## Act 1 — a normal release")
    return


@app.cell
def _():
    # Act 1 progress: a `beat` pointer into ACT1_STEPS (−1 = not started, so the first
    # click is a visible change) plus the real values read back from the live services.
    a1_get, a1_set = mo.state({"beat": -1})
    return a1_get, a1_set


@app.cell
def _(a1_set, demo_stack, driver):
    # Each button runs one beat against the live services and records its result. Every
    # handler is wrapped so a failure is shown on the board as a ⚠ message instead of
    # silently doing nothing, and each click lands on its own board frame.
    #
    # IMPORTANT (marimo reactivity): this cell must NOT read the `a1_get` getter — a cell
    # that both reads and writes the same state does not propagate its updates (that was
    # the "① does nothing" bug). The one value later beats need from an earlier one (the
    # request id) is carried in this captured `_ctx` dict instead of read back from state.
    _ctx: dict[str, str] = {}

    _shown_voter = demo_lib.person(demo_lib.ACT1_SHOWN_VOTER)  # Ada — the inbox shown on camera

    def _announce_and_upload(_value):
        # One button for the whole "kick off the release" beat: the heads-up email AND the
        # upload, back to back. They were two buttons before, which confused the presenter —
        # after the heads-up they opened the inbox expecting the approval request, but that
        # only goes out on upload. Now a single click lands BOTH emails in Ada's inbox at once.
        try:
            delivered = demo_flow.act1_announce(demo_stack)
            inbox_link = demo_flow.mailpit_link_for(
                demo_stack, _shown_voter, subject_contains=demo_flow.ACT1_ANNOUNCE_SUBJECT
            )
            cookie, token = demo_flow.act1_prepare_requester(driver)
            draft_id, request_id, artifact = demo_flow.act1_submit_with_self_cancel(
                driver, cookie, token
            )
            _ctx["request_id"] = request_id
            # The draft upload emailed the approvers before it was cancelled; drop that
            # cancelled request's stale "Approval needed" (it carries the draft id) so Ada's
            # inbox holds only the heads-up + the one live approval, not a look-alike pair.
            demo_flow.delete_mail_referencing(demo_stack, draft_id)
            approval_link = demo_flow.mailpit_link_for(
                demo_stack, _shown_voter, subject_contains="Approval needed"
            )
            a1_set(
                lambda s: {
                    **s,
                    "beat": 2,
                    "announced": delivered,
                    "inbox_link": inbox_link,
                    "draft_id": draft_id,
                    "request_id": request_id,
                    "sha256": artifact.sha256,
                    "approval_link": approval_link,
                    "error": None,
                }
            )
        except Exception as exc:
            a1_set(lambda s: {**s, "error": f"Announce & upload failed: {exc}"})

    def _inspect(_value):
        try:
            request_id = _ctx["request_id"]
            matches = demo_flow.act1_inspect_and_vote(
                driver, request_id, demo_flow.benign_release()
            )
            approvals, quorum = driver.tally(request_id)
            a1_set(
                lambda s: {
                    **s,
                    "beat": 3,
                    "inspected": matches,
                    "approvals": approvals,
                    "quorum": quorum,
                    "error": None,
                }
            )
        except Exception as exc:
            a1_set(lambda s: {**s, "error": f"Inspect & approve failed: {exc}"})

    def _self_votes(_value):
        try:
            request_id = _ctx["request_id"]
            demo_flow.act1_self_driven_votes(driver, request_id)
            approvals, quorum = driver.tally(request_id)
            a1_set(
                lambda s: {
                    **s,
                    "beat": 5,
                    "approvals": approvals,
                    "quorum": quorum,
                    "state": driver.state(request_id),
                    "index_link": demo_flow.pypiserver_index_url(demo_stack),
                    "error": None,
                }
            )
        except Exception as exc:
            a1_set(lambda s: {**s, "error": f"Voting failed: {exc}"})

    def _install(_value):
        try:
            files = demo_flow.index_files(demo_stack)
            a1_set(
                lambda s: {
                    **s,
                    "beat": 6,
                    "installable": demo_flow.index_has_version(files, "1.0.0"),
                    "index_link": demo_flow.pypiserver_index_url(demo_stack),
                    "error": None,
                }
            )
        except Exception as exc:
            a1_set(lambda s: {**s, "error": f"Install check failed: {exc}"})

    # marimo only wires up a UI element's interactivity when it is bound to a variable —
    # buttons created inline inside an hstack list render but their on_click never fires
    # (that was the "nothing happens" bug; the working Act 0 controls bind their buttons the
    # same way). So bind each button here. The board cell — the one cell allowed to read
    # `a1_get` — lays them out as a control row where only the *next* action is live; the
    # done and not-yet-reachable steps render as greyed, disabled look-alikes, so a stray
    # click while filming can only ever land on the one correct button.
    _shown = demo_lib.person(demo_lib.ACT1_SHOWN_VOTER).given_name
    a1_labels = [
        "① Announce & upload 1.0.0",
        f"② {_shown} inspects & approves",
        "③ The other owners approve",
        "④ Install the release",
    ]
    a1_kickoff_btn = mo.ui.button(label=a1_labels[0], on_click=_announce_and_upload)
    a1_inspect_btn = mo.ui.button(label=a1_labels[1], on_click=_inspect)
    a1_others_btn = mo.ui.button(label=a1_labels[2], on_click=_self_votes)
    a1_install_btn = mo.ui.button(label=a1_labels[3], on_click=_install)
    return a1_inspect_btn, a1_install_btn, a1_kickoff_btn, a1_labels, a1_others_btn


@app.cell
def _(
    a1_get,
    a1_inspect_btn,
    a1_install_btn,
    a1_kickoff_btn,
    a1_labels,
    a1_others_btn,
    presenter_cue,
):
    _s = a1_get()
    _beat = _s.get("beat", -1)
    _shown = demo_lib.person(demo_lib.ACT1_SHOWN_VOTER).given_name
    _visual = []  # the board (visuals) — rendered above the buttons
    _prose = []  # the status lines + presenter cues (prose) — rendered below the buttons
    if _s.get("error"):
        _prose.append(mo.md(f"⚠ **{_s['error']}**"))
    if _beat < 0:
        if not _s.get("error"):
            _prose.append(mo.md("_Press **① Announce & upload 1.0.0** to begin Act 1._"))
    else:
        _step = demo_lib.ACT1_STEPS[_beat]
        _overlays = demo_lib.act1_overlays(
            _step,
            artifact_sha256=_s.get("sha256"),
            approvals=_s.get("approvals"),
            quorum=_s.get("quorum"),
            published_version="1.0.0" if _beat >= 5 else None,
            installable=_s.get("installable"),
        )
        _lines: list[str] = []
        if "announced" in _s:
            _lines.append("- The other owners get a heads-up that 1.0.0 is on the way.")
        if "request_id" in _s:
            _lines.append(
                "- A stray debug file is caught and cancelled; a clean 1.0.0 is uploaded and "
                f"fingerprinted (`sha256:{(_s.get('sha256') or '')[:16]}…`)."
            )
        if "inspected" in _s:
            _mark = "it matches ✓" if _s["inspected"] else "it does NOT match ✗"
            _lines.append(
                f"- {_shown} downloads the exact release, confirms {_mark}, and approves."
            )
        if "state" in _s:
            _lines.append(
                f"- All approvals in ({_s.get('approvals')}/{_s.get('quorum')}) — the release "
                "publishes to PyPI."
            )
        if "installable" in _s:
            _ok = "works ✓" if _s["installable"] else "is not found ✗"
            _lines.append(f"- `pip install {demo_lib.PACKAGE_NAME}==1.0.0` {_ok}.")
        _visual.append(mo.md(f"**Act 1 — {_step.title}**"))
        _visual.append(mo.Html(demo_lib.render_board_svg(_step, overlays=_overlays)))
        _prose.append(mo.md("\n".join(_lines)))
        # Presenter cues: what to show on the live UIs at this beat (still viewer-facing).
        _requester_name = demo_lib.person(demo_lib.ACT1_REQUESTER).given_name
        if _beat == 2 and _s.get("approval_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        f"{_requester_name}'s heads-up <b>and</b> the <b>Approval needed</b> request "
                        f"are now in <b>{_shown}'s inbox</b> — open the Approval needed email, the "
                        "link she clicks to review the exact release.",
                        url=_s["approval_link"],
                        link_text=f"{_shown}'s inbox ↗",
                    )
                )
            )
        if _beat == 3 and _s.get("approval_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        f"Open the <b>Approval needed</b> email in {_shown}'s inbox — that is the "
                        "link she clicks to review the exact release.",
                        url=_s["approval_link"],
                        link_text=f"{_shown}'s inbox ↗",
                    )
                )
            )
        if _beat >= 5 and _s.get("index_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        "See the release land on the <b>internal PyPI</b> index.",
                        url=_s["index_link"],
                        link_text="internal PyPI ↗",
                    )
                )
            )
    # Control row: exactly one live button (the next action). Done steps show a greyed ✓
    # look-alike; still-locked steps show a greyed plain one — both disabled, so a stray
    # click can only ever hit the correct button. `_done_at[i]` is the beat button i lands
    # on; the first button whose beat is not yet reached is the live one (None once all done).
    _real = [a1_kickoff_btn, a1_inspect_btn, a1_others_btn, a1_install_btn]
    _done_at = (2, 3, 5, 6)
    _active = next((_i for _i, _b in enumerate(_done_at) if _beat < _b), None)
    _row = []
    for _i, (_btn, _lbl) in enumerate(zip(_real, a1_labels)):
        if _i == _active:
            _row.append(_btn)  # the one live, clickable button
        else:
            _tick = "✓ " if _beat >= _done_at[_i] else ""
            _row.append(mo.ui.button(label=f"{_tick}{_lbl}", disabled=True))
    _controls = mo.hstack(_row, justify="start", wrap=True)
    # Buttons sit between the board and the prose so a click and its result are adjacent.
    mo.vstack([*_visual, _controls, *_prose])
    return


@app.cell
def _():
    mo.md("## Act 2 — the night an account is stolen")
    return


@app.cell
def _():
    # −1 = not started, so the first click is a visible change on the board.
    a2_get, a2_set = mo.state({"beat": -1})
    return a2_get, a2_set


@app.cell
def _(a2_set, demo_stack, driver):
    # The stolen account is a *planted, throwaway* credential (demo_lib.DEMO_TEAM) — no real
    # theft. Only the login is "stolen"; the owner's inbox stays intact, which is why the
    # direct check below is trustworthy. Each handler is wrapped so a failure shows as ⚠.
    #
    # As in Act 1, this cell must NOT read the `a2_get` getter (a cell that reads and writes
    # the same state does not propagate — the "① does nothing" bug). The request id later
    # beats need is carried in this captured `_ctx` dict.
    _ctx: dict[str, str] = {}
    _diligent_person = demo_lib.person(demo_lib.ACT2_DILIGENT)  # Ada — receives the owner's reply

    def _two_am(_value):
        try:
            with driver.sessions() as _session:
                _stolen, request_id, artifact = demo_flow.act2_submit_from_stolen_seat(
                    driver, _session
                )
            _ctx["request_id"] = request_id
            approvals, quorum = driver.tally(request_id)
            a2_set(
                lambda s: {
                    **s,
                    "beat": 0,
                    "request_id": request_id,
                    "sha256": artifact.sha256,
                    "approvals": approvals,
                    "quorum": quorum,
                    "error": None,
                }
            )
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Malicious upload failed: {exc}"})

    def _careless(_value):
        # The second owner's rubber-stamp *is* the freeze: it lands the request at 2 of 3,
        # and 2 of 3 is where it stops — there is no separate "now it's frozen" action to
        # take, so this is one beat, not two. Nothing moves until the out-of-band check.
        try:
            request_id = _ctx["request_id"]
            demo_flow.act2_careless_rubber_stamp(driver, request_id)
            approvals, quorum = driver.tally(request_id)
            a2_set(
                lambda s: {**s, "beat": 1, "approvals": approvals, "quorum": quorum, "error": None}
            )
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Careless approval failed: {exc}"})

    def _verify(_value):
        try:
            question_sent, reply_sent = demo_flow.act2_verify_out_of_band(demo_stack)
            # Render the "direct check" from the exchange just sent, not read back from Mailpit:
            # the question is addressed to the seat's owner, so the Ada-only shown inbox does not
            # hold it — building from the sent content keeps the full question → reply on screen.
            thread_html = demo_flow.render_thread_html(demo_flow.verification_thread())
            reply_link = demo_flow.mailpit_link_for(
                demo_stack, _diligent_person, subject_contains="Are you pushing"
            )
            a2_set(
                lambda s: {
                    **s,
                    "beat": 2,
                    "verify_sent": question_sent,
                    "reply_sent": reply_sent,
                    "thread_html": thread_html,
                    "reply_link": reply_link,
                    "error": None,
                }
            )
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Verification email failed: {exc}"})

    def _deny(_value):
        try:
            request_id = _ctx["request_id"]
            demo_flow.act2_diligent_deny(driver, request_id)
            a2_set(lambda s: {**s, "beat": 3, "state": driver.state(request_id), "error": None})
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Deny failed: {exc}"})

    def _blocked(_value):
        try:
            files = demo_flow.index_files(demo_stack)
            a2_set(
                lambda s: {
                    **s,
                    "beat": 4,
                    "absent": not demo_flow.index_has_version(files, "1.0.1"),
                    "index_link": demo_flow.pypiserver_index_url(demo_stack),
                    "error": None,
                }
            )
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Index check failed: {exc}"})

    def _reveal(_value):
        try:
            setup_py = demo_flow.extract_text_member(
                demo_flow.malicious_release().content, "setup.py"
            )
            a2_set(lambda s: {**s, "beat": 5, "payload": setup_py, "error": None})
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Payload read failed: {exc}"})

    # Bind each button to a variable so marimo wires up its on_click (see the Act 1 note).
    # The board cell — the only reader of `a2_get` — lays them out with just the next action
    # live and the rest greyed/disabled, so a stray click can only ever hit the right button.
    _owner = demo_lib.person(demo_lib.ACT2_STOLEN_SEAT).given_name
    a2_labels = [
        "① 2 a.m. — malicious 1.0.1 pushed",
        f"② A second owner rubber-stamps — stuck at 2 of {demo_lib.QUORUM}",
        f"③ 9 a.m. — {_owner} is asked directly",
        "④ Deny the release",
        "⑤ It never reached PyPI",
        "⑥ What it would have done",
    ]
    a2_twoam_btn = mo.ui.button(label=a2_labels[0], on_click=_two_am)
    a2_careless_btn = mo.ui.button(label=a2_labels[1], on_click=_careless)
    a2_verify_btn = mo.ui.button(label=a2_labels[2], on_click=_verify)
    a2_deny_btn = mo.ui.button(label=a2_labels[3], on_click=_deny)
    a2_blocked_btn = mo.ui.button(label=a2_labels[4], on_click=_blocked)
    a2_reveal_btn = mo.ui.button(label=a2_labels[5], on_click=_reveal)
    return (
        a2_blocked_btn,
        a2_careless_btn,
        a2_deny_btn,
        a2_labels,
        a2_reveal_btn,
        a2_twoam_btn,
        a2_verify_btn,
    )


@app.cell
def _(
    a2_blocked_btn,
    a2_careless_btn,
    a2_deny_btn,
    a2_get,
    a2_labels,
    a2_reveal_btn,
    a2_twoam_btn,
    a2_verify_btn,
    presenter_cue,
):
    _s = a2_get()
    _beat = _s.get("beat", -1)
    _owner = demo_lib.person(demo_lib.ACT2_STOLEN_SEAT).given_name
    _diligent = demo_lib.person(demo_lib.ACT2_DILIGENT).given_name
    _visual = []  # the board (visuals) — rendered above the buttons
    _prose = []  # the status lines + evidence + presenter cues — rendered below the buttons
    if _s.get("error"):
        _prose.append(mo.md(f"⚠ **{_s['error']}**"))
    if _beat < 0:
        if not _s.get("error"):
            _prose.append(mo.md("_Press **① 2 a.m. — malicious 1.0.1 pushed** to begin Act 2._"))
    else:
        _step = demo_lib.ACT2_STEPS[_beat]
        _overlays = demo_lib.act2_overlays(
            _step,
            approvals=_s.get("approvals"),
            quorum=_s.get("quorum"),
            state=_s.get("state"),
            blocked_version="1.0.1" if _beat >= 4 else None,
        )
        _lines: list[str] = []
        if "request_id" in _s:
            _lines.append(
                f"- 2 a.m.: a release request appears from {_owner}'s account — with no heads-up "
                "to the team."
            )
        if _beat >= 1 and "approvals" in _s:
            _lines.append(
                f"- Stuck at {_s.get('approvals')}/{_s.get('quorum')} — without the third "
                "approval, nothing ships."
            )
        if "verify_sent" in _s:
            _lines.append(
                f'- {_diligent} asks {_owner} directly; {_owner} replies *"I was asleep"* — '
                "a channel the attacker never had."
            )
        if "state" in _s:
            _lines.append(
                f"- {_diligent} denies the release. No one had to read a line of its code."
            )
        if "absent" in _s:
            _ok = "fails ✓ (1.0.1 never reached PyPI)" if _s["absent"] else "unexpectedly WORKS ✗"
            _lines.append(f"- `pip install {demo_lib.PACKAGE_NAME}==1.0.1` {_ok}.")
        _visual.append(mo.md(f"**Act 2 — {_step.title}**"))
        _visual.append(mo.Html(demo_lib.render_board_svg(_step, overlays=_overlays)))
        _prose.append(mo.md("\n".join(_lines)))
        if _s.get("thread_html"):
            _prose.append(mo.md("**The direct check:**"))
            _prose.append(mo.Html(_s["thread_html"]))
        if _s.get("payload"):
            _prose.append(mo.md("**What that release would have run when installed:**"))
            _prose.append(mo.md(f"```python\n{_s['payload']}\n```"))
        # Presenter cues: what to open on the live UIs at this beat.
        if _beat == 2 and _s.get("reply_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        f"In <b>{_diligent}'s inbox</b>, {_owner}'s reply has arrived — the channel "
                        "the attacker never had.",
                        url=_s["reply_link"],
                        link_text=f"{_diligent}'s inbox ↗",
                    )
                )
            )
        if _beat >= 4 and _s.get("index_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        "Open the <b>internal PyPI</b> index — there is no 1.0.1; users were never "
                        "exposed.",
                        url=_s["index_link"],
                        link_text="internal PyPI ↗",
                    )
                )
            )
    # Control row: only the next action is live; done steps show a greyed ✓ look-alike and
    # still-locked steps a greyed plain one — both disabled, so a stray click while filming
    # can only hit the correct button. Here button i lands on beat i, so the live one is the
    # first whose beat is not yet reached (None once all six are done).
    _real = [
        a2_twoam_btn,
        a2_careless_btn,
        a2_verify_btn,
        a2_deny_btn,
        a2_blocked_btn,
        a2_reveal_btn,
    ]
    _done_at = (0, 1, 2, 3, 4, 5)
    _active = next((_i for _i, _b in enumerate(_done_at) if _beat < _b), None)
    _row = []
    for _i, (_btn, _lbl) in enumerate(zip(_real, a2_labels)):
        if _i == _active:
            _row.append(_btn)  # the one live, clickable button
        else:
            _tick = "✓ " if _beat >= _done_at[_i] else ""
            _row.append(mo.ui.button(label=f"{_tick}{_lbl}", disabled=True))
    _controls = mo.hstack(_row, justify="start", wrap=True)
    # Buttons sit between the board and the prose so a click and its result are adjacent.
    mo.vstack([*_visual, _controls, *_prose])
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
def _(a1_set, a2_set, demo_stack, driver, reset_set):
    def _reset(_value):
        summary = demo_flow.reset_demo(driver, demo_stack)
        # reset_demo clears the DB rows, but not the notebook's own beat state — so also
        # rewind both acts to their start, or the boards would stay on their last frame.
        a1_set({"beat": -1})
        a2_set({"beat": -1})
        reset_set(summary)

    mo.ui.button(label="⟲ Reset demo (clear rows + drop the package + empty the inbox)", on_click=_reset)
    return


@app.cell
def _(reset_get):
    _summary = reset_get()
    if _summary is None:
        _out = mo.md(
            "_Clears the demo's requests / staged artifacts / votes / tokens, drops "
            "`acme-widgets` from the index, and empties the Mailpit inbox, so a take re-runs "
            "in seconds on a clean slate. Team accounts are kept; a full cold start is "
            "`docker compose … down -v`._"
        )
    else:
        _out = mo.md(
            f"Reset: **{_summary.requests_deleted}** requests and **{_summary.tokens_deleted}** "
            f"tokens cleared; index removal: **{_summary.index_removed}**; inbox emptied: "
            f"**{_summary.mail_cleared}**."
        )
    _out
    return


if __name__ == "__main__":
    app.run()
