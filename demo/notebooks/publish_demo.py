"""Evaluation demo — Act 0: the admin's chair (setup prologue). Issue #143, epic #142.

A marimo notebook that drives the **live `compose.publish.yaml` stack** — nothing
mocked. Act 0 stands up a 3-of-3 publishing service and introduces the team of three
co-owners with a **single button press**: all three are born enrolled (Mode-B) and
revealed together, each with an Ed25519 keypair whose readable public key sits beside a
ciphertext-at-rest private key — no step-by-step enrollment ceremony. The credential
state shown is read from **real DB rows**; the flow + crypto live in the tested
`demo_lib` beside this file (backing check: `tests/demo/`), so this notebook only
*sequences and draws*.

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
app = marimo.App(width="medium", app_title="MPA Proxy — Demo")

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
    mo.md(f"""
    # Act 0 — Meet the team

    **`{demo_lib.PACKAGE_NAME}`** ships only with **all {demo_lib.QUORUM} owners' approval** —
    no single account, stolen or not, can publish alone.

    Owners: **{" · ".join(p.given_name for p in demo_lib.CO_OWNERS)}** — each holds a personal
    signing key, its private half encrypted at rest.
    """)
    return


@app.cell
def _():
    # Stand up the stack + provision the team. Idempotent (create-if-absent), so it runs
    # on load and is safe to re-run; the live stack points MSIG_DATABASE_URL at the
    # proxy's shared SQLite so these are the very rows Acts 1/2 vote on.
    sessions = demo_lib.demo_sessionmaker()
    with sessions() as _provision_session:
        demo_lib.provision_demo_team(_provision_session)
        _provision_session.commit()

    # mo.md(
    #     f"""
    #     **The service is set up.** Publishing **`{demo_lib.PACKAGE_NAME}`** now takes all
    #     **{len(demo_lib.CO_OWNERS)}** owners' approval.
    #     """
    # )
    return (sessions,)


@app.cell
def _():
    # The `step` state variable: buttons advance it; the board + detail cells read it.
    get_step, set_step = mo.state(0)
    return get_step, set_step


@app.cell
def _(get_step, sessions):
    # Live data painted onto the board: read every co-owner's REAL rows and derive a
    # public-key fingerprint per owner. Nothing here is fabricated.
    step_index = get_step()
    step_obj = demo_lib.ACT0_STEPS[step_index]

    with sessions() as _s:
        _fingerprints = {
            _owner.key: demo_lib.read_credential_state(
                _s, _owner.username, password=_owner.password
            ).public_key_hex[:8]
            for _owner in demo_lib.CO_OWNERS
        }

    # The step->overlay mapping is tested flow logic in demo_lib (not glue in here); we
    # only feed it each co-owner's real public-key fingerprint read above.
    overlays = demo_lib.overlays_for_step(step_obj, fingerprints=_fingerprints)

    mo.md(f"### Step {step_index + 1}/{len(demo_lib.ACT0_STEPS)} — {step_obj.title}")
    return overlays, step_obj


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
    # Act 0 is a SINGLE-BUTTON reveal: the board opens on the standup, and one click
    # surfaces the whole team at once (all three co-owners, keys encrypted at rest) — no
    # step-by-step enrollment. Restart rewinds to the standup for the next take. Nav sits
    # under the board so a click and the board it advances stay close together, matching
    # Acts 1 & 2. Buttons are bound to variables to stay live (see the Act 1 note).
    reveal_button = mo.ui.button(label="Reveal the team ▶", on_click=lambda _value: set_step(1))
    restart_button = mo.ui.button(label="⟲ Restart Act 0", on_click=lambda _value: set_step(0))
    mo.hstack([reveal_button, restart_button], justify="start")
    return


@app.cell
def _(sessions, step_obj):
    # The keypair beat, read from every co-owner's REAL rows: each readable public key
    # beside its private key as ciphertext at rest. Shown only on the single reveal beat,
    # so the crypto lands together with the team it introduces.
    if step_obj.key == demo_lib.ACT0_REVEAL_BEAT:
        _rows = []
        with sessions() as _s:
            for _owner in demo_lib.CO_OWNERS:
                _state = demo_lib.read_credential_state(
                    _s, _owner.username, password=_owner.password
                )
                _priv = _state.encrypted_private_key or b""
                _rows.append(
                    f"| **{_owner.given_name}** "
                    f"| `ed25519:{_state.public_key_hex[:24]}…` "
                    f"| 🔒 `{_priv[:12].hex()}…` ({len(_priv)} bytes of ciphertext) |"
                )
        _header = (
            "#### Each owner's key pair — public half readable, private half encrypted 🔒\n\n"
            "| Owner | Public key | Private key (encrypted at rest) |\n"
            "|---|---|---|\n"
        )
        _explain = (
            "\n\nThe **public key** verifies each approval and detects tampering, so it never "
            "has to be secret. The **private key signs** each approval — proof it was really "
            "them — and is stored **encrypted**, unlocked only in memory, only when the owner "
            "enters their password, for the instant it takes to sign. Read the database "
            "without the password and all you get is ciphertext."
        )
        _out = mo.md(_header + "\n".join(_rows) + _explain)
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
    driver = demo_flow.ProxyDriver(
        client=_proxy_client, sessions=sessions, base_url=demo_stack.proxy_url
    )
    mo.md(
        """
        ---
        # Two releases, two outcomes

        With the control in place, we follow two publishing runs — one routine, one hostile.
        """
    )
    return demo_stack, driver


@app.function
# A presenter-facing action cue rendered under a beat's narration: an imperative line
# ("open Ada's inbox", "check the demo PyPI") that is still viewer-friendly, with
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


@app.function
# A self-contained copy-to-clipboard button. It renders as its own iframe document, so the
# inline click handler runs without tripping marimo's HTML sanitizer, and
# document.execCommand('copy') copies from a hidden textarea with no clipboard-permission
# prompt (localhost is a secure origin). Used by the Act 1 presenter helper so the operator
# can paste a throwaway demo password / live 2FA code into the real approve page — the proxy
# still verifies both, this only spares the typing.
def copy_button(label: str, value: str, *, height: str = "46px"):
    safe = (
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )
    label_txt = label.replace("<", "&lt;").replace(">", "&gt;")
    doc = (
        # Zero the iframe body's default 8px margin and clip overflow: without this the button
        # sits 8px down and its bottom spills past the fixed height, so the iframe grows a
        # scrollbar. margin:0 + overflow:hidden keeps it flush and bar-free.
        "<style>html,body{margin:0;padding:0;overflow:hidden}</style>"
        "<button onclick=\"var t=document.getElementById('v');t.select();"
        "document.execCommand('copy');this.textContent='Copied \\u2713';\" "
        'style="font:600 13px system-ui,sans-serif;padding:8px 13px;border:1px solid #3b6ea5;'
        'border-radius:6px;background:#eef4fb;color:#1c3a5e;cursor:pointer">'
        f"{label_txt}</button>"
        f'<textarea id="v" readonly style="position:fixed;top:0;left:0;width:1px;height:1px;'
        f'opacity:0;border:0">{safe}</textarea>'
    )
    return mo.iframe(doc, height=height)


@app.function
# Off-camera presenter helper, shown only on the shown owner's turn (approve in Act 1, deny in
# Act 2): copy her throwaway password and read her live 2FA code, so the operator can act on the
# real page without typing secrets under a 30-second clock. NOT an auth bypass — the page still
# verifies the real password and a real TOTP; this only saves the typing.
def credentials_panel(person, code, *, verb):
    return mo.vstack(
        [
            mo.md(
                f"**{verb} as {person.given_name}.** "
                f"Username **`{person.username}`**; the proxy still verifies the real "
                "password + 2FA."
            ),
            mo.hstack(
                [
                    copy_button("Copy password", person.password),
                    copy_button("Copy 2FA", code),
                    mo.md(f"### 2FA&nbsp;`{code}`"),
                ],
                justify="start",
            ),
        ]
    )


@app.cell
def _():
    mo.md("""
    ## Act 1 — a normal release
    """)
    return


@app.cell
def _(a1_get):
    # Auto-refresh that keeps Ada's live 2FA code current. It is mounted — and therefore only
    # ticks — while it is Ada's turn (Act 1, beat 2); every other beat it renders nothing, so
    # the credentials helper the board builds from `a1_totp_tick.value` appears only then, then
    # vanishes once she has approved, and the board is not re-running on a timer the rest of the
    # act. (mo.ui.refresh must be its own displayed element — a cell can't create and read it.)
    a1_totp_tick = mo.ui.refresh(default_interval="5s", label="2FA auto-refresh")
    a1_totp_tick if a1_get().get("beat") == 2 else mo.md("")
    return (a1_totp_tick,)


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

    _shown_voter = demo_lib.person(demo_lib.ACT1_SHOWN_VOTER)  # Ada — approves live, on camera

    # VOTE ORDER (deciding-vote demo): Charles proposes + self-approves (1/N) at upload;
    # Grace's approval is self-driven by the notebook (2/N); and Ada — the shown owner —
    # casts the DECIDING vote (N/N) HERSELF on the real approve page. So the on-camera
    # approval is the one that reaches quorum and ships the release, and it is cast when the
    # presenter submits the real form, not when a button fires. Ada's button only READS the
    # live result (a read-only fingerprint check + the real tally); it never votes.

    def _announce_and_upload(_value):
        # One button for the whole "kick off the release" beat: the heads-up email AND the
        # upload + Charles's self-approval, back to back. Both emails (the heads-up and the
        # approval request) land in Ada's inbox at once, and the tally opens at 1/N.
        try:
            delivered = demo_flow.act1_announce(demo_stack)
            inbox_link = demo_flow.mailpit_link_for(
                demo_stack, _shown_voter, subject_contains=demo_flow.ACT1_ANNOUNCE_SUBJECT
            )
            cookie, token = demo_flow.act1_prepare_requester(driver)
            request_id, artifact = demo_flow.act1_submit(driver, cookie, token)
            _ctx["request_id"] = request_id
            approval_link = demo_flow.mailpit_link_for(
                demo_stack, _shown_voter, subject_contains="Approval needed"
            )
            # 1/N — proposing the release counts as Charles's own approval (act1_submit).
            approvals, quorum = driver.tally(request_id)
            a1_set(
                lambda s: {
                    **s,
                    "beat": 1,
                    "announced": delivered,
                    "inbox_link": inbox_link,
                    "request_id": request_id,
                    "sha256": artifact.sha256,
                    "approval_link": approval_link,
                    "approvals": approvals,
                    "quorum": quorum,
                    "error": None,
                }
            )
        except Exception as exc:
            a1_set(lambda s: {**s, "error": f"Announce & upload failed: {exc}"})

    def _grace_approves(_value):
        # The middle vote, self-driven by the notebook (ACT1_SELF_VOTERS = Grace): lands the
        # tally at 2/N so the ONE approval left is Ada's on-camera deciding vote.
        try:
            request_id = _ctx["request_id"]
            demo_flow.act1_self_driven_votes(driver, request_id)
            approvals, quorum = driver.tally(request_id)
            a1_set(
                lambda s: {
                    **s,
                    "beat": 2,
                    "grace_approved": True,
                    "approvals": approvals,
                    "quorum": quorum,
                    "error": None,
                }
            )
        except Exception as exc:
            a1_set(lambda s: {**s, "error": f"Grace's approval failed: {exc}"})

    def _ada_confirm(_value):
        # Ada's approval is cast LIVE by the presenter on the real approve page (see the
        # credentials helper above). This button does NOT vote — it reads the live result: a
        # read-only fingerprint check for the board, plus the real tally. If Ada's approval has
        # landed (>= quorum) the release has already published (the executor runs on the
        # quorum-reaching vote); if not, the board stays on Grace's frame with a nudge to
        # approve first, then click again.
        try:
            request_id = _ctx["request_id"]
            matches = demo_flow.inspect_matches(driver, request_id, demo_flow.benign_release())
            approvals, quorum = driver.tally(request_id)
            published = approvals >= quorum
            published_link = (
                demo_flow.mailpit_link_for(demo_stack, _shown_voter, subject_contains="Published")
                if published
                else None
            )
            a1_set(
                lambda s: {
                    **s,
                    "beat": 3 if published else 2,
                    "inspected": matches,
                    "approvals": approvals,
                    "quorum": quorum,
                    "awaiting_ada": not published,
                    "index_link": demo_flow.pypi_project_url(demo_stack),
                    "published_link": published_link,
                    "error": None,
                }
            )
        except Exception as exc:
            a1_set(lambda s: {**s, "error": f"Reading Ada's approval failed: {exc}"})

    def _ada_auto_approve(_value):
        # TEST-ONLY shortcut: cast Ada's approval programmatically so the flow can be rehearsed
        # end-to-end without doing the real on-camera approval. It is surfaced by the board
        # ONLY after ③ has been pressed while Ada has not yet voted (awaiting_ada). Same effect
        # as her live vote — download + fingerprint check, then approve, reaching quorum and
        # publishing. If she has in fact already approved, the vote is rejected and shown as ⚠.
        try:
            request_id = _ctx["request_id"]
            matches = demo_flow.act1_inspect_and_vote(driver, request_id, demo_flow.benign_release())
            approvals, quorum = driver.tally(request_id)
            a1_set(
                lambda s: {
                    **s,
                    "beat": 3,
                    "inspected": matches,
                    "approvals": approvals,
                    "quorum": quorum,
                    "awaiting_ada": False,
                    "index_link": demo_flow.pypi_project_url(demo_stack),
                    "published_link": demo_flow.mailpit_link_for(
                        demo_stack, _shown_voter, subject_contains="Published"
                    ),
                    "error": None,
                }
            )
        except Exception as exc:
            a1_set(lambda s: {**s, "error": f"Auto-approve (test) failed: {exc}"})

    def _install(_value):
        try:
            files = demo_flow.index_files(demo_stack)
            a1_set(
                lambda s: {
                    **s,
                    "beat": 4,
                    "installable": demo_flow.index_has_version(files, "1.0.0"),
                    "index_link": demo_flow.pypi_project_url(demo_stack),
                    "pip_command": demo_flow.pip_install_command(demo_stack, "1.0.0"),
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
    _shown = _shown_voter.given_name
    _grace = demo_lib.person(demo_lib.ACT1_SELF_VOTERS[0]).given_name
    a1_labels = [
        "① Announce & upload 1.0.0",
        f"② {_grace} reviews & approves",
        f"③ {_shown} approves — the deciding vote",
        "④ Install the release",
    ]
    a1_kickoff_btn = mo.ui.button(label=a1_labels[0], on_click=_announce_and_upload)
    a1_grace_btn = mo.ui.button(label=a1_labels[1], on_click=_grace_approves)
    a1_ada_btn = mo.ui.button(label=a1_labels[2], on_click=_ada_confirm)
    a1_install_btn = mo.ui.button(label=a1_labels[3], on_click=_install)
    # Test-only shortcut, surfaced by the board only while awaiting Ada's live approval.
    a1_ada_auto_btn = mo.ui.button(
        label=f"⏩ Auto-approve as {_shown} (test)", on_click=_ada_auto_approve
    )
    return (
        a1_ada_auto_btn,
        a1_ada_btn,
        a1_grace_btn,
        a1_install_btn,
        a1_kickoff_btn,
        a1_labels,
    )


@app.cell
def _(
    a1_ada_auto_btn,
    a1_ada_btn,
    a1_get,
    a1_grace_btn,
    a1_install_btn,
    a1_kickoff_btn,
    a1_labels,
    a1_totp_tick,
    driver,
):
    _s = a1_get()
    _beat = _s.get("beat", -1)
    _shown = demo_lib.person(demo_lib.ACT1_SHOWN_VOTER).given_name
    _grace = demo_lib.person(demo_lib.ACT1_SELF_VOTERS[0]).given_name
    _requester = demo_lib.person(demo_lib.ACT1_REQUESTER).given_name
    _visual = []  # the board (visuals) — rendered above the buttons
    _prose = []  # the status lines + presenter cues (prose) — rendered below the buttons
    if _s.get("error"):
        _prose.append(mo.md(f"⚠ **{_s['error']}**"))
    if _beat < 0:
        if not _s.get("error"):
            _prose.append(mo.md("_Press **① Announce & upload 1.0.0** to begin Act 1._"))
    else:
        _step = demo_lib.ACT1_STEPS[_beat]
        # Ada's deciding approval publishes the release, so the pypiserver overlay lights up
        # from her beat (3) onward — but not while we're still waiting on her live click.
        _published = _beat >= 3 and not _s.get("awaiting_ada")
        _overlays = demo_lib.act1_overlays(
            _step,
            artifact_sha256=_s.get("sha256"),
            approvals=_s.get("approvals"),
            quorum=_s.get("quorum"),
            published_version="1.0.0" if _published else None,
            installable=_s.get("installable"),
        )
        # The progress so far, one sentence per beat completed — rendered as a numbered list
        # (the steps are ordered), so the viewer reads it as 1 → N. The install beat carries a
        # trailing code block, kept in `_code` and appended after the numbered steps.
        _lines: list[str] = []
        _code: str | None = None
        if "announced" in _s:
            _lines.append(f"{_requester} gives the team a heads-up that 1.0.0 is on the way.")
        if "request_id" in _s:
            _lines.append(
                "A clean 1.0.0 is uploaded and fingerprinted "
                f"(`sha256:{(_s.get('sha256') or '')[:16]}…`) — and by proposing it, "
                f"{_requester} casts the first approval."
            )
        if _s.get("grace_approved"):
            _lines.append(f"{_grace} reviews and approves — two of three.")
        if _s.get("inspected") is not None and not _s.get("awaiting_ada"):
            _mark = "matches ✓" if _s["inspected"] else "does NOT match ✗"
            _lines.append(
                f"{_shown} downloads the exact release, confirms the fingerprint {_mark} without "
                "running it, and casts the deciding approval — all three in, so the release "
                "publishes to PyPI."
            )
        if "installable" in _s:
            _ok = "works ✓" if _s["installable"] else "is not found ✗"
            _cmd = _s.get("pip_command", f"pip install {demo_lib.PACKAGE_NAME}==1.0.0")
            _lines.append(f"Installing 1.0.0 from the demo PyPI index {_ok}:")
            _code = f"```sh\n{_cmd}\n```"
        # The board SVG draws the step title in its own header, so no separate heading here.
        _visual.append(mo.Html(demo_lib.render_board_svg(_step, overlays=_overlays)))
        _numbered = [f"{_n}. {_line}" for _n, _line in enumerate(_lines, 1)]
        if _code:
            _numbered.append(f"\n{_code}")
        _prose.append(mo.md("\n".join(_numbered)))
        # Presenter cues: what to do / show on the live UIs at this beat.
        if _beat == 1 and _s.get("inbox_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        f"{_requester}'s heads-up <b>and</b> the <b>Approval needed</b> request "
                        f"are now in <b>{_shown}'s inbox</b> — open {_requester}'s email "
                        "announcing that 1.0.0 is being published.",
                        url=_s["inbox_link"],
                        link_text=f"{_requester}'s heads-up ↗",
                    )
                )
            )
        if _beat == 2 and _s.get("approval_link"):
            # The off-camera credentials helper — rendered ONLY on Ada's turn (this beat), under
            # the buttons and right on top of the "your turn" cue, and gone once she's approved
            # (beat 3+). NOT an auth bypass: the real approve page still verifies her password
            # and a real TOTP; this only spares typing the throwaway secrets. Reading
            # `a1_totp_tick.value` re-runs this on each refresh tick so the 2FA code stays
            # current — and the tick only fires here, because the refresh is mounted only now.
            _ada = demo_lib.person(demo_lib.ACT1_SHOWN_VOTER)
            _ = a1_totp_tick.value
            _prose.append(credentials_panel(_ada, driver.totp(_ada), verb="Approve"))
            if _s.get("awaiting_ada"):
                _prose.append(
                    mo.md(
                        f"_{_shown} hasn't approved yet — approve on the real page, then press "
                        f"**③ {_shown} approves** again, or use the test shortcut to auto-approve._"
                    )
                )
                _prose.append(a1_ada_auto_btn)
            _prose.append(
                mo.md(
                    presenter_cue(
                        f"Your turn, as <b>{_shown}</b>: open the <b>Approval needed</b> request, "
                        "verify the exact release, re-authenticate (use the credentials just "
                        "above), and approve — the vote that reaches quorum. Then press ③.",
                        url=_s["approval_link"],
                        link_text=f"{_shown}'s approval request ↗",
                    )
                )
            )
        if _beat >= 3 and not _s.get("awaiting_ada") and _s.get("index_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        "See the release land on its <b>demo PyPI</b> project page.",
                        url=_s["index_link"],
                        link_text="demo PyPI ↗",
                    )
                )
            )
            if _s.get("published_link"):
                _prose.append(
                    mo.md(
                        presenter_cue(
                            "…and see that every approver is notified — open the "
                            f"<b>Published: {demo_lib.PACKAGE_NAME} 1.0.0</b> email.",
                            url=_s["published_link"],
                            link_text="Published email ↗",
                        )
                    )
                )
    # Control row: exactly one live button (the next action). Done steps show a greyed ✓
    # look-alike; still-locked steps show a greyed plain one — both disabled, so a stray
    # click can only ever hit the correct button. `_done_at[i]` is the beat button i lands
    # on; the first button whose beat is not yet reached is the live one (None once all done).
    _real = [a1_kickoff_btn, a1_grace_btn, a1_ada_btn, a1_install_btn]
    _done_at = (1, 2, 3, 4)
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
    mo.md("""
    ## Act 2 — the night an account is stolen
    """)
    return


@app.cell
def _(a2_get):
    # Auto-refresh for Ada's live 2FA code during her DENY (Act 2, beat 2) — mounted, and so only
    # ticking, on that beat; every other beat it renders nothing, so the credentials helper the
    # Act 2 board builds from `a2_totp_tick.value` appears only then and vanishes once she's denied.
    a2_totp_tick = mo.ui.refresh(default_interval="5s", label="2FA auto-refresh")
    a2_totp_tick if a2_get().get("beat") == 2 else mo.md("")
    return (a2_totp_tick,)


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
            inbox_link = demo_flow.mailpit_link_for(
                demo_stack, _diligent_person, subject_contains="Approval needed"
            )
            a2_set(
                lambda s: {
                    **s,
                    "beat": 0,
                    "request_id": request_id,
                    "sha256": artifact.sha256,
                    "approvals": approvals,
                    "quorum": quorum,
                    "inbox_link": inbox_link,
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
            reply_link = demo_flow.mailpit_link_for(
                demo_stack, _diligent_person, subject_contains="Are you pushing"
            )
            # The approve/deny page link — the same Approval-needed email from 2 a.m. — that Ada
            # opens to cast the live denial (the page carries both an approve and a deny action).
            request_link = demo_flow.mailpit_link_for(
                demo_stack, _diligent_person, subject_contains="Approval needed"
            )
            a2_set(
                lambda s: {
                    **s,
                    "beat": 2,
                    "verify_sent": question_sent,
                    "reply_sent": reply_sent,
                    "reply_link": reply_link,
                    "request_link": request_link,
                    "error": None,
                }
            )
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Verification email failed: {exc}"})

    def _deny(_value):
        # Ada's denial is cast LIVE by the presenter on the real approve/deny page (credentials
        # helper above). This button does NOT vote — it reads the live state: if she has denied,
        # the request is closed and 1.0.1 can never ship; if not, the board stays put with a nudge
        # (and a test shortcut) to deny first, then click again.
        try:
            request_id = _ctx["request_id"]
            state = driver.state(request_id)
            denied = state == demo_lib.DENIED
            a2_set(
                lambda s: {
                    **s,
                    "beat": 3 if denied else 2,
                    "state": state,
                    "awaiting_deny": not denied,
                    "error": None,
                }
            )
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Reading the denial failed: {exc}"})

    def _deny_auto(_value):
        # TEST-ONLY shortcut: cast Ada's denial programmatically so the flow can be rehearsed
        # without the real on-camera deny. Surfaced by the board only after ④ has been pressed
        # while the request is still open (awaiting_deny).
        try:
            request_id = _ctx["request_id"]
            demo_flow.act2_diligent_deny(driver, request_id)
            a2_set(
                lambda s: {
                    **s,
                    "beat": 3,
                    "state": driver.state(request_id),
                    "awaiting_deny": False,
                    "error": None,
                }
            )
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Auto-deny (test) failed: {exc}"})

    def _blocked(_value):
        try:
            files = demo_flow.index_files(demo_stack)
            a2_set(
                lambda s: {
                    **s,
                    "beat": 4,
                    "absent": not demo_flow.index_has_version(files, "1.0.1"),
                    "index_link": demo_flow.pypi_project_url(demo_stack),
                    "pip_command": demo_flow.pip_install_command(demo_stack, "1.0.1"),
                    "error": None,
                }
            )
        except Exception as exc:
            a2_set(lambda s: {**s, "error": f"Index check failed: {exc}"})

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
    ]
    a2_twoam_btn = mo.ui.button(label=a2_labels[0], on_click=_two_am)
    a2_careless_btn = mo.ui.button(label=a2_labels[1], on_click=_careless)
    a2_verify_btn = mo.ui.button(label=a2_labels[2], on_click=_verify)
    a2_deny_btn = mo.ui.button(label=a2_labels[3], on_click=_deny)
    a2_blocked_btn = mo.ui.button(label=a2_labels[4], on_click=_blocked)
    # Test-only shortcut, surfaced by the board only while awaiting Ada's live denial.
    a2_deny_auto_btn = mo.ui.button(
        label=f"⏩ Auto-deny as {_diligent_person.given_name} (test)", on_click=_deny_auto
    )
    return (
        a2_blocked_btn,
        a2_careless_btn,
        a2_deny_auto_btn,
        a2_deny_btn,
        a2_labels,
        a2_twoam_btn,
        a2_verify_btn,
    )


@app.cell
def _(
    a2_blocked_btn,
    a2_careless_btn,
    a2_deny_auto_btn,
    a2_deny_btn,
    a2_get,
    a2_labels,
    a2_totp_tick,
    a2_twoam_btn,
    a2_verify_btn,
    driver,
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
        # The progress so far, one sentence per beat completed — a numbered list so the
        # viewer reads it as 1 → N.
        _lines: list[str] = []
        _code: str | None = None
        if "request_id" in _s:
            _lines.append(
                f"2 a.m.: a release request appears from {_owner}'s account — with no heads-up "
                "to the team."
            )
        if _beat >= 1 and "approvals" in _s:
            _lines.append(
                f"Stuck at {_s.get('approvals')}/{_s.get('quorum')} — without the third "
                "approval, nothing ships."
            )
        if "verify_sent" in _s:
            _lines.append(
                f'{_diligent} asks {_owner} directly; {_owner} replies *"I was asleep"* — '
                "a channel the attacker never had."
            )
        if _s.get("state") == demo_lib.DENIED:
            _lines.append(f"{_diligent} denies the release. No one had to read a line of its code.")
        if "absent" in _s:
            _cmd = _s.get("pip_command", f"pip install {demo_lib.PACKAGE_NAME}==1.0.1")
            if _s["absent"]:
                _lines.append(
                    "Installing 1.0.1 the same way we installed 1.0.0 fails ✗ — the index has no "
                    "such release (`No matching distribution found`), so it never reached anyone:"
                )
            else:
                _lines.append("The 1.0.1 install unexpectedly WORKS ✗:")
            _code = f"```sh\n{_cmd}\n```"
        # The board SVG draws the step title in its own header, so no separate heading here.
        _visual.append(mo.Html(demo_lib.render_board_svg(_step, overlays=_overlays)))
        _numbered = [f"{_n}. {_line}" for _n, _line in enumerate(_lines, 1)]
        if _code:
            _numbered.append(f"\n{_code}")
        _prose.append(mo.md("\n".join(_numbered)))
        # Presenter cues: what to do / open on the live UIs at this beat.
        if _beat == 0 and _s.get("inbox_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        f"Open <b>{_diligent}'s inbox</b>: the request landed as an "
                        f"<b>Approval needed</b> email — but there's no heads-up from {_owner}, "
                        "the way every real release has one.",
                        url=_s["inbox_link"],
                        link_text=f"{_diligent}'s inbox ↗",
                    )
                )
            )
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
        if _beat == 2:
            # Ada's turn to DENY, live — same pattern as her Act 1 approval: the off-camera
            # credentials helper (shown only on this beat, gone once she's denied), the auto-refresh
            # 2FA, and a link to the real approve/deny page. A test shortcut appears only if ④ is
            # pressed while the request is still open.
            _ada = demo_lib.person(demo_lib.ACT2_DILIGENT)
            _ = a2_totp_tick.value
            _prose.append(credentials_panel(_ada, driver.totp(_ada), verb="Deny"))
            if _s.get("awaiting_deny"):
                _prose.append(
                    mo.md(
                        f"_{_diligent} hasn't denied yet — deny on the real page, then press "
                        "**④ Deny the release** again, or use the test shortcut to auto-deny._"
                    )
                )
                _prose.append(a2_deny_auto_btn)
            if _s.get("request_link"):
                _prose.append(
                    mo.md(
                        presenter_cue(
                            f"Your turn, as <b>{_diligent}</b>: open the <b>Approval needed</b> "
                            "request, re-authenticate (use the credentials just above), and "
                            "<b>Deny</b> — one denial closes it before quorum. Then press ④.",
                            url=_s["request_link"],
                            link_text=f"{_diligent}'s request ↗",
                        )
                    )
                )
        if _beat >= 4 and _s.get("index_link"):
            _prose.append(
                mo.md(
                    presenter_cue(
                        "Open the <b>demo PyPI</b> project page — the release history stops at "
                        "1.0.0; there is no 1.0.1, so users were never exposed.",
                        url=_s["index_link"],
                        link_text="demo PyPI ↗",
                    )
                )
            )
    # Control row: only the next action is live; done steps show a greyed ✓ look-alike and
    # still-locked steps a greyed plain one — both disabled, so a stray click while filming
    # can only hit the correct button. Here button i lands on beat i, so the live one is the
    # first whose beat is not yet reached (None once all five are done).
    _real = [
        a2_twoam_btn,
        a2_careless_btn,
        a2_verify_btn,
        a2_deny_btn,
        a2_blocked_btn,
    ]
    _done_at = (0, 1, 2, 3, 4)
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
    mo.md("""
    ## Reset the demo
    """)
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

    mo.ui.button(
        label="⟲ Reset demo (clear rows + drop the package + empty the inbox)", on_click=_reset
    )
    return


@app.cell
def _(reset_get):
    _summary = reset_get()
    if _summary is None:
        _out = mo.md(
            "_Clears the demo's requests / staged artifacts / votes / tokens, drops "
            "`bernoulli` from the index, and empties the Mailpit inbox, so you can run the "
            "demo again in seconds on a clean slate. Team accounts are kept; a full cold "
            "start is `docker compose … down -v`._"
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
