"""The demo board scaffold (#143, epic #142).

Act 0 establishes the light-mode, Maltego-style link-analysis board — the three
co-owners + Admin as actor nodes and the services (Proxy pipeline
intake→quorum→executor→audit, Mailpit, pypiserver) — that Acts 1/2 reuse. These
tests lock the *reusable contract*: the node-set is present, the primary SVG
renderer emits well-formed markup that highlights the step's active nodes, and the
degradation-ladder fallbacks (mermaid, capability checklist) render — so a later act
can extend the step list or swap the render backend without silently breaking it.

The board is illustrative, so these are structural checks, not pixel checks (an AFK
agent cannot eyeball the render — that is a presenter step).
"""

from __future__ import annotations

from xml.dom import minidom

import demo_lib


def test_board_node_set_covers_the_cast_and_services() -> None:
    labels = " | ".join(node.label for node in demo_lib.BOARD_NODES)
    ids = {node.id for node in demo_lib.BOARD_NODES}

    # Every co-owner + the admin is an actor node...
    for person in demo_lib.DEMO_TEAM:
        assert person.key in ids
    # ...the proxy pipeline stages are present...
    for stage in ("intake", "quorum", "executor", "audit"):
        assert stage in ids
    # ...and the external services, labelled as the real things they stand in for
    # (the email service and PyPI), not the emulator product names.
    assert "email" in labels.lower()
    assert "pypi" in labels.lower()


def test_act0_steps_are_ordered_and_reference_real_nodes() -> None:
    node_ids = {node.id for node in demo_lib.BOARD_NODES}
    assert len(demo_lib.ACT0_STEPS) >= 3  # stand up service, show enrollment, born-enrolled team
    for step in demo_lib.ACT0_STEPS:
        assert step.title  # every step names itself for the runbook fallback
        # A step highlights a subset of the real node-set (no dangling ids).
        assert step.active_nodes <= node_ids


def test_render_board_svg_is_well_formed_and_shows_active_nodes() -> None:
    step = demo_lib.ACT0_STEPS[1]  # "ada-account" — the shown co-owner joins (SHOWN_PERSON lit)
    svg = demo_lib.render_board_svg(step)

    # parseString here is a well-formedness check on the board's OWN generated markup
    # (not untrusted input), so the XML-attack rule does not apply.
    parsed = minidom.parseString(svg)  # noqa: S318 - trusted self-generated SVG
    root = parsed.documentElement
    assert root is not None
    assert root.tagName == "svg"
    # Every node label is drawn somewhere on the board.
    for node in demo_lib.BOARD_NODES:
        assert node.label in svg
    # The step's active nodes carry the CSS `active` token (styled via `.node.active`);
    # a node the step does not touch does not. In this beat the shown co-owner is active,
    # the other two co-owners and the admin are not.
    assert 'class="node actor active"' in svg  # the shown co-owner, lit
    assert 'class="node actor"' in svg  # the other co-owners + admin, not lit


def test_render_board_svg_paints_live_overlays() -> None:
    step = demo_lib.ACT0_STEPS[1]
    svg = demo_lib.render_board_svg(step, overlays={demo_lib.SHOWN_PERSON.key: "ed25519:ab12cd34"})
    assert "ed25519:ab12cd34" in svg  # live data painted onto the graph, not baked in


def test_overlays_for_step_maps_live_data_to_the_right_nodes() -> None:
    # The step->overlay mapping is tested flow logic (extracted from the notebook).
    keypair = next(s for s in demo_lib.ACT0_STEPS if s.key == demo_lib.ADA_KEYPAIR_BEAT)
    overlays = demo_lib.overlays_for_step(keypair, shown_fingerprint="ab12cd34")
    # The shown co-owner's real fingerprint is painted on their node once their key exists.
    assert overlays[demo_lib.SHOWN_PERSON.key] == "ed25519:ab12cd34"

    already = next(s for s in demo_lib.ACT0_STEPS if s.key == "already-enrolled")
    overlays_b = demo_lib.overlays_for_step(already)
    # The already-set-up pair get a tag on their beat; the shown co-owner is not featured.
    for member in demo_lib.BORN_ENROLLED:
        assert overlays_b[member.key] == "already set up"
    assert demo_lib.SHOWN_PERSON.key not in overlays_b
    # No fingerprint is fabricated when none is supplied.
    assert demo_lib.overlays_for_step(keypair) == {}


def test_locked_nodes_flag_the_sealed_key_only_on_the_sealed_beat() -> None:
    sealed = next(s for s in demo_lib.ACT0_STEPS if s.key == demo_lib.ADA_SEALED_BEAT)
    assert demo_lib.locked_nodes_for_step(sealed) == frozenset({demo_lib.SHOWN_PERSON.key})
    # The padlock only appears on the sealed beat, not the bare keypair beat.
    keypair = next(s for s in demo_lib.ACT0_STEPS if s.key == demo_lib.ADA_KEYPAIR_BEAT)
    assert demo_lib.locked_nodes_for_step(keypair) == frozenset()
    # And the lock glyph is drawn when a node is passed as locked.
    svg = demo_lib.render_board_svg(sealed, locked_nodes=frozenset({demo_lib.SHOWN_PERSON.key}))
    assert 'class="lock"' in svg


def test_degradation_ladder_fallbacks_render() -> None:
    step = demo_lib.ACT0_STEPS[0]
    # Fallback 2: mermaid graph.
    mermaid = demo_lib.render_board_mermaid(step)
    assert "graph" in mermaid.lower()
    # Fallback 3: capability checklist, each row traced to a real test id.
    checklist = demo_lib.render_capability_checklist()
    assert "tests/demo/" in checklist  # capabilities trace to the backing tests


# --- Acts 1 & 2 extend the same board -------------------------------------


def test_act1_and_act2_steps_reference_real_nodes() -> None:
    node_ids = {node.id for node in demo_lib.BOARD_NODES}
    assert len(demo_lib.ACT1_STEPS) >= 5  # announce → submit → inspect/vote → publish → install
    assert len(demo_lib.ACT2_STEPS) >= 5  # 2am submit → stuck at 2/3 → verify → deny → blocked
    for step in (*demo_lib.ACT1_STEPS, *demo_lib.ACT2_STEPS):
        assert step.title  # every beat names itself for the runbook fallback
        assert step.active_nodes <= node_ids  # no dangling ids — reuses Act 0's node-set


def test_act1_overlays_paint_only_live_data_on_the_right_nodes() -> None:
    submit = next(s for s in demo_lib.ACT1_STEPS if s.key == "act1-submit")
    overlays = demo_lib.act1_overlays(submit, artifact_sha256="deadbeefcafe", approvals=0, quorum=3)
    assert overlays["intake"].startswith("sha256:deadbeef")  # the real bound hash
    assert overlays["quorum"] == "0/3 approvals"

    publish = next(s for s in demo_lib.ACT1_STEPS if s.key == "act1-install")
    installed = demo_lib.act1_overlays(publish, published_version="1.0.0", installable=True)
    assert "1.0.0" in installed["pypiserver"] and "install" in installed["pypiserver"]
    # Nothing is fabricated for a node the beat does not light or with no value supplied.
    assert demo_lib.act1_overlays(submit) == {}


def test_act2_overlays_paint_frozen_tally_and_denied() -> None:
    frozen = next(s for s in demo_lib.ACT2_STEPS if s.key == "act2-frozen")
    assert demo_lib.act2_overlays(frozen, approvals=2, quorum=3)["quorum"] == "2/3 — frozen"

    deny = next(s for s in demo_lib.ACT2_STEPS if s.key == "act2-deny")
    assert demo_lib.act2_overlays(deny, state=demo_lib.DENIED)["quorum"] == "DENIED"

    blocked = next(s for s in demo_lib.ACT2_STEPS if s.key == "act2-blocked")
    assert "✗ absent" in demo_lib.act2_overlays(blocked, blocked_version="1.0.1")["pypiserver"]


def test_act2_second_stamp_and_freeze_are_a_single_beat() -> None:
    # The careless approval and the freeze are one beat, not two: the second stamp is what
    # lands the request at 2/3, and 2/3 is where it stops — a separate "now frozen" click
    # added nothing. The merged beat lights the careless approver and carries the tally.
    keys = [s.key for s in demo_lib.ACT2_STEPS]
    assert "act2-careless" not in keys  # the standalone careless beat is gone
    frozen = next(s for s in demo_lib.ACT2_STEPS if s.key == "act2-frozen")
    assert demo_lib.ACT2_CARELESS in frozen.active_nodes  # the second owner is shown approving
    assert demo_lib.act2_overlays(frozen, approvals=2, quorum=3)["quorum"] == "2/3 — frozen"


def test_act2_clock_swings_from_two_am_to_nine_am() -> None:
    # The corner clock is Act 2's overnight-vs-morning device: the compromise and the freeze
    # sit at 2 a.m.; it swings to 9 a.m. exactly when the diligent owner wakes and checks, so
    # the viewer sees that the frozen release simply waited hours for a human to look.
    clocks = {s.key: s.clock for s in demo_lib.ACT2_STEPS}
    assert clocks["act2-2am"] == (2, 0)
    assert clocks["act2-frozen"] == (2, 0)  # still 2 a.m. — the second stamp *is* the freeze
    assert clocks["act2-verify"] == (9, 0)  # 9 a.m. — the wake-up, where the clock swings
    assert clocks["act2-deny"] == (9, 0)
    # Act 1 (a normal daytime release) carries no clock — the device is Act 2's alone.
    assert all(s.clock is None for s in demo_lib.ACT1_STEPS)


def test_render_board_svg_draws_the_clock_only_when_the_beat_has_one() -> None:
    two_am = next(s for s in demo_lib.ACT2_STEPS if s.key == "act2-2am")
    nine_am = next(s for s in demo_lib.ACT2_STEPS if s.key == "act2-verify")

    assert '<circle class="clock-face"' in demo_lib.render_board_svg(two_am)  # clock is drawn
    assert ">2 AM<" in demo_lib.render_board_svg(two_am)  # ...labelled with the beat's time
    assert ">9 AM<" in demo_lib.render_board_svg(nine_am)  # the morning swing
    # A clockless beat (any Act 1 step) draws no clock element (only the shared CSS is present).
    assert '<circle class="clock-face"' not in demo_lib.render_board_svg(demo_lib.ACT1_STEPS[0])


def test_capability_checklist_traces_all_three_acts() -> None:
    checklist = demo_lib.render_capability_checklist()
    assert "tests/demo/test_act0_provisioning.py" in checklist
    assert "tests/demo/test_act1_happy_path.py" in checklist
    assert "tests/demo/test_act2_compromise.py" in checklist
    # The t = m-1 worst case traces to its adversarial twin in the main suite.
    assert "tests/service_types/one_time/test_compromise_boundary.py" in checklist
