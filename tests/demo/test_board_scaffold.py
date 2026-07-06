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
    # ...and the external services the demo drives.
    assert "mailpit" in labels.lower()
    assert "pypiserver" in labels.lower()


def test_act0_steps_are_ordered_and_reference_real_nodes() -> None:
    node_ids = {node.id for node in demo_lib.BOARD_NODES}
    assert len(demo_lib.ACT0_STEPS) >= 3  # stand up service, show enrollment, born-enrolled team
    for step in demo_lib.ACT0_STEPS:
        assert step.title  # every step names itself for the runbook fallback
        # A step highlights a subset of the real node-set (no dangling ids).
        assert step.active_nodes <= node_ids


def test_render_board_svg_is_well_formed_and_shows_active_nodes() -> None:
    step = demo_lib.ACT0_STEPS[1]  # the shown-enrollment beat (SHOWN_PERSON enrolls)
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
    # the born-enrolled pair and the admin are not.
    assert 'class="node actor active"' in svg  # the shown co-owner, lit
    assert 'class="node actor"' in svg  # the born-enrolled pair + admin, not lit


def test_render_board_svg_paints_live_overlays() -> None:
    step = demo_lib.ACT0_STEPS[1]
    svg = demo_lib.render_board_svg(step, overlays={demo_lib.SHOWN_PERSON.key: "ed25519:ab12cd34"})
    assert "ed25519:ab12cd34" in svg  # live data painted onto the graph, not baked in


def test_overlays_for_step_maps_live_data_to_the_right_nodes() -> None:
    # The step->overlay mapping is tested flow logic (extracted from the notebook).
    enroll = next(s for s in demo_lib.ACT0_STEPS if s.key == "enroll-shown")
    overlays = demo_lib.overlays_for_step(enroll, shown_fingerprint="ab12cd34")
    # The shown co-owner's real fingerprint is painted on their node while their beat runs.
    assert overlays[demo_lib.SHOWN_PERSON.key] == "ed25519:ab12cd34"

    mode_b = next(s for s in demo_lib.ACT0_STEPS if s.key == "mode-b")
    overlays_b = demo_lib.overlays_for_step(mode_b)
    # The born-enrolled pair get a tag on their beat; the shown co-owner is not featured.
    for member in demo_lib.BORN_ENROLLED:
        assert overlays_b[member.key] == "born enrolled"
    assert demo_lib.SHOWN_PERSON.key not in overlays_b
    # No fingerprint is fabricated when none is supplied.
    assert demo_lib.overlays_for_step(enroll) == {}


def test_degradation_ladder_fallbacks_render() -> None:
    step = demo_lib.ACT0_STEPS[0]
    # Fallback 2: mermaid graph.
    mermaid = demo_lib.render_board_mermaid(step)
    assert "graph" in mermaid.lower()
    # Fallback 3: capability checklist, each row traced to a real test id.
    checklist = demo_lib.render_capability_checklist()
    assert "tests/demo/" in checklist  # capabilities trace to the backing tests
