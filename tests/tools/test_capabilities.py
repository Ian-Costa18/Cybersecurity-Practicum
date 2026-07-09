"""The capabilities catalog's contract, enforced inside the pytest suite (issue #157).

The point of the catalog is that a claim cannot outlive the test that backs it. That only
holds if the checks run where a rename would be noticed — so, exactly as
``test_threat_model.py`` does for threats, the live catalog is validated here. Rename a
cited test and this module goes red until the citation is fixed.

The shared spine (``tools/evidence.py``) is tested through both of its callers rather than
in isolation: a synthetic ``check_tests`` unit test would only re-assert the regex.
"""

from __future__ import annotations

import capabilities as caps
import evidence
import pytest

_LIVE_CATALOG = caps.load_catalog()


# --------------------------------------------------------------------------- #
# The live catalog satisfies its contract
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def live_violations() -> dict[str, list[evidence.Violation]]:
    by_owner: dict[str, list[evidence.Violation]] = {}
    for violation in caps.validate_catalog(_LIVE_CATALOG):
        by_owner.setdefault(violation.owner, []).append(violation)
    return by_owner


@pytest.mark.parametrize("capability", _LIVE_CATALOG, ids=lambda c: c.id)
def test_capability_satisfies_contract(
    capability: caps.Capability, live_violations: dict[str, list[evidence.Violation]]
) -> None:
    offending = live_violations.get(capability.id, [])
    assert not offending, "; ".join(f"[{v.rule}] {v.message}" for v in offending)


def test_live_catalog_has_no_violations() -> None:
    # Whole-catalog gate — also covers the cross-entry rule (duplicate ids) that no
    # single-entry test can see.
    violations = caps.validate_catalog(_LIVE_CATALOG)
    assert violations == [], "\n".join(f"{v.owner}: [{v.rule}] {v.message}" for v in violations)


def test_catalog_is_not_empty_and_every_entry_is_backed() -> None:
    assert _LIVE_CATALOG  # an empty catalog would make every other check vacuous
    assert all(capability.tests for capability in _LIVE_CATALOG)
    assert all(capability.user_stories for capability in _LIVE_CATALOG)


def test_shared_account_capabilities_are_out_of_scope() -> None:
    # The evaluation covers package publishing only (#109). Because the suite is *defined*
    # as the union of the catalogs' tests, that scope is a property of what runs — no
    # forward-auth test can be selected by it — rather than a promise in prose.
    nodes = {node for capability in _LIVE_CATALOG for node in capability.tests}
    assert not [node for node in nodes if "forward_auth" in node]


# --------------------------------------------------------------------------- #
# The rules bite (synthetic entries)
# --------------------------------------------------------------------------- #


#: A node in *this* file, so the synthetic entries resolve against something real on disk.
_SELF = "tests/tools/test_capabilities.py::test_synthetic_well_formed_is_clean"


def _capability(**overrides: object) -> caps.Capability:
    fields: dict[str, object] = {
        "id": "CAP-99",
        "statement": "Do the thing",
        "user_stories": (1,),
        "tests": (_SELF,),
        "demo": ("act1",),
    }
    fields.update(overrides)
    return caps.Capability(**fields)  # ty: ignore[invalid-argument-type]


def _rules(capability: caps.Capability) -> set[str]:
    return {v.rule for v in caps.validate_catalog([capability])}


def test_synthetic_well_formed_is_clean() -> None:
    assert caps.validate_catalog([_capability()]) == []


def test_a_capability_with_no_test_is_a_violation() -> None:
    # The analog of "bucket 1 requires a test": an unbacked capability is a checkmark the
    # report could carry with nothing behind it. That is the bug this catalog exists to kill.
    assert "tests-required" in _rules(_capability(tests=()))


def test_a_dangling_user_story_is_a_violation() -> None:
    # mvp-prd.md §User Stories is append-only precisely so this citation stays valid.
    assert "stories-dangling" in _rules(_capability(user_stories=(9999,)))


def test_a_capability_with_no_user_story_is_a_violation() -> None:
    assert "stories-required" in _rules(_capability(user_stories=()))


def test_an_unknown_demo_act_is_a_violation() -> None:
    # A typo'd act would silently drop the entry from the on-camera checklist.
    assert "enum-demo" in _rules(_capability(demo=("act3",)))


def test_a_malformed_id_is_a_violation() -> None:
    assert "id-format" in _rules(_capability(id="CAPABILITY-1"))


def test_a_duplicate_id_is_a_violation() -> None:
    rules = {v.rule for v in caps.validate_catalog([_capability(), _capability()])}
    assert "id-duplicate" in rules


def test_a_renamed_backing_test_is_a_violation() -> None:
    # The drift guard: the node's file exists, but nothing defines that function any more.
    broken = _capability(tests=("tests/tools/test_capabilities.py::test_this_def_does_not_exist",))
    assert "tests-missing" in _rules(broken)


def test_a_malformed_node_id_is_a_violation() -> None:
    assert "tests-format" in _rules(_capability(tests=("not a node id",)))


def test_known_story_numbers_reads_only_the_user_stories_section() -> None:
    # The PRD holds other ordered lists (the evaluation triad restarts at 1); if those
    # leaked in, a stale citation like `user_stories: [4]` would validate against the wrong
    # list. The section has 31 stories and no story 0.
    stories = caps.known_story_numbers()
    assert stories == set(range(1, max(stories) + 1))
    assert max(stories) >= 31


# --------------------------------------------------------------------------- #
# The evaluation suite is the union of both catalogs
# --------------------------------------------------------------------------- #


def test_the_suite_is_both_catalogs_and_nothing_else() -> None:
    items, testless_threats = evidence.load_evidence()
    kinds = {item.kind for item in items}
    assert kinds == {"capability", "threat"}
    assert testless_threats > 0  # buckets ②③④ exist and are reported, not hidden

    nodes = evidence.suite_node_ids(items)
    assert nodes == sorted(set(nodes))  # deduped and sorted: a stable, legible CI selector
    assert nodes  # a `test -n "$ids"` guard in CI depends on this never being empty
    assert all(evidence.TEST_NODE.match(node) for node in nodes)


def test_every_threat_in_the_suite_carries_tests() -> None:
    items, _ = evidence.load_evidence()
    assert all(item.tests for item in items)


def test_double_duty_is_cross_kind_only() -> None:
    # A node cited by two *threats* is unremarkable. A node cited by a capability *and* a
    # threat is the interesting one: the same executable fact shows the feature works and
    # the attack fails. Only the latter is reported.
    items, _ = evidence.load_evidence()
    kinds = {item.id: item.kind for item in items}
    for node, citers in evidence.double_duty_nodes(items).items():
        assert len({kinds[cid] for cid in citers}) == 2, node


def test_render_suite_names_the_testless_threats() -> None:
    items, testless = evidence.load_evidence()
    rendered = evidence.render_suite(items, testless, show_tests=False)
    # Omitting them would let a reader take "N threats" for the size of the catalog.
    assert f"{testless} threats carry no tests" in rendered
    assert "evaluation suite:" in rendered
