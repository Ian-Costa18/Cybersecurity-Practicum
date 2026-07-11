# /// script
# requires-python = ">=3.14"
# dependencies = ["pyyaml>=6.0.3"]
# ///
"""The evidence catalog's shared spine (issue #157).

An **evidence item** is a named claim backed by tests. The repo keeps two kinds:

* **capabilities** (``docs/evaluation-capabilities.yaml``) — what the system *does*, the
  claims a Requester, Approver, Admin, or Operator invokes or receives;
* **threats** (``docs/threat-model/``) — what the system *prevents*, the properties it
  holds so an attacker cannot act.

They differ in everything but their spine: both name a claim and cite the pytest nodes that
demonstrate it, and both are worthless if a cited node has been renamed away. That spine —
:class:`Violation` and :func:`check_tests` — lives here, so ``threat_model.py`` and
``capabilities.py`` enforce one contract rather than two that drift.

The **evaluation suite** is defined as the union of every evidence item's ``tests:``. It is
therefore a thing you can run, not a phrase in a document::

      uv run tools/evidence.py suite                  # counts, per item
      uv run tools/evidence.py suite --tests          # …expanded to node ids
      uv run pytest $(uv run tools/evidence.py suite --format ids)

Like ``threat_model.py`` this is repo dev/analysis tooling: it reads catalogs that never
ship in the wheel, so it is deliberately not a ``[project.scripts]`` console command.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

#: A ``tests:`` entry is a pytest node id: ``tests/<path>.py::<function>``.
TEST_NODE = re.compile(r"^(?P<path>tests/[^\s:]+\.py)::(?P<name>[A-Za-z0-9_]+)$")

#: Marks an item whose tests do double duty — the same node backs a capability *and* a
#: threat, i.e. one test proves both that a thing works and that it cannot be subverted.
DOUBLE_DUTY = "‡"


@dataclass(frozen=True)
class Violation:
    """One contract breach: which item, which rule, and a human-readable message.

    ``owner`` is whatever names the breach to a reader — a threat's filename, a
    capability's id.
    """

    owner: str
    rule: str
    message: str


@dataclass(frozen=True)
class EvidenceItem:
    """One claim and the pytest nodes that demonstrate it."""

    kind: str  # "capability" | "threat"
    id: str
    title: str
    tests: tuple[str, ...]


def force_utf8_lf() -> None:
    """Make stdout safe for both audiences of the evidence tools.

    ``utf-8`` because the human views spell the double-duty dagger, the bucket ordinals,
    and em-dashes, and a Windows console defaults to cp1252 — it would raise rather than
    print. ``\\n`` because ``evidence.py suite --format ids`` is a **pytest selector**:
    Windows' default CRLF translation glues a ``\\r`` to every node id, and
    ``pytest $(… --format ids)`` then reports every one of them as "not found" — a failure
    that cannot reproduce on Linux CI. Captured (non-``TextIOWrapper``) streams are left
    alone, which is what makes this a no-op under pytest.
    """
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")


def repo_root_for(path: Path, *, depth: int) -> Path | None:
    """The repo root ``depth`` directories above ``path``, or ``None``.

    A catalog file knows where the root is by how deep it sits: a threat at
    ``<repo>/docs/threat-model/<file>.md`` is three levels down, the capabilities YAML at
    ``<repo>/docs/<file>.yaml`` is two. ``None`` means the root can't be located — e.g. a
    synthetic in-memory record in the unit tests, whose path is a bare filename — and the
    caller then verifies node-id *format* but skips the on-disk existence check.
    """
    resolved = path.resolve()
    if len(resolved.parents) > depth:
        candidate = resolved.parents[depth]
        if (candidate / "tests").is_dir():
            return candidate
    return None


def check_tests(owner: str, tests: Sequence[str], *, repo_root: Path | None) -> list[Violation]:
    """Every entry in ``tests`` resolves to a real pytest node: ``tests/<path>.py::<def>``,
    the file exists, and the function is defined in it.

    The on-disk resolution is what keeps a catalog honest: rename a cited test and this
    check — which runs in the pytest suite for both catalogs — fails until the id is fixed.
    It proves the node's *format* and its *definition*; that pytest can actually select it
    is proved by the ``evidence`` CI check, which collects the whole suite.
    """
    violations: list[Violation] = []
    for node in tests:
        match = TEST_NODE.match(node)
        if match is None:
            violations.append(
                Violation(owner, "tests-format", f"test {node!r} is not tests/<path>.py::<name>")
            )
            continue
        if repo_root is None:
            continue  # format verified; existence unverifiable in this context
        test_file = repo_root / match.group("path")
        if not test_file.is_file():
            violations.append(
                Violation(owner, "tests-missing", f"{node}: file {match.group('path')} not found")
            )
            continue
        func = match.group("name")
        defined = re.search(
            rf"^\s*(async\s+)?def\s+{re.escape(func)}\s*\(",
            test_file.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        if not defined:
            violations.append(
                Violation(owner, "tests-missing", f"{node}: no def {func} in {match.group('path')}")
            )
    return violations


# --------------------------------------------------------------------------- #
# The evaluation suite: the union of both catalogs' tests
# --------------------------------------------------------------------------- #


def load_evidence() -> tuple[list[EvidenceItem], int]:
    """Both catalogs as evidence items, plus the count of threats that cite no test.

    Only threats *carrying* tests become items — the rest are mitigated by argument,
    operator configuration, or accepted as limitations (buckets ②③④), and have no place in
    a suite selector. Their count is returned so a reader is never left to infer that the
    catalog holds only the threats shown.

    Both catalog modules import this one, so they are imported inside the function body —
    at module scope the import would be circular.
    """
    import capabilities
    import threat_model

    items = [
        EvidenceItem("capability", capability.id, capability.statement, tuple(capability.tests))
        for capability in capabilities.load_catalog()
    ]
    testless = 0
    for threat in threat_model.load_catalog():  # already sorted by id (group, then number)
        cited = threat.frontmatter.get("tests")  # absent on the argued/accepted threats
        tests = tuple(str(node) for node in cited) if isinstance(cited, list) else ()
        if not tests:
            testless += 1
            continue
        items.append(EvidenceItem("threat", threat.id, threat.title, tests))
    return items, testless


def suite_node_ids(items: Iterable[EvidenceItem]) -> list[str]:
    """Every distinct pytest node the evidence cites, sorted.

    Deduped because a node may back several items, and sorted so the CI selector diffs
    legibly and the output is stable across runs.
    """
    return sorted({node for item in items for node in item.tests})


def double_duty_nodes(items: Iterable[EvidenceItem]) -> dict[str, list[str]]:
    """Nodes cited by a capability *and* a threat → the ids that cite them, in order.

    Cross-kind only. Plenty of nodes back more than one *threat*; that is unremarkable and
    would drown the signal. A node that backs both kinds is the interesting one: the same
    executable fact proves the feature works and proves the attack fails.
    """
    citers: dict[str, list[str]] = {}
    kinds: dict[str, set[str]] = {}
    for item in items:
        for node in item.tests:
            citers.setdefault(node, []).append(item.id)
            kinds.setdefault(node, set()).add(item.kind)
    return {node: ids for node, ids in citers.items() if len(kinds[node]) > 1}


#: Statements run long; past this the title column pushes the test count off a terminal.
_TITLE_WIDTH = 88


def _elide(text: str) -> str:
    return text if len(text) <= _TITLE_WIDTH else f"{text[: _TITLE_WIDTH - 1]}…"


def _render_group(
    items: Sequence[EvidenceItem], *, double_duty: dict[str, list[str]], show_tests: bool
) -> list[str]:
    if not items:
        return []
    id_width = max(len(item.id) for item in items)
    title_width = min(_TITLE_WIDTH, max(len(item.title) for item in items))
    lines: list[str] = []
    for item in items:
        plural = "" if len(item.tests) == 1 else "s"
        mark = f"  {DOUBLE_DUTY}" if any(node in double_duty for node in item.tests) else ""
        count = f"{len(item.tests)} test{plural}"
        title = _elide(item.title)
        lines.append(f"  {item.id:<{id_width}}  {title:<{title_width}}  {count:>8}{mark}".rstrip())
        if show_tests:
            # Under --tests the dagger lands on the node itself: the reader can see which
            # exact test is carrying both a capability and a threat, and who else cites it.
            for node in item.tests:
                others = [cid for cid in double_duty.get(node, ()) if cid != item.id]
                suffix = f"  {DOUBLE_DUTY} {' · '.join(others)}" if others else ""
                lines.append(f"      {node}{suffix}")
    return lines


def render_suite(items: Sequence[EvidenceItem], testless_threats: int, *, show_tests: bool) -> str:
    """The human view: one line per evidence item, grouped by kind, with the totals that
    make the suite a number rather than an adjective."""
    double_duty = double_duty_nodes(items)
    blocks: list[str] = []
    for kind, plural in (("capability", "capabilities"), ("threat", "threats")):
        group = [item for item in items if item.kind == kind]
        nodes = suite_node_ids(group)
        blocks.append(f"{plural} — {len(group)} items, {len(nodes)} tests")
        blocks.extend(_render_group(group, double_duty=double_duty, show_tests=show_tests))
        blocks.append("")

    total = len(suite_node_ids(items))
    if double_duty:
        blocks.append(
            f"{DOUBLE_DUTY} double duty — {len(double_duty)} of {total} tests back a capability "
            "*and* a threat: the same executable fact shows the feature works and the attack "
            "fails. Run with --tests to see which."
        )
        blocks.append("")

    if testless_threats:
        # Named, not silently omitted: without this line the reader would read "22 threats"
        # as the size of the catalog. `validate` already fails a bucket-① threat with no
        # test, so these are the argued, operator-enforced, and accepted ones by contract.
        blocks.append(
            f"{testless_threats} threats carry no tests — "
            "buckets ②③④ (argued, operator-enforced, accepted)."
        )
        blocks.append("")

    blocks.append(f"evaluation suite: {total} distinct tests across {len(items)} evidence items")
    return "\n".join(blocks)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence.py", description="The evaluation suite, derived from the evidence catalogs."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    suite = sub.add_parser("suite", help="list every evidence item and the tests backing it")
    suite.add_argument(
        "--tests", action="store_true", help="expand each item to the pytest node ids it cites"
    )
    suite.add_argument(
        "--format",
        choices=("human", "ids"),
        default="human",
        help="'ids' prints bare, deduped, sorted node ids — a pytest selector",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    force_utf8_lf()
    items, testless = load_evidence()
    if args.format == "ids":
        print("\n".join(suite_node_ids(items)))
    else:
        print(render_suite(items, testless, show_tests=args.tests))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
