# /// script
# requires-python = ">=3.14"
# dependencies = ["pyyaml>=6.0.3"]
# ///
"""Validate and render the capabilities catalog (``docs/evaluation-capabilities.yaml``).

The sibling of ``threat_model.py``: a capability is what the system **does**, a threat is
what it **prevents**, and both are evidence items — a named claim backed by tests. The
``tests:`` contract they share is enforced once, in ``evidence.py``.

Run it standalone from a repo checkout — no virtualenv, the PEP 723 metadata declares the
lone dep::

      uv run tools/capabilities.py validate
      uv run tools/capabilities.py report --format latex

``report`` prints to stdout and commits nothing: the rendered table belongs in the final
report and the deck, which are the graded artifacts (#132). There is deliberately **no
``query`` verb** — ``threat_model.py`` has one because 33 threats across a dozen
frontmatter fields is a real search problem; 28 capabilities across four fields is a file
you read.

The field contract this module enforces is documented in the catalog's own header.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from evidence import Violation, check_tests, force_utf8_lf, repo_root_for

#: ``demo:`` values. A typo'd ``act3`` would silently drop an entry from the on-camera
#: checklist, so the vocabulary is closed and validated.
DEMO_ACTS: tuple[str, ...] = ("act0", "act1", "act2")

#: The capabilities YAML sits at ``<repo>/docs/<file>.yaml`` — two levels down.
_CATALOG_DEPTH = 1

#: A numbered story in ``mvp-prd.md`` §User Stories: ``12. **[Publishing]** As a …``
_STORY_LINE = re.compile(r"^(?P<number>\d+)\. ", re.MULTILINE)

_ID_PATTERN = re.compile(r"^CAP-\d+$")


def _find_docs() -> Path:
    """Locate ``docs/`` from the working tree.

    Walks up from the CWD first (so the tool works wherever it is run in the repo), then
    from this file's own location (so ``uv run tools/capabilities.py`` works regardless of
    CWD). Mirrors ``threat_model._find_catalog``."""
    module_dir = Path(__file__).resolve().parent
    for base in (Path.cwd(), module_dir):
        for parent in (base, *base.parents):
            candidate = parent / "docs"
            if (candidate / "evaluation-capabilities.yaml").is_file():
                return candidate
    return module_dir.parent / "docs"


DOCS_DIR = _find_docs()
CATALOG_PATH = DOCS_DIR / "evaluation-capabilities.yaml"
PRD_PATH = DOCS_DIR / "mvp-prd.md"


@dataclass(frozen=True)
class Capability:
    """One capability: a claim about what the system does, and the tests that show it."""

    id: str
    statement: str
    user_stories: tuple[int, ...]
    tests: tuple[str, ...]
    demo: tuple[str, ...] = ()
    path: Path = field(default_factory=lambda: CATALOG_PATH)


def load_catalog(path: Path = CATALOG_PATH) -> list[Capability]:
    """Parse the catalog in file order (which is persona/lifecycle order)."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [
        Capability(
            id=str(entry.get("id", "")),
            statement=str(entry.get("statement", "")),
            user_stories=tuple(int(n) for n in entry.get("user_stories") or ()),
            tests=tuple(str(node) for node in entry.get("tests") or ()),
            demo=tuple(str(act) for act in entry.get("demo") or ()),
            path=path,
        )
        for entry in raw
    ]


def demo_rows(capabilities: Sequence[Capability], act: str | None = None) -> list[Capability]:
    """The capabilities the demo shows — all acts, or just ``act``."""
    return [
        capability
        for capability in capabilities
        if capability.demo and (act is None or act in capability.demo)
    ]


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def known_story_numbers(path: Path = PRD_PATH) -> set[int]:
    """The story numbers defined in ``mvp-prd.md`` §User Stories.

    Read out of the one section, not the whole file, because the PRD's other ordered lists
    (the evaluation triad, for one) restart at 1 and would silently widen the valid range.
    """
    text = path.read_text(encoding="utf-8")
    start = text.find("\n## User Stories")
    if start == -1:  # pragma: no cover - the section is a spec invariant
        return set()
    end = text.find("\n## ", start + 1)
    section = text[start : end if end != -1 else len(text)]
    return {int(match.group("number")) for match in _STORY_LINE.finditer(section)}


def validate_catalog(capabilities: Sequence[Capability]) -> list[Violation]:
    """Every contract check over the catalog.

    Three rules beyond the shared ``tests:`` contract:

    1. **Every capability names at least one backing test.** The analog of the threat
       catalog's "bucket ① requires a test": a capability with no test is a hole the
       report must not be able to hide.
    2. **Every cited story number exists.** The catalog is the only thing pointing at the
       PRD's numbering, so a typo'd or stale citation would otherwise go unnoticed.
    3. **Every ``demo:`` value is a known act.**
    """
    violations: list[Violation] = []
    seen: set[str] = set()
    stories = known_story_numbers()
    for capability in capabilities:
        owner = capability.id or "<missing id>"
        if not _ID_PATTERN.match(capability.id):
            violations.append(Violation(owner, "id-format", f"id {capability.id!r} is not CAP-<n>"))
        if capability.id in seen:
            violations.append(Violation(owner, "id-duplicate", f"duplicate id {capability.id!r}"))
        seen.add(capability.id)
        if not capability.statement:
            violations.append(Violation(owner, "statement-required", "statement is empty"))
        if not capability.tests:
            violations.append(
                Violation(owner, "tests-required", "a capability requires >=1 backing test")
            )
        if not capability.user_stories:
            violations.append(
                Violation(owner, "stories-required", "a capability cites >=1 mvp-prd user story")
            )
        for number in capability.user_stories:
            if number not in stories:
                violations.append(
                    Violation(
                        owner,
                        "stories-dangling",
                        f"user story {number} is not defined in mvp-prd.md §User Stories",
                    )
                )
        for act in capability.demo:
            if act not in DEMO_ACTS:
                violations.append(
                    Violation(owner, "enum-demo", f"invalid demo act {act!r}; want {DEMO_ACTS}")
                )
        repo_root = repo_root_for(capability.path, depth=_CATALOG_DEPTH)
        violations.extend(check_tests(owner, capability.tests, repo_root=repo_root))
    return violations


# --------------------------------------------------------------------------- #
# Report — the capability checklist (issue #132: stdout, no committed artifact)
# --------------------------------------------------------------------------- #


def _latex_escape(text: str) -> str:
    for char in ("\\", "&", "%", "$", "#", "_", "{", "}"):
        text = text.replace(char, f"\\{char}")
    return text


def render_markdown(capabilities: Sequence[Capability]) -> str:
    """The checklist as a Markdown table: capability, stories, backing tests."""
    lines = ["| Capability | Stories | Backing tests |", "|---|---|---|"]
    for capability in capabilities:
        stories = ", ".join(str(n) for n in capability.user_stories)
        tests = "<br>".join(f"`{node}`" for node in capability.tests)
        lines.append(f"| {capability.statement} | {stories} | {tests} |")
    return "\n".join(lines)


def render_latex(capabilities: Sequence[Capability]) -> str:
    """The checklist as a LaTeX ``tabularx`` body, for the final report's appendix."""
    lines = [
        r"\begin{tabularx}{\textwidth}{@{}lXc@{}}",
        r"\toprule",
        r"ID & Capability & Tests \\",
        r"\midrule",
    ]
    for capability in capabilities:
        lines.append(
            f"{_latex_escape(capability.id)} & {_latex_escape(capability.statement)} "
            f"& {len(capability.tests)} \\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabularx}"])
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capabilities.py", description="Validate and render the capabilities catalog."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="check the catalog against its field contract")
    report = sub.add_parser("report", help="render the capability checklist to stdout")
    report.add_argument("--format", choices=("md", "latex"), default="md")
    report.add_argument(
        "--demo-only", action="store_true", help="only capabilities the demo shows on camera"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    force_utf8_lf()  # `report` is redirected into a .tex; keep the em-dashes, keep LF
    capabilities = load_catalog()
    if args.command == "validate":
        violations = validate_catalog(capabilities)
        for violation in violations:
            print(f"{violation.owner}: [{violation.rule}] {violation.message}", file=sys.stderr)
        if violations:
            print(f"FAIL: {len(violations)} violation(s)", file=sys.stderr)
            return 1
        tests = {node for capability in capabilities for node in capability.tests}
        print(f"ok: {len(capabilities)} capabilities, {len(tests)} distinct tests, no violations")
        return 0

    rows = demo_rows(capabilities) if args.demo_only else capabilities
    print(render_latex(rows) if args.format == "latex" else render_markdown(rows))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
