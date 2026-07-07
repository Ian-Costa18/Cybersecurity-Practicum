# /// script
# requires-python = ">=3.14"
# dependencies = ["pyyaml>=6.0.3"]
# ///
"""Query and validate the threat-model catalog (``docs/threat-model/``).

A dependency-light tool with two faces over one parser: an AI-usable CLI
(``query`` / ``sections`` / ``validate``) and, in ``docs/threat-model/``, a
marimo notebook that imports the functions here. This module is repo dev/analysis
tooling — it is deliberately **not** part of the ``msig_proxy`` runtime package or
its vertical-slice rules.

Run it standalone from a repo checkout — no virtualenv, the PEP 723 metadata above
declares the lone dep::

      uv run tools/threat_model.py query stride=Spoofing --only id,title
      uv run tools/threat_model.py validate

It is intentionally not a ``[project.scripts]`` console command: it reads the catalog
under ``docs/threat-model/``, which is never shipped in the wheel, so an installed
command would have nothing to operate on.

The frontmatter contract, tag vocabulary, and rating method this module mechanizes
are defined in ``docs/threat-model/CONTRIBUTING.md`` (the authority) — this file
enforces them, it does not redefine them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

# --------------------------------------------------------------------------- #
# The contract (mirrors docs/threat-model/CONTRIBUTING.md §Frontmatter contract).
# --------------------------------------------------------------------------- #

#: Frontmatter fields in their fixed, semantic order. ``delta`` precedes the rated
#: pairs and ``bucket`` because it gates them.
FIELD_ORDER: tuple[str, ...] = (
    "id",
    "title",
    "stride",
    "attack",
    "capability",
    "delta",
    "likelihood_baseline",
    "likelihood_residual",
    "severity_baseline",
    "severity_residual",
    "bucket",
    "related",
    "tests",
)

#: Fields the contract allows to be absent. When present they must appear in their
#: ``FIELD_ORDER`` position, but a threat that cites no test simply omits ``tests``.
OPTIONAL_FIELDS: frozenset[str] = frozenset({"tests"})

#: The nine thematic group prefixes; a threat id is ``<PREFIX>-<n>``.
GROUP_PREFIXES: tuple[str, ...] = (
    "CORE",
    "IDENT",
    "VOTE",
    "HOST",
    "CRYPTO",
    "PUB",
    "DOS",
    "CODE",
    "INFO",
)

STRIDE_VALUES = frozenset(
    {
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    }
)
DELTA_VALUES = frozenset({"improved", "inherited", "introduced"})
LIKELIHOOD_VALUES = frozenset({"high", "medium", "low"})
SEVERITY_VALUES = frozenset({"critical", "high", "medium", "low"})
BUCKET_VALUES = frozenset({"1", "2", "3", "4"})
NA = "N/A"

#: Ordinal rank for the two rated axes (higher = more dangerous), used by the
#: ``improved`` cross-check to decide "baseline strictly worse".
LIKELIHOOD_RANK = {"low": 1, "medium": 2, "high": 3}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

#: Frontmatter fields that carry a list of values (membership, not equality).
LIST_FIELDS = frozenset({"stride", "attack", "capability", "related", "tests"})

#: The six anatomy-table rows, keyed by their bold label → stable projection slug.
ANATOMY_SLUGS: dict[str, str] = {
    "Category": "category",
    "Capability": "capability-note",
    "What the attacker gains": "gains",
    "What they cannot do": "cannot",
    "Current defenses": "current-defenses",
    "Operator configuration": "operator-config",
}

#: ``## <heading>`` → canonical section slug, matched by heading prefix so variants
#: (e.g. "Rating rationale — inherited, reported once") still resolve.
_CANONICAL_SECTIONS: tuple[tuple[str, str], ...] = (
    ("delta story", "delta-story"),
    ("rating rationale", "rating-rationale"),
    ("bucket", "bucket-section"),
    ("planned defenses", "planned-defenses"),
)


def _find_catalog() -> Path:
    """Locate ``docs/threat-model`` from the working tree.

    Walks up from the CWD first (so the tool finds the catalog wherever it is run in
    the repo), then from this file's own location (so ``uv run tools/threat_model.py``
    works regardless of CWD). Falls back to the module-relative guess."""
    module_dir = Path(__file__).resolve().parent
    for base in (Path.cwd(), module_dir):
        for parent in (base, *base.parents):
            candidate = parent / "docs" / "threat-model"
            if candidate.is_dir():
                return candidate
    return module_dir.parent / "docs" / "threat-model"


CATALOG_DIR = _find_catalog()

#: A threat file is ``<PREFIX>-<n>-<slug>.md`` — this excludes the navigator and
#: meta docs (00-overview.md, taxonomies.md, CONTRIBUTING.md, REVIEW/PHASE working docs).
_THREAT_FILENAME = re.compile(rf"^({'|'.join(GROUP_PREFIXES)})-\d+-.+\.md$")
_ID_PATTERN = re.compile(rf"^({'|'.join(GROUP_PREFIXES)})-\d+$")
#: A ``tests:`` entry is a pytest node id: ``tests/<path>.py::<function>``.
_TEST_NODE = re.compile(r"^(?P<path>tests/[^\s:]+\.py)::(?P<name>[A-Za-z0-9_]+)$")
_FRONTMATTER = re.compile(r"^---\n(?P<yaml>.*?)\n---\n(?P<body>.*)\Z", re.DOTALL)
_H1 = re.compile(r"^# .+$", re.MULTILINE)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Section:
    """A ``## `` body section. ``slug`` is a generic slug of the heading; ``canonical``
    is the stable slug (delta-story / rating-rationale / bucket-section /
    planned-defenses) when the heading matches a known section, else ``None``."""

    heading: str
    slug: str
    canonical: str | None
    body: str


@dataclass(frozen=True)
class Threat:
    """One parsed threat file, split into its three addressable layers."""

    id: str
    path: Path
    frontmatter: dict[str, object]
    anatomy: dict[str, str]
    sections: tuple[Section, ...] = ()

    @property
    def title(self) -> str:
        value = self.frontmatter.get("title", "")
        return str(value) if value is not None else ""


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def slugify(text: str) -> str:
    """Lowercase, collapse every non-alphanumeric run to a single hyphen, trim."""
    return re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")


def _canonical_section(heading: str) -> str | None:
    normalized = heading.strip().lower()
    for prefix, slug in _CANONICAL_SECTIONS:
        if normalized.startswith(prefix):
            return slug
    return None


def _parse_anatomy(body_after_h1: str) -> dict[str, str]:
    """Pull the anatomy key/value rows from the first pipe-table block after the H1.

    Only the first table block is considered, so later body tables (e.g. CRYPTO-2's
    "instances" table) are never mistaken for the anatomy. Missing rows are fine —
    an inherited threat may omit "Operator configuration"."""
    rows: dict[str, str] = {}
    in_table = False
    for line in body_after_h1.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            in_table = True
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if len(cells) != 2:
                continue
            key_cell, value_cell = cells
            label = key_cell.strip("* ").strip()
            if label in ANATOMY_SLUGS and value_cell:
                rows[ANATOMY_SLUGS[label]] = value_cell
        elif in_table:
            break  # first table block ended
    return rows


def _parse_sections(body: str) -> tuple[Section, ...]:
    """Split the body on ``## `` headings into addressable sections."""
    sections: list[Section] = []
    matches = list(re.finditer(r"^## +(?P<heading>.+?)\s*$", body, re.MULTILINE))
    for index, match in enumerate(matches):
        heading = match.group("heading").strip()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        sections.append(
            Section(
                heading=heading,
                slug=slugify(heading),
                canonical=_canonical_section(heading),
                body=body[start:end].strip(),
            )
        )
    return tuple(sections)


def parse_threat(path: Path) -> Threat:
    """Parse one threat file into frontmatter + anatomy + sections."""
    text = path.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(text)
    if match is None:
        raise ValueError(f"{path.name}: no YAML frontmatter block found")
    frontmatter = yaml.safe_load(match.group("yaml")) or {}
    if not isinstance(frontmatter, dict):
        raise ValueError(f"{path.name}: frontmatter is not a mapping")
    body = match.group("body")
    h1 = _H1.search(body)
    body_after_h1 = body[h1.end() :] if h1 else body
    identifier = str(frontmatter.get("id", "")) or path.stem
    return Threat(
        id=identifier,
        path=path,
        frontmatter=frontmatter,
        anatomy=_parse_anatomy(body_after_h1),
        sections=_parse_sections(body_after_h1),
    )


def is_threat_file(path: Path) -> bool:
    """True for ``<PREFIX>-<n>-<slug>.md`` files (excludes navigator/meta docs)."""
    return bool(_THREAT_FILENAME.match(path.name))


def load_catalog(directory: Path = CATALOG_DIR) -> list[Threat]:
    """Parse every threat file in ``directory``, sorted by id (group, then number)."""
    threats = [parse_threat(p) for p in sorted(directory.iterdir()) if is_threat_file(p)]
    return sorted(threats, key=_id_sort_key)


def _id_sort_key(threat: Threat) -> tuple[str, int, str]:
    match = re.match(r"^([A-Z]+)-(\d+)$", threat.id)
    if match:
        return (match.group(1), int(match.group(2)), threat.id)
    return (threat.id, 0, threat.id)


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #


def _as_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _field_matches(threat: Threat, key: str, wanted: str) -> bool:
    """Does ``threat``'s ``key`` field match the single ``wanted`` value?

    List fields match by membership; ``attack`` is prefix-aware so ``T1078`` also
    matches ``T1078.001``. Scalar fields match by case-insensitive equality."""
    actual = threat.frontmatter.get(key)
    if key in LIST_FIELDS:
        values = _as_str_list(actual)
        if key == "attack":
            return any(v == wanted or v.startswith(f"{wanted}.") for v in values)
        return any(v.casefold() == wanted.casefold() for v in values)
    return actual is not None and str(actual).casefold() == wanted.casefold()


def filter_threats(threats: Iterable[Threat], filters: dict[str, list[str]]) -> list[Threat]:
    """AND across distinct keys, OR within a repeated key. Empty filters → all."""

    def keep(threat: Threat) -> bool:
        return all(
            any(_field_matches(threat, key, wanted) for wanted in values)
            for key, values in filters.items()
        )

    return [t for t in threats if keep(t)]


def parse_filters(tokens: Sequence[str]) -> dict[str, list[str]]:
    """Turn ``key=value`` tokens into ``{key: [value, ...]}`` (repeats accumulate)."""
    filters: dict[str, list[str]] = {}
    for token in tokens:
        if "=" not in token:
            raise ValueError(f"filter {token!r} is not in key=value form")
        key, value = token.split("=", 1)
        filters.setdefault(key.strip(), []).append(value.strip())
    return filters


# --------------------------------------------------------------------------- #
# Projection
# --------------------------------------------------------------------------- #


def section_slugs(threat: Threat) -> list[str]:
    """The addressable section slugs for a threat (canonical where known)."""
    return [s.canonical or s.slug for s in threat.sections]


def _resolve_key(threat: Threat, key: str) -> dict[str, object]:
    """Resolve one projection key to ``{resolved_key: value}`` (possibly several).

    Order: frontmatter field → anatomy slug → section (canonical or generic slug) →
    finally the key is treated as a regex over section headings/slugs."""
    if key in threat.frontmatter:
        return {key: threat.frontmatter[key]}
    if key in threat.anatomy:
        return {key: threat.anatomy[key]}
    for section in threat.sections:
        if key in (section.canonical, section.slug):
            return {section.canonical or section.slug: section.body}
    try:
        pattern = re.compile(key, re.IGNORECASE)
    except re.error:
        return {}
    matched: dict[str, object] = {}
    for section in threat.sections:
        if pattern.search(section.heading) or pattern.search(section.slug):
            matched[section.canonical or section.slug] = section.body
    return matched


def project(threat: Threat, only: Sequence[str] | None = None) -> dict[str, object]:
    """Build a record for a threat. ``only=None`` → the whole record (frontmatter +
    anatomy + sections); otherwise just the requested keys. ``id`` is always present
    and first, so every record is re-addressable."""
    record: dict[str, object] = {"id": threat.id}
    if only is None:
        record.update({k: v for k, v in threat.frontmatter.items() if k != "id"})
        record.update(threat.anatomy)
        for section in threat.sections:
            record[section.canonical or section.slug] = section.body
        return record
    for key in only:
        if key == "id":
            continue
        record.update(_resolve_key(threat, key))
    return record


def parse_only(value: str | None) -> list[str] | None:
    """Split a ``--only`` comma list into keys, or ``None`` for the whole record."""
    if value is None:
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


# --------------------------------------------------------------------------- #
# Validation (mechanizes the CONTRIBUTING.md contract)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Violation:
    """One contract breach: which file, which rule, and a human-readable message."""

    file: str
    rule: str
    message: str


def _check_fields(threat: Threat) -> list[Violation]:
    name = threat.path.name
    violations: list[Violation] = []
    keys = list(threat.frontmatter.keys())
    for required in FIELD_ORDER:
        if required in OPTIONAL_FIELDS:
            continue
        if required not in threat.frontmatter:
            violations.append(Violation(name, "field-presence", f"missing field {required!r}"))
    present_in_order = [k for k in keys if k in FIELD_ORDER]
    expected_order = [k for k in FIELD_ORDER if k in threat.frontmatter]
    if present_in_order != expected_order:
        violations.append(
            Violation(
                name,
                "field-order",
                f"fields out of order: {present_in_order} (expected {expected_order})",
            )
        )
    return violations


def _check_enums(threat: Threat) -> list[Violation]:
    name = threat.path.name
    fm = threat.frontmatter
    violations: list[Violation] = []

    def bad(rule: str, message: str) -> None:
        violations.append(Violation(name, rule, message))

    for value in _as_str_list(fm.get("stride")):
        if value not in STRIDE_VALUES:
            bad("enum-stride", f"invalid stride {value!r}")
    for value in _as_str_list(fm.get("capability")):
        if value != "external" and not re.fullmatch(r"L[1-9]", value):
            bad("enum-capability", f"invalid capability {value!r}")
    for value in _as_str_list(fm.get("attack")):
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", value):
            bad("enum-attack", f"invalid ATT&CK id {value!r}")
    if str(fm.get("delta")) not in DELTA_VALUES:
        bad("enum-delta", f"invalid delta {fm.get('delta')!r}")
    for axis, allowed in (("likelihood", LIKELIHOOD_VALUES), ("severity", SEVERITY_VALUES)):
        baseline = str(fm.get(f"{axis}_baseline"))
        residual = str(fm.get(f"{axis}_residual"))
        if baseline not in allowed | {NA}:
            bad(f"enum-{axis}", f"invalid {axis}_baseline {baseline!r}")
        if residual not in allowed:
            bad(f"enum-{axis}", f"invalid {axis}_residual {residual!r}")
    if str(fm.get("bucket")) not in BUCKET_VALUES | {NA}:
        bad("enum-bucket", f"invalid bucket {fm.get('bucket')!r}")
    return violations


def _check_na_rules(threat: Threat) -> list[Violation]:
    name = threat.path.name
    fm = threat.frontmatter
    delta = str(fm.get("delta"))
    violations: list[Violation] = []

    introduced = delta == "introduced"
    for axis in ("likelihood", "severity"):
        is_na = str(fm.get(f"{axis}_baseline")) == NA
        if introduced and not is_na:
            violations.append(
                Violation(name, "na-baseline", f"{axis}_baseline must be N/A when delta=introduced")
            )
        if not introduced and is_na:
            violations.append(
                Violation(
                    name, "na-baseline", f"{axis}_baseline may be N/A only when delta=introduced"
                )
            )

    bucket_na = str(fm.get("bucket")) == NA
    if delta == "inherited" and not bucket_na:
        violations.append(Violation(name, "na-bucket", "bucket must be N/A when delta=inherited"))
    if delta != "inherited" and bucket_na:
        violations.append(
            Violation(name, "na-bucket", "bucket may be N/A only when delta=inherited")
        )
    return violations


def _check_id_integrity(threat: Threat) -> list[Violation]:
    name = threat.path.name
    identifier = str(threat.frontmatter.get("id", ""))
    violations: list[Violation] = []
    if not _ID_PATTERN.match(identifier):
        violations.append(
            Violation(name, "id-format", f"id {identifier!r} is not <PREFIX>-<n> in a known group")
        )
    if not name.startswith(f"{identifier}-"):
        violations.append(
            Violation(name, "id-filename", f"filename does not start with id {identifier!r}")
        )
    return violations


def _repo_root_for(path: Path) -> Path | None:
    """Repo root for a threat file at ``<repo>/docs/threat-model/<file>.md``.

    Returns ``None`` when the root can't be located (e.g. a synthetic in-memory
    ``Threat`` in the unit tests, whose ``path`` is a bare filename) — the caller
    then verifies node-id *format* but skips the on-disk existence check."""
    resolved = path.resolve()
    if len(resolved.parents) >= 3:
        candidate = resolved.parents[2]
        if (candidate / "tests").is_dir():
            return candidate
    return None


def _check_tests(threat: Threat) -> list[Violation]:
    """The ``tests:`` contract: every entry resolves to a real pytest node
    (``tests/<path>.py::<def>`` — the file exists *and* the function is defined),
    and ``bucket: 1`` (executably demonstrated) carries at least one backing test.

    The on-disk resolution is what keeps the catalog honest: rename a cited test
    and this check — which runs in the pytest suite — fails until the id is fixed."""
    name = threat.path.name
    fm = threat.frontmatter
    tests = _as_str_list(fm.get("tests")) if fm.get("tests") is not None else []
    violations: list[Violation] = []
    if str(fm.get("bucket")) == "1" and not tests:
        violations.append(
            Violation(
                name,
                "tests-required",
                "bucket 1 (executably demonstrated) requires >=1 backing test in `tests:`",
            )
        )
    repo_root = _repo_root_for(threat.path)
    for node in tests:
        match = _TEST_NODE.match(node)
        if match is None:
            violations.append(
                Violation(name, "tests-format", f"test {node!r} is not tests/<path>.py::<name>")
            )
            continue
        if repo_root is None:
            continue  # format verified; existence unverifiable in this context
        test_file = repo_root / match.group("path")
        if not test_file.is_file():
            violations.append(
                Violation(name, "tests-missing", f"{node}: file {match.group('path')} not found")
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
                Violation(name, "tests-missing", f"{node}: no def {func} in {match.group('path')}")
            )
    return violations


def _check_semantics(threat: Threat) -> list[Violation]:
    """Stretch cross-checks: improved ⇒ baseline strictly worse on ≥1 axis;
    inherited ⇒ likelihoods equal."""
    name = threat.path.name
    fm = threat.frontmatter
    delta = str(fm.get("delta"))
    violations: list[Violation] = []
    if delta == "improved":
        lb = LIKELIHOOD_RANK.get(str(fm.get("likelihood_baseline")))
        lr = LIKELIHOOD_RANK.get(str(fm.get("likelihood_residual")))
        sb = SEVERITY_RANK.get(str(fm.get("severity_baseline")))
        sr = SEVERITY_RANK.get(str(fm.get("severity_residual")))
        worse = (lb is not None and lr is not None and lb > lr) or (
            sb is not None and sr is not None and sb > sr
        )
        if not worse:
            violations.append(
                Violation(name, "improved-worse", "improved requires baseline worse on ≥1 axis")
            )
    if delta == "inherited" and fm.get("likelihood_baseline") != fm.get("likelihood_residual"):
        violations.append(
            Violation(
                name,
                "inherited-likelihood",
                "inherited requires equal baseline/residual likelihood",
            )
        )
    return violations


def validate_catalog(threats: Sequence[Threat]) -> list[Violation]:
    """Run every contract check over the catalog and return all violations."""
    violations: list[Violation] = []
    seen_ids: dict[str, str] = {}
    related: dict[str, set[str]] = {}
    for threat in threats:
        violations.extend(_check_fields(threat))
        violations.extend(_check_enums(threat))
        violations.extend(_check_na_rules(threat))
        violations.extend(_check_id_integrity(threat))
        violations.extend(_check_tests(threat))
        violations.extend(_check_semantics(threat))
        identifier = str(threat.frontmatter.get("id", threat.id))
        if identifier in seen_ids:
            violations.append(
                Violation(threat.path.name, "id-duplicate", f"duplicate id {identifier!r}")
            )
        seen_ids[identifier] = threat.path.name
        related[identifier] = {str(r) for r in _as_str_list(threat.frontmatter.get("related"))}
    # related symmetry: A lists B ⟺ B lists A
    for identifier, targets in related.items():
        for target in targets:
            if target not in related:
                violations.append(
                    Violation(
                        seen_ids.get(identifier, identifier),
                        "related-dangling",
                        f"{identifier} → {target}: {target} is not a known threat",
                    )
                )
            elif identifier not in related[target]:
                violations.append(
                    Violation(
                        seen_ids.get(identifier, identifier),
                        "related-symmetry",
                        f"{identifier} lists {target} but {target} does not list {identifier}",
                    )
                )
    return violations


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_json(records: Sequence[dict[str, object]]) -> str:
    return json.dumps(list(records), indent=2, ensure_ascii=False)


def render_markdown(records: Sequence[dict[str, object]]) -> str:
    """Human-readable Markdown: one ``## id — title`` block per record."""
    blocks: list[str] = []
    for record in records:
        identifier = record.get("id", "?")
        title = record.get("title")
        heading = f"## {identifier} — {title}" if title else f"## {identifier}"
        lines = [heading, ""]
        for key, value in record.items():
            if key in ("id", "title"):
                continue
            rendered = ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
            lines.append(f"**{key}:** {rendered}")
            lines.append("")
        blocks.append("\n".join(lines).rstrip())
    return "\n\n".join(blocks)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

_SUBCOMMANDS = ("query", "sections", "validate")


def _add_catalog_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--catalog",
        type=Path,
        default=CATALOG_DIR,
        help=f"catalog directory (default: {CATALOG_DIR})",
    )


def _query_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat_model.py query",
        description="Filter the catalog and project chosen parts (the default command).",
    )
    parser.add_argument("filters", nargs="*", help="key=value filters (AND across keys, OR within)")
    parser.add_argument(
        "--only", help="comma-separated keys to project (frontmatter / anatomy / section)"
    )
    parser.add_argument("-H", "--human", action="store_true", help="Markdown output (default JSON)")
    _add_catalog_arg(parser)
    return parser


def _sections_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat_model.py sections",
        description="List a threat's section slugs, or the whole catalog map.",
    )
    parser.add_argument("id", nargs="?", help="threat id; omit for a catalog-wide map")
    _add_catalog_arg(parser)
    return parser


def _validate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat_model.py validate",
        description="Check the frontmatter contract; non-zero exit on any violation.",
    )
    _add_catalog_arg(parser)
    return parser


def _cmd_query(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    selected = filter_threats(catalog, parse_filters(args.filters))
    only = parse_only(args.only)
    records = [project(t, only) for t in selected]
    print(render_markdown(records) if args.human else render_json(records))
    return 0


def _cmd_sections(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    if args.id:
        match = next((t for t in catalog if t.id == args.id), None)
        if match is None:
            print(f"no threat with id {args.id!r}", file=sys.stderr)
            return 1
        print(render_json([{"id": match.id, "sections": section_slugs(match)}]))
        return 0
    print(render_json([{"id": t.id, "sections": section_slugs(t)} for t in catalog]))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    violations = validate_catalog(catalog)
    if not violations:
        print(f"ok: {len(catalog)} threats, no violations")
        return 0
    for v in violations:
        print(f"{v.file}: [{v.rule}] {v.message}", file=sys.stderr)
    print(f"\n{len(violations)} violation(s)", file=sys.stderr)
    return 1


_TOP_HELP = (
    "usage: uv run tools/threat_model.py [query|sections|validate] ...\n\n"
    "Query and validate the threat-model catalog. `query` is the default command, so\n"
    "`uv run tools/threat_model.py stride=Spoofing --only id,title` needs no verb.\n\n"
    "  query     filter the catalog and project chosen parts (default)\n"
    "  sections  list a threat's section slugs, or the whole catalog map\n"
    "  validate  check the frontmatter contract; non-zero exit on violation\n\n"
    "Run `uv run tools/threat_model.py <command> -h` for a command's options.\n"
)


def main(argv: Sequence[str] | None = None) -> int:
    # UTF-8 stdout so the catalog's em-dashes / smart quotes survive on any console.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8")
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in ("-h", "--help"):
        print(_TOP_HELP)
        return 0
    # `query` is the default verb: a leading token that isn't a known command
    # (including a bare filter or flag) is parsed as query.
    if raw and raw[0] in _SUBCOMMANDS:
        verb, rest = raw[0], raw[1:]
    else:
        verb, rest = "query", raw
    if verb == "sections":
        return _cmd_sections(_sections_parser().parse_args(rest))
    if verb == "validate":
        return _cmd_validate(_validate_parser().parse_args(rest))
    return _cmd_query(_query_parser().parse_args(rest))


if __name__ == "__main__":
    raise SystemExit(main())
