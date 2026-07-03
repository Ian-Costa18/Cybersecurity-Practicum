"""Behavioral tests for the threat-model query/validate tool (issue #130).

Tests exercise the module's public API and the CLI's observable output — parsed
structures, filtered/projected results, validation pass/fail, exit codes — not
private parsing helpers. The parser functions are pure (path in, plain data out),
so most tests run directly against the real ``docs/threat-model/*.md`` catalog;
validator logic is pinned with small synthetic ``Threat`` values.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import threat_model as tm


@pytest.fixture(scope="module")
def catalog() -> list[tm.Threat]:
    return tm.load_catalog()


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


_ID_RE = re.compile(rf"^({'|'.join(tm.GROUP_PREFIXES)})-\d+$")


def test_load_catalog_excludes_meta_docs(catalog: list[tm.Threat]) -> None:
    ids = {t.id for t in catalog}
    assert "CORE-1" in ids and "CRYPTO-2" in ids
    # Navigator/meta docs (CONTRIBUTING, taxonomies, 00-overview, REVIEW/PHASE) are not threats.
    assert all(_ID_RE.match(t.id) for t in catalog)


def test_is_threat_file() -> None:
    assert tm.is_threat_file(Path("CORE-1-single-approver-account-compromise.md"))
    assert not tm.is_threat_file(Path("CONTRIBUTING.md"))
    assert not tm.is_threat_file(Path("00-overview.md"))
    assert not tm.is_threat_file(Path("taxonomies.md"))


def _by_id(catalog: list[tm.Threat], threat_id: str) -> tm.Threat:
    return next(t for t in catalog if t.id == threat_id)


def test_anatomy_rows_parsed(catalog: list[tm.Threat]) -> None:
    core1 = _by_id(catalog, "CORE-1")
    assert core1.anatomy["category"] == "Elevation of Privilege"
    assert set(tm.ANATOMY_SLUGS.values()) <= set(core1.anatomy) | {"operator-config"}
    assert "gains" in core1.anatomy and "operator-config" in core1.anatomy


def test_anatomy_tolerates_missing_rows(catalog: list[tm.Threat]) -> None:
    # CRYPTO-2 (inherited) omits the "Operator configuration" row — must not error.
    crypto2 = _by_id(catalog, "CRYPTO-2")
    assert "category" in crypto2.anatomy
    assert "operator-config" not in crypto2.anatomy


def test_section_canonical_slug_handles_variant(catalog: list[tm.Threat]) -> None:
    # CRYPTO-2's heading is "Rating rationale — inherited, reported once".
    crypto2 = _by_id(catalog, "CRYPTO-2")
    assert "rating-rationale" in tm.section_slugs(crypto2)


def test_known_section_slugs(catalog: list[tm.Threat]) -> None:
    host4 = _by_id(catalog, "HOST-4")
    slugs = tm.section_slugs(host4)
    assert {"rating-rationale", "bucket-section", "planned-defenses"} <= set(slugs)


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #


def test_filter_by_scalar_field(catalog: list[tm.Threat]) -> None:
    improved = tm.filter_threats(catalog, {"delta": ["improved"]})
    assert improved
    assert all(t.frontmatter["delta"] == "improved" for t in improved)


def test_or_within_repeated_key(catalog: list[tm.Threat]) -> None:
    both = tm.filter_threats(catalog, {"delta": ["improved", "inherited"]})
    deltas = {t.frontmatter["delta"] for t in both}
    assert deltas == {"improved", "inherited"}


def test_and_across_keys(catalog: list[tm.Threat]) -> None:
    result = tm.filter_threats(catalog, {"delta": ["improved"], "severity_residual": ["medium"]})
    assert all(
        t.frontmatter["delta"] == "improved" and t.frontmatter["severity_residual"] == "medium"
        for t in result
    )


def test_attack_filter_is_prefix_aware(catalog: list[tm.Threat]) -> None:
    # IDENT-1 carries T1136.001; a query for the parent technique must match it.
    result_ids = {t.id for t in tm.filter_threats(catalog, {"attack": ["T1136"]})}
    assert "IDENT-1" in result_ids


def test_empty_filters_returns_whole_catalog(catalog: list[tm.Threat]) -> None:
    assert tm.filter_threats(catalog, {}) == catalog


def test_parse_filters_accumulates_repeats() -> None:
    assert tm.parse_filters(["stride=Spoofing", "stride=Tampering", "delta=improved"]) == {
        "stride": ["Spoofing", "Tampering"],
        "delta": ["improved"],
    }


def test_parse_filters_rejects_non_kv() -> None:
    with pytest.raises(ValueError):
        tm.parse_filters(["not-a-filter"])


# --------------------------------------------------------------------------- #
# Projection
# --------------------------------------------------------------------------- #


def test_project_only_selected_keys(catalog: list[tm.Threat]) -> None:
    record = tm.project(_by_id(catalog, "CORE-1"), ["id", "title", "delta"])
    assert set(record) == {"id", "title", "delta"}


def test_project_always_includes_id(catalog: list[tm.Threat]) -> None:
    record = tm.project(_by_id(catalog, "CORE-1"), ["delta"])
    assert record["id"] == "CORE-1"


def test_project_addresses_section_by_slug(catalog: list[tm.Threat]) -> None:
    record = tm.project(_by_id(catalog, "CORE-1"), ["delta-story"])
    assert "delta-story" in record
    assert "flagship" in str(record["delta-story"])


def test_project_addresses_anatomy_slug(catalog: list[tm.Threat]) -> None:
    record = tm.project(_by_id(catalog, "CORE-1"), ["gains"])
    assert "One vote" in str(record["gains"])


def test_project_full_record_has_all_layers(catalog: list[tm.Threat]) -> None:
    record = tm.project(_by_id(catalog, "CORE-1"), None)
    assert record["id"] == "CORE-1"
    assert "stride" in record  # frontmatter
    assert "gains" in record  # anatomy
    assert "delta-story" in record  # section


def test_parse_only_splits_and_strips() -> None:
    assert tm.parse_only("id, title , delta") == ["id", "title", "delta"]
    assert tm.parse_only(None) is None


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def test_render_json_is_parseable(catalog: list[tm.Threat]) -> None:
    records = [tm.project(t, ["id", "title"]) for t in catalog[:3]]
    assert json.loads(tm.render_json(records)) == records


def test_render_markdown_has_heading(catalog: list[tm.Threat]) -> None:
    record = tm.project(_by_id(catalog, "CORE-1"), ["id", "title", "delta"])
    out = tm.render_markdown([record])
    assert out.startswith("## CORE-1 — Single Approver Account Compromise")
    assert "**delta:** improved" in out


# --------------------------------------------------------------------------- #
# ID-pinned catalog facts (unblocked now the renumber has landed)
# --------------------------------------------------------------------------- #


def test_core1_is_improved_and_maps_t1078(catalog: list[tm.Threat]) -> None:
    core1 = _by_id(catalog, "CORE-1")
    assert core1.frontmatter["delta"] == "improved"
    # Asserted through the public filter: CORE-1 maps to ATT&CK T1078.
    assert tm.filter_threats([core1], {"attack": ["T1078"]}) == [core1]


def test_crypto2_is_inherited_with_na_bucket(catalog: list[tm.Threat]) -> None:
    crypto2 = _by_id(catalog, "CRYPTO-2")
    assert crypto2.frontmatter["delta"] == "inherited"
    assert str(crypto2.frontmatter["bucket"]) == "N/A"


# --------------------------------------------------------------------------- #
# Validation — the live catalog must be clean, and the checks must bite
# --------------------------------------------------------------------------- #


# Loaded at import so the contract check can be parametrized per threat file: a
# failure then names the offending file (via the test id) and its rules.
_LIVE_CATALOG = tm.load_catalog()


@pytest.fixture(scope="module")
def live_violations() -> dict[str, list[tm.Violation]]:
    by_file: dict[str, list[tm.Violation]] = {}
    for violation in tm.validate_catalog(_LIVE_CATALOG):
        by_file.setdefault(violation.file, []).append(violation)
    return by_file


@pytest.mark.parametrize("threat", _LIVE_CATALOG, ids=lambda t: t.id)
def test_threat_file_satisfies_contract(
    threat: tm.Threat, live_violations: dict[str, list[tm.Violation]]
) -> None:
    offending = live_violations.get(threat.path.name, [])
    assert not offending, "; ".join(f"[{v.rule}] {v.message}" for v in offending)


def test_live_catalog_has_no_violations(catalog: list[tm.Threat]) -> None:
    # Whole-catalog gate — also covers the cross-file rules (related symmetry,
    # duplicate ids) that no single-file test can see.
    violations = tm.validate_catalog(catalog)
    assert violations == [], "\n".join(f"{v.file}: [{v.rule}] {v.message}" for v in violations)


def _fm(**overrides: object) -> dict[str, object]:
    """A well-formed *introduced* threat's frontmatter, in contract order."""
    base: dict[str, object] = {
        "id": "PUB-9",
        "title": "Synthetic",
        "stride": ["Spoofing"],
        "attack": ["T1078"],
        "capability": ["L2"],
        "delta": "introduced",
        "likelihood_baseline": "N/A",
        "likelihood_residual": "low",
        "severity_baseline": "N/A",
        "severity_residual": "high",
        "bucket": "1",
        "related": [],
    }
    base.update(overrides)
    return base


def _threat(fm: dict[str, object], name: str = "PUB-9-synthetic.md") -> tm.Threat:
    return tm.Threat(
        id=str(fm.get("id", "")), path=Path(name), frontmatter=fm, anatomy={}, sections=()
    )


def _rules(violations: list[tm.Violation]) -> set[str]:
    return {v.rule for v in violations}


def test_synthetic_well_formed_is_clean() -> None:
    assert tm.validate_catalog([_threat(_fm())]) == []


def test_na_baseline_rule_bites() -> None:
    # introduced but a baseline is rated (must be N/A)
    violations = tm.validate_catalog([_threat(_fm(likelihood_baseline="high"))])
    assert "na-baseline" in _rules(violations)


def test_bucket_na_rule_bites() -> None:
    # inherited must force bucket N/A; here it is a number → violation (+ semantic checks)
    fm = _fm(delta="inherited", likelihood_baseline="low", severity_baseline="high", bucket="2")
    assert "na-bucket" in _rules(tm.validate_catalog([_threat(fm)]))


def test_enum_rejects_unknown_stride() -> None:
    assert "enum-stride" in _rules(tm.validate_catalog([_threat(_fm(stride=["Bogus"]))]))


def test_field_order_bites() -> None:
    fm = _fm()
    items = list(fm.items())
    items[0], items[1] = items[1], items[0]  # title before id
    assert "field-order" in _rules(tm.validate_catalog([_threat(dict(items))]))


def test_related_symmetry_bites() -> None:
    a = _threat(_fm(id="PUB-8", related=["PUB-9"]), name="PUB-8-a.md")
    b = _threat(_fm(id="PUB-9", related=[]), name="PUB-9-b.md")
    assert "related-symmetry" in _rules(tm.validate_catalog([a, b]))


def test_id_filename_mismatch_bites() -> None:
    violations = tm.validate_catalog([_threat(_fm(id="PUB-9"), name="HOST-1-wrong.md")])
    assert "id-filename" in _rules(violations)


def test_improved_requires_worse_baseline() -> None:
    # improved but baseline == residual on both axes → no improvement shown
    fm = _fm(
        delta="improved",
        likelihood_baseline="low",
        severity_baseline="high",
        bucket="1",
    )
    assert "improved-worse" in _rules(tm.validate_catalog([_threat(fm)]))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_validate_ok(capsys: pytest.CaptureFixture[str]) -> None:
    assert tm.main(["validate"]) == 0
    assert "no violations" in capsys.readouterr().out


def test_cli_query_default_verb_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert tm.main(["delta=improved", "--only", "id"]) == 0
    records = json.loads(capsys.readouterr().out)
    assert {r["id"] for r in records} == {"CORE-1", "CORE-2", "CORE-3"}


def test_cli_sections_for_one_threat(capsys: pytest.CaptureFixture[str]) -> None:
    assert tm.main(["sections", "CRYPTO-2"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == [{"id": "CRYPTO-2", "sections": ["rating-rationale"]}]


def test_cli_human_flag_emits_markdown(capsys: pytest.CaptureFixture[str]) -> None:
    assert tm.main(["id=CORE-1", "--only", "id,title", "-H"]) == 0
    assert capsys.readouterr().out.startswith("## CORE-1 —")


def test_cli_validate_flags_broken_catalog(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A file whose delta=introduced contradicts its rated baseline.
    (tmp_path / "PUB-9-broken.md").write_text(
        "---\n"
        "id: PUB-9\n"
        'title: "Broken"\n'
        "stride: [Spoofing]\n"
        "attack: [T1078]\n"
        "capability: [L2]\n"
        "delta: introduced\n"
        "likelihood_baseline: high\n"
        "likelihood_residual: low\n"
        "severity_baseline: high\n"
        "severity_residual: high\n"
        "bucket: 1\n"
        "related: []\n"
        "---\n\n# PUB-9 — Broken\n",
        encoding="utf-8",
    )
    assert tm.main(["validate", "--catalog", str(tmp_path)]) == 1
    assert "na-baseline" in capsys.readouterr().err
