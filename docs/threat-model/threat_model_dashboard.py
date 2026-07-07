"""Threat-model dashboard — a visual view of docs/threat-model/ (issue #130).

A marimo notebook that reads the catalog through the tested ``tools/threat_model.py``
core and renders it: a likelihood × severity risk matrix (the centerpiece), the
baseline→residual movement view, the delta ledger, ATT&CK coverage, and STRIDE /
bucket distributions, with a reactive explorer at the bottom.

Run it::

    uv run marimo edit --watch docs/threat-model/threat_model_dashboard.py   # interactive
    uv run marimo run  docs/threat-model/threat_model_dashboard.py   # read-only app

The parsing/validation logic is *not* redefined here — it is imported from the
core module, which the pytest suite covers. This file only shapes and draws.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium", app_title="Threat Model Dashboard")

with app.setup:
    import math
    import re
    import sys
    from pathlib import Path

    import marimo as mo
    import altair as alt
    import pandas as pd

    # The single-file core lives in tools/; add it to the path and import it.
    _tools = Path(__file__).resolve().parents[2] / "tools"
    if str(_tools) not in sys.path:
        sys.path.insert(0, str(_tools))
    import threat_model as tm


@app.cell
def _():
    # Vega tooltips render each field's value in a table cell that collapses
    # newlines by default. `pre-line` lets the bulleted `tests_pretty` string
    # break onto its own lines instead of bunching up on one row.
    mo.Html(
        "<style>"
        "#vg-tooltip-element .value, .vg-tooltip .value "
        "{ white-space: pre-line; text-align: left; max-width: 34em; }"
        "</style>"
    )
    return


@app.cell
def _():
    mo.md("""
    # Threat-model dashboard

    A live view of the threat catalog under `docs/threat-model/`. Every number
    below is read straight from the threat files' frontmatter through the
    `threat_model` core — so this dashboard cannot drift from the catalog it
    describes. The **risk matrix** is the centerpiece: it plots each threat by
    *likelihood* and *severity*, coloured by its **delta** — whether the proxy
    **improves** a baseline threat, **inherits** it unchanged, or **introduces**
    it as the cost of existing. Introduced threats are drawn just as boldly as
    the improvements: the cost ledger is not hidden.
    """)
    return


@app.cell
def _():
    # Rank maps for the two rated axes (higher = more dangerous).
    LIK = {"low": 1, "medium": 2, "high": 3}
    SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    DELTA_DOMAIN = ["improved", "inherited", "introduced"]
    # Three vivid, equal-weight hues — nothing muted.
    DELTA_RANGE = ["#2ca02c", "#1f77b4", "#d62728"]

    threats = tm.load_catalog()

    def _join(value: object) -> str:
        return ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)

    def _summarize(text: str, limit: int = 220) -> str:
        """Plain-text one-line gist of a threat's 'What the attacker gains' section.
        Tooltips don't render Markdown, so strip emphasis/code marks and unwrap links
        to a bare label before truncating on a word boundary."""
        text = " ".join(text.split())
        text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # [label](url) -> label
        text = re.sub(r"[`*]+", "", text)  # drop **bold**, *italic*, `code` marks
        if len(text) <= limit:
            return text
        return text[:limit].rsplit(" ", 1)[0] + "…"

    rows = []
    for threat in threats:
        fm = threat.frontmatter
        rows.append(
            {
                "id": threat.id,
                "group": threat.id.split("-")[0],
                "title": str(fm.get("title", "")),
                "summary": _summarize(threat.anatomy.get("gains", "")),
                "stride": _join(fm.get("stride", [])),
                "attack": _join(fm.get("attack", [])),
                "capability": _join(fm.get("capability", [])),
                "delta": str(fm.get("delta", "")),
                "likelihood_baseline": str(fm.get("likelihood_baseline", "")),
                "likelihood_residual": str(fm.get("likelihood_residual", "")),
                "severity_baseline": str(fm.get("severity_baseline", "")),
                "severity_residual": str(fm.get("severity_residual", "")),
                "bucket": str(fm.get("bucket", "")),
                # Display label (glyph + name), shared from the core so it can't drift
                # (#132). The numeric `bucket` above stays the sort/filter key.
                "bucket_label": tm.bucket_label(fm.get("bucket", "")),
                "related": _join(fm.get("related", [])),
                "n_tests": len(fm.get("tests") or []),
                # A pre-bulleted, newline-joined list of the test *function* names
                # (node id after "::"). Rendered as real bullets by the tooltip-CSS
                # cell below; Vega collapses the newlines without it.
                "tests_pretty": "\n".join(
                    f"• {node.split('::')[-1]}" for node in (fm.get("tests") or [])
                )
                or "—",
            }
        )
    df = pd.DataFrame(rows)
    for _axis, _ranks in (("likelihood", LIK), ("severity", SEV)):
        for _phase in ("baseline", "residual"):
            _col = f"{_axis}_{_phase}"
            df[f"{_col}_rank"] = df[_col].map(_ranks)
    return DELTA_DOMAIN, DELTA_RANGE, LIK, SEV, df, threats


@app.cell
def _(df):
    total = len(df)
    counts = df["delta"].value_counts().to_dict()
    mo.md(
        f"""
        **{total} threats** in the catalog · improved **{counts.get("improved", 0)}** ·
        inherited **{counts.get("inherited", 0)}** · introduced **{counts.get("introduced", 0)}**.
        """
    )
    return


@app.cell
def _():
    phase = mo.ui.radio(
        options=["residual", "baseline"],
        value="residual",
        label="Risk matrix — show",
        inline=True,
    )
    phase
    return (phase,)


@app.cell
def _(LIK, SEV):
    def cell_grid(sub: pd.DataFrame, xcol: str, ycol: str) -> pd.DataFrame:
        """Stack each cell's threat labels in a centred vertical column. IDs are
        wider than they are tall, so a column keeps them from colliding sideways
        with a neighbour the way a square tiling would."""
        sub = sub.copy()
        sub["bx"] = sub[xcol].astype(float)
        sub["by"] = sub[ycol].astype(float)
        for (_, _), group in sub.groupby([xcol, ycol]):
            ordered = sorted(group.index, key=lambda i: str(sub.loc[i, "id"]))
            n = len(ordered)
            for k, idx in enumerate(ordered):
                sub.loc[idx, "by"] = float(sub.loc[idx, ycol]) + (k - (n - 1) / 2) * 0.155
        return sub

    def _axis(ranks: dict[str, int], title: str) -> alt.Axis:
        expr = " : ".join(f"datum.value == {v} ? '{k}'" for k, v in ranks.items()) + " : ''"
        return alt.Axis(
            values=list(ranks.values()),
            labelExpr=expr,
            title=title,
            grid=False,
            labelAngle=0,
            titleFontWeight="bold",
        )

    # Titles carry the direction, risk-matrix style: rightward = worse, upward = likelier.
    SEV_AXIS = _axis(SEV, "Severity — more severe →")
    LIK_AXIS = _axis(LIK, "Likelihood — more likely ↑")
    return LIK_AXIS, SEV_AXIS, cell_grid


@app.cell
def _(
    DELTA_DOMAIN,
    DELTA_RANGE,
    LIK,
    LIK_AXIS,
    SEV,
    SEV_AXIS,
    cell_grid,
    df,
    phase,
):
    xcol = f"severity_{phase.value}_rank"
    ycol = f"likelihood_{phase.value}_rank"
    plotted = df.dropna(subset=[xcol, ycol]).copy()
    positioned = cell_grid(plotted, xcol, ycol)

    # Background: a *continuous* risk gradient. The catalog assigns no composite
    # score, so this is purely visual — a fine mesh of small rects shaded by the
    # severity×likelihood product, drawn strokeless so the cells melt into a smooth
    # diagonal wash (cool/low bottom-left → hot/high top-right) instead of a grid.
    x0d, x1d = 0.4, max(SEV.values()) + 0.6
    y0d, y1d = 0.4, max(LIK.values()) + 0.6
    _nx, _ny = 56, 44
    _dx, _dy = (x1d - x0d) / _nx, (y1d - y0d) / _ny
    _mesh = [
        {
            "x": x0d + _i * _dx,
            "x2": x0d + (_i + 1) * _dx,
            "y": y0d + _j * _dy,
            "y2": y0d + (_j + 1) * _dy,
            "heat": (x0d + (_i + 0.5) * _dx) * (y0d + (_j + 0.5) * _dy),
        }
        for _i in range(_nx)
        for _j in range(_ny)
    ]
    # The axes live on the gradient (the bottom layer). Defining them here — and
    # NOT passing axis=None on the label layer — is what keeps the worded axes
    # visible: an explicit axis=None on any layer of a shared scale suppresses them.
    gradient = (
        alt.Chart(pd.DataFrame(_mesh))
        .mark_rect()
        .encode(
            x=alt.X("x:Q", scale=alt.Scale(domain=[x0d, x1d]), axis=SEV_AXIS),
            x2="x2:Q",
            y=alt.Y("y:Q", scale=alt.Scale(domain=[y0d, y1d]), axis=LIK_AXIS),
            y2="y2:Q",
            color=alt.Color("heat:Q", scale=alt.Scale(scheme="yelloworangered"), legend=None),
            opacity=alt.value(0.55),
        )
    )

    # Each threat is its own ID, stacked within its cell so the group prefix is
    # readable at a glance. Colour still encodes delta; hover carries a plain-language
    # gist. Click to filter the explorer below.
    selection = alt.selection_point(fields=["id"], on="click", empty=True)
    labels = (
        alt.Chart(positioned)
        .mark_text(fontSize=10, fontWeight="bold")
        .encode(
            x=alt.X("bx:Q", scale=alt.Scale(domain=[x0d, x1d])),
            y=alt.Y("by:Q", scale=alt.Scale(domain=[y0d, y1d])),
            text="id:N",
            color=alt.Color(
                "delta:N",
                scale=alt.Scale(domain=DELTA_DOMAIN, range=DELTA_RANGE),
                legend=alt.Legend(title="delta", orient="top"),
            ),
            opacity=alt.condition(selection, alt.value(1.0), alt.value(0.28)),
            tooltip=[
                alt.Tooltip("id:N", title="ID"),
                alt.Tooltip("title:N", title="Threat"),
                alt.Tooltip("delta:N", title="Delta"),
                alt.Tooltip("bucket_label:N", title="Bucket"),
                alt.Tooltip("stride:N", title="STRIDE"),
                alt.Tooltip("attack:N", title="ATT&CK"),
                alt.Tooltip("tests_pretty:N", title="Backing tests"),
                alt.Tooltip("summary:N", title="What the attacker gains"),
            ],
        )
        .add_params(selection)
    )

    matrix = mo.ui.altair_chart(
        (gradient + labels).properties(
            width=620, height=470, title=f"Risk matrix ({phase.value})"
        )
    )
    matrix
    return (matrix,)


@app.cell
def _():
    mo.md("""
    **Group key** — the prefix on each label says which part of the system the threat
    lives in: **`CORE`** approver accounts, tokens & collusion ·
    **`IDENT`** approver identity & authentication ·
    **`VOTE`** approval integrity (sessions, replay, coercion) ·
    **`HOST`** host & database compromise ·
    **`CRYPTO`** cryptographic design & side channels ·
    **`PUB`** publishing pipeline & bypass ·
    **`DOS`** denial of service & availability ·
    **`CODE`** proxy code & supply chain ·
    **`INFO`** information disclosure.
    """)
    return


@app.cell
def _():
    mo.md("""
    ### Movement — what the proxy buys

    One small panel per **improved** threat. In each, the arrow runs from the
    **baseline** position (grey dot — direct-publish to PyPI) to the **residual**
    position the proxy leaves it at (green dot). The gain is almost always on the
    **severity** axis: the proxy rarely makes an attack less likely — it makes it
    *matter less*. Splitting the threats into their own panels keeps CORE-1 and
    CORE-2, which share a baseline, from landing on top of each other.
    """)
    return


@app.cell
def _(DELTA_RANGE, LIK, SEV, df):
    moved = df[
        (df["delta"] == "improved")
        & df["severity_baseline_rank"].notna()
        & df["likelihood_baseline_rank"].notna()
    ].copy()
    moved["sev_b"] = moved["severity_baseline_rank"]
    moved["sev_r"] = moved["severity_residual_rank"]
    moved["lik_b"] = moved["likelihood_baseline_rank"]
    moved["lik_r"] = moved["likelihood_residual_rank"]
    # Heading of the baseline→residual vector, in degrees clockwise from "up",
    # so a triangle marker rotated by it points the way the threat moved.
    moved["angle"] = [
        math.degrees(math.atan2(r.sev_r - r.sev_b, r.lik_r - r.lik_b))
        for r in moved.itertuples()
    ]

    def _worded(ranks: dict[str, int], title: str) -> alt.Axis:
        expr = " : ".join(f"datum.value == {v} ? '{k}'" for k, v in ranks.items()) + " : ''"
        return alt.Axis(
            values=list(ranks.values()), labelExpr=expr, title=title,
            grid=True, tickCount=len(ranks), labelAngle=0,
        )

    _xscale = alt.Scale(domain=[0.5, max(SEV.values()) + 0.5])
    _yscale = alt.Scale(domain=[0.5, max(LIK.values()) + 0.5])
    _tip = [
        alt.Tooltip("title:N", title="Threat"),
        alt.Tooltip("summary:N", title="What the attacker gains"),
    ]

    # One panel per improved threat: layer the arrow + baseline dot + residual dot
    # off a data-less base, then facet by id so shared-baseline threats never overlap.
    _base = alt.Chart()
    _arrow = _base.mark_rule(strokeWidth=2.5, color=DELTA_RANGE[0]).encode(
        x=alt.X("sev_b:Q", scale=_xscale, axis=_worded(SEV, "Severity →")),
        x2="sev_r:Q",
        y=alt.Y("lik_b:Q", scale=_yscale, axis=_worded(LIK, "Likelihood →")),
        y2="lik_r:Q",
    )
    _from = _base.mark_point(size=80, color="#8a8a8a", filled=True).encode(
        x="sev_b:Q", y="lik_b:Q", tooltip=_tip
    )
    # Destination marker is a triangle rotated to the heading — an actual arrowhead,
    # so "down"/"left" is unmistakable rather than inferred from the two endpoints.
    _to = _base.mark_point(
        shape="triangle", size=280, color=DELTA_RANGE[0], filled=True,
        stroke="white", strokeWidth=0.8,
    ).encode(
        x="sev_r:Q", y="lik_r:Q", angle=alt.Angle("angle:Q", scale=None), tooltip=_tip
    )

    movement = (
        alt.layer(_arrow, _from, _to, data=moved)
        .properties(width=180, height=180)
        .facet(
            column=alt.Column(
                "id:N",
                title=None,
                header=alt.Header(labelFontWeight="bold", labelFontSize=13),
            )
        )
        .resolve_scale(x="shared", y="shared")
    )
    movement
    return


@app.cell
def _():
    mo.md("""
    ### The catalog's shape — delta ledger, ATT&CK coverage, STRIDE, buckets & backing tests
    """)
    return


@app.cell
def _(DELTA_DOMAIN, DELTA_RANGE, df):
    ledger = (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("delta:N", sort=DELTA_DOMAIN, title=None),
            y=alt.Y("count()", title="threats"),
            color=alt.Color(
                "delta:N",
                scale=alt.Scale(domain=DELTA_DOMAIN, range=DELTA_RANGE),
                legend=None,
            ),
            tooltip=["delta", "count()"],
        )
        .properties(width=220, height=240, title="Delta ledger")
    )
    return (ledger,)


@app.cell
def _(df):
    _rows = []
    for _, _row in df.iterrows():
        for _technique in [a.strip() for a in _row["attack"].split(",") if a.strip()]:
            _rows.append({"technique": _technique, "id": _row["id"]})
    attack_df = pd.DataFrame(_rows)
    coverage = (
        alt.Chart(attack_df)
        .mark_bar(color="#555")
        .encode(
            x=alt.X("count()", title="threats"),
            y=alt.Y("technique:N", sort="-x", title="ATT&CK technique"),
            tooltip=["technique", "count()"],
        )
        .properties(width=280, height=320, title="ATT&CK coverage")
    )
    return (coverage,)


@app.cell
def _(df):
    _rows = []
    for _, _row in df.iterrows():
        for _category in [s.strip() for s in _row["stride"].split(",") if s.strip()]:
            _rows.append({"stride": _category})
    stride_chart = (
        alt.Chart(pd.DataFrame(_rows))
        .mark_bar(color="#7b5ea7")
        .encode(
            x=alt.X("count()", title="threats"),
            y=alt.Y("stride:N", sort="-x", title=None),
            tooltip=["stride", "count()"],
        )
        .properties(width=280, height=200, title="STRIDE distribution")
    )
    # Ordered by the numeric bucket ordinal (glyph order ①②③④, N/A last), but
    # labelled glyph + name (#132).
    _bucket_order = [tm.bucket_label(b) for b in ("1", "2", "3", "4", "N/A")]
    bucket_chart = (
        alt.Chart(df)
        .mark_bar(color="#3a7ca5")
        .encode(
            x=alt.X("bucket_label:N", title="bucket", sort=_bucket_order),
            y=alt.Y("count()", title="threats"),
            tooltip=[alt.Tooltip("bucket_label:N", title="bucket"), alt.Tooltip("count()")],
        )
        .properties(width=220, height=200, title="Bucket distribution")
    )
    return bucket_chart, stride_chart


@app.cell
def _(DELTA_DOMAIN, DELTA_RANGE, df):
    # Backing tests (#111): the tests: frontmatter field, single-sourced from each
    # threat and validated by `tools/threat_model.py`. Only threats that cite tests appear.
    tested = df[df["n_tests"] > 0]
    tests_chart = (
        alt.Chart(tested)
        .mark_bar()
        .encode(
            x=alt.X("n_tests:Q", title="backing tests", axis=alt.Axis(tickMinStep=1)),
            y=alt.Y("id:N", sort="-x", title=None),
            color=alt.Color(
                "delta:N",
                scale=alt.Scale(domain=DELTA_DOMAIN, range=DELTA_RANGE),
                legend=None,
            ),
            tooltip=[
                alt.Tooltip("id:N", title="ID"),
                alt.Tooltip("title:N", title="Threat"),
                alt.Tooltip("bucket_label:N", title="Bucket"),
                alt.Tooltip("n_tests:Q", title="Count"),
                alt.Tooltip("tests_pretty:N", title="Backing tests"),
            ],
        )
        .properties(width=460, height=360, title="Backing tests per threat (#111)")
    )
    return (tests_chart,)


@app.cell
def _(bucket_chart, coverage, ledger, stride_chart, tests_chart):
    mo.vstack(
        [
            mo.hstack(
                [mo.vstack([ledger, bucket_chart]), stride_chart, coverage],
                justify="start",
                gap=1.5,
            ),
            tests_chart,
        ],
        gap=1.5,
    )
    return


@app.cell
def _():
    mo.md("""
    ## Explorer

    Slice the catalog with the filters, then click a row for the full detail of a
    single threat. Filters are AND-combined; leave one at *all* to ignore it.
    **Clicking badges in the risk matrix above** also narrows this table to the
    selected threats.
    """)
    return


@app.cell
def _(df):
    def scalar_options(column: str) -> list[str]:
        values = sorted({v for v in df[column] if v and v != "nan"})
        return ["all", *values]

    def token_options(column: str) -> list[str]:
        seen: set[str] = set()
        for cell in df[column]:
            for token in (t.strip() for t in str(cell).split(",")):
                if token:
                    seen.add(token)
        return ["all", *sorted(seen)]

    return scalar_options, token_options


@app.cell
def _(scalar_options, token_options):
    stride_pick = mo.ui.dropdown(token_options("stride"), value="all", label="stride")
    delta_pick = mo.ui.dropdown(scalar_options("delta"), value="all", label="delta")
    bucket_pick = mo.ui.dropdown(scalar_options("bucket_label"), value="all", label="bucket")
    severity_pick = mo.ui.dropdown(scalar_options("severity_residual"), value="all", label="severity")
    attack_pick = mo.ui.text(placeholder="e.g. T1078", label="attack contains")
    mo.hstack(
        [stride_pick, delta_pick, bucket_pick, severity_pick, attack_pick],
        justify="start",
        gap=1,
    )
    return attack_pick, bucket_pick, delta_pick, severity_pick, stride_pick


@app.cell
def _(
    attack_pick,
    bucket_pick,
    delta_pick,
    df,
    matrix,
    severity_pick,
    stride_pick,
):
    filtered = df
    # Clicking badges in the risk matrix drives the explorer: apply_selection() is
    # marimo's way to read a *layered* chart's selection. An empty (or full) click
    # set means "no constraint". Guarded so the table renders even before any click.
    try:
        selected = matrix.apply_selection(df)
    except Exception:
        selected = None
    if selected is not None and 0 < len(selected) < len(df):
        filtered = filtered[filtered["id"].isin(list(selected["id"]))]
    if stride_pick.value != "all":
        filtered = filtered[filtered["stride"].str.contains(stride_pick.value, regex=False)]
    if delta_pick.value != "all":
        filtered = filtered[filtered["delta"] == delta_pick.value]
    if bucket_pick.value != "all":
        filtered = filtered[filtered["bucket_label"] == bucket_pick.value]
    if severity_pick.value != "all":
        filtered = filtered[filtered["severity_residual"] == severity_pick.value]
    if attack_pick.value.strip():
        filtered = filtered[
            filtered["attack"].str.contains(attack_pick.value.strip(), case=False, regex=False)
        ]

    table = mo.ui.table(
        filtered[
            ["id", "title", "delta", "stride", "attack", "bucket_label", "severity_residual", "n_tests"]
        ].rename(
            columns={"bucket_label": "bucket", "severity_residual": "severity", "n_tests": "tests"}
        ),
        selection="single",
        page_size=15,
    )
    table
    return (table,)


@app.cell
def _(table, threats):
    def _detail() -> str:
        rows = table.value
        if rows is None or len(rows) == 0:
            return "*Select a row above to see the full threat.*"
        threat_id = list(rows["id"])[0]
        threat = next((t for t in threats if t.id == threat_id), None)
        if threat is None:
            return f"*Unknown id {threat_id}.*"
        fm = threat.frontmatter
        lines = [f"### {threat.id} — {fm.get('title', '')}", ""]
        for key in (
            "stride",
            "attack",
            "capability",
            "delta",
            "likelihood_residual",
            "severity_residual",
            "bucket",
            "related",
        ):
            value = fm.get(key)
            if key == "bucket":
                shown = tm.bucket_label(value)
            elif isinstance(value, list):
                shown = ", ".join(str(v) for v in value)
            else:
                shown = value
            lines.append(f"- **{key}:** {shown}")
        gains = threat.anatomy.get("gains")
        if gains:
            lines += ["", f"**What the attacker gains.** {gains}"]
        cannot = threat.anatomy.get("cannot")
        if cannot:
            lines += ["", f"**What they cannot do.** {cannot}"]
        tests = fm.get("tests") or []
        if tests:
            lines += ["", f"**Backing tests ({len(tests)}).**"]
            lines += [f"- `{node}`" for node in tests]
        return "\n".join(lines)

    mo.md(_detail())
    return


if __name__ == "__main__":
    app.run()
