"""Threat-model dashboard — a visual view of docs/threat-model/ (issue #130).

A marimo notebook that reads the catalog through the tested ``tools/threat_model.py``
core and renders it: a likelihood × severity risk matrix (the centerpiece), the
baseline→residual movement view, the delta ledger, ATT&CK coverage, and STRIDE /
bucket distributions, with a reactive explorer at the bottom.

Run it::

    uv run marimo edit docs/threat-model/threat_model_dashboard.py   # interactive
    uv run marimo run  docs/threat-model/threat_model_dashboard.py   # read-only app

The parsing/validation logic is *not* redefined here — it is imported from the
core module, which the pytest suite covers. This file only shapes and draws.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo

    return (mo,)


@app.cell
def _():
    import math
    import sys
    from pathlib import Path

    import altair as alt
    import pandas as pd

    # The single-file core lives in tools/; add it to the path and import it.
    _tools = Path(__file__).resolve().parents[2] / "tools"
    if str(_tools) not in sys.path:
        sys.path.insert(0, str(_tools))
    import threat_model as tm

    return alt, math, pd, tm


@app.cell
def _(mo):
    mo.md(
        """
        # Threat-model dashboard

        A live view of the threat catalog under `docs/threat-model/`. Every number
        below is read straight from the threat files' frontmatter through the
        `threat_model` core — so this dashboard cannot drift from the catalog it
        describes. The **risk matrix** is the centerpiece: it plots each threat by
        *likelihood* and *severity*, coloured by its **delta** — whether the proxy
        **improves** a baseline threat, **inherits** it unchanged, or **introduces**
        it as the cost of existing. Introduced threats are drawn just as boldly as
        the improvements: the cost ledger is not hidden.
        """
    )
    return


@app.cell
def _(pd, tm):
    # Rank maps for the two rated axes (higher = more dangerous).
    LIK = {"low": 1, "medium": 2, "high": 3}
    SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    DELTA_DOMAIN = ["improved", "inherited", "introduced"]
    # Three vivid, equal-weight hues — nothing muted.
    DELTA_RANGE = ["#2ca02c", "#1f77b4", "#d62728"]

    threats = tm.load_catalog()

    def _join(value: object) -> str:
        return ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)

    rows = []
    for threat in threats:
        fm = threat.frontmatter
        rows.append(
            {
                "id": threat.id,
                "group": threat.id.split("-")[0],
                "title": str(fm.get("title", "")),
                "stride": _join(fm.get("stride", [])),
                "attack": _join(fm.get("attack", [])),
                "capability": _join(fm.get("capability", [])),
                "delta": str(fm.get("delta", "")),
                "likelihood_baseline": str(fm.get("likelihood_baseline", "")),
                "likelihood_residual": str(fm.get("likelihood_residual", "")),
                "severity_baseline": str(fm.get("severity_baseline", "")),
                "severity_residual": str(fm.get("severity_residual", "")),
                "bucket": str(fm.get("bucket", "")),
                "related": _join(fm.get("related", [])),
            }
        )
    df = pd.DataFrame(rows)
    for _axis, _ranks in (("likelihood", LIK), ("severity", SEV)):
        for _phase in ("baseline", "residual"):
            _col = f"{_axis}_{_phase}"
            df[f"{_col}_rank"] = df[_col].map(_ranks)
    return DELTA_DOMAIN, DELTA_RANGE, LIK, SEV, df, threats


@app.cell
def _(df, mo):
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
def _(mo):
    phase = mo.ui.radio(
        options=["residual", "baseline"],
        value="residual",
        label="Risk matrix — show",
        inline=True,
    )
    phase
    return (phase,)


@app.cell
def _(LIK, SEV, alt, math, pd):
    def cell_grid(sub: pd.DataFrame, xcol: str, ycol: str) -> pd.DataFrame:
        """Lay each threat's badge out on a mini-grid inside its (severity, likelihood)
        cell so badges in the same cell tile neatly instead of overlapping."""
        sub = sub.copy()
        sub["bx"] = sub[xcol].astype(float)
        sub["by"] = sub[ycol].astype(float)
        for (_, _), group in sub.groupby([xcol, ycol]):
            n = len(group)
            cols = max(1, math.ceil(math.sqrt(n)))
            for k, idx in enumerate(group.index):
                r, c = divmod(k, cols)
                rows_n = math.ceil(n / cols)
                sub.loc[idx, "bx"] = float(sub.loc[idx, xcol]) + (c - (cols - 1) / 2) * 0.19
                sub.loc[idx, "by"] = float(sub.loc[idx, ycol]) + (r - (rows_n - 1) / 2) * 0.19
        return sub

    def _axis(ranks: dict[str, int], title: str) -> alt.Axis:
        expr = " : ".join(f"datum.value == {v} ? '{k}'" for k, v in ranks.items()) + " : ''"
        return alt.Axis(values=list(ranks.values()), labelExpr=expr, title=title, grid=False)

    SEV_AXIS = _axis(SEV, "Severity →")
    LIK_AXIS = _axis(LIK, "Likelihood →")
    return LIK_AXIS, SEV_AXIS, cell_grid


@app.cell
def _(DELTA_DOMAIN, DELTA_RANGE, LIK, LIK_AXIS, SEV, SEV_AXIS, alt, cell_grid, df, mo, pd, phase):
    xcol = f"severity_{phase.value}_rank"
    ycol = f"likelihood_{phase.value}_rank"
    plotted = df.dropna(subset=[xcol, ycol]).copy()
    positioned = cell_grid(plotted, xcol, ycol)

    # Background heat: one rect per (severity, likelihood) cell, shaded by a purely
    # visual severity×likelihood product (the catalog assigns no composite score).
    cells = pd.DataFrame(
        [{"sx": sx, "sy": sy, "heat": sx * sy} for sx in SEV.values() for sy in LIK.values()]
    )
    heat = (
        alt.Chart(cells)
        .mark_rect(stroke="white", strokeWidth=2)
        .encode(
            x=alt.X("sx:O", axis=None),
            y=alt.Y("sy:O", axis=None, sort="descending"),
            color=alt.Color(
                "heat:Q",
                scale=alt.Scale(scheme="reds"),
                legend=None,
            ),
            opacity=alt.value(0.35),
        )
    )

    selection = alt.selection_point(fields=["id"], on="click", empty=True)
    badges = (
        alt.Chart(positioned)
        .mark_text(fontSize=11, fontWeight="bold")
        .encode(
            x=alt.X("bx:Q", scale=alt.Scale(domain=[0.4, 4.6]), axis=SEV_AXIS),
            y=alt.Y("by:Q", scale=alt.Scale(domain=[0.4, 3.6]), axis=LIK_AXIS),
            text="id:N",
            color=alt.Color(
                "delta:N",
                scale=alt.Scale(domain=DELTA_DOMAIN, range=DELTA_RANGE),
                legend=alt.Legend(title="delta", orient="top"),
            ),
            opacity=alt.condition(selection, alt.value(1.0), alt.value(0.25)),
            tooltip=["id", "title", "delta", "bucket", "stride", "attack"],
        )
        .add_params(selection)
    )

    matrix = mo.ui.altair_chart(
        (heat + badges).properties(width=560, height=420, title=f"Risk matrix ({phase.value})")
    )
    matrix
    return (matrix,)


@app.cell
def _(mo):
    mo.md(
        """
        ### Movement — what the proxy buys

        For each **improved** threat, the arrow runs from where the *baseline* world
        sits (direct-publish to PyPI) to where the *proxy* leaves it. The improvement
        is almost always on the **severity** axis: the proxy rarely makes an attack
        less likely — it makes it *matter less*.
        """
    )
    return


@app.cell
def _(DELTA_RANGE, alt, df):
    moved = df[
        (df["delta"] == "improved")
        & df["severity_baseline_rank"].notna()
        & df["likelihood_baseline_rank"].notna()
    ].copy()
    moved["sev_b"] = moved["severity_baseline_rank"]
    moved["sev_r"] = moved["severity_residual_rank"]
    moved["lik_b"] = moved["likelihood_baseline_rank"]
    moved["lik_r"] = moved["likelihood_residual_rank"]

    arrows = (
        alt.Chart(moved)
        .mark_rule(strokeWidth=2, color=DELTA_RANGE[0], opacity=0.7)
        .encode(
            x=alt.X("sev_b:Q", scale=alt.Scale(domain=[0.5, 4.5]), title="Severity →"),
            x2="sev_r:Q",
            y=alt.Y("lik_b:Q", scale=alt.Scale(domain=[0.5, 3.5]), title="Likelihood →"),
            y2="lik_r:Q",
        )
    )
    origin = (
        alt.Chart(moved)
        .mark_point(size=40, color="#999", filled=True)
        .encode(x="sev_b:Q", y="lik_b:Q", tooltip=["id", "title"])
    )
    dest = (
        alt.Chart(moved)
        .mark_text(fontSize=11, fontWeight="bold", color=DELTA_RANGE[0])
        .encode(x="sev_r:Q", y="lik_r:Q", text="id:N", tooltip=["id", "title"])
    )
    movement = (arrows + origin + dest).properties(width=560, height=360, title="Baseline → residual")
    movement
    return (movement,)


@app.cell
def _(mo):
    mo.md("### The catalog's shape — delta ledger, ATT&CK coverage, STRIDE & buckets")
    return


@app.cell
def _(DELTA_DOMAIN, DELTA_RANGE, alt, df):
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
def _(alt, df, pd):
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
def _(alt, df, pd):
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
    bucket_chart = (
        alt.Chart(df)
        .mark_bar(color="#3a7ca5")
        .encode(
            x=alt.X("bucket:N", title="bucket"),
            y=alt.Y("count()", title="threats"),
            tooltip=["bucket", "count()"],
        )
        .properties(width=220, height=200, title="Bucket distribution")
    )
    return bucket_chart, stride_chart


@app.cell
def _(bucket_chart, coverage, ledger, mo, stride_chart):
    mo.hstack(
        [
            mo.vstack([ledger, bucket_chart]),
            stride_chart,
            coverage,
        ],
        justify="start",
        gap=1.5,
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## Explorer

        Slice the catalog with the filters, then click a row for the full detail of a
        single threat. Filters are AND-combined; leave one at *all* to ignore it.
        **Clicking badges in the risk matrix above** also narrows this table to the
        selected threats.
        """
    )
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
def _(mo, scalar_options, token_options):
    stride_pick = mo.ui.dropdown(token_options("stride"), value="all", label="stride")
    delta_pick = mo.ui.dropdown(scalar_options("delta"), value="all", label="delta")
    bucket_pick = mo.ui.dropdown(scalar_options("bucket"), value="all", label="bucket")
    severity_pick = mo.ui.dropdown(scalar_options("severity_residual"), value="all", label="severity")
    attack_pick = mo.ui.text(placeholder="e.g. T1078", label="attack contains")
    mo.hstack(
        [stride_pick, delta_pick, bucket_pick, severity_pick, attack_pick],
        justify="start",
        gap=1,
    )
    return attack_pick, bucket_pick, delta_pick, severity_pick, stride_pick


@app.cell
def _(attack_pick, bucket_pick, delta_pick, df, matrix, mo, severity_pick, stride_pick):
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
        filtered = filtered[filtered["bucket"] == bucket_pick.value]
    if severity_pick.value != "all":
        filtered = filtered[filtered["severity_residual"] == severity_pick.value]
    if attack_pick.value.strip():
        filtered = filtered[
            filtered["attack"].str.contains(attack_pick.value.strip(), case=False, regex=False)
        ]

    table = mo.ui.table(
        filtered[
            ["id", "title", "delta", "stride", "attack", "capability", "severity_residual", "bucket"]
        ],
        selection="single",
        page_size=15,
    )
    table
    return (table,)


@app.cell
def _(mo, table, threats):
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
            shown = ", ".join(str(v) for v in value) if isinstance(value, list) else value
            lines.append(f"- **{key}:** {shown}")
        gains = threat.anatomy.get("gains")
        if gains:
            lines += ["", f"**What the attacker gains.** {gains}"]
        cannot = threat.anatomy.get("cannot")
        if cannot:
            lines += ["", f"**What they cannot do.** {cannot}"]
        return "\n".join(lines)

    mo.md(_detail())
    return


if __name__ == "__main__":
    app.run()
