"""Publish-flow driver notebook — STUB (#101 decision 9).

This is a placeholder marimo notebook wired into the publish demo stack
(`compose.publish.yaml`). The real behavior — driving a one-time publish end to end
against the proxy (upload an artifact, gather quorum, watch it publish to the local
pypiserver) — is deferred to a separate issue. For now it documents the intended flow
and renders a TODO so the marimo service has something to open.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App()


@app.cell
def _():
    import marimo as mo

    mo.md(
        """
        # Publish demo (stub)

        **TODO** — drive the full one-time publish flow against the proxy:

        1. authenticate, then `POST` an artifact to the proxy's PyPI upload route;
        2. gather quorum via the approval links delivered to **Mailpit**
           (<http://localhost:8025>);
        3. watch the proxy publish to the local **pypiserver**
           (<http://localhost:8081>) — never real PyPI.

        Real driving behavior is deferred to a separate issue; this notebook is a
        placeholder so the demo stack's `marimo` service has something to open.
        """
    )
    return (mo,)


if __name__ == "__main__":
    app.run()
