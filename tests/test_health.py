"""The walking skeleton is live end-to-end: health routes answer over real ASGI."""

from __future__ import annotations

import httpx

from msig_proxy import __version__


async def test_health_returns_200_ok(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


async def test_health_db_round_trips_through_real_db(client: httpx.AsyncClient) -> None:
    # Exercises the session dependency + sync DB seam against the real (temp) DB.
    response = await client.get("/health/db")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}
