"""Forward-auth ``/auth`` latency metric — report-only (issue #19).

Evaluation triad #3: how much latency the ``/auth`` subrequest adds to each
forwarded request. Measured at the forward-auth boundary at **steady state** — a
valid (open-path) Service Grant is already in place, so the sample reflects the
recurring per-request overhead, not the one-time approval wait.

This is a reproducible, **report-only** harness: it drives the real ``GET /auth``
gate over the ASGI surface ``_SAMPLES`` times, times each call with
``time.perf_counter``, and reports p50/p95. There is deliberately **no** pass/fail
threshold asserted — the AC is to measure and report the overhead, not to gate on
it (optimization is out of scope). The harness asserts only that it ran and
produced finite, ordered percentiles.
"""

from __future__ import annotations

import logging
import statistics
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core.config import AppConfig, AuthConfig, ServerConfig, ServiceConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import (
    APPROVED,
    FORWARD_AUTH,
    GRANT_ACTIVE,
    ApprovalRequest,
    ServiceGrant,
    User,
)
from tests.support import current_totp

# A few hundred in-process ASGI calls keep the suite fast while giving a stable
# p50/p95. Raise locally for a smoother distribution; the AC is report-only.
_SAMPLES = 300
_SERVICE_NAME = "internal-app"
_PASSWORD = "pw-dave-123"
_REPORT_LOGGER = "msig_proxy.bench.auth_latency"


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        auth=AuthConfig(session_expiry_hours=8),
        services={
            _SERVICE_NAME: ServiceConfig(
                type="forward-auth",
                quorum=2,
                approvers=["alice", "bob"],
                endpoint="http://internal-app:8080",
            )
        },
    )


def _open_path_grant(app: FastAPI) -> None:
    """Seed ``dave`` and persist a valid (active, unexpired) forward-auth grant.

    Mirrors ``tests/test_auth_gate.py``'s grant setup so ``/auth`` resolves the
    open path (200) on every call — the steady state we want to time.
    """
    for session in session_scope(app.state.session_factory):
        seed_user(session, username="dave", email="dave@example.com", password=_PASSWORD)
        user = session.scalars(select(User).where(User.username == "dave")).one()
        request = ApprovalRequest(
            requester_id=user.id,
            service_name=_SERVICE_NAME,
            service_type=FORWARD_AUTH,
            quorum=1,
            state=APPROVED,
        )
        session.add(request)
        session.flush()
        session.add(
            ServiceGrant(
                approval_request_id=request.id,
                user_id=user.id,
                service_name=_SERVICE_NAME,
                state=GRANT_ACTIVE,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )


def _percentiles(samples_ms: list[float]) -> tuple[float, float]:
    """p50 and p95 (ms) via ``statistics.quantiles`` with 100 buckets.

    ``quantiles(n=100)`` returns the 99 inter-percentile cut points; index 49 is
    the 50th percentile and index 94 the 95th.
    """
    cut_points = statistics.quantiles(samples_ms, n=100)
    return cut_points[49], cut_points[94]


async def test_auth_latency_p50_p95_report_only(
    client: httpx.AsyncClient,
    app: FastAPI,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _open_path_grant(app)
    login = await client.post(
        "/login",
        data={
            "username": "dave",
            "password": _PASSWORD,
            "totp": current_totp(app.state.session_factory, "dave"),
        },
        follow_redirects=False,
    )
    auth = {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}

    # Warm up once (first-call import/connection costs shouldn't skew the sample)
    # and confirm we're on the open path before timing the steady state.
    warmup = await client.get("/auth", params={"service": _SERVICE_NAME}, headers=auth)
    assert warmup.status_code == 200

    samples_ms: list[float] = []
    for _ in range(_SAMPLES):
        start = time.perf_counter()
        response = await client.get("/auth", params={"service": _SERVICE_NAME}, headers=auth)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        assert response.status_code == 200  # steady state, never the approval wait
        samples_ms.append(elapsed_ms)

    p50, p95 = _percentiles(samples_ms)

    # Report the overhead (visible in the captured log / pytest report). No
    # threshold is asserted — this metric is descriptive, not a gate.
    with caplog.at_level(logging.INFO, logger=_REPORT_LOGGER):
        logging.getLogger(_REPORT_LOGGER).info(
            "GET /auth steady-state overhead over %d calls: p50=%.3fms p95=%.3fms",
            _SAMPLES,
            p50,
            p95,
        )

    # Report-only acceptance: the harness ran and produced ordered percentiles.
    assert len(samples_ms) == _SAMPLES
    assert p50 >= 0.0
    assert p95 >= p50
    assert "p50=" in caplog.text and "p95=" in caplog.text  # the metric was reported
