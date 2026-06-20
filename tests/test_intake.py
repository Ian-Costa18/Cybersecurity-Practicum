"""The intake service seam: turn an uploaded artifact into a ``pending`` Approval
Request bound by hash, with the eligible-approver set and quorum snapshotted
(ADR 0008) and the bytes staged for the Executor.

Real DB, real crypto. This exercises the logic below the HTTP layer; the route
itself is covered end-to-end in ``test_pypi_upload.py``.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto
from msig_proxy.config import ServiceConfig
from msig_proxy.core import models
from msig_proxy.core.models import ApprovalRequest, ApprovalRequestApprover, StagedArtifact, User
from msig_proxy.db import Base, create_db_engine, create_session_factory
from msig_proxy.intake import UnknownApproverError, create_publish_request
from msig_proxy.seed import seed_user


@pytest.fixture
def session() -> Iterator[Session]:
    """A real session over a throwaway in-memory SQLite DB (never mocked)."""
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = create_session_factory(engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _service(quorum: int = 2, approvers: list[str] | None = None) -> ServiceConfig:
    return ServiceConfig(
        type="one-time",
        action="publish-to-pypi",
        quorum=quorum,
        approvers=approvers or ["alice", "bob", "carol"],
    )


def _seed_cast(session: Session) -> User:
    """Seed the three approvers plus a separate requester; return the requester."""
    for name in ("alice", "bob", "carol"):
        seed_user(session, username=name, email=f"{name}@example.com", password=f"pw-{name}-123")
    return seed_user(
        session, username="publisher", email="publisher@example.com", password="pub-pw-123"
    ).user


def test_creates_a_pending_request_bound_to_the_artifact_hash(session: Session) -> None:
    requester = _seed_cast(session)
    content = b"the exact artifact bytes"

    request = create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=_service(quorum=2),
        package_name="foo",
        package_version="1.2.3",
        filename="foo-1.2.3.tar.gz",
        content=content,
    )

    stored = session.get(ApprovalRequest, request.id)
    assert stored is not None
    assert stored.state == models.PENDING
    assert stored.action == "publish-to-pypi"
    assert stored.service_name == "pypi"
    assert stored.requester_id == requester.id
    assert stored.package_name == "foo"
    assert stored.package_version == "1.2.3"
    assert stored.quorum == 2  # threshold snapshotted at creation (ADR 0008)
    assert stored.artifact_sha256 == crypto.sha256_hex(content)  # Hash Binding (constraints §6)


def test_snapshots_the_eligible_approver_set_at_creation(session: Session) -> None:
    requester = _seed_cast(session)
    approvers = {
        name: session.scalars(select(User).where(User.username == name)).one()
        for name in ("alice", "bob", "carol")
    }

    request = create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=_service(approvers=["alice", "bob", "carol"]),
        package_name="foo",
        package_version="1.2.3",
        filename="foo-1.2.3.tar.gz",
        content=b"bytes",
    )

    snapshot = session.scalars(
        select(ApprovalRequestApprover.user_id).where(
            ApprovalRequestApprover.approval_request_id == request.id
        )
    ).all()
    assert set(snapshot) == {approvers["alice"].id, approvers["bob"].id, approvers["carol"].id}


def test_stages_the_uploaded_bytes_for_the_executor(session: Session) -> None:
    requester = _seed_cast(session)
    content = b"PK\x03\x04 ... a wheel's bytes"

    request = create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=_service(),
        package_name="foo",
        package_version="1.2.3",
        filename="foo-1.2.3-py3-none-any.whl",
        content=content,
    )

    staged = session.get(StagedArtifact, request.id)
    assert staged is not None
    assert staged.content == content  # the exact bytes are held for re-verification
    assert staged.filename == "foo-1.2.3-py3-none-any.whl"
    assert staged.sha256 == crypto.sha256_hex(content) == request.artifact_sha256


def test_rejects_a_service_referencing_an_unknown_approver(session: Session) -> None:
    requester = _seed_cast(session)

    with pytest.raises(UnknownApproverError, match="nobody"):
        create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=_service(quorum=1, approvers=["alice", "nobody"]),
            package_name="foo",
            package_version="1.2.3",
            filename="foo-1.2.3.tar.gz",
            content=b"bytes",
        )


# --- wildcard approver patterns (expanded at snapshot time) ----------------


def _snapshot_ids(session: Session, request: ApprovalRequest) -> set[object]:
    return set(
        session.scalars(
            select(ApprovalRequestApprover.user_id).where(
                ApprovalRequestApprover.approval_request_id == request.id
            )
        ).all()
    )


def _create(session: Session, requester: User, approvers: list[str]) -> ApprovalRequest:
    return create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=_service(quorum=1, approvers=approvers),
        package_name="foo",
        package_version="1.2.3",
        filename="foo-1.2.3.tar.gz",
        content=b"bytes",
    )


def test_star_snapshots_every_user(session: Session) -> None:
    requester = _seed_cast(session)  # alice/bob/carol + publisher

    request = _create(session, requester, ["*"])

    all_user_ids = set(session.scalars(select(User.id)).all())
    assert _snapshot_ids(session, request) == all_user_ids  # "*" = all users, incl. requester


def test_prefix_glob_matches_only_that_prefix(session: Session) -> None:
    requester = _seed_cast(session)
    seed_user(session, username="admin_ops", email="ops@example.com", password="adminops123")
    seed_user(session, username="admin_sec", email="sec@example.com", password="adminsec123")

    request = _create(session, requester, ["admin_*"])

    admin_ids = {
        session.scalars(select(User.id).where(User.username == name)).one()
        for name in ("admin_ops", "admin_sec")
    }
    alice_id = session.scalars(select(User.id).where(User.username == "alice")).one()
    snapshot = _snapshot_ids(session, request)
    assert snapshot == admin_ids  # only the admin_ prefix
    assert alice_id not in snapshot  # a non-matching literal user is excluded


def test_glob_and_literal_dedupe_to_distinct_users(session: Session) -> None:
    requester = _seed_cast(session)

    request = _create(session, requester, ["*", "alice"])  # alice also matched by "*"

    snapshot = list(
        session.scalars(
            select(ApprovalRequestApprover.user_id).where(
                ApprovalRequestApprover.approval_request_id == request.id
            )
        ).all()
    )
    all_user_ids = set(session.scalars(select(User.id)).all())
    assert len(snapshot) == len(set(snapshot)) == len(all_user_ids)  # no duplicate-PK row
    assert set(snapshot) == all_user_ids


def test_glob_matching_no_users_is_allowed(session: Session) -> None:
    requester = _seed_cast(session)  # no admin_* users exist

    # The empty glob contributes nothing and does not raise; the literal resolves.
    request = _create(session, requester, ["admin_*", "alice"])

    alice_id = session.scalars(select(User.id).where(User.username == "alice")).one()
    assert _snapshot_ids(session, request) == {alice_id}
