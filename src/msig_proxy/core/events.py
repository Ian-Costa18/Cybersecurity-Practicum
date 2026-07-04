"""A minimal in-process event seam (ADR 0005: the lifecycle emits *blind*).

The lifecycle advances and emits events without knowing who listens; consumers
subscribe. This is **not** a durable bus — the proxy is single-process and
best-effort. The seam is an :class:`EventBus` instance **owned by the application**
(``app.state.event_bus``, created in the app factory); the audit (#85) and
notification (#13/#65) subscribers register against that instance during app wiring,
and emit sites obtain it from application state / DI rather than a module global.
One bus per app means a test that builds a fresh app gets a fresh bus, with nothing
to clear between cases. The waiting room projects lifecycle state by polling the DB
(it does not consume this seam).

Subscribers must not raise into the emitter: a handler failure is logged and
swallowed so a notification fault never blocks the lifecycle.

**The emitter's session is bound once, at the session scope — not at each emit.**
A lifecycle event is emitted *inside* the transition's transaction (the row is
flushed, not yet committed). A subscriber that must read the just-transitioned state
needs the emitter's own session — a separate connection would not see uncommitted
rows. Rather than have every emit site hand-lend its session, the request session
dependency (:func:`msig_proxy.deps.get_session`) and the provisioning session scope
bind it **once** via :func:`session_bound`; :func:`emit` and the subscribers read it
ambiently through :func:`active_session`. :func:`deliver_with_session` owns the
borrow-vs-own choice in one place — borrow the bound transition when one is in flight,
otherwise open a session off a factory — so each subscriber supplies only its dispatch
body and never re-implements that closure.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

_log = logging.getLogger(__name__)

# The session of the transition currently in flight, if any. Bound by the session
# scope (:func:`session_bound`) so a subscriber can read flushed-but-uncommitted state
# from the same transaction; emit no longer sets it per-call.
_active_session: contextvars.ContextVar[Session | None] = contextvars.ContextVar(
    "msig_active_event_session", default=None
)


def active_session() -> Session | None:
    """The emitter's bound session for the current scope, or ``None`` outside one."""
    return _active_session.get()


def bind_active_session(session: Session) -> contextvars.Token[Session | None]:
    """Bind ``session`` as the active event session; the returned token undoes it.

    Pass the token to :func:`reset_active_session` to restore the prior binding.
    The web request path uses the token form because the bind must straddle an
    ``async`` ``yield`` (the FastAPI session dependency); synchronous callers and tests
    use the :func:`session_bound` context manager instead.
    """
    return _active_session.set(session)


def reset_active_session(token: contextvars.Token[Session | None]) -> None:
    """Undo a :func:`bind_active_session`, restoring the previously bound session."""
    _active_session.reset(token)


@contextlib.contextmanager
def session_bound(session: Session) -> Iterator[None]:
    """Bind ``session`` as the active event session for the duration of the block.

    Used by synchronous session scopes (the provisioning CLI) and by tests that
    exercise the borrow path below HTTP. The web request dependency binds with
    :func:`bind_active_session` instead, because its bind spans an ``async`` yield.
    """
    token = bind_active_session(session)
    try:
        yield
    finally:
        reset_active_session(token)


def deliver_with_session(
    body: Callable[[Session], object],
    *,
    session_factory: sessionmaker[Session],
    commit: bool,
) -> None:
    """Run ``body`` with a session, borrowing the bound transition or opening its own.

    The borrow-vs-own choice the audit and notification subscribers used to each
    re-implement, owned here once. When a transition is in flight (:func:`active_session`),
    ``body`` runs on that **borrowed** session — neither committed nor closed here, since
    its owning scope (the request dependency / provisioning scope) does that, so an audit
    row commits atomically with the transition it records. With no transition bound,
    ``body`` runs on an **owned** session opened off ``session_factory``, always closed
    and committed only when ``commit`` is set — the *critical* audit consumer needs its
    row durable even outside a transition; the *best-effort* notification consumer reads.
    """
    active = active_session()
    if active is not None:
        body(active)
        return
    session = session_factory()
    try:
        body(session)
        if commit:
            session.commit()
    finally:
        session.close()


# Typed lifecycle events (ADR 0014). Each event is a frozen dataclass with typed
# fields; **the discriminator is the concrete type** — subscribers ``match`` on it,
# never on a string. The hierarchy is intentionally **flat**: a single base with flat
# children, no intermediate category nodes, because no consumer dispatches on one
# (audit handles every event uniformly; notifications branch on concrete types). A
# node would earn its place only when deleting it forces a consumer to enumerate its
# concrete children by hand (ADR 0014); none does yet.


@dataclass(frozen=True)
class Event:
    """Base lifecycle event. ``name`` is the stable catalog label
    (``docs/request-lifecycle.md`` §Event catalog / ``docs/account-management.md``
    §Account Events) carried **only** for the audit trail's ``event_name`` column —
    nothing dispatches on it. No behavior (notify/render/audit) lives on an event: the
    lifecycle emits *blind* (ADR 0005); "what to do" belongs per-consumer."""

    name: ClassVar[str]


# --- request aggregate ------------------------------------------------------


@dataclass(frozen=True)
class RequestCreated(Event):
    name: ClassVar[str] = "request.created"
    approval_request_id: UUID
    service_name: str
    requester_id: UUID


@dataclass(frozen=True)
class RequestApproved(Event):
    name: ClassVar[str] = "request.approved"
    approval_request_id: UUID
    service_name: str
    requester_id: UUID


@dataclass(frozen=True)
class RequestDenied(Event):
    name: ClassVar[str] = "request.denied"
    approval_request_id: UUID
    service_name: str
    requester_id: UUID


@dataclass(frozen=True)
class RequestCancelled(Event):
    name: ClassVar[str] = "request.cancelled"
    approval_request_id: UUID


@dataclass(frozen=True)
class RequestFrozen(Event):
    """The execution-time integrity re-check (#121) refused an ``approved`` request.

    The snapshotted policy no longer matches the live config or a Vote no longer
    verifies against its frozen key, so the Executor parked the request for manual
    review instead of publishing on tampered state. ``reason`` names the tamper."""

    name: ClassVar[str] = "request.frozen"
    approval_request_id: UUID
    service_name: str
    requester_id: UUID
    reason: str


# --- action aggregate (one-time publish outcome) ----------------------------


@dataclass(frozen=True)
class ActionSucceeded(Event):
    name: ClassVar[str] = "action.succeeded"
    approval_request_id: UUID


@dataclass(frozen=True)
class ActionFailed(Event):
    name: ClassVar[str] = "action.failed"
    approval_request_id: UUID
    reason: str | None


# --- grant aggregate (forward-auth) -----------------------------------------


@dataclass(frozen=True)
class GrantActivated(Event):
    name: ClassVar[str] = "grant.activated"
    grant_id: UUID
    approval_request_id: UUID
    expires_at: datetime


@dataclass(frozen=True)
class GrantExpired(Event):
    name: ClassVar[str] = "grant.expired"
    grant_id: UUID


# --- held artifact (one-time) -----------------------------------------------


@dataclass(frozen=True)
class ArtifactDestroyed(Event):
    name: ClassVar[str] = "artifact.destroyed"
    approval_request_id: UUID
    action_id: str | None
    terminal_state: str


# --- out-of-band publish detection (PUB-2, #124) ----------------------------
# Emitted by the reconciler, not by a lifecycle transition: a release appeared on
# PyPI that the proxy's publish log never approved (complete-mediation violation).
# Carries only identifiers — ``service_name`` lets a consumer resolve the alert
# audience (approvers + admin) from config; the proxy holds no state for the rogue
# release itself, which by definition never touched it.


@dataclass(frozen=True)
class OutOfBandPublishDetected(Event):
    name: ClassVar[str] = "publish.out_of_band_detected"
    service_name: str
    project: str
    version: str


# --- account aggregate (``docs/account-management.md`` §Account Events) ------
# The affected User is the subject; the notification matrix is in
# ``docs/notification-system.md``. ``actor_id`` names the acting admin so the audit
# row attributes *who* changed the roster (#121) — the attribution IDENT-1's
# detection argument leans on; null for a system-initiated action (provisioning).


@dataclass(frozen=True)
class EnrollmentIssued(Event):
    name: ClassVar[str] = "account.enrollment_issued"
    user_id: UUID
    email: str
    actor_id: UUID | None = None


@dataclass(frozen=True)
class CredentialsReset(Event):
    name: ClassVar[str] = "account.credentials_reset"
    user_id: UUID
    email: str
    actor_id: UUID | None = None


@dataclass(frozen=True)
class AccountDeactivated(Event):
    name: ClassVar[str] = "account.deactivated"
    user_id: UUID
    email: str
    actor_id: UUID | None = None


@dataclass(frozen=True)
class AccountDeleted(Event):
    name: ClassVar[str] = "account.deleted"
    user_id: UUID
    email: str
    actor_id: UUID | None = None


class EventBus:
    """The in-process lifecycle event seam (ADR 0005), owned by the application.

    Holds the subscriber registry on the instance — one bus per app, created at app
    construction — so there is no process-global state to clear between tests. The
    seam stays **blind, in-process, and best-effort**: a subscriber that raises is
    logged and swallowed and never blocks a transition.
    """

    def __init__(self) -> None:
        self._subscribers: list[Callable[[Event], None]] = []

    def subscribe(self, handler: Callable[[Event], None]) -> None:
        """Register a handler to receive every emitted event."""
        self._subscribers.append(handler)

    def unsubscribe(self, handler: Callable[[Event], None]) -> None:
        """Remove a previously registered handler (idempotent)."""
        if handler in self._subscribers:
            self._subscribers.remove(handler)

    def emit(self, event: Event) -> None:
        """Deliver ``event`` to every subscriber, best-effort (failures are logged).

        The seam stays blind: the emitting transition's session is bound ambiently at
        the session scope (:func:`active_session`), so emit takes no session argument.
        A subscriber that must read the flushed-but-uncommitted transition borrows that
        session through :func:`deliver_with_session`; emit only fans the event out.
        """
        for handler in list(self._subscribers):
            try:
                handler(event)
            except Exception:
                _log.warning("event subscriber failed for %s", event.name, exc_info=True)
