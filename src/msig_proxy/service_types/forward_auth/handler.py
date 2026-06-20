"""The forward-auth Service Handler: terminal handling for an interactive-access request.

Approval issues a Service Grant; denial has nothing to clean up (a forward-auth
service stages no artifact). Grant issuance and resolution are siblings in this
slice (``grant``/``resolve``); this file is only the terminal contract the dispatcher
reaches without knowing the type.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import ApprovalRequest
from msig_proxy.service_types.dispatch import ServiceHandler
from msig_proxy.service_types.forward_auth import grant


class ForwardAuthServiceHandler(ServiceHandler):
    """Forward-auth: approval issues a Service Grant; denial has nothing to clean up
    (a forward-auth service stages no artifact)."""

    def on_approved(self, session: Session, config: AppConfig, request: ApprovalRequest) -> None:
        grant.issue_service_grant(session, config, request)

    def on_denied(self, session: Session, config: AppConfig, request: ApprovalRequest) -> None:
        # Nothing to undo: no artifact is staged for a forward-auth request.
        return
