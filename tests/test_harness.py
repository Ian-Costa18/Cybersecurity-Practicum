"""The two non-DB boundaries behave as the spec mandates.

* SMTP is *real* and in-process (aiosmtpd): mail actually leaves the app and is
  received. This is the boundary the suite deliberately does NOT mock.
* PyPI is the *one* mocked boundary: an httpx POST to ``upload.pypi.org`` is
  intercepted by respx, and the captured request is the assertion oracle.
"""

from __future__ import annotations

from email.message import EmailMessage

import aiosmtplib
import httpx
import respx

from tests.support import PYPI_UPLOAD_URL, SmtpProbe, envelope_as_message


async def test_in_process_smtp_receives_real_mail(smtp_server: SmtpProbe) -> None:
    message = EmailMessage()
    message["From"] = "proxy@example.com"
    message["To"] = "approver@example.com"
    message["Subject"] = "Approval requested"
    message.set_content("Please review request #1.")

    await aiosmtplib.send(message, hostname=smtp_server.host, port=smtp_server.port)

    assert len(smtp_server.messages) == 1
    received = envelope_as_message(smtp_server.messages[0])
    assert received["Subject"] == "Approval requested"
    assert "review request #1" in received.get_content()


async def test_pypi_boundary_is_mocked(mock_pypi: respx.MockRouter) -> None:
    async with httpx.AsyncClient() as client:
        response = await client.post(PYPI_UPLOAD_URL, content=b"package-bytes")

    assert response.status_code == 200
    route = mock_pypi["pypi_upload"]
    assert route.called
    assert route.calls.last.request.content == b"package-bytes"
