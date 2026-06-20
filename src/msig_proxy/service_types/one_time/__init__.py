"""One-time service vertical (e.g. PyPI): submit-then-publish.

Owns inbound upload, intake + artifact staging, hash re-verification + publish,
artifact destruction, and its Service Handler. The held artifact lives here.
"""
