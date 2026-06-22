"""Auth slice (see docs/source-layout.md).

Prove who you are, and enforce it per route: login/logout, the session and admin
guards, and credential + Proxy Session logic. The framework-free verifiers live in
``credentials``; the web-edge guards (the FastAPI-wired checks) live in ``guards``.
"""
