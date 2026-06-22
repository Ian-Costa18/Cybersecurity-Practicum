"""Service-type slice: everything that DIVERGES by service type (see docs/source-layout.md).

Holds the type-blind ``dispatch`` seam and the per-type verticals ``one_time`` and
``forward_auth``, each owning that type's behavior across the whole request lifetime.
"""
