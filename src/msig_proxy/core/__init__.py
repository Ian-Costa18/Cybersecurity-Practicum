"""Shared schema and infrastructure owned by no slice (see docs/source-layout.md).

``core`` holds the cross-slice essentials — models, db, config, the events seam,
crypto. Per the dependency rule, ``core`` imports no slice; slices import ``core``.
"""
