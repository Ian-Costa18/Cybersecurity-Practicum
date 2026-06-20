"""Notifications slice (see docs/source-layout.md).

A best-effort event subscriber (ADR 0005): consume lifecycle events, render and
deliver them. ``notifier`` renders + sends; ``subscriber`` wires the event seam.
"""
