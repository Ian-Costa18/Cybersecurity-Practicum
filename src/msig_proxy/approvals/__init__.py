"""Approval slice (see docs/source-layout.md).

Votes an Approval Request to a terminal outcome, type-agnostically: the /approve
routes, the waiting room + SSE, the eligibility+quorum snapshot, and the vote-read
seam — intent-named, request-keyed reads (tally, effective decisions, Endorsing
Approvers, the snapshot approver set) that own the fetch-then-reduce so no caller
recomposes it by hand.
"""
