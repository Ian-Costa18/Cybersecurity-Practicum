<!--
TEMPORARY WORKING DOC — cross-session handoff for the Phase C parallel split (#107).
The top-down session owns Batches 1–4; the bottom-up session owns Batches 8–5 (see
REVIEW-PLAN.md § Phase C conventions → "Parallel sessions"). Entries here are edits one
session needs made in the OTHER session's files. Check this file at every batch start;
tick + strike an entry when applied; delete the file alongside REVIEW-PLAN.md when the
deep-dive closes.
-->

# Phase C cross-session handoff

## For the bottom-up session (Batches 8–5)

- [ ] **T2** (Batch 7): add `T1` to `related:` — reciprocal of T1's new link (Batch 1 settled: the compromised-approver position's deny/withdraw direction is T2's threat, and T2 is the same-capability sibling of T1).
- [x] ~~**T4** (Batch 8): add `T11` to `related:` — reciprocal of T11's new link (Batch 1 settled: the L6 token-holding-proxy variant of payload substitution is disclaimed in T11 and owned by T4 as an accepted MVP limitation).~~ Applied in Batch 8 (T4 `related: [T5, T6, T11, T18]`).

## For the top-down session (Batches 1–4)

- [ ] **T1** (finalized in Batch 1 — amend when convenient, or fold into Phase D symmetry pass): add `T14` to `related:` — T14 (Proxy Bypass) is the credential-exclusivity condition T1's improvement rests on; T14's delta prose credits the consolidation improvement to T1/T26, counted once. Optional prose hook: T1's improved-delta story may cite T14 as its completeness condition.
- [ ] **T26** (committed with `related: [T1, T5, T11]`): add `T14` — same reciprocal as T1's (machine-credential side of the exclusivity condition).
- [ ] **T5** (Batch 3): add `T4` to `related:` — host compromise reaches the DB; T4 lists T5.
- [ ] **T6** (Batch 3): add `T4` to `related:` — same, write direction; T4's body also points at T6 for the stored-public-key caveat.

## Cross-cutting notes (bottom-up session, Batch 8 · 2026-07-02)

- **uv.lock pin count is 549, not 557.** The prep note's 557 predates the uv-audit lockfile
  changes; T18 cites 549 (verified `hash = "sha256:` count). Don't cite 557 anywhere.
- **Dependabot vulnerability alerts were DISABLED on the repo — now enabled** (grill
  decision, `gh api -X PUT …/vulnerability-alerts`, verified). T18 cites them as a current
  defense.
- **T14 grill outcome:** delta challenged and **kept `introduced`** — the double-counting
  argument (consolidation improvement counted once under T1/T26) is written into T14's
  delta prose. `likelihood_residual: medium` is a justified deviation from the L2 default.
  File renamed `T14-network-path-bypass.md` → `T14-proxy-bypass.md` (git mv; repo-wide
  reference sweep remains Phase D).
