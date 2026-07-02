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

- [x] ~~**T2** (Batch 7): add `T1` to `related:` — reciprocal of T1's new link (Batch 1 settled: the compromised-approver position's deny/withdraw direction is T2's threat, and T2 is the same-capability sibling of T1).~~ Applied in Batch 7 (T2 `related: [T1, T3, T27, T30]`).
- [x] ~~**T4** (Batch 8): add `T11` to `related:` — reciprocal of T11's new link (Batch 1 settled: the L6 token-holding-proxy variant of payload substitution is disclaimed in T11 and owned by T4 as an accepted MVP limitation).~~ Applied in Batch 8 (T4 `related: [T5, T6, T11, T18]`).
- [x] ~~**T4** (Batch 8): add `T24` to `related:` — reciprocal of T24's new link (Batch 2 settled: T24 reclassified introduced ③, retitled "External Account Recovery Bypass"; T4 is the sibling "direct upstream access bypasses the proxy" — both defeat quorum by reaching PyPI outside the proxy's data path).~~ Applied in Batch 7 (T4 `related: [T5, T6, T11, T18, T24, T30]`).
- **Invariant-vs-instance findings** for your threats (T10, T16, T21, T2, T8, T9, T18) are recorded in REVIEW-PLAN.md § "Invariant-vs-instance pass (2026-07-02)" — read at each batch start, apply at grill time. (If you've already grilled any of these, circle back per the finding.)

## For the top-down session (Batches 1–4)

- [ ] **T1** (finalized in Batch 1 — amend when convenient, or fold into Phase D symmetry pass): add `T14` to `related:` — T14 (Proxy Bypass) is the credential-exclusivity condition T1's improvement rests on; T14's delta prose credits the consolidation improvement to T1/T26, counted once. Optional prose hook: T1's improved-delta story may cite T14 as its completeness condition.
- [x] ~~**T26** (committed with `related: [T1, T5, T11]`): add `T14` — same reciprocal as T1's (machine-credential side of the exclusivity condition).~~ Applied in Batch 2 (T26 `related: [T1, T5, T11, T14, T15]`).
- [x] ~~**T5** (Batch 3): add `T4` to `related:` — host compromise reaches the DB; T4 lists T5.~~ Applied in Batch 3 (T5 `related: [T4, T6, T26, T30]`).
- [x] ~~**T6** (Batch 3): add `T4` to `related:` — same, write direction; T4's body also points at T6 for the stored-public-key caveat.~~ Applied in Batch 2 (T6 `related: [T4, T11, T13]`).
- [x] ~~**T5**: add `T30` to `related:` — T30 (destructive availability, new in Batch 7) rates the availability consequence of the DB capability rungs; T30 lists T5.~~ Applied in Batch 3 (T5 `related: [T4, T6, T26, T30]`).
- [x] ~~**T6**: add `T30` to `related:` — same; L5 (DB write) is T30's cheapest enabling rung.~~ Applied in Batch 3 (T6 `related: [T4, T5, T11, T13, T28, T30]`).
- [x] ~~**T28** (Batch 4, when created): add `T30` to `related:` — integrity twin (T30 owns "capability lost," T28 owns "history erased"; shared offsite/WORM defense family).~~ Applied in Batch 3. **T28 created as `T28-database-repudiation-attack.md`** (in Batch 3, not Batch 4) with `related: [T6, T13, T30]`. T30 already lists T28, so the reciprocal holds — but T30's body still references T28 by **ID only** (the filename didn't exist when T30 was written); the file exists now, so the Phase D sweep can turn that prose mention into a link.

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

## Cross-cutting notes (bottom-up session, Batch 7 · 2026-07-02)

- **#126 filed** (upload size + artifact-count caps): T27's storage-exhaustion leg had no
  issue; deliberately split from #32 (upload-edge validation vs. rate limiting). T27's
  promotion is per leg: #32 → flooding legs, #126 → storage leg.
- **T30 created** (`T30-destructive-availability-attack.md`, provisional ID per X6):
  DoS · T1485/T1531/T1490 · [L5, L6, L8] · introduced ③ medium/low, fails safe. No Planned
  defenses section — backups/restore/ACLs are operator territory by nature, no issue
  invented.
- **T2 grill outcome:** the "rate limiting on denials / anomaly detection" planned defense
  was **dropped** — deny-path throttling contradicts T25's settled never-throttle-deny
  design, and a denial spike is indistinguishable from the defense working (one malicious
  requester, one diligent approver). Demoted to alert-only operator monitoring. T2/T3 now
  both carry the single-approver-availability-veto invariant (instance split: loud/signed
  vs. traceless), per the invariant-vs-instance soft note.
- **T18 circle-back applied** (invariant-vs-instance): one-paragraph scope generalization
  added to T18 (any upstream code entering the TCB — base image, build/CI toolchain,
  install source), committed with Batch 7.
