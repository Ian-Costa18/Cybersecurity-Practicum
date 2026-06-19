# Clear one `ready-for-agent` issue, end-to-end

Clear a single `ready-for-agent` issue and leave it ready for human review.

1. **Pick.** `gh issue list --label ready-for-agent --state open`. Choose ONE
   (smallest / most self-contained if unsure). If none are open, stop and say so.
2. **Branch off the integration branch:**
   - `git checkout progress-report-3 && git pull --ff-only`
   - `git checkout -b phase<phase>-<issue#>-<slug>`
3. **Implement** with `/implement`, working from that issue's body. Run typecheck
   + single test files as you go; the full test suite must pass before you open a PR.
4. **Open the PR INTO `progress-report-3`** (never `main`):
   - push the branch, then
   - `gh pr create --base progress-report-3 --body "Closes #<issue#> ..."`
   - The `Closes #<issue#>` line is what links the PR to the issue.
5. **Mark the PR ready:** `gh pr ready <pr#>` (it must not be a draft).
6. **Relabel the issue:** remove `ready-for-agent`, add `ready-for-human`:
   - `gh issue edit <issue#> --remove-label ready-for-agent --add-label ready-for-human`
7. **Do NOT merge, and do NOT close the issue** — that's the human's call after review.
   Report the issue #, branch name, and PR URL.

## Notes
- One issue per run: each iteration = one reviewable PR.
- Step 2 always branches off fresh `progress-report-3`, so runs produce independent
  PRs (not a chain). Two issues touching the same file can conflict at merge — fine
  for a disjoint backlog, just be aware.
