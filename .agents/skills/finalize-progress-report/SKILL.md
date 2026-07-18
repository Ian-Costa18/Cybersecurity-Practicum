---
name: finalize-progress-report
description: Close out a progress-report milestone — verify the report's GitHub links resolve, fast-forward the current progress-report-N integration branch into main (local merge, no PR, branch kept), and open the next progress-report-(N+1) branch off main.
disable-model-invocation: true
---

# Finalize a progress report

Run this at a progress-report milestone, when the report is ready to submit. It moves `main` up to the work accumulated on the current integration branch, then starts the next one.

Two rules define this skill:

- **Fast-forward only.** The history here is linear: each `progress-report-N` branch's tip *becomes* `main` with no merge commit, and the branch is kept pointing at that same commit (today `main` and `progress-report-2` are one commit). Use `git merge --ff-only`. If the fast-forward is refused, **stop** — never create a merge commit, never force.
- **No PR.** Merging locally sidesteps GitHub's auto-delete-head-branch setting, so the finished branch survives untouched on local and remote. That preservation is the whole reason to avoid a PR.

The `git push` commands are **handed to the user** — a guardrails hook blocks the agent from pushing.

## Steps

1. **Pin down N.** The integration branch is `progress-report-N` (the branch you're on, or the highest-numbered one); N also matches the report being submitted (`Progress Report N.tex`, `\PRNumber` N). State which N you are finalizing and that the next branch will be `progress-report-(N+1)`; the rest of the run uses those numbers.

2. **Verify the report's links resolve.** Every link in `Progress Report N.tex` is rooted at `blob/progress-report-N` through the `\RepoURL`/`\DiffURL` macros, so each one 404s unless its target is committed on that branch. Check, on `progress-report-N`:
   - `\PRNumber` equals N. A stale number repoints *every* link — and the diff URL — at the wrong branch.
   - Every `\href` target exists in the branch tip. Grep `\href` in the tex; for each `\RepoURL/<path>` (decode `\%20` → space), run `git cat-file -e "progress-report-N:<path>"`. The `\DiffURL` PDF (`Practicum Work/Progress Reports/diffs/diff_PR{N-1}_PR{N}.pdf`) is the usual culprit — it is often still untracked.

   _Completion: every `\href` target resolves to a path committed on `progress-report-N`._ For any miss, commit the file to `progress-report-N` (or fix the path / `\PRNumber`) before continuing — and note that a new commit here means the branch is no longer "unchanged on the remote," so it must be pushed in step 6.

3. **Confirm a clean fast-forward is possible.** Run `git status -sb` (tree must be clean) and `git log --oneline progress-report-N..main`. _Completion: that log is empty_ — `main` holds nothing the integration branch lacks. If it prints any commit, **stop** and surface them: `main` has diverged and `--ff-only` will refuse; ask how to proceed rather than merging.

4. **Fast-forward main.** `git checkout main && git merge --ff-only progress-report-N`. _Completion: `git rev-parse main` equals `git rev-parse progress-report-N`._

5. **Open the next integration branch.** `git checkout -b progress-report-(N+1) main`. This leaves you on the new branch — the base for future feature branches and their PRs (`git checkout -b <issue#>-<slug>`, `gh pr create --base progress-report-(N+1)`).

6. **Hand off the push.** Output these for the user to run; the guardrails hook blocks the agent from running them:

   ```
   git push origin main
   git push -u origin progress-report-(N+1)
   ```

   `progress-report-N` is already on the remote — nothing to push for it, and nothing gets deleted — **unless step 2 added a commit to it**, in which case also hand off `git push origin progress-report-N`, or the report's links stay broken on the remote.

## Note

The merge does not gate on the grading-software upload: the report PDF is already committed, so finalizing the branch has no bearing on the submission. Run this whenever. If you'd rather not advance remote `main` until after the upload, just hold back the `git push origin main` line.
