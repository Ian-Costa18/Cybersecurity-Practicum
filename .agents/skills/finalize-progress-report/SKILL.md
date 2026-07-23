---
name: finalize-progress-report
description: Close out a progress-report milestone — verify the report's GitHub links resolve, then advance the protected main by merging the current progress-report-N integration branch through a pull request (merge commit, branch preserved), and open the next progress-report-(N+1) branch.
disable-model-invocation: true
---

# Finalize a progress report

Run this at a progress-report milestone, when the report is ready to submit. It advances `main` to the work accumulated on the current integration branch through a pull request, then starts the next one.

Two rules define this skill:

- **`main` advances only through a PR.** `main` is a protected branch: it refuses direct pushes (`GH006: Protected branch update failed`) and takes changes only via a merged pull request. The finalize PR's head is the integration branch itself — `progress-report-N`, already on the remote — and its base is `main`. Merge it with a **merge commit**, not squash and not rebase, so `progress-report-N` stays a real ancestor of `main` and its commits live in `main`'s history.
- **The integration branch is preserved.** `progress-report-N` must survive the merge untouched on local and remote — the submitted report's links are rooted at `blob/progress-report-N`, so they 404 the moment the branch disappears. Before merging, confirm GitHub's *auto-delete head branches* setting is off (step 3); after merging, never delete the branch.

Because the PR does a three-way merge, this flow self-heals divergence: if `main` picked up commits out-of-band (e.g. a Dependabot PR merged straight into `main`), the finalize PR's merge commit absorbs them — no local merge or rebase needed.

Guardrails: a local hook blocks `git reset --hard`, `git push --force`, `git branch -D`, `git clean -f`, and friends, and by convention the agent **hands every `git push` and the PR merge itself to the user**. Never force-push or hard-reset a progress-report branch.

## Steps

1. **Pin down N.** The integration branch is `progress-report-N` (the branch you're on, or the highest-numbered one); N also matches the report being submitted (`Progress Report N.tex`, `\PRNumber` N). State which N you are finalizing and that the next branch will be `progress-report-(N+1)`; the rest of the run uses those numbers.

2. **Verify the report's links resolve.** Every link in `Progress Report N.tex` is rooted at `blob/progress-report-N` through the `\RepoURL`/`\DiffURL` macros, so each one 404s unless its target is committed on that branch. Check, on `progress-report-N`:
   - `\PRNumber` equals N. A stale number repoints *every* link — and the diff URL — at the wrong branch.
   - Every `\href` target exists in the branch tip. Grep `\href` in the tex; for each `\RepoURL/<path>` (decode `\%20` → space), run `git cat-file -e "progress-report-N:<path>"`. The `\DiffURL` PDF (`Practicum Work/Progress Reports/diffs/diff_PR{N-1}_PR{N}.pdf`) is the usual culprit — it is often still untracked.

   _Completion: every `\href` target resolves to a path committed on `progress-report-N`._ For any miss, commit the file to `progress-report-N` (or fix the path / `\PRNumber`) before continuing — and note that a new commit here means the branch is no longer "unchanged on the remote," so it must be pushed in step 7.

3. **Make sure the merge won't delete the branch.** The finalize PR's head *is* `progress-report-N`, so GitHub's repo-level *auto-delete head branches* would delete the submitted report's branch on merge. Check it, and turn it off if needed:
   ```
   gh repo view <owner>/<repo> --json deleteBranchOnMerge
   gh repo edit <owner>/<repo> --delete-branch-on-merge=false   # only if it was true
   ```
   _Completion: `deleteBranchOnMerge` is `false`._ This is repo-wide, so per-issue feature branches also stop auto-deleting on merge — clean those up by hand. (The more surgical alternative, a branch-protection rule that forbids deleting `progress-report-*`, is more setup; turning the repo setting off is the simple durable fix, and every `progress-report-N` must live forever anyway.)

4. **Open the finalize PR.** `progress-report-N` is already on the remote, so no push is needed to open it:
   ```
   gh pr create --base main --head progress-report-N \
     --title "Finalize Progress Report N" --body-file <file>
   ```
   (A hook requires `--body-file`; an inline `--body` is blocked.) If `main` took out-of-band commits, `git log --oneline progress-report-N..origin/main` lists them — you do **not** reconcile locally; the merge commit does. Confirm the PR is mergeable (`gh pr view <#> --json mergeable`); only if GitHub reports a conflict do you resolve it, keeping the trivial/shared resolution. _Completion: the finalize PR is open and mergeable._

5. **Open the next integration branch.** Cut it from the current integration tip, **not** `main` (which does not move until the PR merges): `git checkout -b progress-report-(N+1) progress-report-N`. It will not descend from `main`'s post-merge tip, and that is fine — any out-of-band delta on `main` reconciles at the next milestone's PR merge. This is the base for future feature branches and their PRs (`git checkout -b <issue#>-<slug>`, `gh pr create --base progress-report-(N+1)`).

6. **Scaffold the next report document.** Still on `progress-report-(N+1)`, seed the next report from the one just finalized so the branch starts with a working draft:
   - Copy `Progress Report N.tex` → `Progress Report (N+1).tex`.
   - In the copy, bump the two per-report macros: `\PRNumber` → N+1 (this alone repoints every `\RepoURL` link to `progress-report-(N+1)`) and `\DiffURL` → `.../diffs/diff_PR{N}_PR{N+1}.pdf`. Leave the body identical — it is the starting draft the author edits through the milestone, not a fresh blank.
   - Leave `Progress Report N Notes.md` alone; each report gets fresh notes, not a copy of the last one's.
   - Commit the copy on `progress-report-(N+1)` (e.g. `git commit -m "chore(report): scaffold Progress Report (N+1) from PR N"`) so the push in step 7 carries it to the remote. _Completion: `Progress Report (N+1).tex` exists with `\PRNumber` N+1 and the `diff_PR{N}_PR{N+1}.pdf` diff URL, committed on the new branch._ The diff PDF itself does not exist yet — that is expected; it gets created and committed at the next finalize (step 2's usual culprit).

7. **Hand off.** Output for the user to run / do — the agent pushes nothing and merges nothing here:
   - Push the new branch and its scaffold: `git push -u origin progress-report-(N+1)`.
   - Merge the finalize PR **with a merge commit** (GitHub's "Create a merge commit" option, not squash or rebase), and **keep** the branch — do not delete `progress-report-N`.
   - After the merge, fast-forward local `main` onto the updated remote: `git fetch origin && git checkout main && git merge --ff-only origin/main`.
   - If step 2 added a commit to `progress-report-N`, also `git push origin progress-report-N`, or the report's links stay broken on the remote.

## Note

Finalizing does not gate on the grading-software upload: the report PDF is already committed on `progress-report-N`, so opening or merging the PR has no bearing on the submission. Run this whenever. If you'd rather not advance `main` until after the upload, open the PR but hold the merge.
