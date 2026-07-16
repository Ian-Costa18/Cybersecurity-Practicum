<!-- LTeX: enabled=false -->
# GitHub required reviews + branch protection / commit signing — row 4

**Axis:** Code-repo **merge** decision
**Verdicts:** Stolen credential `✓` · Trusted insider `~` · Compromised CI `✗` · Direct publish `✗`

Scenario names and verdicts are fixed by [evaluation-plan.md §1, Move 1](../../../../docs/evaluation-plan.md).

## Primary sources
- GitHub Docs, "About protected branches" — https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches (accessed 2026-07-15) → `gh-about-protected-branches`
- GitHub Docs, "Approving a pull request with required reviews" — https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/approving-a-pull-request-with-required-reviews (accessed 2026-07-15) → `gh-approving-pr-required-reviews`
- GitHub Docs, "About commit signature verification" — https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification (accessed 2026-07-15) → `gh-commit-signature-verification`
- A. Freund, "backdoor in upstream xz/liblzma leading to ssh server compromise" (oss-security), CVE-2024-3094 — https://www.openwall.com/lists/oss-security/2024/03/29/4 (accessed 2026-07-15) → `openwall-xz-backdoor`

## What it actually gates
Branch protection plus required reviews gates **the merge of a pull request into a protected branch of the code repository** — and, with required signed commits, gates *which commits may land* there. It governs the repo's *merge* decision: whether proposed code may enter the protected branch, and on whose approval. It does **not** touch anything downstream of merge — build, CI, or the registry publish — so the two `✗` cells fall straight out of the axis: a compromised CI pipeline runs *after* the merge the gate protects, and a direct registry publish never opens a pull request at all. The control's own scenario for column A is scoped by the spec to an **ordinary contributor/maintainer credential** (the Shai-Hulud archetype), which the merge gate genuinely defeats; the stolen *registry publishing token* going straight to the registry is a distinct archetype, scored in column D.

## Documented behavior (anchored)
> "You can enforce certain workflows or requirements before a collaborator can push changes to a branch in your repository, including merging a pull request into the branch." "Repository administrators or custom roles with the 'edit repository rules' permission can require that all pull requests receive a specific number of approving reviews before someone merges the pull request into a protected branch." "If you enable required reviews, collaborators can only push changes to a protected branch via a pull request that is approved by the required number of reviewers." "By default, the restrictions of a branch protection rule don't apply to people with admin permissions to the repository or custom roles with the 'bypass branch protections' permission." "People and apps with admin permissions to a repository are always able to push to a protected branch."
— *About protected branches* (docs.github.com)

> Required reviews require "a specific number of approving reviews from people with write or admin permissions in the repository before they can be merged." "Pull request authors cannot approve their own pull requests."
— *Approving a pull request with required reviews* (docs.github.com)

> Commit signing lets "other people … be confident that the changes come from a trusted source"; a commit is labelled **Verified** only when "the signature was successfully verified," and an operator can "enforce required commit signing on a branch to block all commits that are not signed and verified."
— *About commit signature verification* (docs.github.com)

> "The upstream xz repository and the xz tarballs have been backdoored." "Given the activity over several weeks, the committer is either directly involved or there was some quite severe compromise of their system." The exploit code was carried "obfuscated in repository test files (`bad-3-corrupt_lzma2.xz` and `good-large_compressed.lzma`)."
— A. Freund, oss-security disclosure of CVE-2024-3094 (2024-03-29). The backdoor was landed through the project's normal contribution flow by a trusted committer.

## Per-column analysis

| Scenario | Verdict | Catches / Misses | Source |
|---|:--:|---|---|
| Stolen credential | `✓` | **Catches** the modeled ordinary contributor-credential theft: a stolen dev credential can push to a PR branch but cannot *land* on the protected branch — merge needs an approving review from a **different** account (GitHub forbids self-approval), and unsigned commits are rejected where signing is required. ⚠ | `gh-about-protected-branches`, `gh-approving-pr-required-reviews`, `gh-commit-signature-verification` |
| Trusted insider | `~` | **Catches** the lone non-admin insider — required reviews force a second, independent approver, so a single malicious maintainer cannot unilaterally land code. **Misses** (a) an insider holding admin / "bypass branch protections," and (b) an insider who skips the PR flow and publishes directly. ⚠ | `gh-about-protected-branches`, `openwall-xz-backdoor` |
| Compromised CI | `✗` | The subverted pipeline runs *after* merge (build/publish); the merge gate is upstream of it and never sees the injected artifact. | axis argument |
| Direct publish | `✗` | A straight-to-registry publish never opens a pull request, so the merge gate is bypassed in full — the structural weakness shared across the whole D column. | axis argument |

> ⚠ **Caveat (Stolen credential).** `✓` holds for the scenario column A models — theft of an **ordinary contributor/maintainer credential** (the Shai-Hulud archetype). A stolen **admin** credential is a higher precondition and bypasses by default: "the restrictions of a branch protection rule don't apply to people with admin permissions." That exemption is operator-closeable ("Do not allow bypassing the above settings" / "Include administrators"), so it is a config edge on a different, rarer attack — a caveat, not a downgrade of the modeled case.

> ⚠ **Caveat (Trusted insider).** The `~` catches the lone non-admin insider but misses the two cases the proxy closes: an insider with admin/bypass, and an insider who skips the PR flow to publish directly. Collusion, rubber-stamp approval, and payloads engineered to survive review — the XZ pattern, malicious bytes hidden in binary test fixtures (`bad-3-corrupt_lzma2.xz`) no reviewer decodes — are **shared** with the proxy: quorum *raises the bar* (one approver → *m* independent approvals) but does not beat them.

## How the proxy beats this row
Branch protection gates the **repo merge**, which sits off the registry-publish path: it exempts admins by default and is bypassed in full by a direct publish (hence `✗` on both Compromised-CI and Direct-publish). The proxy operates at **authorization time, at the publish point**: it holds the sole publish credential and binds the exact artifact by hash, so there is **no bypass exemption and no gate to skip** — the admin escape and the direct-publish escape both close. Against the insider it raises the bar from one independent reviewer to **m independent, re-authenticated approvals bound to the exact artifact**. It does **not** claim to defeat an obfuscated payload engineered to survive review: that is the XZ case, where quorum *raises the bar but is not immunity* (Case Study B) — the same limitation this row carries, said once and not overclaimed.
