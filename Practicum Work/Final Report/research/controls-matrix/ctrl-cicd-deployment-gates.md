<!-- LTeX: enabled=false -->
# CI/CD deployment-approval gates (GH environments / GitLab) — row 5

**Axis:** Pipeline **deploy-job** gate (platform-bound)
**Verdicts:** Stolen credential `✓` · Trusted insider `~` · Compromised CI `~` · Direct publish `✗`

Scenario names and verdicts are fixed by [evaluation-plan.md §1, Move 1](../../../../docs/evaluation-plan.md).

## Primary sources
- GitHub Docs, "Managing environments for deployment" (deployment protection rules) — https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments (accessed 2026-07-15) → `gh-environments-deployment`
- GitLab Docs, "Deployment approvals" — https://docs.gitlab.com/ci/environments/deployment_approvals/ (accessed 2026-07-15) → `gitlab-deployment-approvals`
- MITRE ATT&CK, Campaign C0024 "SolarWinds Compromise" — https://attack.mitre.org/campaigns/C0024/ (accessed 2026-07-15) → `mitre-c0024-solarwinds`

## What it actually gates
A CI/CD deployment-approval gate gates **whether a deployment job runs** — the deploy/publish step bound to a named environment inside a build platform (GitHub Actions environments, GitLab protected environments). A job that references the environment blocks until a *separate* required reviewer approves it, and the person who triggered it cannot self-approve. That is the axis: the decision governed is *may this pipeline's deploy job proceed*, on an independent human's approval. Because the gate lives at the deploy step, it sits **inside** the pipeline — unlike the repo-merge gate (row 4), which sits entirely upstream of CI — so it can interpose a human between a compromised *build* stage and the actual publish (hence Compromised CI is `~`, not `✗`). But the gate is **platform-bound**: it fires only for a deploy job on that platform, so a direct registry publish that never opens a pipeline is bypassed in full (`✗`), and its approval is bound to *a deployment*, not to the artifact by hash, so an authentically-built poisoned artifact passes review.

## Documented behavior (anchored)
> A job "that references an environment must follow any protection rules for the environment before running or accessing the environment's secrets." Required reviewers: "Enter up to 6 people or teams." "Only one of the required reviewers needs to approve the job for it to proceed." An operator can "Prevent users from approving workflows runs that they triggered." Administrators can be permitted to skip the gate via "Allow administrators to bypass configured protection rules" (closed by "Disallow bypassing configured protection rules"). A wait timer can "Specify the amount of time to wait before allowing workflow jobs that use this environment to proceed."
— *Managing environments for deployment* (docs.github.com)

> "You can require approvals for deployments to protected environments in a project." "All jobs deploying to the environment are blocked and wait for approvals before running." "By default, the user who triggers a deployment pipeline can't also approve the deployment job." "Add multiple approval rules to control who can approve and execute deployment jobs." "A GitLab administrator can approve or reject all deployments."
— *Deployment approvals* (docs.gitlab.com)

> "APT29 used customized malware to inject malicious code into the SolarWinds Orion software build process that was later distributed through a normal software update." "APT29 was able to get SUNBURST signed by SolarWinds code signing certificates by injecting the malware into the SolarWinds Orion software lifecycle." "APT29 gained initial network access to some victims via a trojanized update of SolarWinds Orion software."
— MITRE ATT&CK, Campaign C0024 (*SolarWinds Compromise*). The malicious code was injected into the **build**, then signed with SolarWinds' own certificates and shipped through the normal update channel — an authentically-built poisoned artifact.

## Per-column analysis

| Scenario | Verdict | Catches / Misses | Source |
|---|:--:|---|---|
| Stolen credential | `✓` | **Catches** the modeled ordinary-credential theft: a stolen maintainer credential can *trigger* the pipeline but cannot cast the **independent** deploy approval — GitHub can "Prevent users from approving workflows runs that they triggered," GitLab defaults to the triggerer being unable to self-approve. ⚠ | `gh-environments-deployment`, `gitlab-deployment-approvals` |
| Trusted insider | `~` | **Catches** the lone insider — an independent required reviewer is forced onto the deploy, so one malicious maintainer cannot unilaterally ship. **Misses** (a) an insider with admin / "bypass configured protection rules," and (b) an insider who skips the pipeline to publish directly. ⚠ | `gh-environments-deployment`, `gitlab-deployment-approvals` |
| Compromised CI | `~` | **Catches** an auto-deploying compromised *build* stage: because the gate sits inside the pipeline at the deploy step, a poisoned artifact from an earlier stage still blocks on an independent human before it can promote to the registry. **Misses** the SolarWinds case — the approval is bound to *a deployment*, not to the artifact hash, so an authentically-built poisoned artifact passes; and a compromise living in the gated deploy runner runs *after* approval with the environment's publish secret. ⚠ | `gh-environments-deployment`, `mitre-c0024-solarwinds` |
| Direct publish | `✗` | The gate is platform-bound: `twine upload` straight to PyPI never starts a gated deploy job, so the gate never fires — the structural weakness shared across the whole D column. | axis argument |

> ⚠ **Caveat (Stolen credential).** `✓` holds for what column A models — theft of an *ordinary* maintainer credential (the Shai-Hulud archetype), which can trigger a pipeline but cannot cast the independent deploy approval. A stolen **admin** credential is a higher, rarer precondition that bypasses by default via "Allow administrators to bypass configured protection rules" — operator-closeable ("Disallow bypassing configured protection rules"), a config edge on a different attack. A stolen *registry publish token* pushed straight to PyPI is column D's archetype, not A's. Edge, not a downgrade of the modeled case.

> ⚠ **Caveat (Trusted insider).** The `~` catches the lone insider but misses the two cases the proxy closes: an insider holding **admin / bypass**, and an insider who **skips the pipeline to publish directly**. Rubber-stamp approval and a colluding quorum are **shared** with the proxy — quorum *raises the bar* (one reviewer → *m* independent, re-authenticated approvals) but does not beat them (the XZ / **CORE-3** limit) — so they are not counted as this row's misses.

> ⚠ **Caveat (Compromised CI).** The gate approves *a deployment*, not *an artifact by hash*. In SolarWinds (CVE-tracked as the SUNBURST campaign), APT29 "inject[ed] malicious code into the SolarWinds Orion software build process," got it "signed by SolarWinds code signing certificates," and it "was later distributed through a normal software update." A deploy reviewer clicking approve inspects neither the built bytes nor a hash, so an authentically-built poisoned artifact of this kind sails through the gate. Separately, if the compromise lives *in* the gated deploy runner, the gate is already satisfied and the malicious code executes with the environment's publish secret.

## How the proxy beats this row
The deploy gate approves *a deployment* on *a platform*, artifact-unbound: a poisoned-but-authentically-built artifact passes an unwitting approver (Compromised CI `~`), and a direct registry publish never opens a gated job at all (Direct publish `✗`). The proxy authorizes at the **publish point**: it holds the **sole** publish credential and binds the **exact artifact by hash** at authorization time. So a SolarWinds-style byte-poisoned artifact fails the execution-time hash re-check even when a human approves, and there is **no platform-bound gate to skip** — the admin-bypass escape and the direct-publish escape both close. Against the insider it raises the bar from one independent reviewer to **m independent, re-authenticated approvals bound to the exact artifact**. It does **not** claim to defeat rubber-stamping, collusion, or a payload engineered to survive review: that is the XZ case, where quorum *raises the bar but is not immunity* (Case Study B, **CORE-3**) — the same limitation this row carries, said once and not overclaimed.
