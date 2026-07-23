---
bucket: P1
title: Multi-party approval as an industry primitive (platform-siloed)
report_home:
  - "§4 — Move 3: industry adoption trend that reinforces the gap"
proxy_grounding:
  - docs/adr/0001-credential-backed-approval.md
  - docs/evaluation-plan.md   # §1 Move 3
related_notes:
  - method-evaluation-frameworks.md
  - ../controls-matrix/ctrl-the-proxy.md
bib_keys: [aws-mpa, aws-backup-mpa, google-cloud-pam, google-workspace-mpa, azure-pim-approval, azure-backup-mua, intune-maa]
status: vetted
---

## Why the report needs this

**Synthesis.** The Intro thesis is that m-of-n human authorization is an *under-used general
primitive*. §4 Move 3 discharges the "under-used" half with evidence: the primitive is real and
being adopted by the largest platforms — **and every adoption is a narrow, product-locked bolt-on
welded to one platform's own control plane.** The strongest form of the argument is not "nobody
does this" (false, and a reviewer would catch it) but "**all three hyperscalers do it, and even
between them it is a scattering of one-off, product-specific features — none general, none reaching
the registry-publish point.**" That scattered, siloed adoption is *exactly* what "under-used"
looks like in practice, and it reinforces the gap the proxy fills rather than closing it.

Two sub-points make it land: (1) where a *general* privileged-access product exists (Azure PIM),
it does not even support a **quorum** — the first approver resolves the request, so it is 1-of-n,
not m-of-n; (2) the one use case where two independent clouds *converged* on multi-party approval
is **protecting their own backup vaults** (AWS Backup MPA ≈ Azure Backup MUA) — which only
underlines how bounded each implementation is.

## Sources (vetted this session)

- AWS, *What is Multi-party approval?* — https://docs.aws.amazon.com/mpa/latest/userguide/what-is.html
  (accessed 2026-07-18) → `aws-mpa` · the general AWS MPA capability; its Requester/Administrator/
  Approver model; the **two** services it now gates (Backup + Payment Cryptography) · [primary]
- AWS, *AWS Backup launches Multi-party approval support for logically air-gapped vaults*, Jun 17
  2025 — https://aws.amazon.com/about-aws/whats-new/2025/06/aws-backup-multi-party-approval-logically-air-gapped-vaults/
  (accessed 2026-07-18) → `aws-backup-mpa` · dates the launch; the air-gapped-vault use case · [primary]
- Google Cloud, *Privileged Access Manager overview* — https://docs.cloud.google.com/iam/docs/pam-overview
  (accessed 2026-07-18) → `google-cloud-pam` · a second hyperscaler; multi-level, multi-approver
  gating of privileged IAM grants · [primary]
- Google Workspace, *Multi-party approval for sensitive actions* —
  https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions
  (accessed 2026-07-18) → `google-workspace-mpa` · MPA over sensitive admin-console settings ·
  [primary]
- Microsoft, *Approve requests for Azure resource roles in PIM* —
  https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-approval-workflow
  (accessed 2026-07-18) → `azure-pim-approval` · the general PAM tool — **first approver resolves,
  no quorum** · [primary]
- Microsoft, *Configure Multi-user authorization using Resource Guard — Azure Backup* —
  https://learn.microsoft.com/en-us/azure/backup/multi-user-authorization (accessed 2026-07-18) →
  `azure-backup-mua` · Azure's backup-vault second-person gate — the direct parallel to AWS Backup
  MPA · [primary]
- Microsoft, *Use Multi Admin Approval in Intune* —
  https://learn.microsoft.com/en-us/intune/fundamentals/role-based-access-control/multi-admin-approval
  (accessed 2026-07-18) → `intune-maa` · a third Azure silo — dual-control over Intune device-mgmt
  changes · [primary]

## Key facts (anchored)

### AWS — multi-party approval is a general capability of AWS Organizations, siloed to AWS operations
> "Multi-party approval is a capability of AWS Organizations that allows you to protect a
> predefined list of operations through a distributed approval process. Use Multi-party approval to
> establish approval workflows and transform security processes into team-based decisions."
— AWS, *What is Multi-party approval?*, "What is Multi-party approval?"

> "Multi-party approval requires AWS Organizations and AWS IAM Identity Center."
— AWS, *What is Multi-party approval?*, "Required services"

Backs the "adopted as a primitive" claim; the "Required services" line is the *siloed* anchor — it
only functions inside AWS's own Organizations / Identity-Center plane, over a *predefined list* of
AWS operations.

### AWS — already expanded beyond Backup to a second service (root-of-trust key imports)
> "You can use Multi-party approval to protect the import of root certificate public keys… Requiring
> multi-party approval for this operation helps ensure that no single individual can unilaterally
> establish or change the root of trust for your AWS Payment Cryptography keys."
— AWS, *What is Multi-party approval?*, "What operations are currently supported"

Backs the *growing* half of the trend: two AWS services now (Backup + Payment Cryptography),
which [evaluation-plan.md](../../../../docs/evaluation-plan.md) §1 Move 3 states. The quoted
phrase ("no single individual can unilaterally…") is also the cleanest external statement of the
proxy's own value proposition.

### AWS — recent (June 2025); the incumbent accepts the latency trade-off the proxy also makes
> "AWS Backup launches Multi-party approval support for logically air-gapped vaults" · "Posted on:
> Jun 17, 2025"
— AWS, *AWS Backup launches Multi-party approval…*

> [Not the best choice] "For operations that require immediate execution without delay"
— AWS, *What is Multi-party approval?*, "When Multi-party approval might not be the best choice"

Anchors "2025 / live territory," and corroborates the proxy's "enforced friction = time to think"
design property (eval-plan §2): the incumbent agrees the primitive is for high-consequence,
non-urgent actions and accepts the delay.

### Google — a second hyperscaler, again siloed to its own IAM plane
> "Privileged Access Manager administrators can mandate more than one approval level per entitlement,
> allowing up to two levels of sequential approvals for each entitlement. Administrators can mandate
> up to five approvals per level."
— Google Cloud, *Privileged Access Manager overview*

> "Privileged Access Manager supports creating entitlements and requesting grants for projects,
> folders, and organizations."
— Google Cloud, *Privileged Access Manager overview*

Turns the trend from one vendor into a genuine cross-industry pattern. Same siloing: it gates
temporary grants of **Google Cloud IAM roles** on Google Cloud resources.

### Google — the same primitive again in Workspace, over admin-console settings
> "When multi-party approval is on, a second administrator must approve changes to sensitive
> settings."
— Google Workspace, *Multi-party approval for sensitive actions*, "Definition"

> "You can use multi-party approval for certain security, Google Groups, Domains, Google Calendar,
> and Google Vault settings."
— Google Workspace, *Multi-party approval for sensitive actions*, "Scope"

A same-vendor, different-product silo: the primitive keeps reappearing, always bounded to one
product's surface.

### Azure — the general PAM product (PIM) does NOT support a quorum (1-of-n, not m-of-n)
> "Requests are resolved by the first approver who approves or denies."
— Microsoft, *Approve requests for Azure resource roles in PIM*, "Workflow notifications"

**Load-bearing.** Azure PIM lets you *list* several approvers, but the request completes the moment
**one** of them acts — there is no m-of-n quorum and no multi-step requirement. So the one
general-purpose privileged-access approval product among the three clouds is not even a
*multi-party* control in the quorum sense the thesis means. This is the sharpest single data point
for "under-used": the general tool exists and still stops short of m-of-n.

### Azure — has multi-party approval, but only as product-specific silos (Backup, Intune)
> "This article describes how to configure Multi-User Authorization (MUA) for Azure Backup to
> enhance the security of critical operations on Recovery Services vaults."
— Microsoft, *Configure Multi-user authorization using Resource Guard — Azure Backup*

> "use Microsoft Intune access policies to require that a second administrative account approves a
> change before the change is applied. This capability is known as Multi Admin Approval."
— Microsoft, *Use Multi Admin Approval in Intune*

> "An administrator can't approve their own requests… A different administrator must approve the
> request."
— Microsoft, *Use Multi Admin Approval in Intune*, "Role 3: Change requestor" note

Azure *does* have real second-person authorization — but only bolted onto **Backup vaults** (MUA
via a cross-tenant Resource Guard) and **Intune** device management (MAA, dual-control over apps,
scripts, device actions). Neither is a general capability; each is welded to one product. And the
Backup case is the **same use case AWS chose** — two clouds independently reached for multi-party
approval in precisely one place: guarding their own backup vaults.

## The pattern (synthesis — the one honest point)

Line up the evidence and the "under-used" thesis is on the page, not asserted:

| Platform | Multi-party feature | m-of-n quorum? | Bound to |
|---|---|---|---|
| AWS | Multi-party approval | yes | AWS operations (Backup, Payment Cryptography) |
| Google Cloud | Privileged Access Manager | yes (≤5/level, ≤2 levels) | Google Cloud IAM grants |
| Google Workspace | MPA for sensitive actions | 2-person | Workspace admin settings |
| Azure | PIM approval | **no** (first approver wins) | Azure resource-role activation |
| Azure | Backup MUA / Intune MAA | 2-person | Backup vaults / Intune configs |

All three giants have reached for the primitive; not one offers it as a general, cross-platform
capability, and the single general privileged-access product (Azure PIM) stops short of a quorum.
Every implementation is fused to the platform that ships it and gates *that platform's own*
operations. **None can authorize "publish version X of package Y to PyPI/npm, bound to this exact
artifact hash."** The registry-publish point sits between platforms, owned by none of them — and
the adoption pattern (scattered, product-locked, accelerating but never general) is the strongest
evidence that m-of-n human authorization is an under-used general primitive. The trend is the
argument *for* the proxy.

## How the proxy relates

The proxy is the **general-purpose, platform-independent** instantiation of the exact primitive
these platforms ship internally — AWS's own words: "no single individual can unilaterally… change
the root of trust." It moves the enforcement point to where none of the incumbents put it: in front
of the public-registry publish, bound to the artifact by hash, registry-agnostic. Honest boundary:
the proxy does not out-secure AWS/Google/Azure's implementations of *their* operations — those are
native and stronger inside their own planes. Its contribution is **coverage of a target none of them
reach**, plus the §7 argument that this belongs natively in the registry (Trusted Publishing is
precedent that registries add auth features).

## Source decisions

- **Cover all three hyperscalers (AWS + Google + Azure).** The thesis word is *under-used*; the
  honest, verifiable way to show that is breadth-with-siloing across the three giants, not a false
  claim of absence. This supports the Move 3 argument.
- **Correct the "Azure lacks it" premise.** Azure has MUA (Backup) and MAA (Intune); asserting
  otherwise would be wrong and fragile. The *stronger* true point is that Azure's general PAM tool
  (PIM) does not do a quorum — "first approver resolves" — and its real multi-party features are
  product-locked silos. Reported faithfully; it makes the argument harder, not softer.
- **Keep the AWS↔Azure backup-vault convergence.** That two independent clouds both chose
  backup-vault protection as their multi-party use case is a vivid, defensible illustration of how
  bounded each implementation is.
- **Vault → C1, not P1.** Shamir unseal is key custody, often auto-unsealed; citing it as industry
  *human-approval* adoption would overclaim. It earns its place in C1 as "m-of-n threshold is the
  default of a mainstream secrets manager" lineage.
- **Authelia is not the multi-party primitive.** It is single-user forward-auth SSO and therefore
  does not support this note's §4 argument. Forward-auth/shared-account generalizability is outside
  this bibliography deep-dive; the untagged `authelia` bib stub remains available if that topic is
  needed later.
