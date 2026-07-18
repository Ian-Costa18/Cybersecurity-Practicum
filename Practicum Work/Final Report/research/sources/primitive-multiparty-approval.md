---
bucket: P1
title: Multi-party approval as an industry primitive (platform-siloed)
report_home:
  - "§4 — Move 3: industry adoption trend that reinforces the gap"
  - "§7 — Future Work & Generalizability: forward-auth-gated resources (Authelia)"
proxy_grounding:
  - docs/adr/0001-credential-backed-approval.md
  - docs/evaluation-plan.md   # §1 Move 3
related_notes:
  - method-evaluation-frameworks.md
  - ../controls-matrix/ctrl-the-proxy.md
bib_keys: [aws-mpa, aws-backup-mpa, google-cloud-pam, google-workspace-mpa, vault-seal-unseal, authelia]
status: draft
---

## Why the report needs this

**Synthesis.** §4 Move 3 makes the claim that m-of-n human approval is *proven and being
adopted* as a primitive by major platforms — which is exactly why the registry-publish gap the
proxy fills is worth filling. The load-bearing rhetorical move is that every one of these
adoptions is **siloed inside a single platform's own control plane**: AWS multi-party approval
gates AWS operations, Google's gates Google operations, Vault's threshold gates Vault's own
unseal. The primitive ships in production, but **no general-purpose, registry-agnostic
enforcement point exists** — so the trend *reinforces* the gap rather than closing it. That is the
honest, non-victory-lap framing: the idea is validated by industry; the specific instantiation
(authorizing an arbitrary public-registry publish, bound to the exact artifact) is not.

§7 uses one source here (`authelia`) for a different job: the forward-auth reverse-proxy pattern
is the reference architecture the proxy's generalizability leg mirrors — an authorization gate
that sits in front of an arbitrary protected resource. Authelia is *not* an m-of-n adopter; it is
cited as the deployment shape, not as approval-primitive evidence (see *Source decisions*).

## Sources (vetted this session)

- AWS, *What is Multi-party approval?* — https://docs.aws.amazon.com/mpa/latest/userguide/what-is.html
  (accessed 2026-07-18) → `aws-mpa` · the general AWS MPA capability, its Requester/Administrator/
  Approver model, and the **two** services it now gates (Backup + Payment Cryptography) · [primary]
- AWS, *AWS Backup launches Multi-party approval support for logically air-gapped vaults*, Jun 17
  2025 — https://aws.amazon.com/about-aws/whats-new/2025/06/aws-backup-multi-party-approval-logically-air-gapped-vaults/
  (accessed 2026-07-18) → `aws-backup-mpa` · dates the launch; the air-gapped-vault use case · [primary]
- Google Cloud, *Privileged Access Manager overview* — https://docs.cloud.google.com/iam/docs/pam-overview
  (accessed 2026-07-18) → `google-cloud-pam` · a **second independent hyperscaler** shipping
  multi-level, multi-approver gating of privileged IAM grants · [primary]
- Google Workspace, *Multi-party approval for sensitive actions* —
  https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions
  (accessed 2026-07-18) → `google-workspace-mpa` · MPA over sensitive **admin-console** settings;
  same primitive, again siloed to one platform · [primary]
- HashiCorp, *Seal/Unseal* + *operator init* — https://developer.hashicorp.com/vault/docs/concepts/seal
  (accessed 2026-07-18) → `vault-seal-unseal` · Shamir m-of-n threshold, **default 3-of-5**,
  production-proven — but at the **key-custody** layer, not operation authorization · [primary]
- Authelia — https://www.authelia.com/ (accessed 2026-07-18) → `authelia` · forward-auth
  reverse-proxy reference architecture for the §7 generalizability leg · [primary]

## Key facts (anchored)

### AWS multi-party approval is a general capability of AWS Organizations, not a one-off feature
> "Multi-party approval is a capability of AWS Organizations that allows you to protect a
> predefined list of operations through a distributed approval process. Use Multi-party approval
> to establish approval workflows and transform security processes into team-based decisions."
— AWS, *What is Multi-party approval?*, "What is Multi-party approval?"

> "Multi-party approval requires AWS Organizations and AWS IAM Identity Center."
— AWS, *What is Multi-party approval?*, "Required services"

Backs §4 Move 3's core claim: a major platform ships m-of-n human approval **as a primitive** —
and the "Required services" line is the anchor for *siloed*: it only works inside AWS's own
Organizations/Identity-Center control plane. Scope: it protects a *predefined list* of AWS
operations, not arbitrary external actions.

### AWS MPA has already expanded beyond Backup to a second service (root-of-trust key imports)
> "You can use Multi-party approval to protect the import of root certificate public keys, which
> establish the trust anchor for subsequent key imports and exports using asymmetric key exchange
> such as TR-34. Requiring multi-party approval for this operation helps ensure that no single
> individual can unilaterally establish or change the root of trust for your AWS Payment
> Cryptography keys."
— AWS, *What is Multi-party approval?*, "What operations are currently supported"

Backs the *growing trend* half of Move 3: the eval-plan currently says AWS MPA is scoped to "AWS
Backup logically air-gapped vaults" — as of this session it also gates **AWS Payment
Cryptography**. The primitive is *expanding* across a platform's operations. (Staleness flag: the
"currently AWS Backup" phrasing in [evaluation-plan.md](../../../../docs/evaluation-plan.md) §1
Move 3 is now narrower than reality — see *Open threads*.)

### AWS's own framing: distributed decision-making that deliberately trades away immediacy
> "You need distributed decision-making for sensitive or critical operations" / "You need to
> protect against unintended operations on sensitive or critical resources"
— AWS, *What is Multi-party approval?*, "When Multi-party approval is beneficial"

> "For operations that require immediate execution without delay"
— AWS, *What is Multi-party approval?*, "When Multi-party approval might not be the best choice"

Corroborates the proxy's own design property (the report's "enforced friction/latency = time to
think" line, eval-plan §2 Act 2): the incumbent agrees the primitive is for high-consequence,
non-urgent actions and accepts the latency cost. Color/support, not a load-bearing §4 cell.

### The AWS launch is recent (June 2025) — the trend is live, not historical
> "AWS Backup launches Multi-party approval support for logically air-gapped vaults" · "Posted on:
> Jun 17, 2025"
— AWS, *AWS Backup launches Multi-party approval…*

> "requires multiple authorized individuals to approve critical operations"
— AWS, *AWS Backup launches Multi-party approval…*

Anchors the "2025 / live industry territory" phrasing in Move 3.

### Google Cloud is a second, independent hyperscaler shipping multi-approver gating
> "Privileged Access Manager administrators can mandate more than one approval level per
> entitlement, allowing up to two levels of sequential approvals for each entitlement.
> Administrators can mandate up to five approvals per level."
— Google Cloud, *Privileged Access Manager overview*

> "Privileged Access Manager supports creating entitlements and requesting grants for projects,
> folders, and organizations."
— Google Cloud, *Privileged Access Manager overview*

Turns Move 3 from an anecdote (one vendor) into a **trend** (two independent hyperscalers). Same
siloing: PAM gates temporary grants of **Google Cloud IAM roles** on Google Cloud projects/folders/
orgs — its own control plane, not an external publish.

### Google Workspace ships the same primitive again, over admin-console settings
> "When multi-party approval is on, a second administrator must approve changes to sensitive
> settings."
— Google Workspace, *Multi-party approval for sensitive actions*, "Definition"

> "You can use multi-party approval for certain security, Google Groups, Domains, Google Calendar,
> and Google Vault settings."
— Google Workspace, *Multi-party approval for sensitive actions*, "Scope"

A third data point (same vendor, different product) that the primitive is being applied broadly —
and, again, siloed to one product's admin surface. Supporting, not a distinct §4 cell.

### The m-of-n threshold idea is production-proven even at the key-custody layer (Vault)
> "Instead of distributing the unseal key to an operator as a single key, the default Vault
> configuration uses an algorithm known as Shamir's Secret Sharing to split the key into shares."
— HashiCorp, *Seal/Unseal*

> "Vault requires a certain threshold of shares to reconstruct the unseal key."
— HashiCorp, *Seal/Unseal*

> `-key-shares` "(int: 5)" · `-key-threshold` "(int: 3)"
— HashiCorp, *operator init* (defaults: split into 5 shares, any 3 reconstruct the key)

Backs the lineage point that m-of-n is not a novel or fringe idea — it is the *default*
configuration of a widely-deployed secrets manager. **Honest scope:** this is a *cryptographic
threshold over a secret* (key custody / cluster unseal), not *human authorization of an
operation*. It shows the m-of-n shape is load-bearing in real infrastructure; it is **not**
evidence of human-approval-workflow adoption, and it overlaps the C1 crypto-lineage note (see
*Open threads / Source decisions*).

### Authelia — the forward-auth reference architecture for the §7 generalizability leg
> "Authelia is an open-source authentication and authorization server and portal fulfilling the
> identity and access management (IAM) role of information security in providing multi-factor
> authentication and single sign-on (SSO) for your applications via a web portal."
— Authelia, home page

> Authelia "acts as a companion for common reverse proxies," letting administrators "Control which
> users and groups have access to which specific resources or domains with incredibly granular
> policy definitions."
— Authelia, home page

Backs §7's claim that an authorization gate *in front of* an arbitrary protected resource is an
established deployment pattern — the shape the proxy's shared-account / forward-auth
generalization would take. Authelia does **not** do m-of-n approval; it is cited for the
architecture, not the primitive.

## The pattern (synthesis — the one honest point)

Across AWS, Google Cloud, Google Workspace, and (at the crypto layer) Vault, the m-of-n primitive
is **validated and shipping** — and in every case it is **welded to the platform that ships it**:
AWS MPA needs AWS Organizations + IAM Identity Center and protects a predefined list of AWS
operations; Google PAM gates Google Cloud IAM grants; Google Workspace MPA gates Workspace admin
settings; Vault's threshold guards Vault's own unseal. None of them can authorize *"publish
version X of package Y to PyPI/npm, bound to this exact artifact hash."* The registry-publish
point sits between platforms, owned by none of them. That is the gap: **the primitive is proven,
its adoption is accelerating (AWS added a second service in 2025; Google offers it across two
products), and yet a registry-agnostic enforcement point for it does not exist.** The trend is the
argument *for* the proxy, not against it.

## How the proxy relates

The proxy is the **general-purpose, platform-independent** instantiation of the exact primitive
these platforms ship internally. It reuses the same idea (distributed m-of-n human authorization of
a high-consequence operation, AWS's own words: "no single individual can unilaterally… change the
root of trust") but moves the enforcement point to where none of the incumbents put it: in front
of the public-registry publish, bound to the artifact by hash. Honest boundary: the proxy does not
out-secure AWS/Google's implementations of *their* operations — those are native and stronger
inside their own planes. Its contribution is *coverage of a target none of them reach*, and the
§7 argument that this belongs natively in the registry (Trusted Publishing is precedent that
registries add auth features).

## Open threads / to verify

- **eval-plan staleness (factual, low-effort):** [evaluation-plan.md](../../../../docs/evaluation-plan.md)
  §1 Move 3 says AWS MPA is "currently AWS Backup logically air-gapped vaults." It now also gates
  **AWS Payment Cryptography**. Per CLAUDE.md "overrides update the spec," if the report leans on
  the two-service point, Move 3's phrasing should be widened to "AWS Backup and Payment
  Cryptography" (or "a growing list of AWS operations"). **Confirm with Ian before editing the
  spec** — it may be intentional to keep the example minimal.
- **Vault ↔ C1 overlap:** Vault Shamir is threshold *crypto*, which is also C1's territory
  (threshold-signature lineage behind ADR 0001's "not threshold signatures" decision). Decide
  whether `vault-seal-unseal` is cited in P1 (as "m-of-n ships in production") or C1 (as crypto
  lineage), or both with distinct framings, to avoid double-spending it. Recommendation below.
- **Azure PIM (not cited, context only):** Azure Privileged Identity Management offers JIT access
  with **approval workflows**, but the common configuration is single-approver, so it is a weaker
  m-of-n example than AWS/Google. Named as context if a reviewer asks "what about Azure?"; not
  worth a bib entry unless the trend paragraph wants a third vendor.

## Source decisions

- **Widen P1 from the 4 original stubs to include Google Cloud PAM and Google Workspace MPA
  (RECOMMEND, but a genuine fork for Ian).** Rationale: Move 3 asserts a *trend*. One vendor (AWS)
  is an anecdote; two independent hyperscalers plus AWS's own within-platform expansion is a trend,
  at the cost of one extra `\cite` in a single sentence. If Ian prefers to keep §4 lean and cite
  AWS alone, `google-cloud-pam` / `google-workspace-mpa` drop cleanly (they only appear in this
  note and one Move-3 sentence). Landed the bib entries anyway per the "front-load, throw away if
  needed" instruction.
- **Keep Vault, framed as key-custody lineage, not human-approval adoption.** Citing it as "an
  industry m-of-n *approval*" would overclaim — unsealing is a cryptographic reconstruction, often
  automated via auto-unseal. It earns its place as "the m-of-n threshold is the *default* of a
  mainstream secrets manager," which is the honest, defensible claim. Final P1-vs-C1 home is Ian's
  call (see Open threads).
- **Authelia stays §7-only and is not counted as MPA adoption.** It is a forward-auth architecture,
  not an approval primitive; conflating them would be a category error.
