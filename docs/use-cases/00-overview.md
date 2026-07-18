# Multi-Party Authorization Use Cases

This directory documents real-world scenarios where multi-party (m-of-n) approval is implementable and valuable. Each use case is grounded in actual research or technical feasibility, not theoretical scenarios.

## One approval core, two post-approval shapes

Both use cases run through the **same approval core** and differ only in what happens *after* quorum. This is the system's central design (see [ADR 0007](../adr/0007-two-aggregate-request-model.md) and [request-lifecycle.md](../request-lifecycle.md)):

- The **Approval Request** owns the vote. Its whole life is the m-of-n decision; it reaches a terminal state and does no post-approval work itself.
- On `approved` it hands off to one of two **Post-Approval Objects**:
  - an **Action** (`one-time`) — executes a single operation against an external service, then ends (Package Publishing); or
  - a **Service Grant** (`forward-auth`) — grants the Requester bounded interactive access to a protected backend (Shared Account Management).

Actors use the **canonical roles** from [CONTEXT.md](../CONTEXT.md): **Requester**, **Approver**, **Admin**, and **User** (one person is routinely both a Requester and an Approver, across different services) — not persona labels like "maintainer," "guardian," or "co-owner."

## Implemented Use Cases

### [01. Package Publishing](01-package-publishing.md) (MVP, headline)

**Domain:** Supply-chain security. **MVP target is PyPI** (the design generalizes to other registries, but only PyPI is in scope).

**Problem:** A single compromised or malicious maintainer can publish backdoored code to many downstream users.

**Solution:** Require a quorum of Approvers to approve before publication. The artifact is **hash-bound** to the approval: the proxy records `SHA-256` at upload, Approvers approve that hash, and the Executor **re-verifies the hash immediately before publishing**, refusing on mismatch. This defends the internal **upload→publish substitution window** and makes record tampering detectable offline — it is *not* a transport defense (transport is already TLS) and does not resist a fully compromised proxy holding the live upload token (see [mvp-prd.md](../mvp-prd.md) Security ②).

**Flow shape (`one-time`, asynchronous):** the Requester submits via normal tooling (Twine) and walks away — they do **not** wait at a browser. On quorum the Approval Request hands off to an **Action** that a background **Executor** runs asynchronously, publishing to PyPI with bounded retry. The held artifact is destroyed at every terminal outcome.

**Research backing:** the literature review documents real supply-chain attacks (event-stream, ctx, XZ Utils) where multi-approval would have broken the single-point-of-authority.

---

### [02. Shared Account Management](02-shared-account-management.md) (generality evidence — not evaluated this term)

**Domain:** Joint account access (savings accounts, shared credit cards, collaborative tools).

**Problem:** One owner can unilaterally access a shared resource without the others' consent.

**Solution:** Put the shared account's web interface behind the proxy in the **`forward-auth`** pattern. Raw credentials are **never revealed** to the Requester: on quorum the proxy issues a **Service Grant** and the reverse proxy forwards the Requester into the backend with **injected identity headers**, holding any backend Service Credential internally.

**Flow shape (`forward-auth`, synchronous):** the Requester waits in a browser; on quorum a Service Grant is issued and they are redeemed on their next `GET /auth` (grant expiry is evaluated lazily at `/auth`). Access is bounded by the grant's lifetime, then re-gated.

**Real-world example:** separated parents managing a child's education savings account — both should consent before either accesses or modifies it.

---

## Why These Two

- **Package Publishing** carries the rigorous supply-chain motivation and both adversarial demos; it is the headline `one-time` use case.
- **Shared Account Management** is **generality evidence** (designed-for, not evaluated this term; see [#109](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/109)): the *same approval core* driving a structurally different (`forward-auth`, credential-never-revealed) post-approval outcome. It is the better narrative but the weaker security case, retained for relatability and as evidence the design generalizes.

Both avoid theoretical scenarios and focus on implementable systems with clear threat models and workflows.

## Future Use Cases

As the system matures, other use cases can be added if backed by similar rigor:
- Infrastructure/deployment approval (requires research into SRE workflows and approval practices)
- Sensitive data access (requires compliance framework analysis)
- HSM/vault key ceremonies (well-established but niche)

For now, the focus is on shipping the MVP and evaluating whether multi-party authorization is genuinely useful in the Package Publishing context.
