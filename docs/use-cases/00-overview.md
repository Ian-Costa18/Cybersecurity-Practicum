# Multi-Signature Authentication Use Cases

This directory documents real-world scenarios where multi-signature (m-of-n) approval is implementable and valuable. Each use case is grounded in actual research or technical feasibility, not theoretical scenarios.

## Implemented Use Cases

### [01. Package Publishing](01-package-publishing.md) (MVP)

**Domain:** Supply-chain security (npm, PyPI, RubyGems)

**Problem:** A single compromised or malicious maintainer can publish backdoored code to millions of users.

**Solution:** Require multiple maintainers to approve before publication. Package is hash-bound to the approval, preventing MITM attacks.

**Research backing:** Literature review documents real supply-chain attacks (event-stream, ctx, XZ Utils) where multi-approval would have prevented compromise.

**Implementation:** Server holds package, approvers authenticate and approve, server publishes to PyPI/npm.

---

### [02. Shared Account Management](02-shared-account-management.md)

**Domain:** Joint account access (savings accounts, shared credit cards, collaborative tools)

**Problem:** One guardian/co-owner can unilaterally access shared resources without the other's consent.

**Solution:** Require multiple account owners to approve before credentials are revealed or access is granted.

**Real-world example:** Separated parents managing a child's education savings account. Both parents should consent before one accesses or modifies the account.

**Implementation:** Server stores account credentials encrypted. To access, user authenticates, requests credentials, approvers authenticate and approve, server reveals credentials or grants temporary access.

---

## Why These Two

- **Package Publishing:** Grounded in rigorous supply-chain research; MVP scope aligns with research findings.
- **Shared Account Management:** Structurally simple (authenticate → request → approve → grant credentials); real human use case mentioned in project proposal.

Both use cases avoid theoretical scenarios and focus on implementable systems with clear threat models and workflows.

## Future Use Cases

As the system matures, other use cases can be added if backed by similar rigor:
- Infrastructure/deployment approval (requires research into SRE workflows and approval practices)
- Sensitive data access (requires compliance framework analysis)
- HSM/vault key ceremonies (well-established but niche)

For now, the focus is on shipping the MVP and evaluating whether multi-signature approval is genuinely useful in the Package Publishing context.
