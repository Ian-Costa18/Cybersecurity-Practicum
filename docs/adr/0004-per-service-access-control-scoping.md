# Per-Service Access-Control Scoping

## Status
Accepted

## Context

The architecturally significant decision here is the **unit of access control** — the granularity at which approvers and quorum are bound to what they protect. This determines how every incoming request is matched to a policy and is expensive to change once services and ACLs depend on it. The candidate units are per-service, per-user, per-action, and per-path.

The serialization format (YAML, in a version-controlled file) is a secondary implementation detail, not the subject of this decision; it is recorded in the Implications section for completeness. The scoping decision criteria are:

1. **Clarity of the access-control unit:** It must be obvious what a given approver can approve.
2. **Auditability:** Policy changes are tracked in version control (git blame/log).
3. **Flexibility:** Support different approval thresholds and post-approval actions across protected targets.
4. **Coverage:** Work for both forward-auth (internal apps) and one-time approval (PyPI publish).

## Considered Options

### Option A: Per-Service YAML Configuration
- Single ACL file with one entry per protected service
- Each service specifies: approvers, quorum, and post-approval action
- **Advantage:** Simple, declarative, easy to audit (diffs show who changed what)
- **Disadvantage:** Monolithic file; can become large; less granular control

### Option B: Per-User Configuration
- Each user has their own approval threshold
- **Advantage:** Fine-grained control per user
- **Disadvantage:** Complex (many more config entries); unclear who can approve what; harder to audit

### Option C: Per-Action Configuration
- Each type of action (publish, restart, backup) has its own threshold
- **Advantage:** Flexible
- **Disadvantage:** Overlaps with per-service; unclear which takes precedence

### Option D: Per-Path Configuration
- Each HTTP path/endpoint has its own threshold (e.g., `/admin/*`, `/api/*`)
- **Advantage:** Works for forward-auth scenarios
- **Disadvantage:** Not applicable to one-time approval scenarios (PyPI); adds complexity for non-HTTP services

## Decision

**Chosen: Per-Service scoping (Option A).** The unit of access control is the protected service. Each service names its approvers, its quorum, and its post-approval action. Format note: this is expressed as a version-controlled YAML ACL (illustrated below); the format is an implementation choice, not the decision.

```yaml
services:
  pypi-publish:
    approvers:
      - alice
      - bob
      - charlie
    quorum: 3
    type: one-time
    action: publish-to-pypi

  internal-billing-app:
    approvers:
      - alice
      - bob
    quorum: 2
    type: forward-auth
    backend: http://internal-app:8080
```

## Rationale

1. **Clarity:** Each service is independent. It is obvious what approvers can approve, what the threshold is, and what happens after approval.

2. **Auditability:** Configuration is in version control (git). Changes to approvers or thresholds are auditable (git blame, git log). Operators can review and discuss changes before merging.

3. **Simplicity for MVP:** Per-service is the minimum granularity needed to support both forward-auth (internal apps) and one-time approval (PyPI). More fine-grained models (per-user, per-action) add complexity without clear benefit for the practicum scope.

4. **Scalability:** As the number of services grows, the YAML can be split into multiple files (e.g., `config/services/*.yaml`) to keep it manageable.

5. **No per-user variance (for MVP):** The MVP assumes all users are equal; approvers for a service are listed, and any of them can approve. If future use cases require per-user thresholds (e.g., "Alice can approve package X, but Bob needs 2-of-3 for package Y"), that can be added as a nested structure without breaking the current design.

## Implications

- The proxy loads the YAML ACL at startup (or on signal for runtime reload).
- Each incoming request is matched against the service name in the ACL.
- Approvers are looked up from the ACL; the quorum is enforced strictly.
- Post-approval behavior (forward-auth vs. one-time) is determined by the `type` field.

## Trade-offs Accepted

- **Monolithic for small deployments:** For a small number of services (< 10), a single YAML file is maintainable. For larger deployments, the file can be split.
- **No dynamic discovery:** Services must be explicitly configured. New services added to a backend app require proxy config updates. This is acceptable because it acts as a control point (approvers must opt-in to multi-approval for a service).
