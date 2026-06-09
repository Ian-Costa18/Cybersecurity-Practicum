# Multi-Signature Authentication Proxy — PyPI Use Case Research Notes

**Project:** CS 6727 Cybersecurity Practicum — Multi-Signature Authentication Web Proxy
**Author:** Ian Barish

Created with the help of AI.

---

## Overview

The multi-signature authentication proxy's core value proposition is requiring multiple distinct
people to cooperate before a sensitive action is taken. While the initial proposal frames this
around general web authentication, a particularly compelling concrete use case — one with direct
supply chain security implications — is gating package publication to public registries like PyPI.

This document captures the architecture, data flow, limitations, and research framing developed
for this use case.

---

## Why Package Publication?

Supply chain attacks targeting public registries (PyPI, npm, RubyGems, etc.) frequently exploit
the fact that a single developer account, once compromised, can publish a malicious package to
thousands of downstream consumers. The `XZ Utils` backdoor (2024) and the `event-stream` npm
incident are canonical examples. In both cases, a single actor with unilateral publish access was
the attack vector.

The natural mitigation is requiring multiple parties to approve a publication — the same principle
as multi-sig cryptocurrency wallets. No major public registry currently offers this natively. The
proxy demonstrates that the pattern is technically viable and makes the case for platforms to adopt
it as a first-class feature.

---

## PyPI Permission Model Gap

PyPI has two project roles:

| Role | Upload releases | Manage collaborators | Delete project |
|------|----------------|----------------------|----------------|
| Owner | ✓ | ✓ | ✓ |
| Maintainer | ✓ | ✗ | ✗ |

**There is no role that allows project membership without upload rights.** A legitimate maintainer
can always publish a new release unilaterally. PyPI's permission model provides no mechanism for
separation of duties between project association and publish capability.

This gap is a direct motivation for the proxy. It also means native platform support would be a
meaningful improvement over the current state.

---

## Architecture

```
Developer machine          Proxy                       PyPI
──────────────────         ──────────────────────      ──────────────────
twine upload dist/*   →    intercept POST
                           store package files
                           return 202 Accepted    →   (nothing yet)
                           notify approvers

Approver 1: msig-proxy approve <id> --key ~/.ssh/id_ed25519
Approver 2: msig-proxy approve <id> --key ~/.ssh/id_ed25519

                           quorum reached         →   POST https://upload.pypi.org/legacy/
                                                      Authorization: Bearer <proxy-token>
                                                  ←   200 OK
                      ←    200 OK
```

The proxy holds the only PyPI API token scoped to the project. No developer credential can reach
the project's upload endpoint directly.

---

## Data Flow (Real Commands)

### One-time setup

The developer's `pyproject.toml` declares the proxy as a named index with a `publish-url`:

```toml
[[tool.uv.index]]
name = "proxy"
url = "https://multisig-proxy.company.internal/simple/"
publish-url = "https://multisig-proxy.company.internal/legacy/"
```

The developer authenticates to the proxy via an environment variable (their own proxy-scoped
token, not the real PyPI token):

```bash
export UV_INDEX_PROXY_TOKEN=<developer-scoped-proxy-token>
```

The proxy holds the real PyPI token in a secrets manager (environment variable, HashiCorp Vault,
etc.). This token is scoped to the specific project and is never distributed to any developer.

### Step 1 — Developer builds and submits

```bash
uv build
# produces: dist/mypackage-1.0.0-py3-none-any.whl
#           dist/mypackage-1.0.0.tar.gz

uv publish --index proxy
```

`uv publish` sends a multipart POST to the proxy's `publish-url`:

```
POST https://multisig-proxy.company.internal/legacy/
Authorization: Basic <base64(__token__:<developer-proxy-token>)>
Content-Type: multipart/form-data

:action=file_upload
name=mypackage
version=1.0.0
content=<wheel and sdist binaries>
```

### Step 2 — Proxy holds the request

The proxy stores the package files, assigns a request ID, and notifies approvers:

```
HTTP 202 Accepted
{ "status": "pending", "approval_id": "d7c2a4", "required": 2, "approved": 0 }
```

> **Implementation note:** `uv publish` does not natively expect a 202. In practice the proxy must
> either hold the connection open until quorum is reached, or a custom upload client is required.
> This is a known friction point with the proxy approach.

### Step 3 — Approvers sign off

Each approver authenticates to the proxy and signs the pending request:

```bash
msig-proxy approve d7c2a4 --key ~/.ssh/id_ed25519
```

The proxy verifies each signature against the ACL, incrementing its approval count.

### Step 4 — Proxy forwards to PyPI

Once quorum is reached, the proxy replays the original POST using its own token, set via
`UV_PUBLISH_TOKEN` (or passed directly to an HTTP client):

```
POST https://upload.pypi.org/legacy/
Authorization: Basic <base64(__token__:<real-pypi-api-token>)>
Content-Type: multipart/form-data

<identical body>
```

PyPI returns `200 OK`. The proxy returns `200 OK` to the original `uv publish` call.

---

## Bypass Prevention

Because PyPI is a public internet service, network isolation is not available. Bypass prevention
relies entirely on credential and permission controls.

### Control 1 — Credential scoping (primary lock)

PyPI API tokens can be scoped to a single project. The proxy holds the only token with upload
rights to the project. A developer attempting to upload directly:

```bash
UV_PUBLISH_TOKEN=<their-own-token> uv publish --publish-url https://upload.pypi.org/legacy/
# → 403 Forbidden (their token has no rights to this project)
```

### Control 2 — PyPI maintainer list

No individual developer accounts are listed as Owners or Maintainers on the PyPI project page.
The only entity with project access is a service account whose credentials are held exclusively
by the proxy. Even if a developer has a valid PyPI account, they have no upload rights.

### Residual trust boundary

A PyPI Owner can add new collaborators, which would grant them upload rights outside the proxy.
The service account that owns the project must therefore be secured with strong 2FA and its
credentials managed with the same rigor as the proxy's API token. This is an organizational
control, not a technical one enforced by the proxy.

---

## Limitations of the Proxy Approach

The current proxy architecture requires a workaround that is functional but not optimal:

- Every project requires a dedicated PyPI service account
- No human Owners or Maintainers can be listed on the project (they would bypass the proxy)
- The credential custody problem shifts from "who has publish rights" to "who administers the
  proxy's service account"
- `uv publish`'s expectation of a synchronous response creates implementation friction

The closest approximation achievable today requires removing all human maintainers from a project
and routing uploads through a proxy holding a single service account credential. This workaround
is functional but introduces its own credential custody problem and is operationally fragile.

---

## Research Contribution and Advocacy

The proxy is a proof of concept, not a production solution. The intended contribution is twofold:

**1. Demonstrating the gap**

No major public package registry (PyPI, npm, RubyGems, crates.io, Docker Hub) natively supports
multi-party publish authorization. This is a systemic supply chain security gap, not a PyPI-
specific issue.

**2. Demonstrating viability**

The proxy shows the pattern is technically achievable today, even within existing platform
constraints. This makes the case that native platform support is a matter of prioritization, not
feasibility.

### What native support would look like

For PyPI, the natural analogy is GitHub's branch protection rules — a developer can push code,
but it will not merge without required reviewers. The equivalent for PyPI would be:

- A per-project setting: "Require N-of-M maintainer approvals before a release is published"
- `twine upload` submits the package, but PyPI holds it in a pending state
- Designated approvers are notified and can approve via PyPI's interface
- On quorum, PyPI publishes the release

This would preserve normal maintainer roles, eliminate service account workarounds, and make the
credential custody problem disappear entirely.

### Broader applicability

The same gap exists across the ecosystem:

| Registry | Language | Native multi-party publish support |
|----------|----------|------------------------------------|
| PyPI | Python | ✗ |
| npm | JavaScript | ✗ |
| crates.io | Rust | ✗ |
| RubyGems | Ruby | ✗ |
| Docker Hub | Containers | ✗ |

The proxy generalizes across all of these, since they all use HTTP upload endpoints. The advocacy
generalizes as well — this is a call for the open-source registry ecosystem to adopt separation
of duties as a first-class security property.

---

## Connection to Original Proposal

The PyPI use case directly instantiates the supply chain attack motivation already present in the
proposal. The concrete data flow addresses the reviewer feedback requesting a more detailed and
compelling use case. The distinction between the proxy-as-workaround and native-platform-support
positions the project clearly as research rather than production tooling, which is appropriate for
a practicum deliverable.
