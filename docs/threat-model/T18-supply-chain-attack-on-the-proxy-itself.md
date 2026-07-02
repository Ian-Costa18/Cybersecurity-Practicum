---
id: T18
title: "Supply Chain Attack on the Proxy Itself"
stride: ["Tampering", "Elevation of Privilege"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: []
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T18 — Supply Chain Attack on the Proxy Itself

| | |
|---|---|
| **Category** | Tampering, Elevation of Privilege |
| **Capability** | External — attacker compromises a dependency of the proxy |
| **What the attacker gains** | A malicious dependency (e.g., a compromised Python package used by the proxy) could exfiltrate credentials, approval data, or private keys; silently approve requests; or provide a backdoor into the proxy host. This is the same class of attack the proxy is designed to prevent in downstream packages. |
| **What they cannot do** | Forge historical Ed25519 approval signatures already stored in the database (prior records remain tamper-evident). |
| **Current defenses** | None specifically documented. |
| **Planned defenses** | Dependency pinning (lock file with hashes for all transitive dependencies). Reproducible builds. Automated dependency vulnerability scanning (Dependabot, pip-audit, etc.). Code signing of proxy releases. |
| **Operator configuration** | Only install the proxy from a trusted source; verify release signatures if provided. Use a private package index mirror where possible rather than pulling directly from PyPI at deploy time. Audit third-party dependencies in the proxy's lock file. Run the proxy in a container with a minimal base image to limit the blast radius of a compromised dependency. |
