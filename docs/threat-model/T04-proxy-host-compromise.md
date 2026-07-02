---
id: T4
title: "Proxy Host Compromise"
stride: ["Elevation of Privilege", "Information Disclosure"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L6]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T4 — Proxy Host Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege, Information Disclosure |
| **Capability** | L6 |
| **What the attacker gains** | (a) Publishing credentials (PyPI token, shared account passwords) held in memory unencrypted — this is a documented MVP limitation. (b) Ed25519 private keys during the signing window (the transient window between PBKDF2 derivation and signing is a few milliseconds; the key is then discarded). (c) Plaintext passwords submitted during the current authentication request (transient in memory). (d) TOTP codes at the moment of authentication (transient). (e) Full visibility into in-flight approval requests and their state. |
| **What they cannot do** | Forge retroactive approvals already recorded in the database — Ed25519 signatures over canonical approval records are independently verifiable with the stored public keys; the proxy cannot fabricate a signature without the approver's private key. Modify stored approval records without detection — any change is caught by `Ed25519Verify`. |
| **Current defenses** | Hash binding: for one-time transactional requests, the payload hash is fixed at upload time; a compromised proxy cannot swap the package being published without breaking the approval-hash linkage. Audit trail: all approval records are signed and tamper-evident; post-compromise forensics can establish what was and was not approved before the compromise. |
| **Planned defenses** | Per-user credential wrapping: publishing credentials would be encrypted with each approver's key material, requiring m simultaneous approver decryptions — a compromised proxy alone could not read them. Integration with external secret managers (HashiCorp Vault, AWS Secrets Manager): credentials fetched at publish time, not held in memory. Minimizing the private key window (the key is already designed to be discarded immediately after signing; runtime memory zeroing should be confirmed in implementation). |
| **Operator configuration** | Harden the proxy host: minimal OS footprint, no unnecessary services, regular patching. Run the proxy in a container or VM with no persistent storage other than the database connection. Use network egress filtering to prevent the proxy from making unexpected outbound connections. Monitor for unexpected process execution, outbound connections, or memory dumps. Treat the proxy host as a Tier-1 asset requiring the same controls as a secrets manager. |
