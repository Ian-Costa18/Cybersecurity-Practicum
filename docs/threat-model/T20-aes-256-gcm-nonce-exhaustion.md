---
id: T20
title: "AES-256-GCM Nonce (IV) Exhaustion"
stride: ["Information Disclosure"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L4]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T20 — AES-256-GCM Nonce (IV) Exhaustion

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L4 |
| **What the attacker gains** | AES-256-GCM provides confidentiality and authentication guarantees with probability ≤ 2^{−18} for adversary advantage given random 96-bit IVs, up to 2^48 invocations per key. Exceeding this bound (or reusing an IV) destroys authentication and enables plaintext recovery. |
| **What they cannot do** | Exploit this without also having L4 access to the ciphertext blobs. |
| **Current defenses** | Each encryption event generates a fresh 96-bit random IV. For the MVP use case (per-user key encrypted at enrollment and re-encrypted on password change only), the per-key invocation count will be orders of magnitude below the 2^48 limit. |
| **Planned defenses** | If key rotation or re-encryption is ever performed at high frequency, add an invocation counter per key and rotate the AES key before reaching the 2^32 limit (as recommended by NIST SP 800-38D §8.3). |
| **Operator configuration** | No action required for typical use. If the system is extended to encrypt large numbers of objects under a single key, enforce key rotation before the invocation limit is reached. |
