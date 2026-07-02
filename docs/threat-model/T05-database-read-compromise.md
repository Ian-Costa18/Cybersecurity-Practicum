---
id: T5
title: "Database Read Compromise"
stride: ["Information Disclosure", "Elevation of Privilege"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L4]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T5 — Database Read Compromise

| | |
|---|---|
| **Category** | Information Disclosure, Elevation of Privilege (deferred) |
| **Capability** | L4 |
| **What the attacker gains** | `encrypted_private_key` blobs (encrypted with AES-256-GCM; useless without the user's password). `bcrypt` password hashes (offline cracking target). TOTP secrets in plaintext — once the attacker cracks the bcrypt hash, they have both factors, enabling full account takeover without any network interaction. Public keys and all approval records (read-only; cannot forge without private keys). ACL config (if stored in DB; in MVP it is a YAML file, so not directly accessible via DB read). API tokens and enrollment tokens are stored only as hashes; a database read yields useless hashes, not replayable tokens. |
| **What they cannot do** | Immediately authenticate or approve without cracking passwords (bcrypt cost ≥ 12 ≈ 300 ms/attempt on modern hardware). Forge approval signatures without the private keys (which require cracking the password to decrypt). |
| **Current defenses** | AES-256-GCM encryption of private keys at rest: the plaintext private key is never stored. bcrypt password hashing at cost ≥ 12: makes offline cracking expensive; unique per-user salts prevent precomputed tables. 128-bit random salt per user (PBKDF2): prevents cross-user rainbow tables. Token hashing: API tokens and enrollment tokens are stored only as hashes — the plaintext is shown or delivered once and never persisted, so a database read cannot recover or replay them. |
| **Planned defenses** | Encrypt TOTP secrets at rest (currently stored plaintext; should be encrypted analogously to the private key — this is an unmitigated gap). Formal access controls on the database (IP allowlist to proxy host only; dedicated DB credentials with minimal privileges). |
| **Operator configuration** | Never expose the database port to the internet; bind to localhost or a private network accessible only to the proxy host. Use a dedicated database user with only the necessary table-level permissions (no superuser). Enable database audit logging. Rotate database credentials if a breach is suspected. Establish a credential rotation policy for bcrypt cost escalation as hardware improves. |
