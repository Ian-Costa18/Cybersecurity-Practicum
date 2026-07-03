---
id: T4
title: "Proxy Host Compromise"
stride: ["Elevation of Privilege", "Information Disclosure"]
attack: [T1003, T1005]
capability: [L6]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: low
severity_baseline: N/A
severity_residual: critical
bucket: 4
related: [T5, T6, T11, T18, T24, T29, T30]
---

# T4 — Proxy Host Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege, Information Disclosure |
| **Capability** | L6 — code execution on the proxy host itself. |
| **What the attacker gains** | (a) Publishing credentials (PyPI token, shared account passwords) held in memory unencrypted — a documented MVP limitation ([mvp.md](../mvp.md)). (b) Ed25519 private keys during the signing window (the transient interval between PBKDF2 derivation and signing; the key is then discarded). (c) Plaintext passwords submitted during the current authentication request (transient in memory). (d) TOTP codes at the moment of authentication (transient). (e) Full visibility into in-flight approval requests and their state. With the live PyPI token in hand, the attacker can publish at will — mission failure. |
| **What they cannot do** | Forge or silently modify approval records *already stored* before the compromise — Ed25519 signatures over canonical vote records verify independently of the proxy, and the attacker cannot fabricate a signature without an approver's private key (which never rests on the host unwrapped; see T5 for the at-rest story and T6 for the stored-public-key caveat). Tamper-evidence of the past is the one guarantee that survives. |
| **Current defenses** | Honest audit: nothing running on the host defends against the host. What survives is forensic: the signed audit trail is independently verifiable after the fact (`tests/approvals/test_votes.py::test_vote_is_ed25519_signed_and_verifies_offline`, `tests/core/test_crypto.py::test_verify_detects_a_tampered_record`), so post-compromise analysis can establish what was and was not approved before the compromise. At-rest encryption bounds what a disk/DB read yields (`tests/core/test_crypto.py::test_invariant_2_enc_key_is_never_persisted_on_the_record`); the live-memory window is the accepted core of this threat. |
| **Operator configuration** | Harden the proxy host: minimal OS footprint, no unnecessary services, regular patching. Run the proxy in a container or VM with no persistent storage other than the database connection. Use network egress filtering to prevent unexpected outbound connections. Monitor for unexpected process execution, outbound connections, or memory dumps. Treat the proxy host as a Tier-1 asset requiring the same controls as a secrets manager. |

**Delta.** Introduced: the proxy host is a new, concentrated Tier-1 asset that exists only
because the proxy exists — the baseline world has no intermediary holding a live publishing
credential on behalf of others. (The baseline's *own* credential-on-a-machine exposure is
T26's improved story, counted there.)

**Why bucket ④.** The discriminator this catalog uses for accepted limitations, shared with
[T18](T18-supply-chain-attack-on-the-proxy-itself.md): *if the operator cannot completely
defend or prevent it, we own it — accepted limitation.* Code executing on the host **is**
the proxy for all practical purposes; no configuration survives it. The operator items above
reduce likelihood around an accepted core; they do not retract the acceptance.

**Ratings.** Likelihood residual `low` is the default for the L6–L9 precondition class (host
code execution) with no deviation argued. Severity residual `critical`: the live PyPI token
in memory is durable publish-at-will — the top rung of the mission ladder.

**ATT&CK mapping.** T1003 — *OS Credential Dumping*: the attacker scrapes credentials out
of live process memory — here, the publishing credentials the MVP deliberately holds
unencrypted in memory, plus the transient passwords, TOTP codes, and signing-window Ed25519
keys. (T1552 *Unsecured Credentials* was considered and dropped: it names credentials
unprotected *at rest*, which is [T5](T05-database-read-compromise.md)'s surface, not the
live-memory scrape narrated here.) T1005 — *Data from Local System*: the
attacker collects sensitive local data — here, in-flight approval-request state. How the
attacker *got* code execution (e.g. T1059.006, malicious Python) is the L6 capability's
precondition, not this threat's operation, and is deliberately not tagged.

**On memory zeroing.** An earlier draft asked for "runtime memory zeroing" to be confirmed
in implementation. [#38](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/38)
resolves the question the other way: pure-Python zeroing is not deliverable (immutable
`bytes` copies, GC movement, OpenSSL temporaries) — the real path is architectural
(out-of-process signer, HSM/KMS), tracked below.

## Planned defenses

- **Per-user credential wrapping (threshold decryption)** — [#25](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/25) — no bucket change (shrinks the in-memory exposure; the ④ acceptance stands).
- **Integration with external secret managers** — [#29](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/29) — no bucket change (credentials fetched at publish time instead of held resident).
- **In-memory private-key erasure (out-of-process / HSM signing)** — [#38](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/38) — no bucket change (bounds the signing-window exposure).
