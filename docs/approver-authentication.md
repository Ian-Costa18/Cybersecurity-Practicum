# Approver Authentication & Approval Signing

This document covers the per-approval authentication flow, the approve/deny interaction, and the Ed25519 signing scheme used to cryptographically record approval decisions.

For the user account model, provisioning flow, and admin portal, see [account-management.md](account-management.md).

For the decision to use asymmetric key pairs over MFKDF-style signing, see [ADR 0002](adr/0002-asymmetric-key-approval-signing.md).

---

## Approver Authentication Flow (Per Approval)

Approver sessions are **stateless**. There is no persistent login session. Each approval link triggers a fresh, independent authentication event scoped to that specific approval request.

The page renders **unauthenticated** on `GET /approve/{id}` — it carries only the request details and a credential form (no key material is touched). The decision is then a **single credentialed `POST`** that authenticates, derives the key, decrypts, signs, and records the Vote in one request. This is deliberately *not* a two-phase "decrypt now, sign on a later click" flow: the decrypted private key is never held across a page render, only across the few milliseconds of the signing call.

```mermaid
sequenceDiagram
    actor Approver
    participant Proxy as Proxy
    participant DB as Database

    Proxy->>Approver: Email approval link via SMTP (triggered when request is created)
    Approver->>Proxy: GET /approve/{approval_id}
    Proxy->>DB: Fetch approval request (validate it exists)
    Proxy-->>Approver: Approve/Deny page — request details + credential form (unauthenticated)

    Approver->>Proxy: POST username, password, TOTP code, decision (one submission)
    Proxy->>DB: Fetch password_hash, totp_secret, encrypted_private_key, key_salt for user
    Proxy->>Proxy: Verify bcrypt(password) against password_hash
    Proxy->>Proxy: Verify TOTP code against totp_secret
    Proxy->>DB: Check-and-record (user, TOTP time-step) — reject if already consumed (single-use)

    alt Authentication failed
        Proxy-->>Approver: Error — invalid credentials (no Vote recorded)
    else Authentication succeeded
        Proxy->>Proxy: Derive enc_key = PBKDF2(password, key_salt)
        Proxy->>Proxy: Decrypt private_key from encrypted_private_key
        Proxy->>Proxy: Sign approval_record (with the submitted decision) using private_key (Ed25519)
        Proxy->>Proxy: Discard private_key from memory
        Proxy->>DB: Append signed Vote (approval_record + approval_signature + decision)
        alt Decision = deny
            Proxy->>DB: Mark request as denied (record optional reason)
            Proxy->>Proxy: Emit request.denied event (notification routing handled elsewhere)
            Proxy-->>Approver: Denial recorded — request denied
        else Decision = approve
            Proxy->>Proxy: Check quorum (over effective votes)
            alt Quorum reached
                Proxy->>DB: Mark request as approved
                Proxy->>Proxy: Emit request.approved event; hand off to Post-Approval Object (Service Grant or Action)
                Proxy-->>Approver: Approval recorded — quorum reached
                Note over Proxy: Execution (issue grant / publish to PyPI) happens<br/>asynchronously, out-of-band, in a background Executor —<br/>never inside this approver's request
            else Quorum not yet reached
                Proxy-->>Approver: Approval recorded — waiting for quorum
            end
        end
    end
```

### Approve/Deny Page

The page shown after authentication is intentionally minimal. It displays:

- The service being accessed (e.g., "PyPI publish for `mypackage 1.2.3`")
- For HTTP forward-auth requests: the HTTP method, URL, and relevant headers
- For package publishing: a download link to the package artifact so the approver can inspect it locally
- The live quorum status, naming the **Endorsing Approvers** (the Users whose effective vote is `approve`) and counting the rest — e.g. "Approved by Alice & Bob — 2 of 3, waiting on 1 more." Approvers who denied, withdrew, or have not acted are never named. The list updates live as other approvers act, over a link-scoped SSE stream (`GET /approve/{id}/stream`); see [web-proxy.md](web-proxy.md#live-endorser-updates-sse).
- Two buttons: **Approve** and **Deny**

### TOTP Single-Use Enforcement

A captured `password + TOTP` pair would otherwise be replayable for the lifetime of the TOTP code. [RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2) requires the verifier to **reject a second use of an accepted OTP**. The proxy enforces this per **`(user, time-step)`**: when a TOTP code is accepted, the consumed time-step is recorded, and any later submission for that same `(user, time-step)` is rejected — even with otherwise-valid credentials. Each TOTP code is therefore single-use; this is the burn-check shown in the flow above.

**Residual window.** The verifier accepts the current 30-second time step plus the ±1 adjacent steps (RFC 6238's recommended clock-drift tolerance), so a freshly generated code is valid across a ~90-second span of wall-clock time. Single-use enforcement closes replay *of an already-accepted code* (the second use is rejected); it does not shrink the acceptance window itself. A captured code that has **not** yet been redeemed stays usable until it is first redeemed (after which it is burned) or its time-step window passes — whichever comes first. This residual ±1-step exposure is why **T8 is rated *partially* mitigated, not *fully*** (see [threat model](threat-model/00-overview.md)).

---

## Asymmetric Key Approval Signing

Approval records are signed using per-approver Ed25519 key pairs. See [ADR 0002](adr/0002-asymmetric-key-approval-signing.md) for the full decision rationale, including why MFKDF-style signing was considered and rejected.

### Key Pair Lifecycle

**At enrollment:** The proxy generates a unique Ed25519 key pair for the approver.

```text
(private_key, public_key) = Ed25519.generate()
enc_key = PBKDF2(password_plaintext, key_salt, iterations=600000, dklen=32)
encrypted_private_key = AES-256-GCM-Encrypt(private_key, enc_key)
```

`public_key`, `encrypted_private_key`, and `key_salt` are stored. The plaintext `private_key` is discarded.

**At password change:** The private key is re-encrypted under the new password. The key pair itself does not change; all past signatures remain verifiable with the unchanged public key. **Note:** the MVP has **no self-service password change** — this re-encryption path (which needs the *old* password to decrypt the key) is reserved for a future self-service flow. An admin-initiated **credentials reset** has no old password, so it instead generates a *new* key pair and **orphans** the old one (see [account-management.md](account-management.md#user-keys-table)).

```text
enc_key_old = PBKDF2(old_password, key_salt, ...)
private_key = AES-256-GCM-Decrypt(encrypted_private_key, enc_key_old)
enc_key_new = PBKDF2(new_password, key_salt, ...)
encrypted_private_key = AES-256-GCM-Encrypt(private_key, enc_key_new)
```

**At account deletion:** `encrypted_private_key` is deleted — the account no longer needs signing capability. `public_key` is retained permanently as an audit artifact. Historical approval records signed by this user remain verifiable with the retained public key. Deletion is irreversible; deactivation (`is_active = false`) should be preferred when re-activation is possible.

### Signing the Approval Record

At the moment of authentication, the proxy decrypts the private key transiently, signs the approval record, then discards the private key from memory.

```text
approval_record = {
    approver_id,        // identifies the user
    key_id,             // identifies which key pair was used; links to user_keys table
    approval_request_id,
    timestamp,
    action_hash,        // hash of the payload being approved (e.g., package SHA-256)
    decision            // one of "approve" | "deny" | "withdraw"
}

enc_key = PBKDF2(password_plaintext, key_salt, ...)
private_key = AES-256-GCM-Decrypt(encrypted_private_key, enc_key)
approval_signature = Ed25519Sign(private_key, canonical_json(approval_record))
// private_key discarded from memory
```

Both `approval_record` and `approval_signature` are stored.

**No-artifact (forward-auth) case.** `action_hash` is the SHA-256 of the payload being approved, which exists only for one-time requests that staged an artifact. A **forward-auth** request binds no artifact, so its `action_hash` is signed as the **empty string `""`** — a deliberate placeholder, not a missing field, so the record set and the canonical-JSON signing input stay uniform across both service types. Binding a forward-auth request's own payload hash (e.g. method + URL) is future work; until then the empty placeholder is the documented value.

Under the append-only vote model, an approver may produce **multiple** signed Vote records over a request's `pending` life — supersessions and withdrawals are appended, never overwritten. Each Vote is independently signed and stored, the full sequence is retained for audit, and the approver's **effective Vote** is the latest one. Once the request reaches a terminal state, the votes freeze.

### Security Properties

| Threat | Protection |
|---|---|
| Attacker reads DB (no password) | Has `encrypted_private_key` but cannot decrypt without the password. Cannot forge. |
| Attacker has DB + cracks password | Can decrypt `private_key` and forge signatures. Password cracking is the required bar — same as any credential-backed scheme. |
| Attacker modifies an approval record in DB | `Ed25519Verify(public_key, approval_record, approval_signature)` fails — modification is detectable without any password. |
| Approver changes password | Private key is re-encrypted; public key and all past signatures are unaffected. |
| Replay attack | Each Vote contains its `approval_request_id` and is independently signed. Casting or changing a Vote always requires authenticating as the approver (password + **single-use** TOTP): an accepted TOTP code is burned per `(user, time-step)` and cannot be reused ([RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2)), so a replayed link or a recaptured-and-resubmitted code achieves nothing once that code is redeemed. A captured code that is *not yet* redeemed remains replayable only within its ±1-step (~90 s) acceptance window — see [TOTP Single-Use Enforcement](#totp-single-use-enforcement). While the request is `pending`, an *identical* repeated decision is a no-op and a *changed* decision is an accepted **supersession** (append-only; effective vote = latest); once the request is terminal, no Vote is accepted at all. |

### Audit Verification

**Tamper-evidence (no credentials needed):** Any modification to a stored `approval_record` is immediately detectable using the stored `public_key`:

```text
Ed25519Verify(public_key, canonical_json(approval_record), approval_signature)
```

No password or approver cooperation is required.

**Non-repudiation:** A valid signature proves the approver's private key was used. Since the private key is only accessible by decrypting with the approver's password, a valid signature is strong evidence of the approver's participation. An approver disputing an approval must claim their password was compromised — a high bar.
