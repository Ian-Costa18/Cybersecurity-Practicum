# Approver Authentication & Approval Signing

This document covers the per-approval authentication flow, the approve/deny interaction, and the Ed25519 signing scheme used to cryptographically record approval decisions.

For the user account model, provisioning flow, and admin portal, see [account-management.md](account-management.md).

For the decision to use asymmetric key pairs over MFKDF-style signing, see [ADR 0004](adr/0004-asymmetric-key-approval-signing.md).

---

## Approver Authentication Flow (Per Approval)

Approver sessions are **stateless**. There is no persistent login session. Each approval link triggers a fresh, independent authentication event scoped to that specific approval request.

```mermaid
sequenceDiagram
    actor Approver
    participant Proxy as Proxy
    participant DB as Database

    Proxy->>Approver: Email approval link via SMTP (triggered when request is created)
    Approver->>Proxy: GET /approve/{approval_id}
    Proxy->>DB: Fetch approval request (validate it exists and is pending)
    Proxy-->>Approver: Login page (scoped to this approval request)

    Approver->>Proxy: Submit username, password, TOTP code
    Proxy->>DB: Fetch password_hash, totp_secret, encrypted_private_key, key_salt for user
    Proxy->>Proxy: Verify bcrypt(password) against password_hash
    Proxy->>Proxy: Verify TOTP code against totp_secret

    alt Authentication failed
        Proxy-->>Approver: Error — invalid credentials
    else Authentication succeeded
        Proxy->>Proxy: Derive enc_key = PBKDF2(password, key_salt)
        Proxy->>Proxy: Decrypt private_key from encrypted_private_key
        Proxy-->>Approver: Approve/Deny page (request details)
        Approver->>Proxy: Click Approve or Deny
        Proxy->>Proxy: Sign approval_record with private_key (Ed25519)
        Proxy->>Proxy: Discard private_key from memory
        Proxy->>DB: Store approval_record + approval_signature + decision
        alt Approver clicked Deny
            Proxy->>DB: Mark request as rejected
            Proxy->>Proxy: Notify remaining approvers — request denied
            Proxy-->>Approver: Request rejected
        else Approver clicked Approve
            Proxy->>Proxy: Check quorum
            alt Quorum reached
                Proxy->>Proxy: Execute approved action
                Proxy->>Proxy: Email all approvers — action executed
                Proxy-->>Approver: Action executed
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
- The current quorum status (e.g., "1 of 3 approvals received")
- Two buttons: **Approve** and **Deny**

---

## Asymmetric Key Approval Signing

Approval records are signed using per-approver Ed25519 key pairs. See [ADR 0004](adr/0004-asymmetric-key-approval-signing.md) for the full decision rationale, including why MFKDF-style signing was considered and rejected.

### Key Pair Lifecycle

**At enrollment:** The proxy generates a unique Ed25519 key pair for the approver.

```text
(private_key, public_key) = Ed25519.generate()
enc_key = PBKDF2(password_plaintext, key_salt, iterations=600000, dklen=32)
encrypted_private_key = AES-256-GCM-Encrypt(private_key, enc_key)
```

`public_key`, `encrypted_private_key`, and `key_salt` are stored. The plaintext `private_key` is discarded.

**At password change:** The private key is re-encrypted under the new password. The key pair itself does not change; all past signatures remain verifiable with the unchanged public key.

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
    decision            // "approve" or "deny"
}

enc_key = PBKDF2(password_plaintext, key_salt, ...)
private_key = AES-256-GCM-Decrypt(encrypted_private_key, enc_key)
approval_signature = Ed25519Sign(private_key, canonical_json(approval_record))
// private_key discarded from memory
```

Both `approval_record` and `approval_signature` are stored.

### Security Properties

| Threat | Protection |
|---|---|
| Attacker reads DB (no password) | Has `encrypted_private_key` but cannot decrypt without the password. Cannot forge. |
| Attacker has DB + cracks password | Can decrypt `private_key` and forge signatures. Password cracking is the required bar — same as any credential-backed scheme. |
| Attacker modifies an approval record in DB | `Ed25519Verify(public_key, approval_record, approval_signature)` fails — modification is detectable without any password. |
| Approver changes password | Private key is re-encrypted; public key and all past signatures are unaffected. |
| Replay attack | Approval records contain `approval_request_id`; the proxy rejects duplicate decisions from the same approver for the same request. |

### Audit Verification

**Tamper-evidence (no credentials needed):** Any modification to a stored `approval_record` is immediately detectable using the stored `public_key`:

```text
Ed25519Verify(public_key, canonical_json(approval_record), approval_signature)
```

No password or approver cooperation is required.

**Non-repudiation:** A valid signature proves the approver's private key was used. Since the private key is only accessible by decrypting with the approver's password, a valid signature is strong evidence of the approver's participation. An approver disputing an approval must claim their password was compromised — a high bar.
