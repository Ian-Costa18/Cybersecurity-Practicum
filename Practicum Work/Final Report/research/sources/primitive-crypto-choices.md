---
bucket: C1
title: Cryptographic choices & rationale (inherited-secure, not novel; why not threshold)
report_home:
  - "§5 — System Design: the crypto is inherited-secure, not a novel claim (one line)"
  - "Appendix — Cryptographic-choice rationale: why credential-backed over threshold signatures, plus the primitives actually used"
proxy_grounding:
  - docs/cryptography.md
  - docs/adr/0001-credential-backed-approval.md
  - docs/adr/0003-cryptographic-primitive-selection.md
related_notes:
  - primitive-multiparty-approval.md
  - ../controls-matrix/ctrl-the-proxy.md
bib_keys:
  - ed25519-bernstein
  - ed25519-provable-security
  - rfc8032
  - rfc8018
  - nist-sp-800-132
  - gcm-mcgrew-viega
  - nist-sp-800-38d
  - fips197
  - bcrypt-provos-mazieres
  - fips180-4
  - rfc2104
  - fips198-1
  - rfc6238
  - shamir-secret-sharing
  - bip11-multisig
  - frost
  - gg20
  - gg18
  - dkls18
  - vault-seal-unseal
status: vetted
---

## Why the report needs this

**Synthesis.** The report's contribution is the *authorization layer* (m-of-n human approval bound to
an artifact), not the cryptography under it. This note exists so §5 can say in one honest line that the
crypto is **inherited-secure** — every primitive is a standard, FIPS-forward building block used in
exactly one role — and so the Appendix can defend the one design choice a cryptographer would
challenge: **credential-backed approval over threshold signatures.** The decisive factor there is
**usability, not a security gap**; threshold signatures are stronger on one specific axis but do not
meaningfully beat the proxy's threat model, and they impose key-management on approvers the design
explicitly assumes are non-technical. Everything here is `REUSE`: it consolidates
[docs/cryptography.md](../../../../docs/cryptography.md) (the formal home), [ADR 0001](../../../../docs/adr/0001-credential-backed-approval.md),
and [ADR 0003](../../../../docs/adr/0003-cryptographic-primitive-selection.md) into a report-facing
form, and cites — not copies — the primary standards those docs already anchor.

## Sources (vetted this session)

**Primitives actually used** (each anchors "standard → proxy role"):

- Brendel, Cremers, Jackson, Zhao — *The Provable Security of Ed25519* (IEEE S&P 2021) → `ed25519-provable-security`
  · the SUF-CMA proof for Ed25519-IETF · [formal]
- Bernstein et al. — *High-Speed High-Security Signatures* (2012) → `ed25519-bernstein` · original Ed25519
  algorithm/curve · [primary]
- RFC 8032 — *EdDSA* → `rfc8032` · the IETF variant (the `S ∈ {0,…,l−1}` bounds check) the proxy specifies · [primary]
- RFC 8018 (PKCS #5 v2.1) → `rfc8018` and NIST SP 800-132 → `nist-sp-800-132` · PBKDF2 definition and the
  FIPS-approved parameter envelope · [primary]
- McGrew & Viega — *The Security and Performance of GCM* (2004) → `gcm-mcgrew-viega`; NIST SP 800-38D →
  `nist-sp-800-38d`; FIPS 197 → `fips197` · AES-256-GCM security theorems, mode spec, and cipher · [formal | primary]
- Provos & Mazières — *A Future-Adaptable Password Scheme* (1999) → `bcrypt-provos-mazieres` · bcrypt, and its
  own admission that ε-security is unproven · [primary]
- FIPS 180-4 → `fips180-4` · SHA-256, the artifact-digest primitive · [primary]
- RFC 2104 → `rfc2104` and FIPS 198-1 → `fips198-1` · HMAC-SHA-256 (session-cookie integrity + audit hash chain) · [primary]
- RFC 6238 → `rfc6238` · TOTP, the second factor · [primary]

**Threshold-signature lineage** (context for the why-not argument only — *not implemented tech*):

- Shamir — *How to Share a Secret* (1979) → `shamir-secret-sharing` · the m-of-n threshold foundation · [primary]
- BIP 11 — *M-of-N Standard Transactions* (2011) → `bip11-multisig` · m-of-n in production (Bitcoin multisig) · [primary]
- Komlo & Goldberg — *FROST* (2020) → `frost` · the marquee round-optimized threshold-Schnorr scheme · [formal]
- Gennaro & Goldfeder — *One Round Threshold ECDSA with Identifiable Abort* (2020, GG20) → `gg20` · [formal]
- Gennaro & Goldfeder — *Fast Multiparty Threshold ECDSA…* (2018, GG18) → `gg18` · the scheme whose known
  implementation bugs anchor the "complex protocols with real risk" point · [formal]
- Doerner, Kondi, Lee, Shelat — *Threshold ECDSA from ECDSA Assumptions* (2018, DKLS18) → `dkls18` · the third
  scheme ADR 0001 names alongside FROST/GG20 · [formal]
- HashiCorp — *Seal/Unseal* → `vault-seal-unseal` · m-of-n threshold as the **default** config of a mainstream
  secrets manager · [primary]

## Key facts (anchored)

### (a) The primitives actually used — one anchored line each

Each primitive sits in exactly one role. This is the invariant that makes the security argument
auditable, stated verbatim in the proxy's formal doc:

> "Each primitive has exactly one role. The bcrypt output is never used as key material. The PBKDF2
> output is never stored. The Ed25519 private key is never written to disk in plaintext. These are not
> conventions — they are invariants; violating any one of them collapses the security argument of the
> entire scheme."
— docs/cryptography.md, *System-Level Model*

*Backs the §5 "inherited-secure, disciplined use" line.*

#### Ed25519-IETF — approval-record signing
> "The Ed25519-IETF variant (RFC 8032, with the S ∈ {0,...,l−1} bounds check in verification) achieves
> **SUF-CMA** (strong unforgeability under chosen-message attack) under the ECDLP assumption on
> Curve25519."
— docs/cryptography.md, *Ed25519-IETF › Formal Security Property* (proof chain: Brendel et al. 2021, Thms 3–4)

SUF-CMA is the right property because approval records must be non-repudiable. Primary anchors:
`ed25519-provable-security` (the proof), `ed25519-bernstein` (the algorithm), `rfc8032` (the IETF bounds check).

#### PBKDF2-HMAC-SHA-256 — deriving `enc_key` from the approver password
> "**FIPS 140-2/140-3 approved** (NIST SP 800-132); Argon2id is not NIST-approved."
— ADR 0003, *Key derivation*

Parameters: `c = 600,000`, 128-bit per-user salt, 32-byte output (`nist-sp-800-132` §5; `rfc8018` §5.2). The
output is never stored — it is derived at login and discarded. FIPS-forward standardization is the reason
it beats the memory-hard Argon2id in this threat model.

#### AES-256-GCM — encrypting the Ed25519 private key **and** the TOTP secret at rest
> "Both confidentiality and authentication reduce to a single assumption (AES is a secure PRP), with no
> additional assumptions."
— docs/cryptography.md, *AES-256-GCM › Formal Security Property* (McGrew & Viega Thms 1–2, `gcm-mcgrew-viega`)

AEAD in one primitive removes the Encrypt-then-MAC composition footgun; AAD binds each ciphertext to its
owning row so a cross-key transplant fails (`nist-sp-800-38d` for the IV-uniqueness invariant; `fips197`).

#### bcrypt (cost ≥ 12) — approver password verification (verifier only, never key material)
> "we cannot formally prove bcrypt ε-secure, any flaw would likely deal a serious blow to the
> well-studied blowfish encryption algorithm."
— Provos & Mazières (1999), quoted in docs/cryptography.md, *bcrypt › Formal Security Property* (`bcrypt-provos-mazieres`)

The honest caveat the report should not hide (from ADR 0003): OWASP now ranks bcrypt a **legacy fallback**
(Argon2id → scrypt → PBKDF2 → bcrypt); it is kept here for **FIPS consistency** with the PBKDF2 key-wrap and
its adaptable cost, not because it is the modern first choice.

#### SHA-256 — artifact hash binding (the integrity guarantee behind PUB-1)
> "The hash-binding guarantee reduces to two standard properties of SHA-256:" collision resistance and
> second-preimage resistance.
— docs/cryptography.md, *SHA-256 › Formal Security Property* (`fips180-4`)

Approvers approve *a digest*; a pre-publication recheck of the artifact's SHA-256 blocks any substitution.
SHA-1/MD5 are rejected precisely because a broken collision property would defeat the binding.

#### HMAC-SHA-256 — session-cookie integrity and the audit hash chain
> "the audit rows form an **HMAC-SHA-256 hash chain**: each row's `entry_hash` commits to its content and
> the previous row's digest… The chain detects *modification* **and** *deletion/reordering* of whole rows."
— docs/cryptography.md, *Audit Trail Integrity* (`rfc2104`, `fips198-1`)

Scope honesty carried from the doc: this is **tamper-evident append-only integrity against a database-write
attacker (HOST-2)**, not against a host compromise (HOST-1, which can re-derive the key).

#### TOTP (RFC 6238) — the second factor
> "TOTP is only ever verified at a moment the password is present — interactive login and per-vote
> re-authentication both submit both factors — so it is decrypted transiently for the check and discarded."
— docs/cryptography.md, *AES-256-GCM › Role* (`rfc6238`)

This is why the TOTP secret can be wrapped under the same password-derived key lifecycle as the signing key.

### (b) Why credential-backed approval, not threshold signatures

The one design choice worth defending. The two models, in ADR 0001's own words:

> "**Advantage:** Strongest security model; approvers never trust the proxy with their key" · "**Disadvantage:**
> Requires approvers to manage additional cryptographic secrets (keys, key backups, key storage); complex UX"
— ADR 0001, *Option A: Threshold Signatures (FROST, GG20, DKLS)*

The decisive rationale is that threshold signatures do not actually *win* the proxy's threat model:

> "Threshold signatures don't solve the multi-identity compromise case either; they just shift the attack
> from 'compromise one approver's password' to 'compromise one approver's key' — not a meaningful
> improvement given the constraint that approvers should not manage keys."
— ADR 0001, *Rationale §4*

And the implementation-risk half — why the marquee threshold schemes are not casually adopted:

> "Threshold signature schemes (FROST, GG20) are complex cryptographic protocols with known implementation
> risks (GG18 bugs, Alpha-Rays attacks)."
— ADR 0001, *Rationale §3*

Lineage anchors for that sentence (context, not adopted tech): m-of-n originates with Shamir secret sharing
(`shamir-secret-sharing`) and reached production in Bitcoin multisig (`bip11-multisig`); the modern
threshold-signature line is FROST (`frost` — *"single-round signing variant with a preprocessing stage that
is agnostic to the choice of the signing coalition"*), GG20 (`gg20`, one-round threshold ECDSA with
identifiable abort), GG18 (`gg18`, whose *bugs* are the cited risk), and DKLS18 (`dkls18`).

The security give-up is precisely bounded — worth stating so the report neither over- nor under-claims:

> "The proxy must be trusted to honestly record approvals. A compromised proxy *before* approval can approve
> anything; a compromised proxy *after* approval cannot forge approvals retroactively (they are
> cryptographically tied to past auth events)."
— ADR 0001, *Trade-offs Accepted*

Finally, a data point that m-of-n threshold is not exotic — it is the shipped default of a mainstream tool:

> "the default Vault configuration uses an algorithm known as Shamir's Secret Sharing to split the key into
> shares." · "Vault requires a certain threshold of shares to reconstruct the unseal key."
— HashiCorp, *Seal/Unseal* (`vault-seal-unseal`; defaults `-key-shares (int: 5)`, `-key-threshold (int: 3)`)

This is threshold crypto over a *secret* (key custody), **not** human authorization of an operation — which
is exactly why it lives here as lineage and was moved out of the P1 industry-adoption note. It supports one
sentence: "m-of-n threshold recovery is a well-trodden default; the proxy deliberately chose the
credential-backed variant of the same m-of-n idea for approver usability."

## How the proxy relates

One honest point, said once. Threshold signatures are stronger on exactly **one** axis: the approvers never
have to trust the proxy to record their approval honestly, because the signature is theirs. The proxy gives
that up — a compromised-*before*-approval proxy can forge, though a compromised-*after* one cannot revoke a
recorded approval. Against the adversary the proxy actually targets — a **single compromised identity** — both
models collapse to "compromise one identity," and threshold only relabels that from *one password* to *one
key* while adding key-management burden to approvers the design assumes are non-technical. So the choice is
**not a security concession dressed up as usability**: it is a case where the stronger-looking primitive
does not beat the threat model, and usability breaks the tie cleanly. The crypto is inherited, standard, and
FIPS-forward; the contribution is the authorization gate above it, not the primitives.

## Source decisions

- **Anchor to `docs/cryptography.md` and the ADRs, cite the primary standards through them.** This is a `REUSE`
  bucket over material already read and formally treated in-repo; the load-bearing verbatim quotes are the
  proxy's *own* statements of use (which carry the onward Brendel/McGrew-Viega/RFC anchors), not re-fetched
  paper text. Per the process's "link, don't duplicate," the formal home stays `cryptography.md`; this note is
  the report-facing consolidation.
- **Keep the threshold lineage bounded to ADR 0001's argument.** Cite Shamir + BIP 11 (lineage), FROST +
  GG20 + GG18 + DKLS18 (the schemes/risks the ADR actually invokes), and Vault (shipped default). The broader
  threshold-crypto literature is outside this report-facing rationale; it is not needed to support the
  selected credential-backed design.
- **State the security give-up, don't bury it.** ADR 0001 is explicit that credential-backed is *weaker* than
  threshold on the trust-the-proxy axis. The report is more credible for saying so plainly and then showing the
  give-up does not matter against the actual adversary — same honesty posture as the XZ "not a silver bullet" anchor.
