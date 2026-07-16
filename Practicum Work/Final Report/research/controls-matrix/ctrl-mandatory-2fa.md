<!-- LTeX: enabled=false -->
# Mandatory 2FA / MFA — row 1

**Axis:** Authentication
**Verdicts:** Stolen credential `~` · Trusted insider `✗` · Compromised CI `✗` · Direct publish `✗`

Scenario names and verdicts are fixed by [evaluation-plan.md §1, Move 1](../../../../docs/evaluation-plan.md).

## Primary sources
- PyPI blog, "2FA Required for PyPI" — https://blog.pypi.org/posts/2024-01-01-2fa-enforced/ (accessed 2026-07-15) → `pypi-2fa-enforced`
- npm Docs, "Requiring 2FA for package publishing and settings modification" — https://docs.npmjs.com/requiring-2fa-for-package-publishing-and-settings-modification/ (accessed 2026-07-15) → `npm-2fa-publish`
- Palo Alto Unit 42, "'Shai-Hulud' Worm Compromises npm Ecosystem in Supply Chain Attack" — https://unit42.paloaltonetworks.com/npm-supply-chain-attack/ (accessed 2026-07-15) → `unit42-shai-hulud`

## What it actually gates
Mandatory 2FA is an **authentication-time** control: it strengthens the proof that the person
signing in is the account owner. On PyPI it is required for web login and sensitive account
actions, but package **uploads authenticate with API tokens or Trusted Publishing and are never
prompted for a TOTP**. On npm, the "auth-and-writes" level *does* prompt for an OTP on
`npm publish` — but **granular and automation tokens bypass 2FA entirely**. So 2FA gates *who logs
in*, and only optionally (and bypassably) gates *the publish action itself*. It never authorizes
*which artifact* ships.

## Documented behavior (anchored)
> PyPI "require[s] 2FA for all users" — during the web login process users "will be asked to
> provide their second method of identity verification"; sensitive actions requiring re-auth
> include adding/removing maintainers and generating API tokens.
— *2FA Required for PyPI* (blog.pypi.org, 2024-01-01)

> "auth-and-writes … requires [an OTP] when publishing a module, setting the latest dist-tag, or
> changing access." When a token has **bypass 2FA** enabled it "will bypass all 2FA requirements at
> all times, regardless of account-level or package-level 2FA settings." The "disallow tokens"
> option requires a maintainer to "publish interactively."
— *Requiring 2FA for package publishing* (docs.npmjs.com)

> "Using the stolen npm token, the malware authenticates to the npm registry as the compromised
> developer. It then identifies other packages maintained by that developer, injects malicious code
> into them, and publishes the new, compromised versions to the registry." The harvested credentials
> were npm tokens read from `.npmrc` — the token path that bypasses 2FA.
— *'Shai-Hulud' Worm Compromises npm Ecosystem* (Unit 42, September 2025)

## Per-column analysis

| Scenario | Verdict | Catches / Misses | Source |
|---|:--:|---|---|
| Stolen credential | `~` | Catches a stolen **password** — 2FA blocks the web login, so the attacker cannot mint an upload token or add themselves as a maintainer. Misses a stolen **token** — an upload/automation token bypasses 2FA and publishes directly. Realized in Shai-Hulud (2025): "using the stolen npm token, the malware authenticates to the npm registry … and publishes the new, compromised versions." ⚠ | `pypi-2fa-enforced`, `npm-2fa-publish`, `unit42-shai-hulud` |
| Trusted insider | `✗` | The insider passes their own 2FA legitimately; there is nothing for it to catch. | axis argument |
| Compromised CI | `✗` | CI authenticates with tokens; 2FA is an interactive human control and is absent from the pipeline. | `npm-2fa-publish` (token bypass) |
| Direct publish | `✗` | 2FA proves *identity at login*; it does not authorize *whether this artifact should ship*. The authenticated publish proceeds. | `pypi-2fa-enforced` |

> ⚠ **Caveat (Stolen credential).** 2FA partially blocks this scenario: it stops a stolen
> **password**, but not a stolen **token**. The verdict is `~` because it holds in some cases and
> not others, not in all cases.

## How the proxy beats this row
2FA is **single-party identity proof at authentication time** — one factor, one human, answering
"is this the account owner?" The proxy operates one layer up, at **authorization time**: it
requires **m-of-n independent, re-authenticated approvals bound to the exact artifact by hash**
before the publish credential is ever used. Under 2FA, a single stolen token or a phished OTP
yields a unilateral publish. Under the proxy, one compromised seat cannot reach quorum, and the
surviving approvers see an artifact-bound request they never initiated — which is exactly the
Stolen-credential (Shai-Hulud) result the matrix turns on.

## references.bib — to add (tracked in #171)
- `pypi-2fa-enforced` — PyPI, "2FA Required for PyPI" (2024-01-01).
- `npm-2fa-publish` — npm Docs, "Requiring 2FA for package publishing and settings modification".
- `unit42-shai-hulud` — Palo Alto Unit 42, "'Shai-Hulud' Worm Compromises npm Ecosystem in Supply Chain Attack" (2025).
