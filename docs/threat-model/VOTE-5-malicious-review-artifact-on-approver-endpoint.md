---
id: VOTE-5
title: "Malicious Review Artifact on the Approver Endpoint"
stride: ["Elevation of Privilege"]
attack: [T1204.002]
capability: [L2]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: high
bucket: 3
related: [CORE-1, VOTE-3, CODE-1, HOST-1]
tests:
  - tests/approvals/test_approve.py::test_artifact_download_neutralizes_a_hostile_filename
  - tests/approvals/test_approve.py::test_artifact_download_returns_the_staged_bytes
---

# VOTE-5 — Malicious Review Artifact on the Approver Endpoint

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L2 — a requester who can submit a publish request (a single commodity requester API token). The upload's *bytes* are the weapon: the attacker controls the artifact, and the approve flow invites n trusted approvers to download it for inspection ([mvp.md](../mvp.md) §Approve/Deny Page). |
| **What the attacker gains** | Code execution on an **approver's own endpoint**. Reviewing a Python package usually means running it — an approver who `pip install`s the artifact, executes its `setup.py`, lets a build backend run, or opens it in a code-executing IDE hands the attacker arbitrary execution on the machine they inspect from. The review step, meant to *catch* a malicious upload, is itself the delivery channel: **User Execution: Malicious File (T1204.002)**. What that execution then yields is the compromised endpoint's — most cheaply, that approver's proxy credentials and live TOTP the moment they authenticate a vote. |
| **What they cannot do** | Cause execution *without an approver acting on the file*. The download is served inert (see Current defenses) — nothing runs on receipt; the attacker needs the victim to install/build/open it. A single compromised endpoint also does **not** publish: it yields at most one approver's vote, and m-of-n leaves ≥1 independent barrier standing — this collapses into [CORE-1](CORE-1-single-approver-account-compromise.md) (one identity, one vote). And the artifact bytes cannot mutate on the way to PyPI: publication re-verifies the approved SHA-256 ([PUB-1](PUB-1-package-swap-between-upload-and-publication.md)). |
| **Current defenses** | Honest audit — the download is served **inert**, and that is the whole of the in-app defense. `GET /approve/{id}/artifact` returns `application/octet-stream` with `Content-Disposition: attachment` (never `inline`), plus `X-Content-Type-Options: nosniff` from the app's security-header middleware ([#154](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/154), `src/msig_proxy/app.py`), so a browser will not render or sniff-then-run the bytes it saves; and the requester-controlled filename is encoded injection-safe (RFC 6266 / RFC 5987 `filename*`, `src/msig_proxy/approvals/approve.py`), so a hostile name can neither inject header syntax nor silently disguise the saved file's nature. Demonstrated by `tests/approvals/test_approve.py::test_artifact_download_neutralizes_a_hostile_filename` (a name carrying `"`/CRLF smuggles no header and survives only percent-encoded) and `::test_artifact_download_returns_the_staged_bytes` (the inert headers hold on the normal path). **These close only the browser-auto-open / sniff sliver — they do nothing for `pip install`**, which is why the primary control is operator-enforced, not in-app. |
| **Operator configuration** | Inspect any *unapproved* artifact only in a **disposable, credential-free, network-isolated sandbox** (a throwaway VM or container), never on a primary dev machine, and never `pip install` or build it into a real environment. This is the load-bearing control: a throwaway sandbox holds no standing credentials to steal, and a *per-approver* sandbox breaks the common-mode amplification below — the same artifact detonating on m endpoints no longer harvests m real votes. Onboard it as a hard rule (an [operator-checklist.md](operator-checklist.md) item). |

## Delta

Introduced: this surface exists only because the proxy interposes n approvers between an
untrusted uploader and the publish. In the direct-publish baseline a maintainer publishes
their *own* artifact — there is no third party downloading an untrusted artifact to review,
so there is no baseline exposure for this to cancel against. Both `*_baseline` ratings are
`N/A`.

## Split legs

The threat has two legs with different reach; per the per-leg convention the primary leg is
the headline and the secondary is documented here, not averaged in.

- **Leg 1 — single-endpoint compromise (primary, residual medium × high).** One approver runs
  the artifact; that one endpoint (and, most cheaply, that one approver's vote credentials) is
  compromised. It collapses into [CORE-1](CORE-1-single-approver-account-compromise.md): one
  identity, one vote, the m−1 barrier still standing. This is the headline `medium × high`.
- **Leg 2 — common-mode independence collapse (secondary, residual low × critical).** The
  *same* artifact runs on enough reviewer endpoints that one upload harvests m votes — defeating
  the independence the quorum rests on and publishing with no barrier left. One artifact served
  identically to every reviewer is exactly the common-mode failure m-of-n assumes away. Severity
  is critical (an unauthorized package reaches PyPI), but likelihood is `low`: the one artifact
  must clear the victim-execution gate on m *distinct* endpoints before any reviewer sandboxes it
  or spots the malice — a far higher bar than compromising one.

## Ratings

**Likelihood residual `medium`** is a justified downward deviation from the L2 default (`high`).
Reaching the seat is cheap — any requester can upload — but the vector requires a *second,
non-guaranteed* step the attacker does not control: the victim approver must actually
install / build / open the file, not merely receive it. That victim-execution gate is the
discount. It is deliberately encoded as a **likelihood** discount, **not** a severity one:
forced or automatic execution (an approver *compelled* to run it, or an RCE that fires on mere
receipt — the rejected-viewer case below) would raise severity to critical; requiring the victim
to act is what holds Leg 1 at `high`.

**Severity residual `high`** (Leg 1): code execution on one reviewer endpoint corrupts one
authorization input while ≥1 independent barrier stands — the mission ladder's ceiling for
"anything still gated on other approvers independently approving." Leg 2 reaches `critical`
precisely because it removes that last barrier, but its `low` likelihood keeps it off the
headline.

## Why bucket ③

Operator-enforced: the proxy cannot stop an approver from choosing to run a file on their own
machine — only deployment practice (sandboxed inspection) can, and a throwaway sandbox is also
the one cheap control that touches Leg 2. The in-app safe-download hardening above is real and
tested, but it bounds only the browser-auto-open / sniff sub-path; it does not make `pip install`
of the saved bytes safe, so it cannot raise the headline out of ③. The honest posture is: a
narrow in-app leg is closed and demonstrated, the load-bearing control is operator config.

## ATT&CK mapping

T1204.002 — *User Execution: Malicious File*: the adversary relies on a user (here, an approver)
to run a file they supplied. The exact shape of this threat. The downstream supply-chain
consequence for the compromised developer's *other* work, or for consumers of anything they
later ship, is a consequence, not an operation against this system, and is deliberately not
tagged (T1195.002 stays prose per the catalog's ATT&CK conventions).

## Rejected: an in-proxy artifact viewer — net negative, not built

Serving the artifact through an in-proxy viewer (so approvers need not download it) was
considered and **rejected as the headline fix**. A *naive* parsing viewer — unzip the wheel,
parse the metadata, render the README, syntax-highlight the source — turns the artifact into
input to *our* parser: a bug fires **automatically on open** (removing the victim-action gate
that holds this threat's likelihood down) and moves the blast radius to whichever context
parses. Server-side parsing means code execution on the **proxy that holds the real PyPI
token** — the [CODE-1](CODE-1-application-layer-vulnerability.md) /
[HOST-1](HOST-1-proxy-host-compromise.md) apex. Client-side rendering means XSS in the
approver's authenticated approve session — [VOTE-3](VOTE-3-browser-borne-approval-coercion.md).
Both are common-mode across every reviewer. Only a *strictly non-interpreting, inert* viewer
(bytes as text/hex, a sandboxed archive listing, no active content, strict CSP) is safe, and
even that does not replace download — reviewing a Python package often means installing and
running it. Net: more attack surface for a partial substitute. Not worth building now.

## Future-vision mentions (named, not planned — no committed work)

Per the catalog contract these are explicitly-marked mentions, **not** Planned-defenses entries
(no live issue commits to them):

- **Inert manifest / version-diff** — computed inert data (file listing, sizes, per-file
  SHA-256s, declared dependencies, a diff against the last published version). Lower surface than
  a rendering viewer and often higher review signal; the best "reduce the need to download" option
  if one is ever built.
- **Build provenance / Trusted Publishing** (Sigstore / SLSA / PyPI Trusted Publishing) — the
  root-cause fix: approve "built by our CI from commit X" instead of eyeballing bytes, so nobody
  downloads anything. Expands scope and shifts trust to CI; out of the package-publishing MVP.
- **Server-side scanning / detonation** — heavy, high false-positive, and adds a subsystem that
  parses untrusted input server-side (the very surface the rejected viewer creates). Out of MVP.
