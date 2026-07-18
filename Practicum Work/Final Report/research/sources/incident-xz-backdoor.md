<!-- LTeX: enabled=false -->
---
bucket: I2
title: XZ Utils backdoor / CVE-2024-3094 (2024)
report_home:
  - "§3 — Background case study (marquee, trusted-insider)"
  - "§4 — Trusted-insider column anchor; the honest-limit case the proxy does NOT beat"
proxy_grounding:
  - docs/threat-model/CORE-3-insider-collusion.md
  - research/controls-matrix/ctrl-the-proxy.md   # Caveat 2 — the review-surviving payload
related_notes:
  - controls-matrix/ctrl-the-proxy.md
  - incident-shai-hulud.md
bib_keys: [openwall-xz-backdoor, cve-2024-3094, xz-timeline-swtch]
status: vetted
---

## Why the report needs this

XZ is the report's marquee **trusted-insider** case study (§3) and the anchor for that column of the
§4 positioning matrix — and it is deliberately the mirror image of Shai-Hulud. Shai-Hulud is the
*clean win*: one stolen token, no human in the loop, and the proxy breaks the auto-republish leg
outright. XZ is the *honest limit*: a contributor ("Jia Tan") cultivated legitimate maintainer trust
over **more than two years**, then shipped a backdoor **engineered to survive human review** —
obfuscated inside binary test fixtures and a build script, present only in the release tarball and not
in the git source anyone reads. It is the real-world realization of
[CORE-3 — Insider Collusion](../../../../docs/threat-model/CORE-3-insider-collusion.md) and of
[ctrl-the-proxy Caveat 2](../controls-matrix/ctrl-the-proxy.md): the payload a quorum can approve
without ever seeing it. Leading §3's second case with the attack multi-party authorization *raises the
bar against but does not prevent* is what keeps the whole evaluation honest rather than a sales pitch.
Every control that should have stopped XZ — the committer was authenticated, the release was signed by
the legitimate process, the build was authentically the project's own — was satisfied, because the
malice originated *inside* the trust boundary. (Synthesis; anchors below.)

## Sources (vetted this session)

- Russ Cox, "Timeline of the xz open source attack" (2024, accessed 2026-07-17) → `xz-timeline-swtch`
  · the rigorous multi-year social-engineering reconstruction: the Jia Tan persona, the sockpuppet
  pressure campaign, the trust build 2021–2024 · [formal]
- Andres Freund, "backdoor in upstream xz/liblzma leading to ssh server compromise" (oss-security,
  2024-03-29, accessed 2026-07-15) → `openwall-xz-backdoor` · **primary disclosure**: the accidental
  SSH-latency discovery, and that the exploit lived in the tarball's build/test files, not git ·
  [primary]
- National Vulnerability Database, "CVE-2024-3094" (accessed 2026-06-25) → `cve-2024-3094`
  · the severity record: CVSS 3.1 base 10.0 (Critical) · [primary]

## Key facts (anchored)

### A trusted committer, cultivated over more than two years
> "Over a period of over two years, an attacker using the name 'Jia Tan' worked as a diligent,
> effective contributor to the xz compression library, eventually being granted commit access and
> maintainership."
— Russ Cox, *Timeline of the xz open source attack*

The trust build is dated and legitimate-looking: first innocuous patch to xz-devel on **2021-10-29**;
first commit merged with the `jiat0218@gmail.com` author on **2022-02-07**; maintainer Lasse Collin
notes on **2022-05-19** that "Jia Tan has helped me off-list with XZ Utils and he might have a bigger
role in the future"; GitHub org member **2022-10-28**; first direct repo commits **2022-12-30**; first
release tagged by Jia Tan (v5.4.2) **2023-03-18**. (Russ Cox timeline.) This is the load-bearing
premise of the trusted-insider column: **the attacker was, by every mechanical test, a legitimate
maintainer** by the time the payload shipped.

### The pressure campaign — sockpuppets manufacturing the handoff
> "Patches spend years on this mailing list. There is no reason to think anything is coming soon."
> — "Jigar Kumar" (2022-04-22); and "Why not pass on maintainership for XZ for C so you can give XZ
> for Java more attention?" — "Dennis Ens" (2022-06-21)
— Russ Cox, *Timeline of the xz open source attack*

Coordinated personas pressured the burned-out solo maintainer to cede control, after which Collin
concedes Jia Tan is "practically a co-maintainer already" (2022-06-29). Synthesis: the social
engineering was aimed squarely at the *human* trust decision — exactly the decision the proxy relocates
to a quorum, and exactly the decision this attacker was patient enough to corrupt anyway.

### The payload was built to survive review — hidden where reviewers don't look
> "The files containing the bulk of the exploit are in an obfuscated form in
> tests/files/bad-3-corrupt_lzma2.xz tests/files/good-large_compressed.lzma committed upstream."
— Andres Freund, oss-security disclosure

> "That line is *not* in the upstream source of build-to-host, nor is build-to-host used by xz in git.
> However, it is present in the tarballs released upstream."
— Andres Freund, oss-security disclosure

This is the decisive §4 fact and the heart of Caveat 2: the malicious logic lived in **binary test
fixtures and the release tarball's build machinery**, not in the human-readable git source. The
backdoor was activated at build time and delivered only in the shipped artifact — precisely engineered
to pass the normal review of a competent maintainer.

### Discovered by accident, not by any control
> "After observing a few odd symptoms around liblzma (part of the xz package) on Debian sid
> installations over the last weeks (logins with ssh taking a lot of CPU, valgrind errors) I figured
> out the answer."
— Andres Freund, oss-security disclosure

The backdoor targets `sshd` (via distributions that patch OpenSSH to link `libsystemd`, which depends
on `liblzma`) and was caught only because Freund chased a **~0.5s SSH login slowdown** (`0m0.807s` vs
`0m0.299s`). No authentication check, no signature verification, and no build-provenance attestation
detected it — every one of those was satisfied. Backs the §3 "why existing controls failed" beat.

### Severity and scope
> CVSS 3.1 base score **10.0 (Critical)**; malicious code in xz / liblzma versions **5.6.0–5.6.1**.
— National Vulnerability Database, *CVE-2024-3094*

Caught before wide distribution integration ("xz 5.6.0 and 5.6.1 have not yet widely been integrated
by linux distributions … mostly in pre-release versions" — Freund). The near-miss is part of the
story: near-total compromise of OpenSSH-via-systemd on major distros, averted by one engineer's
curiosity.

## How the proxy relates

**What it beats (the modest, real win).** The proxy forbids *unilateral* publication. The lone Jia Tan
who holds one seat cannot ship on his own signature: a release requires **m independent,
re-authenticated approvals, each Ed25519-bound to the artifact's SHA-256**. So even a fully-trusted
maintainer is reduced to *one vote of m* and must recruit or deceive m−1 independent approvers. Against
the *historical* XZ — a single committer with effective sole control — that is a genuine structural
barrier: the attack as it actually happened needed exactly one trusted seat, and the proxy raises that
floor.

**What it does NOT beat (the honesty anchor — say it plainly).** The XZ payload was **designed to
survive honest review**. The proxy's strongest posture is that approvers approve `hash(the shipping
artifact)`, so they inspect *the poisoned tarball's exact bytes* — not the git repo, not a package
name, the real thing that ships. That closes the origin≠behavior gap that sinks provenance. But it does
**not** raise reviewers' ceiling: if the malice is obfuscated in binary test fixtures and build
machinery well enough that m−1 competent reviewers miss it — as it demonstrably was here, against the
whole open-source community for over two years — then a genuine quorum approves genuine-looking bytes,
and that is a *legitimate approval by construction*. The proxy binds the decision to the right bytes
and puts them in front of humans; it is **not a detector of malice** and never claims to be. Against a
sophisticated actor who spends years building trust specifically to plant a review-surviving payload,
the proxy does not win this cell. That is the accepted limitation ([CORE-3](../../../../docs/threat-model/CORE-3-insider-collusion.md),
bucket ④; ctrl-the-proxy Caveat 2), and stating it is the point of putting XZ in the report.

**The one thing the proxy still adds even here (deterrence, not prevention).** *(Synthesis.)* Every vote
is Ed25519-signed and non-repudiable, so a review-surviving payload that *does* pass quorum leaves m
permanent, provable co-signatures on the exact bytes. It does not stop the ship, but it converts an
anonymous, unattributable maintainer action (a direct `git tag` + release, which XZ was) into a signed
record of who authorized these bytes — raising the personal cost and the forensic footprint. That is
the honest residual value, not a claim of coverage.

## Open threads / to verify

- Confirm with the §4 prose that XZ's `✓` verdict for the proxy in ctrl-the-proxy's Trusted-insider
  column reads consistently with this note's "does not beat" framing: the matrix `✓` means *no
  unilateral action + a human gate on the exact bytes*, explicitly **not** immunity (Caveat 2). The
  note and the matrix must not appear to disagree — the `✓` is "raises the bar," the prose is "does not
  prevent," and both are true. Worth one sentence in §4 tying them together.
- The "reduced to one vote of m" win assumes the historical XZ was effectively single-control. Russ Cox
  supports this (Jia Tan gained sole maintainership), but if §3 states it as fact, anchor the
  sole-maintainer claim explicitly to the timeline rather than leaving it as synthesis.

## Source decisions

- **Three sources, no malware-RE deep-dive.** Freund (primary discovery + where the payload hid) and
  Russ Cox (the multi-year trust build) between them anchor every fact the case study leans on; NVD
  carries severity. A payload-internals source (Kaspersky/Akamai on the IFUNC hook and the RSA-gated
  RCE) was considered and **deliberately not pursued** — the report needs the *shape* (trusted insider,
  review-surviving, why every control was satisfied), not the backdoor's byte-level mechanics. Add one
  only if §3 grows a technical paragraph that these three cannot anchor.
- **Russ Cox chosen over Evan Boehs' "Everything I Know About the XZ Backdoor"** as the trust-build
  anchor: both are widely-cited community timelines, but Cox's is the more careful, dated
  reconstruction and is sufficient alone, so a second overlapping timeline would be redundant weight.
