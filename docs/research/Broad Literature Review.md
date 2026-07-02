# Literature Review: Multi-Party Authorization Proxy

**Prepared for:** Ian Barish, CS 6727 Cybersecurity Practicum

Created with the help of AI.

## TL;DR

- **The novelty claim holds.** Multi-party (m-of-n distinct human) approval is well-established in *narrow, purpose-built* systems — cryptocurrency custody, secrets vaults, cloud backup recovery, and account recovery — but **no existing general-purpose web authentication proxy (Authelia, Authentik, Duo, Okta) requires multiple distinct people to cooperate before granting access to an arbitrary web application.** Those proxies do multi-*factor* authentication for a *single* user, not multi-*person* authentication. This is the project's strongest contribution.
- **The cryptographic substrate is mature but blockchain-motivated.** Shamir's Secret Sharing (1979), threshold signatures (FROST/RFC 9591, GG18/GG20, DKLS), n-of-n multi-signatures (MuSig2), and the threshold MFKDF are all available, but almost none has been adapted to gate the HTTP request lifecycle in a reverse proxy — a concrete, defensible research gap. The project is a **systems/architecture** contribution that *uses* threshold concepts; it is **not** a new cryptographic "proxy signature" scheme, and the report keeps that distinction explicit throughout.
- **The motivating use case is strong and the evaluation path is well-trodden.** Single-maintainer supply-chain compromises (event-stream, ctx, XZ Utils) succeeded precisely because one actor could unilaterally publish a release; m-of-n publish approval would have broken each. Evaluation should follow established templates: the Bonneau et al. (2012) UDS framework + Tamarin/ProVerif formal verification (security), SUS + task-time studies (usability), and proxy-latency/crypto-overhead benchmarks (performance).

---

## 1. OVERVIEW

The proposed project — a general-purpose web authentication proxy (Authelia-style) that requires multiple distinct people to each contribute a secret before access to a protected resource is granted — sits at the intersection of four mature but largely disconnected research areas: (1) software supply-chain security, (2) threshold/multi-party cryptography, (3) reverse-proxy "forward auth" authentication architectures, and (4) usable authentication. The central finding of this review is that the project's core novelty claim is sound: while multi-party approval is well-established in narrow, purpose-built systems, no existing general-purpose web authentication proxy enforces an *m-of-n distinct human* approval requirement before granting access to an arbitrary downstream web application. Existing web auth proxies implement multi-*factor* authentication for a *single* user (something you know + something you have), not multi-*person* authentication across several cooperating users.

The state of the art in the cryptographic substrate is well developed. Shamir's Secret Sharing (Shamir, 1979) provides information-theoretic m-of-n secret splitting; threshold signature schemes such as FROST (Komlo & Goldberg, 2020; standardized in RFC 9591, 2024), GG18/GG20 (Gennaro & Goldfeder, 2018/2020), and the DKLS line (Doerner, Kondi, Lee & shelat, 2018/2019) provide distributed signing without ever reconstructing a key; MuSig2 (Nick, Ruffing & Seurin, CRYPTO 2021) provides n-of-n multi-signatures with key aggregation. These are predominantly motivated by and deployed in blockchain custody, not HTTP authentication. The project must be careful to distinguish itself from cryptographic *proxy-signature* schemes — its contribution is a systems/architecture contribution (a web reverse-proxy enforcement point) that *uses* threshold concepts, not a new cryptographic primitive.

In supply-chain security, recent ecosystem controls have moved toward cryptographic integrity and review — but the *publish/release* action itself in most ecosystems remains a single-actor capability. Several of the most damaging recent incidents succeeded precisely because one compromised or socially-engineered maintainer could unilaterally push a release. This is the strongest motivating use case for the project. On evaluation, the field offers well-defined templates: the Bonneau et al. (2012) UDS framework for comparative authentication evaluation, SUS-based usability studies (SOUPS/USEC), and formal symbolic verification (Tamarin, ProVerif) for protocol security.

---

## 2. AREA-BY-AREA SYNTHESIS

### AREA 1 — Supply-Chain Attacks & Multi-Auth Prevention

**Concrete, named incidents (the use case the instructor asked for):**

- **event-stream / flatmap-stream (npm, 2018).** The original maintainer, Dominic Tarr, who had not actively maintained the package since 2012, transferred ownership to a volunteer ("right9ctrl") who had earned trust through legitimate contributions. The new maintainer added a malicious transitive dependency (`flatmap-stream`) whose minified, published build contained encrypted code not present in the GitHub source. The payload specifically targeted the Copay/copay-dash Bitcoin wallet, harvesting wallet credentials and exfiltrating them. event-stream had roughly 1.5–2 million weekly downloads and ~1,600 dependents, and the malicious dependency went unnoticed for over two months. **A multi-person publish gate would have prevented this:** the single new maintainer could unilaterally publish; requiring a second independent maintainer to co-approve the release would have surfaced the suspicious added dependency.

- **ctx (PyPI) and phpass (PHP/Packagist), May 2022.** A researcher (Yunus Aydın / "SockPuppets") registered the *expired* email domain (`figlief.com`) of the dormant `ctx` maintainer for ~$5, triggered a PyPI password reset, took over the account, and published malicious versions that exfiltrated all environment variables (targeting AWS keys) via Base64 to a Heroku endpoint (`anti-theft-web.herokuapp.com`). The `ctx` package had been untouched since December 2014; roughly 27,000 malicious copies were downloaded. **A multi-person gate breaks the single-account-takeover model:** even with a hijacked account, the attacker would still need a second independent approver to publish.

- **XZ Utils / liblzma backdoor (CVE-2024-3094), 2024.** Over a ~3-year social-engineering campaign, an actor using the alias "Jia Tan" (JiaT75) built trust, gained co-maintainer status, and was able to ship release tarballs containing obfuscated build logic absent from the public Git repository, ultimately backdooring sshd via liblzma (CVSS 10.0). It was caught only because Andres Freund investigated a ~500 ms SSH login delay. **Implication for the project:** even multi-maintainer projects can be compromised if a single trusted actor controls the release artifact; requiring an *independent second human* to sign off on each release tarball would raise the attacker's cost from "compromise one identity" to "compromise/collude with m identities."

- **SolarWinds SUNBURST (build-system context, 2020).** Attackers (UNC2452 / APT29) compromised the *automated build environment* (the SUNSPOT injector) — not the source repo — to insert SUNBURST into digitally signed Orion updates distributed to ~18,000 customers, with selective follow-on targeting (<100 organizations and 9 federal agencies). This illustrates that build/release integrity is a trust boundary distinct from source review, and that single-pipeline control is the weakness; SolarWinds' remediation explicitly added *three separate build environments with separate credentials and cross-checking* — an operational analog of multi-party verification.

**Existing supply-chain controls that already use (partial) multi-party or cryptographic approval:**

- **npm mandatory 2FA.** Per the GitHub Blog (Feb 1, 2022): "Starting today, we are rolling out mandatory 2FA to all maintainers of top-100 npm packages by dependents." The top-500 cohort was enrolled May 31, 2022, and all high-impact maintainers (>1M weekly downloads **or** ≥500 dependents) were enforced Nov 1, 2022. This is **per-maintainer 2FA, still single-actor** — it does not require two people.
- **npm trusted publishing + provenance / staged publishing.** OIDC-based short-lived credentials replace long-lived tokens; "stage-only" permissions can require a human maintainer to review and approve each staged publish with 2FA before it goes public — the closest npm gets to a review gate, but still single-approver.
- **SLSA framework levels.** Level 1 (provenance documentation) → Level 2 (signed, service-generated provenance) → Level 3 (isolated/non-falsifiable build) → **Level 4 (two-party review and hermetic builds)** — Level 4's *two-party review* is the explicit multi-person concept, but it governs source review, not a runtime access decision.
- **Sigstore (cosign/Fulcio/Rekor) + in-toto.** Keyless signing and a transparency log for artifact provenance; integrity, not human quorum.
- **GitHub protected branches with required reviewers.** Code-review quorum for merges — multi-person, but for git merges, not for arbitrary web-app access.

**Key supply-chain analysis papers:** Ohm, Plate, Sykosch & Meier, "Backstabber's Knife Collection" (DIMVA 2020) analyzed **174 malicious packages — 62.6% npm, 16.1% PyPI, 21.3% RubyGems — spanning November 2015 to November 2019**, finding that 61% used typosquatting, 56% triggered on installation, and 55% aimed at data exfiltration; and Vasilakis et al., "A Systematic Analysis of the Event-Stream Incident" (EuroSec 2021).

### AREA 2 — Existing Multi-Person / Multi-Party Authentication Systems

- **AWS Multi-Party Approval (MPA), GA June 2025.** Scoped to a single operation — `CreateRestoreAccessVault` for AWS Backup *logically air-gapped vaults*. An approval team (minimum 3, maximum 20 members; threshold ≥2) authorizes the requester's access via an approval portal. Per AWS documentation, **"Sessions expire 24 hours after the initial request. Expired sessions and non-responses from approvers count as rejections."** This is explicitly **not** general-purpose web auth — it gates one backup-recovery operation.
- **HashiCorp Vault Shamir unseal.** The master key is split with Shamir's Secret Sharing into N shares with threshold K (commonly 3-of-5); a quorum of operators must each submit a share to unseal the vault (and to perform operations like root-token generation). Purpose-built for a secrets vault, manual, and operationally heavy enough that HashiCorp recommends auto-unseal for most users — **not** a general web proxy.
- **CyberArk dual control, Thales/SafeNet HSM multi-custodian ("M-of-N" key ceremonies).** Established enterprise quorum patterns, again purpose-built for privileged-credential release / HSM key operations.
- **Trustee-based social authentication** (Gong & Wang, IEEE TIFS 2014; Facebook Trusted Contacts; Microsoft Windows Live ID per Schechter et al.). The closest academic analog of multi-person approval: a user designates n trustees and needs k (e.g., 3-of-4 or 3-of-5) verification codes — **but for account *recovery*, not routine access**, and the paper's "forest fire attack" shows security correlations between users that the project should heed.

**Assessment of the gap:** None of these functions as a general-purpose web authentication proxy for arbitrary web applications. Every deployed multi-party-approval system is bound to a single resource type (a vault, a backup operation, a blockchain transaction, an account-recovery flow). This is the precise opening the project fills.

### AREA 3 — Web Authentication Proxy Systems

Authelia is the reference architecture. It integrates with reverse proxies via the **forward-auth pattern** (also called external authentication or auth subrequest): the reverse proxy issues a subrequest to an Authelia authorization endpoint (e.g., `/api/authz/forward-auth`) before forwarding traffic. Authelia replies with an HTTP status (200 allow / 401 redirect-to-portal) plus identity headers (`Remote-User`, `Remote-Groups`, `Remote-Email`, `Remote-Name`) that the proxy injects into the upstream request. Authelia is never in the data path to the backend — only authentication metadata reaches it. It supports NGINX (`auth_request` module), Traefik (`ForwardAuth` middleware, v2 and v3), Caddy (`forward_auth` directive), HAProxy, and Kubernetes ingress. Sessions are carried by an HTTP-only, Secure cookie valid across protected subdomains; Authelia only supports resources served over HTTPS (a deliberate decision to avoid misconfiguration risk).

Authentik, Duo, and Okta follow analogous reverse-proxy / IdP patterns. **Crucially, none of these supports multi-*person* approval** — they support multi-*factor* authentication for one user. The project's architecture should follow the forward-auth model (the proxy as a policy enforcement point returning allow/deny), but replace the single-user policy engine with an m-of-n human-approval state machine.

### AREA 4 — Cryptographic Multi-Signature / Threshold Schemes Relevant to Web Auth

- **Shamir's Secret Sharing (SSS), 1979.** Splits a secret S into n shares such that any k reconstruct S and any k−1 reveal *nothing* (information-theoretic security via polynomial interpolation). **Known limitation:** the secret must exist in one place at split time and again at reconstruction — a single point of failure that threshold *signature* schemes avoid.
- **Threshold signature schemes (TSS).** FROST (two-round Schnorr t-of-n; RFC 9591) reduces network rounds and resists known forgery attacks; GG18 (ACM CCS 2018) was the first t≤n threshold ECDSA with no trusted dealer; GG20 added **identifiable abort** (attributing a failed signing round to a specific party — directly relevant to the project's withheld-approval/DoS problem); DKLS (IEEE S&P 2018 two-party, 2019 multiparty) builds threshold ECDSA from minimal assumptions. Implementations have had real bugs (Fireblocks' "A Note on the Security of GG18"; "Alpha-Rays" key-extraction attacks) — a caution that rolling your own TSS is risky.
- **MuSig2 (Nick, Ruffing & Seurin, CRYPTO 2021).** n-of-n multi-signatures with key aggregation, secure under concurrent sessions, outputting ordinary Schnorr signatures in two rounds. Per the authors, MuSig2 is an **n-of-n** scheme (all signers must participate), distinct from **t-of-n** thresholds — a distinction the project should make precise when choosing "all approvers" vs "a quorum."
- **MPC / threshold key derivation for the web.** The threshold **MFKDF** (Nair & Song, USENIX Security 2023) is the rare web-adjacent example: it derives a key from multiple factors with a k-of-n construction, reporting **"less than 12 ms of additional computational overhead in a typical web browser"**; for the 2-of-3 threshold construction, mean setup was ~8.83 ms and mean derivation ~11.90 ms (Figure 7). It targets client-side key derivation/recovery, not request gating, and was later shown vulnerable to cryptanalysis (addressed in MFKDF2) — cite carefully.
- **Adaptation to HTTP/web auth.** There is essentially no published work adapting these primitives to gate a reverse-proxy access decision — the project's opportunity.

### AREA 5 — Technical Challenges in Multi-Person Authentication

- **Proxy bypass for external applications (a real, named limitation).** The forward-auth pattern only protects what is routed through the proxy. Authelia explicitly documents that it relies on the proxy stripping/replacing identity headers and trusting only the proxy's source IP; if a backend trusts injected headers and an attacker can reach it directly, auth is bypassed. For *external SaaS* the user can navigate straight to the vendor's login page. The literature offers no clean cryptographic fix — only network-layer enforcement (the proxy must be the sole network path), trusted-header SSO with strict source-IP allow-listing, or the application natively delegating to the proxy. The project must address this head-on; it cannot retrofit a multi-party gate onto an external site the user can reach independently.
- **Liveness / approver unavailability.** Addressed directly by **m-of-n thresholds** (e.g., 3-of-5 tolerates two missing approvers), as in Vault unseal; Shamir's scheme also lets shares be added/removed without changing the secret. GG20's **identifiable abort** allows the system to attribute a stalled round to a specific non-cooperating party.
- **Replay attacks / time-bounded tokens.** Approval tokens must be nonce- and time-bound; AWS MPA's operational analog is 24-hour session expiry with non-response = rejection. Formal symbolic models (Dolev-Yao; Tamarin/ProVerif) routinely verify replay- and impersonation-resistance.
- **Session hijacking after grant (residual risk).** Once the quorum grants a session cookie (Authelia's model), the session is an ordinary single-user bearer credential — the multi-party property protects the *grant event*, not the *session*. Mitigations: short session lifetimes, re-approval for sensitive actions, token binding.
- **DoS via withheld approval.** A malicious/absent approver can block legitimate access; the m-of-n (not n-of-n) threshold is the mitigation, trading security against availability when choosing m and n.
- **Usability friction / coordination overhead.** Multi-person flows multiply single-user MFA friction (quantified below). Approver-notification UX should follow the Duo Push "approve on your phone" pattern, extended to multiple approvers, with quorum visibility, reminders, and timeout handling. The trustee-authentication literature notes systems must *remind* users who their approvers/trustees are.

### AREA 6 — Evaluation Frameworks for Authentication Systems

**Security.** (a) *Threat modeling* against a defined adversary using the symbolic **Dolev-Yao** model, with automated provers **Tamarin** and **ProVerif** verifying secrecy, authentication, replay-resistance, and impersonation-resistance. Tamarin has been used to verify TLS 1.3, the 5G-AKA authentication protocol, WireGuard, and Apple's PQ3; it supports unbounded sessions and equational theories, making it well-suited to proving properties of the project's approval protocol. (b) *Comparative property analysis* via the **Bonneau, Herley, van Oorschot & Stajano (IEEE S&P 2012) UDS framework** — the canonical rubric that, in the authors' words, evaluates schemes "using a broad set of twenty-five usability, deployability and security benefits that an ideal scheme might provide." (c) Attack-tree / case-study analysis as in Ohm et al. (2020).

**Usability.** The **System Usability Scale (SUS)** is the dominant instrument. Reese et al. (SOUPS 2019) ran a two-week, 72-participant comparative study of five 2FA methods, measuring learnability, satisfaction, and timed task completion. The DuoLungo study (Prapty et al., USEC/NDSS 2026) ran at UC Irvine across the entire 2024–2025 academic year with **2,559 unique participants** (plus a 57-person survey), reporting a **SUS score of 70 ("good" usability, though users find it "annoying"), an average Duo Push overhead of 7.82 seconds**, a 4.35% authentication-failure rate from incomplete Duo tasks, and that **"43.86 percent of survey respondents reported at least one Duo login failure."** De Cristofaro, Du, Freudiger & Norcie (USEC 2014) surveyed **219 Mechanical Turk participants** across security tokens, SMS/email OTPs, and smartphone-app 2FA — note this study measured **ease-of-use, cognitive effort, and trustworthiness factors rather than SUS**. NASA-TLX (cognitive workload) is a recognized complement. Multi-week, ecologically valid deployments are the gold standard over lab-only studies — a methodology the project should replicate for an m-of-n flow, since routine-access multi-person friction is essentially unmeasured in the literature.

**Performance.** For the crypto backend: MFKDF's <12 ms browser overhead and millisecond-scale threshold setup/derive times set expectations; FROST emphasizes round count (two rounds) and network overhead. For the proxy itself: added per-request latency and throughput versus a no-auth baseline — analogous to the cost of Authelia's forward-auth subrequest — are the natural metrics.

---

## 3. RELATED WORK (Structured Table)

| Authors | Year | Title / System | Venue | Relevance |
|---|---|---|---|---|
| A. Shamir | 1979 | How to Share a Secret | Communications of the ACM | Foundational m-of-n secret-sharing primitive; information-theoretically secure; basis for reconstructing a credential from distinct shares. |
| J. Bonneau, C. Herley, P. van Oorschot, F. Stajano | 2012 | The Quest to Replace Passwords | IEEE S&P (Oakland) | Canonical UDS (Usability-Deployability-Security) evaluation framework with 25 benefits; directly usable as the project's evaluation rubric. |
| C. Komlo, I. Goldberg | 2020 | FROST: Flexible Round-Optimized Schnorr Threshold Signatures | SAC 2020 / ePrint 2020/852 | Two-round t-of-n threshold Schnorr signatures; later standardized as RFC 9591; candidate cryptographic backend. |
| J. Nick, T. Ruffing, Y. Seurin | 2021 | MuSig2: Simple Two-Round Schnorr Multi-Signatures | CRYPTO 2021 | n-of-n multi-signatures with key aggregation; clarifies multisig (all sign) vs threshold (t-of-n) distinction central to the project. |
| R. Gennaro, S. Goldfeder | 2018 | Fast Multiparty Threshold ECDSA with Fast Trustless Setup (GG18) | ACM CCS 2018 | First t≤n threshold ECDSA with no trusted dealer; widely deployed in crypto custody; demonstrates multi-party approval in practice. |
| R. Gennaro, S. Goldfeder | 2020 | One Round Threshold ECDSA with Identifiable Abort (GG20) | ePrint 2020/540 | Adds identifiable abort (knowing which party failed) — relevant to the DoS / withheld-approval problem. |
| J. Doerner, Y. Kondi, E. Lee, a. shelat | 2018/2019 | (Two-party / Multiparty) Threshold ECDSA from ECDSA Assumptions (DKLS) | IEEE S&P 2018 & 2019 | Threshold ECDSA from minimal assumptions; supports n-of-n; alternative cryptographic backend. |
| V. Nair, D. Song | 2023 | Multi-Factor Key Derivation Function (MFKDF) | USENIX Security 2023 | Derives keys from multiple factors with a k-of-n threshold; <12 ms browser overhead; closest "web-adjacent" threshold scheme (note later MFKDF2 cryptanalysis). |
| N. Z. Gong, D. Wang | 2014 | On the Security of Trustee-Based Social Authentications | IEEE TIFS | Studies m-of-n recovery via trustees; introduces "forest fire" attacks; closest academic analog of multi-person approval, but for *recovery*. |
| M. Ohm, H. Plate, A. Sykosch, M. Meier | 2020 | Backstabber's Knife Collection | DIMVA 2020 | Dataset/analysis of 174 real malicious packages (npm/PyPI/RubyGems, 2015–2019); attack trees; primary supply-chain evidence base. |
| N. Vasilakis et al. | 2021 | A Systematic Analysis of the Event-Stream Incident | EuroSec 2021 (ACM) | Detailed case study showing single-maintainer-takeover risk. |
| K. Reese, T. Smith, J. Dutson, J. Armknecht, J. Cameron, K. Seamons | 2019 | A Usability Study of Five Two-Factor Authentication Methods | SOUPS 2019 | Two-week, 72-participant comparative 2FA usability study; methodology template. |
| E. De Cristofaro, H. Du, J. Freudiger, G. Norcie | 2014 | A Comparative Usability Study of Two-Factor Authentication | USEC | 219-participant 2FA usability (ease-of-use/cognitive-effort/trust factors); metrics template. |
| R. T. Prapty et al. | 2026 | DuoLungo: Usability Study of Duo 2FA | USEC/NDSS 2026 | 2,559-participant Duo Push study; SUS=70, 7.82 s overhead, 43.86% reported a failure; benchmark data for push-approval UX. |
| S. Meier, B. Schmidt, C. Cremers, D. Basin | 2013 | The Tamarin Prover for Symbolic Analysis of Security Protocols | CAV 2013 / tool | Symbolic model checker (unbounded sessions, Dolev-Yao); used to verify TLS 1.3, 5G-AKA; tool for formally verifying the approval protocol. |
| HashiCorp | — | Vault Shamir Seal/Unseal | Vendor documentation | m-of-n unseal (e.g., 3-of-5) for a secrets vault; purpose-built, not general web auth — supports the gap claim. |
| Amazon Web Services | 2025 | Multi-Party Approval (MPA) for Backup logically air-gapped vaults | Vendor documentation | Quorum approval (team of 3–20, threshold ≥2) for one operation; 24-hour sessions; scoped to AWS Backup — supports the gap claim. |
| Authelia project | — | Authelia forward-auth reverse proxy | Project documentation | Reference architecture for forward-auth / `auth_request` interception; the project's closest single-user analog. |
| SLSA project | — | Supply-chain Levels for Software Artifacts | Specification | Level 4 = two-party review + hermetic builds; the explicit multi-person supply-chain concept. |

---

## 4. KEY CHALLENGES (with citations)

**Technical**

- *Proxy bypass for external applications* — forward-auth only protects routed traffic; external SaaS login pages can be reached directly. No clean fix beyond network-layer sole-path enforcement and strict trusted-header source-IP allow-listing (Authelia documentation).
- *SSS single point of failure* — the secret exists whole at split and reconstruction time; prefer TSS/MPC (FROST, GG20, DKLS) over naive Shamir if the secret is used server-side (Shamir 1979; Wikipedia/SSS analyses; FROST).
- *Replay / time-bounding* — nonce- and time-bound approval tokens, verifiable in Tamarin/ProVerif under a Dolev-Yao attacker (Meier et al. 2013); AWS MPA's 24-hour expiry is the operational analog.
- *Liveness* — m-of-n thresholds tolerate unavailable approvers (Vault 3-of-5); GG20 identifiable abort attributes stalls (Gennaro & Goldfeder 2020).

**Security**

- *Session hijacking after grant* — the granted session is an ordinary bearer credential; the multi-party property protects only the grant event (Authelia session model). Mitigate with short lifetimes, re-approval, token binding.
- *DoS via withheld approval* — mitigated by quorum (m-of-n, not n-of-n); m/n choice trades security vs availability.
- *Insider collusion* — distributing trust so <m insiders cannot act is the core benefit (Shamir 1979; threshold-signature literature) — exactly what would have blocked single-maintainer supply-chain compromises (Ohm et al. 2020; Vasilakis et al. 2021).

**Usability / human factors**

- *Coordination overhead* — multi-person flows compound single-user friction; Duo Push alone adds ~7.82 s and 43.86% of surveyed users reported at least one failure (Prapty et al. 2026); five-method comparative friction documented by Reese et al. (2019).
- *Approver UX* — extend the Duo Push approval pattern to multiple approvers with quorum visibility, reminders, and timeouts; the trustee literature stresses reminding users who their approvers are (Gong & Wang 2014).

---

## 5. EVALUATION FRAMEWORKS (how others evaluated similar systems)

- **Security:** Dolev-Yao threat modeling + automated symbolic verification in **Tamarin/ProVerif** (verified TLS 1.3, 5G-AKA, WireGuard); **Bonneau et al. UDS** 25-benefit comparative scoring; attack-tree analysis (Ohm et al.).
- **Usability:** **SUS** (Duo = 70 in DuoLungo; "Grade A" >80 reported for several methods in prior 2FA work), task-completion time / authentication overhead (DuoLungo 7.82 s), failure/error rates (DuoLungo 4.35% task-failure; 43.86% reporting a failure), qualitative interviews, optionally **NASA-TLX**; multi-week field deployments (Reese et al. two weeks; DuoLungo a full academic year) preferred over lab-only.
- **Performance:** crypto-backend overhead (MFKDF <12 ms; 2-of-3 threshold ~8.83 ms setup / ~11.90 ms derive; FROST two rounds) and proxy-added request latency/throughput vs. a no-auth baseline.

---

## 6. GAPS & OPPORTUNITIES

The clearest gap — and the project's strongest contribution — is **generality**. Every deployed multi-party-approval system the review found is purpose-built for a single resource type: HashiCorp Vault Shamir unseal unlocks a secrets vault; AWS Multi-Party Approval is scoped to one operation (`CreateRestoreAccessVault`) within AWS Backup, with teams of 3–20, a threshold ≥2, and sessions that expire in 24 hours; cryptocurrency custody (GG18/GG20/DKLS-based) signs blockchain transactions; trustee-based social authentication (Gong & Wang; Facebook Trusted Contacts; Microsoft Windows Live ID) handles *account recovery*. None functions as a drop-in reverse-proxy enforcement point that can place an m-of-n human gate in front of *any* HTTP application. The project proposes exactly this — porting the multi-sig-wallet trust model into the Authelia-style forward-auth architecture — and that combination appears genuinely novel.

A second gap is the **adaptation of threshold cryptography to the HTTP/web request lifecycle**. The threshold-signature and MPC literature is deep but almost entirely blockchain- or key-management-motivated; MFKDF is the rare example reaching into the browser, and even it targets client-side key derivation, not request gating. There is little to no published work on time-bounded, replay-resistant multi-party *approval tokens* integrated into a reverse proxy's allow/deny decision — a concrete research opportunity, and one amenable to formal verification in Tamarin/ProVerif.

A third gap is **empirical human-factors data for multi-person (not multi-factor) authentication**. The usability literature thoroughly characterizes single-user MFA (SUS, overhead, failure rates) and the trustee literature studies recovery, but the routine-access, every-request coordination cost of requiring several live human approvers is essentially unmeasured. A user study replicating the Reese et al. / DuoLungo methodology for an m-of-n flow would itself be a publishable contribution. The two dominant risks the project must confront head-on are the **proxy-bypass problem for external applications** and **session hijacking after grant**: the multi-party gate is only as strong as the guarantee that the proxy is the sole path to the resource and that the post-grant session cannot be stolen.

---

## RECOMMENDATIONS (staged, with decision thresholds)

**Stage 1 — Scope and framing (do first).**

- Frame the contribution as a **systems/architecture** novelty ("first general-purpose m-of-n human-approval web auth proxy"), explicitly *not* a new cryptographic primitive. State the problem as: *existing web auth proxies authenticate one user with multiple factors; none requires multiple distinct people to cooperate.*
- Pin the threat model to the supply-chain use case: an attacker who compromises **one** maintainer/approver identity (event-stream, ctx) or socially engineers trust over time (XZ Utils). The benchmark that changes the design: if the realistic adversary can compromise ≥ m identities, raise m or change the approver population.

**Stage 2 — Architecture decision.**

- Build on the **forward-auth pattern** (NGINX `auth_request` / Traefik ForwardAuth / Caddy `forward_auth`) for internal apps where the proxy can be the sole network path. **Decision threshold:** if a target app is *external SaaS* the user can reach directly, do not claim protection — either require the app to natively delegate to the proxy (OIDC/SAML) or descope it.
- Choose the cryptographic backend by requirement: if a secret must be *used* server-side, prefer a **threshold signature scheme (FROST / GG20 / DKLS)** that never reconstructs the key over naive **Shamir reconstruction**. Use **m-of-n (quorum), not n-of-n**, to survive approver unavailability and withheld-approval DoS. **Do not implement TSS from scratch** — use audited libraries (the GG18 bugs and Alpha-Rays attacks show the risk).

**Stage 3 — Build the approval protocol with anti-abuse properties.**

- Time-bounded, nonce-bound approval tokens (model AWS MPA's 24-hour expiry, non-response = rejection). Short post-grant session lifetimes with re-approval for sensitive actions to limit session-hijack blast radius.
- Approver UX modeled on Duo Push, extended to quorum: live quorum status, reminders, and explicit timeout handling.

**Stage 4 — Evaluate on all three axes.**

- *Security:* formalize the approval protocol in **Tamarin or ProVerif** and prove replay-, impersonation-, and secrecy properties under Dolev-Yao; score the system on the **Bonneau UDS** rubric against Authelia/Duo/Vault MPA. **Benchmark:** any falsified lemma → revise the protocol before proceeding.
- *Usability:* run a **SUS** study with task-completion times and failure rates for an m-of-n flow; compare against the Duo baseline (SUS 70, ~7.82 s, 43.86% reporting a failure). **Benchmark:** if SUS < ~68 (below "good") or per-access overhead is many multiples of single-user Duo, redesign the approver UX or relax the threshold.
- *Performance:* measure proxy-added latency/throughput vs. a no-auth baseline and crypto setup/derive/sign times (target the MFKDF/FROST millisecond range). **Benchmark:** if added latency materially degrades interactive use, cache approvals within a bounded, security-justified window.

---

## CAVEATS

- **Source quality.** Incident details (event-stream, ctx, XZ Utils, SolarWinds) are corroborated across multiple reputable sources (ACM/Springer papers, CISA/NVD, vendor advisories, established security press). Some descriptive numbers (e.g., event-stream's "~1.5–2 million weekly downloads," SolarWinds' "~18,000 customers") vary slightly by source and reflect ranges rather than single authoritative figures.
- **Forward-looking material excluded.** Items such as the "ClawHavoc"/agentic-AI supply-chain figures seen in one 2026 search snippet were *not* incorporated, as they appear speculative/unverified.
- **DuoLungo and DKLS specifics.** DuoLungo (USEC/NDSS 2026) is very recent; its SUS=70, 7.82 s, 4.35%, and 43.86% figures are quoted from the preprint and should be re-checked against the final published version. For the DKLS 2018 paper, the canonical IEEE/IACR title is "Secure **Two-party** Threshold ECDSA from ECDSA Assumptions," though the authors' own bibliography lists a "Multi-party" title variant; exact IEEE page numbers should be confirmed against IEEE Xplore if precise pagination is required.
- **MFKDF caution.** Cite MFKDF as a *web-adjacent threshold* example, but note the original construction was shown vulnerable to cryptanalysis over repeated invocations (addressed in the in-progress MFKDF2 work) — do not present it as a settled secure primitive.
- **The novelty claim is "no *general-purpose* web auth proxy,"** which this review supports based on the systems surveyed; it cannot prove a universal negative. The defensible framing is that all surveyed multi-party-approval systems are resource-specific (vault, backup, blockchain, recovery), and the major web auth proxies implement multi-factor rather than multi-person authentication.
- **Two minor citations could not be re-verified before the search budget was exhausted** (the original Schnorr multi-signature lineage and an exhaustive separation-of-duty / two-person-rule access-control survey); the SLSA "two-party review" (Level 4) and GitHub protected-branch required-reviewers features are cited from primary documentation as the concrete separation-of-duty analogs in the supply-chain domain.
