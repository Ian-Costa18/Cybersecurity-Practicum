# Threat-Model Taxonomies

The threat catalog classifies each threat against two established taxonomies so the model is
navigable, defensible, and grounded in recognized vocabulary rather than ad-hoc labels. Both
are applied as machine-readable frontmatter tags on every `T*.md` file:

| Tag | Taxonomy | Lens | Values |
|---|---|---|---|
| `stride` | Microsoft **STRIDE** | Which security *property* the threat violates (design-time) | one or more of the six STRIDE categories |
| `attack` | **MITRE ATT&CK Enterprise** | Which real-world *adversary behavior* the threat represents (operational) | one or more ATT&CK technique IDs (`Txxxx[.xxx]`) |

Two further lenses — **CAPEC** and **OWASP** — are described at the end as available but **not
currently applied**; the frontmatter tags are lists, so a third axis can be added later without
disturbing the existing two.

> This is a **reference** document: it explains what each taxonomy is, why the catalog uses it,
> and where to find the authoritative source. The per-threat *values* live in each threat file;
> the *method* for the evaluation axes (`delta`, `bucket`) lives in
> [evaluation-plan.md](../evaluation-plan.md).

---

## STRIDE — the violated-property lens

STRIDE is a threat-modeling mnemonic that classifies a threat by **the security property it
breaks**. It is a *design-time* framework: you walk a system's components and data flows and ask,
for each, whether each of the six failure classes can occur.

| Letter | Threat | Property it violates |
|---|---|---|
| **S**poofing | Impersonating a user, service, or origin | Authentication |
| **T**ampering | Unauthorized modification of data or code | Integrity |
| **R**epudiation | Denying an action with no evidence to the contrary | Non-repudiation |
| **I**nformation disclosure | Exposing data to those not entitled to it | Confidentiality |
| **D**enial of service | Degrading or denying availability | Availability |
| **E**levation of privilege | Acting beyond one's authorization | Authorization |

**Why the catalog uses it.** STRIDE is the standard framework for *enumerating* what can go wrong
while a system is being designed, and it is property-oriented — which fits a threat model whose
whole job is to reason about which guarantees the proxy does and does not make. It gives a clean,
defensible answer to "did you consider each class of failure?" It is deliberately coarse (six
buckets) and descriptive, not operational — which is exactly why it is paired with ATT&CK.

**Source.** Introduced by Loren Kohnfelder and Praerit Garg, *"The Threats to Our Products,"*
Microsoft internal memo, 1 April 1999; later formalized in the Microsoft SDL and popularized by
Adam Shostack, *Threat Modeling: Designing for Security* (Wiley, 2014). See
<https://en.wikipedia.org/wiki/STRIDE_model> and Microsoft's current reference at
<https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats>.

---

## MITRE ATT&CK Enterprise — the adversary-behavior lens

ATT&CK is a curated knowledge base of **real-world adversary behavior**, organized as a matrix of
**tactics** (the adversary's goal at a step — *why*) and **techniques** (the observed method of
achieving it — *how*, each with a stable `Txxxx` ID and optional `.xxx` sub-techniques). Unlike
STRIDE, which is derived from design principles, ATT&CK is empirical: its techniques are drawn from
documented intrusions.

**Why the catalog uses it.** The evaluation's central argument is a *net delta* — which threats
**pre-exist** the proxy versus which the proxy **introduces** (see
[evaluation-plan.md](../evaluation-plan.md)). That argument is only credible if "pre-existing" is
anchored to a recognized, real-world taxonomy rather than asserted. Mapping each threat to its
ATT&CK technique(s) provides that anchor, and ATT&CK's tactic structure doubles as the **checklist
for the completeness sweep**: we walk each tactic, keep the techniques that touch the proxy's
attack surface, and confirm a threat covers each — adding one where none does.

**Source.** Tactics index (Enterprise): <https://attack.mitre.org/tactics/enterprise/>. Design and
rationale: B. Strom et al., *"MITRE ATT&CK: Design and Philosophy,"* MITRE, 2018 (rev. 2020) —
<https://www.mitre.org/news-insights/publication/mitre-attck-design-and-philosophy>.

### In-scope technique shortlist (the completeness-sweep checklist)

Scoped to **this system**: a self-hosted, single-host FastAPI proxy that authenticates approvers
(password + single-use TOTP), signs each approval with a per-approver Ed25519 key (AES-256-GCM /
PBKDF2 wrapped at rest), stores state in SQLite/Postgres, notifies over SMTP, and holds a PyPI API
token it uses to publish after m-of-n approval. Techniques are kept at **medium depth** — enough to
drive the sweep, not an exhaustive dump. Verified against ATT&CK v15.1.

| Tactic | In-scope techniques (why they apply here) | Out of scope here (why) |
|---|---|---|
| **TA0043 Reconnaissance** | T1595 Active Scanning; T1589 Gather Victim Identity Info (harvest approver emails) | Org/OSINT recon (T1591/T1593/T1594/T1596) — private deployment yields little |
| **TA0042 Resource Development** | T1586.002 Compromise Email Accounts (intercept links); T1585 Establish Accounts (fraudulent approver) | Acquire/develop infra & capabilities (T1583/T1587/T1588) — adversary-side, unobservable |
| **TA0001 Initial Access** | **T1078 Valid Accounts** (stolen approver creds — central); T1190 Exploit Public-Facing App; T1566.002 Spearphishing Link; T1199 Trusted Relationship (proxy→backend) | Removable-media/hardware/drive-by (T1091/T1200/T1189) — no fit for a headless API |
| **TA0002 Execution** | T1059.006 Python (in-process code reaches the PyPI token, bypassing quorum); T1203; T1053.003 cron | T1047 WMI, T1610 containers, T1648 serverless — not central to single-host Python |
| **TA0003 Persistence** | T1078; T1556 Modify Authentication Process (.006 MFA, .009 Conditional-Access ≈ quorum-policy tamper); T1136.001 Create Local Account; T1098 Account Manipulation; T1505.003 Web Shell | OS-autostart (T1547/T1543/T1574) — irrelevant to a headless service |
| **TA0004 Privilege Escalation** | T1548 Abuse Elevation (.001/.003 → reach token/key); T1068; T1098 (grant rogue admin/approver); T1055 Process Injection | T1134 Access Tokens, T1484 Domain Policy, T1611 Escape to Host — AD/container-specific |
| **TA0005 Defense Evasion** | **T1562 Impair Defenses** (disable audit log); **T1070 Indicator Removal** (.002/.004 clear/delete the approval record); T1556; T1036 Masquerading (forged links); T1550.004 Web Session Cookie | T1497 sandbox-evasion, T1218 LOLBins, T1553 trust-subversion — endpoint/EDR tradecraft |
| **TA0006 Credential Access** | **T1110 Brute Force** (.001–.004 — cracking targets bcrypt & PBKDF2-wrapped key post-DB-read); T1555 Password Stores; **T1552 Unsecured Credentials** (.001 Credentials in Files = **PyPI token**; .004 **Private Keys** = Ed25519); T1003 OS Credential Dumping (scrape live token/key); T1556.006 MFA; **T1111 MFA Interception** (relay single-use TOTP); T1621 MFA Request Generation (weak fit); T1606.001 Forge Web Cookies; **T1528 Steal Application Access Token** (PyPI token); T1040 Sniffing; T1539 Steal Web Session Cookie | T1558 Kerberos, T1187 Forced Auth (NTLM), T1649 Forge Certificates — wrong stack |
| **TA0007 Discovery** | T1087.001 Local Account Discovery (enumerate approvers/quorum); T1083 File & Directory (find DB/token/key); T1082 System Info; T1046 Network Service Scanning (map forward-auth backends) | T1018/T1069/T1201 remote/AD/policy enumeration — presupposes host access, low value |
| **TA0008 Lateral Movement** | (narrow) T1550.004 Web Session Cookie (replay forward-auth session → backend); T1210 Exploitation of Remote Services | T1021 RDP/SMB/SSH, T1570, T1534 — no internal fleet to traverse |
| **TA0009 Collection** | T1005 Data from Local System (DB/config/key); T1114 Email Collection (intercept SMTP links); T1213 Data from Info Repositories (approval DB); T1557 Adversary-in-the-Middle | T1113 screen capture, T1056 keylogging, T1530 cloud-storage — no fit |
| **TA0011 Command & Control** | (thin, post-host-compromise) T1071.001 Web Protocols; T1105 Ingress Tool Transfer; T1573 Encrypted Channel | T1090/T1095/T1572/T1219 full C2 tradecraft — no native C2 surface |
| **TA0010 Exfiltration** | (thin) T1041 Exfil Over C2; T1567.002 Exfil to Cloud Storage; T1048 Over Alternative Protocol (reuse SMTP/DNS) | T1052 physical media, T1030/T1029 volume-shaping — out of scope for a system catalog |
| **TA0040 Impact** | **T1565.001 Stored Data Manipulation** (forge approval / alter hash binding → publish malicious pkg — the core integrity impact); T1485 Data Destruction (wipe audit DB); T1490 Inhibit Recovery (delete backups); T1499/T1498 Endpoint/Network DoS (block the quorum); **T1657 Financial Theft** (unauthorized publish = supply-chain harm); T1531 Account Access Removal (lock out approvers) | T1486 ransomware, T1561 disk-wipe, T1496 cryptojacking, T1491 defacement — generic host outcomes |

### Notable judgment calls

- **T1111 MFA Interception is preferred over T1621 MFA Request Generation.** The proxy's second
  factor is a *user-entered* TOTP, not a push approval, so real-time relay/interception fits and
  "MFA fatigue" (T1621) is a weak fit. Both are listed; T1111 is the primary tag.
- **T1565.001 Stored Data Manipulation + T1657 Financial Theft** most precisely name the worst
  outcome — an unauthorized publish that binds a malicious artifact — better than a generic
  "tampering" label.
- **T1195 Supply Chain Compromise** is *out of scope for the runtime attack surface* (the proxy is
  producer-side; consumer-side supply-chain attacks fall outside its boundary — see
  [evaluation-plan.md](../evaluation-plan.md) §1), but is arguably in-scope for a
  dependency-hardening review of the proxy itself (**T18**). Flag when tagging T18.

---

## How these relate — and two lenses we are not (yet) using

The lenses are complementary, answering different questions about the same threat:

- **STRIDE** — *which property is violated?* (design intent)
- **MITRE ATT&CK** — *which real-world behavior is this?* (operational, empirical)
- **CAPEC** — *what is the reusable attack pattern?* (application/design level). The Common Attack
  Pattern Enumeration and Classification (MITRE) is a hierarchy of attack patterns (e.g. Session
  Fixation, Signature Spoofing, Flooding) that cross-references CWE (weaknesses) and ATT&CK. It is
  more granular than STRIDE and would answer "*how* would this be attacked" at the app-design level.
  **Not currently applied.**
- **OWASP** — two candidate artifacts, both **not currently applied**: the **Top 10** (coarse web
  risk categories — Broken Access Control, Cryptographic Failures, Insecure Design, …; awareness
  level) and **ASVS**, the Application Security Verification Standard (a *requirements checklist* by
  chapter — Authentication, Session Management, Access Control, Cryptography, …; the more useful
  OWASP artifact for a completeness sweep because each item is verifiable).

We hold at **STRIDE + ATT&CK** for now: ATT&CK is the lens the evaluation's net-delta argument
requires, and STRIDE was already applied. CAPEC/ASVS can be added as further `*:` frontmatter tags
if a later pass wants attack-pattern or verification-requirement granularity.

---

## Sources

- MITRE ATT&CK Enterprise tactics index — <https://attack.mitre.org/tactics/enterprise/>
- B. Strom et al., *MITRE ATT&CK: Design and Philosophy*, MITRE, 2018 (rev. 2020) —
  <https://www.mitre.org/news-insights/publication/mitre-attck-design-and-philosophy>
- STRIDE — Kohnfelder & Garg (Microsoft, 1999); <https://en.wikipedia.org/wiki/STRIDE_model>;
  Shostack, *Threat Modeling: Designing for Security* (Wiley, 2014).
- CAPEC — <https://capec.mitre.org/> · OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
