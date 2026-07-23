---
bucket: M1
title: Threat-modeling and risk-scoring methodology
report_home:
  - "§6 — Security Analysis: net-delta classification and mitigation evidence"
  - "Appendix — full threat-model classification table"
proxy_grounding:
  - docs/threat-model/CONTRIBUTING.md
  - docs/threat-model/taxonomies.md
  - docs/evaluation-plan.md
related_notes:
  - ../../../../docs/threat-model/00-overview.md
  - ../../../../docs/threat-model/taxonomies.md
  - ../../../../docs/evaluation-plan.md
bib_keys: [microsoft-stride-threat-modeling, dread-leblanc, mitre-attack]
status: vetted
---

## Why the report needs this

**Synthesis.** Section 6 evaluates the proxy as a change from a direct-publish baseline, not as an
absolute claim that it defeats every attack. The project-created net-delta model classifies each
threat as Improved, Inherited, or Introduced; it separately records likelihood, severity, and the
kind of evidence behind a mitigation. This note supports a concise methodology justification and
points the Appendix to the auditable catalog rather than repeating its per-threat values.

The proxy's relation to this methodology is direct: its m-of-n authorization changes the outcome
of some pre-existing single-credential threats, while its own host, approval, and credential
surfaces create an enumerated cost. The method does not claim that STRIDE or ATT&CK proves the
catalog complete, nor that a qualitative cell is a numerical risk score.

## Sources (vetted this session)

- Microsoft, *Microsoft Threat Modeling Tool Threats* — https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
  (accessed 2026-07-17) → `microsoft-stride-threat-modeling` · STRIDE definitions and Microsoft's
  stated use of STRIDE to categorize threats · [primary]
- David LeBlanc, *DREADful* — https://learn.microsoft.com/en-us/archive/blogs/david_leblanc/dreadful
  (accessed 2026-07-17) → `dread-leblanc` · primary critique of DREAD's additive 1–10 score ·
  [primary]
- MITRE ATT&CK — https://attack.mitre.org/ (accessed 2026-07-17) → `mitre-attack` · ATT&CK's
  role as an empirical adversary-behavior vocabulary · [primary]

## Method used in the report

### Enumerate properties; map observed adversary behavior

**Synthesis from the project method.** STRIDE is the design-time enumeration lens: each threat is
tagged with the security property it violates. ATT&CK is the operational lens: each applicable
threat is mapped to an Enterprise technique ID. The two tags answer different questions and remain
separate. The catalog does not claim exhaustive ATT&CK coverage; its mappings make the selected
attacker behaviors inspectable and prevent "pre-existing" from being an unsupported label.

> "Microsoft uses the STRIDE model, which categorizes different types of threats and simplifies the
> overall security conversations."
> — Microsoft, *Microsoft Threat Modeling Tool Threats*, "STRIDE model"

This anchors STRIDE as the report's enumeration vocabulary. The project uses its six categories to
ensure each violated property is considered, not as a completeness proof.

> "MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based
> on real-world observations. The ATT&CK knowledge base is used as a foundation for the development
> of specific threat models and methodologies..."
> — MITRE ATT&CK home page, introductory description

This backs §6's use of ATT&CK as a vocabulary and traceability aid, not as validation that the
proxy's model is complete.

### Measure the security change against the direct-publish baseline

**Synthesis from `docs/evaluation-plan.md` §3.** The baseline is a maintainer publishing to PyPI
with an API token and account 2FA, without the proxy. A threat is **Improved** if the proxy
measurably reduces it, **Inherited** if an equivalent authentication-layer exposure remains
unchanged, and **Introduced** if the surface exists only because the proxy exists. Only Improved
and Introduced threats are assigned one of the four evidence buckets: executably demonstrated,
argued by design, operator-enforced, or accepted limitation.

This is a net accounting, not a gross count of proxy attack surfaces. An authentication mechanism
present in both worlds cancels only when the proxy is standard-practice-equivalent; it remains
catalogued so that "considered" is distinguishable from "forgotten."

### Rate likelihood and severity without a composite score

**Synthesis from `docs/evaluation-plan.md` §3.** Likelihood is anchored to the attacker's required
precondition, and severity to the project mission outcome: preventing an unauthorized package from
reaching PyPI. Each is recorded as a qualitative baseline/residual pair. The pair describes the
risk statement; it is not combined with the mitigation bucket and it is not transformed into a
single number.

> "In WSC, we told you to rate [DREAD components] from 1-10, add them up, and divide by 5. ... This
> is an obvious malfunction."
> — David LeBlanc, *DREADful*, discussion of the original DREAD averaging rule

> "If we're going to have big error bars, let's simplify matters and drop back to high, medium and
> low."
> — David LeBlanc, *DREADful*, after discussing the ambiguity of adjacent 1–10 values

These passages support the narrow methodological choice to avoid additive precision. They do not
validate the project's specific likelihood/severity anchors, which are an explicit project design
choice and are documented in the evaluation plan.

## How the proxy relates

The proxy is evaluated as an authorization layer, not as a replacement for authentication or a
universal malware detector. Its quorum can reduce the impact of one compromised approver or token,
but it introduces its own host, database, session, notification, and approval-request surfaces.
The net-delta model makes both sides of that trade explicit; the evidence buckets then distinguish
what tests demonstrate today from what is reasoned, delegated to an operator, or accepted.

## Source decisions

- **Supplement `stride-shostack` with `microsoft-stride-threat-modeling`.** The Microsoft source
  is the retrieved, primary anchor for STRIDE definitions and its current practical use; retain
  Shostack as canonical background, but do not cite it unless the final prose needs it.
- **Drop `cvss-v4` from M1.** CVSS scores vulnerabilities, whereas this report classifies
  design-time threats relative to a direct-publish baseline. Retain the pre-existing bibliography
  entry because other project material may use it, but do not present it as report methodology.
