<!-- LTeX: enabled=false -->
# Final Report — Fragments

> **TODO (Ian):** run the [writing-fragments skill](../../.agents/skills/writing-fragments/SKILL.md)
> against this file to mine raw material — sentences, analogies, framings in my own voice.
> Put a lot in: this is a **first-class quarry** that [draft-report-section](../../.agents/skills/draft-report-section/SKILL.md)
> mines for **every** section, not just the hard rhetorical bits. Fragments may be tied to
> outline sections or free-floating — no structure imposed. The general→concrete bookend and
> the abstract are the framings hardest to get from the specs, so they especially want good
> fragments here. See [outline.md](outline.md) for the spine.

<!-- Fragments accumulate below, separated by --- . Nothing here yet. -->

The proxy doesn't make approver compromise less likely — it makes it matter less.

Delta story for [CORE-1](../../docs/threat-model/CORE-1-single-approver-account-compromise.md) (single approver account compromise), the threat model's flagship "improved" threat — from the #107 Phase C grill, 2026-07-02. On the rated axes: in the direct-publish baseline, stealing the one maintainer's PyPI credential is likelihood-high / severity-critical (unilateral publish). Under the proxy, stealing one approver's credential pair is *still* likelihood-high — the proxy can't stop credential theft, and [IDENT-5](../../docs/threat-model/IDENT-5-no-anti-automation-on-authentication-endpoints.md)'s missing rate-limiting means the TOTP second factor doesn't buy the rating down — but severity drops to high: the attacker gets one vote, and m−1 independent approvals still stand between them and PyPI. The improvement lives entirely on the severity axis.

Candidate use: the final report's §1 value proposition / security-evaluation narrative.
