---
id: T7
title: "TOTP Secret Exposure in Database (merged into T5)"
merged_into: T5
related: [T5]
---

<!-- TOMBSTONE — merged into T5. ID retired; this file and all references are removed
     in the Phase D renumbering pass (decided 2026-07-02). Do not add content here. -->

# T7 — TOTP Secret Exposure in Database

**Merged into [T5 — Database Read Compromise](T05-database-read-compromise.md).** The plaintext-TOTP-at-rest gap this threat described is one row of T5's credential-at-rest table — the sole credential that is neither one-way hashed nor wrapped under a key the reader lacks. The fix is [#122](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/122) (wrap the TOTP secret under the password-derived key, viable because login always presents the password). This ID is retired; the file and its remaining code/doc references are removed in the Phase D renumbering pass.
