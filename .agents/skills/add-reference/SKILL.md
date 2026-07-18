---
name: add-reference
description: >-
  Add a source-verified entry to the practicum bibliography
  (`Practicum Work/references.bib`, IEEE / BibTeX). Use when the
  user wants to cite a source, add a reference or citation, or drop a paper, doc,
  or URL into the bibliography for the progress reports or the final report.
---

# Add a reference to the bibliography

One job: append a **verified** BibTeX entry to `Practicum Work/references.bib` — the single source of truth for citations, shared by the Progress Reports and the Final Report, which sit one folder below it. The file is IEEE style, pulled into the reports via `\bibliographystyle{IEEEtran}` + `\bibliography{../references}`.

The rule that defines this skill: **no entry goes in unverified.** Every field is read off a live source, never recalled from memory — fabricated citations are the one failure this skill exists to prevent.

## Steps

1. **Resolve the source to a canonical URL.** If the user gave a URL, use it. If they named a paper, tool, spec, or incident, find its authoritative page — publisher docs, the DOI / NVD / PEP / RFC page, the primary advisory — not a blog summary when a primary source exists.

2. **Verify against the live page.** `WebFetch` the URL and read the *exact* title, author or publishing organization, and year **from the page itself**. If no canonical source is reachable, stop and tell the user — do not invent an entry. _Completion: title, author/org, and year each confirmed by the fetch._

3. **Choose a unique kebab-case key** matching the existing scheme (`pep740`, `shai-hulud-cisa`, `aws-mpa`). `grep` both the key and the URL in the file first; if either already exists it is a duplicate — stop and report it instead of adding a second entry.

4. **Archive the source** to the git-ignored evidence store at the repo root (create `.references/` if absent): `curl -L -o ".references/<key>.<ext>" <url>` — `.pdf` for a PDF, `.html` for a web page. If curl returns no usable content (JS-only or blocked page), save the text you fetched in step 2 to `.references/<key>.txt` instead. This is the durable proof the source was real at access time.

5. **Write the entry** in the house format:

   ```bibtex
   @misc{key,
     author       = {{Organization}},        % org: double-braced. people: First Last and First Last
     title        = {Title, with {BibTeX}-brace-protected acronyms/proper nouns},
     year         = {YYYY},
     howpublished = {\url{https://...}},
     note         = {Accessed: <today YYYY-MM-DD>}
   }
   ```

6. **Place it under the matching `% ----` section comment.** Reuse an existing section if one fits; otherwise add a new `% ----` section in a sensible thematic spot.

## Conventions (this file)

- **Author** — an organization is double-braced `{{...}}` so BibTeX does not split it as a person name; people are `First Last and First Last`.
- **Title** — brace-protect anything whose capitalization must survive IEEEtran's lowercasing: `{PyPI}`, `{SLSA}`, `{CVE-2024-3094}`.
- **note** — always carry `Accessed: YYYY-MM-DD` for a web source; any extra fact (CVSS score, PEP status) goes before it.
- **Never write a literal at-sign followed by an entry type inside a comment.** BibTeX has no comment character and parses any `@type` token it finds, even on a `%` line — it errors mid-file. This already broke this file once.
