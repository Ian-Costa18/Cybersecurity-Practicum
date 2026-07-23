# Research Index

Background research supporting the design. Findings that became decisions live in [../adr/](../adr/index.md); the domain glossary lives in the root [CONTEXT.md](../../CONTEXT.md).

## Report-facing evidence store

Citation-ready research for the **final report** — defended, quotable notes that *assemble into* the paper (§3/§4/§6/§7), kept next to the report and `references.bib` in `Practicum Work/`. Distinct from the design-time research here: those notes **cite** this study material rather than duplicate it, so this tree stays the single home for the underlying reading.

- [Final Report/research/sources/research-process.md](../../Practicum%20Work/Final%20Report/research/sources/research-process.md) — bibliography deep-dive: one knowledge-store note per topic (incidents, methodology, primitives). The crypto and threshold-signature buckets there consolidate the material in [crypto/](crypto/index.md) and [Multi-Sig Authentication/](Multi-Sig%20Authentication/); start with its `research-process.md`.
- [Final Report/research/controls-matrix/README.md](../../Practicum%20Work/Final%20Report/research/controls-matrix/README.md) — per-control evidence backing the comparative positioning matrix.

## Reviews & use-case research

- [Broad Literature Review.md](Broad%20Literature%20Review.md) — Literature review across multi-party authorization and related work.
- [PyPi Use Case Research.md](PyPi%20Use%20Case%20Research.md) — PyPI publishing workflow research notes (Twine, upload flow, token scoping).

## Applied cryptography study track

- [crypto/](crypto/index.md) — Self-directed cryptography study: mission, learning records, lessons, and reference papers. See the [crypto index](crypto/index.md).

## Threshold-signature / MPC papers

Paper notes and PDFs surveyed while scoping the approval model. (The proxy ultimately uses credential-backed approval, not threshold signatures — see [../adr/0001-credential-backed-approval.md](../adr/0001-credential-backed-approval.md).)

- [Multi-Sig Authentication/FROST.md](Multi-Sig%20Authentication/FROST.md) — FROST flexible round-optimized threshold signatures.
- [Multi-Sig Authentication/MuSig2.md](Multi-Sig%20Authentication/MuSig2.md) — MuSig2 two-round Schnorr multi-signatures.
- [Multi-Sig Authentication/GG20.md](Multi-Sig%20Authentication/GG20.md) — GG20 threshold ECDSA.
- [Multi-Sig Authentication/DKLS.md](Multi-Sig%20Authentication/DKLS.md) — DKLS threshold ECDSA.
- [Multi-Sig Authentication/MPC-Communication-Graphs.md](Multi-Sig%20Authentication/MPC-Communication-Graphs.md) — Notes on MPC communication-graph requirements.
