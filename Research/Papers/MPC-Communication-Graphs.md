# Paper

- Title: Must the Communication Graph of MPC Protocols be an Expander?
- Authors: Elette Boyle, Ran Cohen, Deepesh Data, Pavel Hubáček
- Year: 2023
- URL / DOI: https://eprint.iacr.org/2023/766 (CRYPTO 2018 preliminary version; full version June 2023)

---

## Quick summary (1–2 lines)

- One-line summary: This paper investigates whether secure multiparty computation protocols require their induced communication graphs to be expanders, establishing both upper bounds (protocols with non-expander graphs exist) and lower bounds (in certain settings, expansion is necessary for correctness).

## Why it matters

- Connection to our project (e.g., authentication, proxy, usability): Critical for understanding the network topology constraints of threshold authentication systems. If the multi-signature approval proxy uses distributed signing among geographically dispersed approvers, the communication graph topology directly impacts protocol latency, bandwidth, and security guarantees. Graph expansion properties determine whether all parties can efficiently communicate secrets and detect compromised communicators.
- Key takeaway: Communication graph structure is a fundamental design parameter for distributed protocols—not all topologies work for all functionalities, and understanding which properties are necessary enables efficient system design without over-constraining the architecture.

## What they did

- Methods / system / experiment (short bullets)
  - Provided formal definitional framework for analyzing communication graphs induced by MPC protocol executions
  - Distinguished between fixed-graph model (known a priori) and dynamic-graph model (determined during protocol execution)
  - Studied edge expansion property (minimum edge cuts between subsets)
  - Constructed explicit protocols whose communication graphs are non-expanders in various settings (computational, information-theoretic, with/without low locality)
  - Proved necessity results showing expansion is required in certain settings (parallel broadcast, adaptive adversaries)
  - Analyzed both static and adaptive corruption models
  - Applied techniques from committee-based MPC constructions using digital signatures and error-correcting codes

- Main results / claims
  - **Upper bounds (Theorem 1.1-1.2):** For any efficient functionality and constant error, there exist secure MPC protocols with non-expander communication graphs in multiple settings including:
    - Computational security with poly-logarithmic locality
    - Information-theoretic PKI model (with/without low locality)
    - Adaptive corruption with poly-logarithmic locality
  - **Lower bounds (Theorem 1.3-1.4):** In plain model with parallel broadcast and adaptive corruption, high connectivity (expansion property) is necessary for protocol correctness
  - **Committee-based construction:** Uses n/2-sized committees elected via signatures; committees form bridges with poly-logarithmic edges
  - **Communication graph has low-weight cuts:** Resulting non-expander graphs split n parties into two linear-size sets with poly-logarithmic crossing edges

## Challenges and solutions

- Challenge: Proving protocols can exist with non-expander graphs contradicts intuition that well-connected topologies are necessary
  - Solution: Show that when setup assumptions (PKI, signatures) are available, you can use committee elections to create specific topology; the committee-based approach reduces communication requirements by using trusted infrastructure

- Challenge: In plain model without setup, adversary can exploit non-expander cuts to block information flow
  - Solution: Introduce "blocked cut" analysis showing that for parallel broadcast functionality, if communication graph has sublinear cuts, adversary can prevent correctness by corrupting the right set of parties

- Challenge: Distinguishing which graph properties (expansion, connectivity, degree bounds) are actually necessary vs. artifacts of construction
  - Solution: Formal definitional framework (Definition 3.10-3.12) with upper/lower bounds that isolate the role of edge expansion specifically

- Challenge: Handling adaptive corruptions where adversary sees communication and can corrupt strategically
  - Solution: Use hidden-channels model where adversary doesn't learn honest-to-honest communication; requires multi-layer analysis of which parties can be attacking which cuts

## Limitations / open questions

- Limitations noticed:
  - Upper bounds require setup assumptions (PKI, signatures, or information-theoretic setup) in non-plain model; result doesn't apply to plain model
  - Lower bound only proven for parallel broadcast functionality; generalization to other functionalities unclear
  - Communication graph analysis focuses on edge expansion; other expansion notions (spectral, vertex) and communication complexity left open
  - Gap between upper bounds (poly-logarithmic expansion can be avoided) and lower bounds (certain functionalities need expansion) remains
  - Analysis assumes synchronous round-by-round execution; asynchronous execution properties not addressed

- Open questions / future work:
  - Bridging gap between upper and lower bounds to characterize exactly which functionalities require expansion
  - Understanding other graph properties (spectral expansion, vertex expansion, degree regularity) for communication efficiency
  - Extending results to asynchronous settings
  - Applicability of framework to specific protocols like threshold signatures and cryptocurrency systems
  - Whether topology-hiding protocols can support non-expander graphs (mentioned in related work but not fully explored)

## Impact on our project

- Adopt/adapt? (yes/no) — notes: **YES - IMPORTANT FOR ARCHITECTURE DESIGN**. If the multi-signature approval system distributes signing across multiple approvers (committees), the network topology between approver committees directly impacts latency and security. This paper's framework helps determine:
  1. Whether you need a fully-connected mesh or can use sparser topologies
  2. How many edge-disjoint paths you need for byzantine resilience
  3. The communication overhead implications of committee structures
  4. How to handle approver unavailability without compromising the graph's security properties

- Pitfalls to avoid:
  - Do not assume fully-connected topologies are required; sparse topologies with careful structure can work
  - Do not ignore the distinction between static topology (known at design time) and dynamic topology (determined during execution)
  - Be aware that plain model (no setup) is much more restrictive—if you want minimal setup assumptions, may need stronger connectivity
  - In adaptive corruption settings, ensure the adversary cannot learn which honest parties are communicating; use authenticated channels or design accordingly

- Changes to evaluation / scope:
  - When designing the proxy's committee structure, analyze the induced communication graph's expansion properties
  - If using sparse topologies for efficiency, verify correctness against Theorem 1.4 (necessity for parallel broadcast)
  - Benchmark latency impact of different committee sizes and connectivity patterns (fully-connected vs. tree vs. random regular graphs)
  - Evaluate how geographic distribution of approvers affects the communication graph topology and corresponding protocol guarantees

## Practical notes

- Implementation hints / libraries mentioned:
  - Constructions use digital signatures and error-correcting secret sharing (ECSS) schemes
  - Committee election via signature verification; requires PKI or information-theoretic setup
  - Low-locality protocols referenced: Boyle-Goldwasser-Tessaro (BGT13), King-Srinivasan-Tessaro (KSST06)
  - Adaptive setting requires hidden-channels model with atomic message delivery (mentioned Cramer-Damgård-Ishai protocols)

- Datasets / benchmarks used:
  - No explicit benchmarking; theoretical analysis via formal definitions and game-based proofs
  - Results are existence proofs (Theorems) rather than empirical measurements
  - Framework formalizes previous implicit assumptions in protocol literature

- Figures / tables to capture (IDs):
  - Figure 1: Phase-based attack strategy illustration; shows how communication graph cut enables information blocking
  - Figure 5: Non-expander protocol structure; two committees C₁, C₂ of poly-log size forming bridge
  - Figure 6: Protocol π^ne in hybrid model; shows committee election and reconstruction phases
  - Definitions 3.8-3.12: Edge expansion and expander protocol definitions; key formalization

## Short quote

> "Is this merely an artifact of a convenient construction, or is it inherent? That is, we investigate the question: Must the communication graph of a generic MPC protocol, tolerating a linear number of corruptions, be an expander graph?"

> "All existing protocols (implicitly or explicitly) yield communication graphs which are expanders, but it is not clear whether this is inherent."

## Citation (copy-paste)

```bibtex
@inproceedings{BCDH23,
  title={Must the Communication Graph of MPC Protocols be an Expander?},
  author={Boyle, Elette and Cohen, Ran and Data, Deepesh and Huba{\v{c}}ek, Pavel},
  booktitle={Advances in Cryptology--CRYPTO 2023},
  year={2023},
  organization={Springer}
}
```

**Short format**: Boyle, Cohen, Data, Hubáček. "Must the Communication Graph of MPC Protocols be an Expander?" CRYPTO 2023.

**ePrint**: https://eprint.iacr.org/2023/766
