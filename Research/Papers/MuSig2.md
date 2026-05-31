# Paper

- Title: MuSig2: Simple Two-Round Schnorr Multi-Signatures
- Authors: Jonas Nick, Tim Ruffing, Yannick Seurin
- Year: 2021
- URL / DOI: https://eprint.iacr.org/2020/1261 (CRYPTO 2021)

---

## Quick summary (1–2 lines)

- One-line summary: MuSig2 achieves the first practical n-of-n multi-signature scheme that is secure under concurrent sessions, requires only two communication rounds, produces ordinary Schnorr signatures, and enables preprocessing of all but one round—a significant improvement over prior schemes that either required three rounds, had larger signatures, or lacked preprocessing capability.

## Why it matters

- Connection to our project (e.g., authentication, proxy, usability): Multi-signature schemes are critical for threshold authentication and authorization systems. MuSig2's combination of two-round efficiency, standard Schnorr signature compatibility, and concurrent-session security directly enables deployment in blockchain systems (notably Bitcoin) and other scenarios where multiple parties must jointly authorize transactions or critical operations. The preprocessing capability supports non-interactive signing without sacrificing security.
- Key takeaway: MuSig2 solves the long-standing problem of creating practical multi-signatures for real-world systems by removing the commitment round that made previous schemes inefficient, while maintaining rigorous security proofs against concurrent attacks.

## What they did

- Methods / system / experiment (short bullets):
  - Introduced a two-round protocol where signers exchange multiple nonces (ν ≥ 2) instead of a single nonce
  - Each signer i generates nonces R_{i,1}, ..., R_{i,ν} in round one and aggregates them using a random linear combination derived from a hash: R̂_i = ∏_j R_{i,j}^{b^{j-1}} where b = H_non(X̃, (R_1, ..., R_ν), m)
  - Analyzed security against Wagner's generalized birthday problem attack and concurrent sessions using the Algebraic One-More Discrete Logarithm (AOMDL) assumption
  - Provided two independent security proofs: ROM-only (ν = 4 nonces) and ROM+AGM (ν = 2 nonces)
  - Compared against MuSig, MuSig-DN, FROST, and DWMS schemes

- Main results / claims:
  - MuSig2 is the first scheme simultaneously achieving: (i) security under concurrent sessions, (ii) key aggregation, (iii) ordinary Schnorr signatures, (iv) two communication rounds, (v) minimal signer complexity
  - Supports preprocessing of all but one round, enabling non-interactive signing while maintaining concurrent-session security
  - Optimal ν = 2 variant requires only 3 multi-exponentiations + 1 exponentiation in signing (vs. MuSig's 1 multi-exponentiation), adding computational overhead of ~2 exponentiations
  - Security reduction to falsifiable AOMDL assumption rather than non-falsifiable OMDL
  - MuSig2* variant further optimizes key aggregation by setting one coefficient to constant 1

## Challenges and solutions

- Challenge: Wagner's algorithm and concurrent attacks on previous two-round schemes exploited the ability to control aggregate nonces across signing sessions
  - Solution: Use multiple nonces per signer with coefficients determined post-first-round by a hash. This prevents attackers from controlling the RHS of the generalized birthday problem equation since b changes with each different nonce response.

- Challenge: Simulating honest signers in security proofs when the reduction doesn't know the secret key
  - Solution: Use ν AOMDL challenges per signing session, allowing ν DL oracle queries per session. When forking causes different signature challenges (c ≠ c'), different b values ensure linearly independent equations that can be solved for the nonce discrete logarithms.

- Challenge: Achieving two rounds without commitment phase (which prevents preprocessing)
  - Solution: Accept that adversaries can control the LHS of attack equations, but prevent them from controlling RHS through the nonce diversification mechanism above.

## Limitations / open questions

- Limitations noticed:
  - Relies on AOMDL assumption (weaker than OMDL but still stronger than standard DL)
  - ROM-only proof requires ν = 4 nonces; AGM is needed for ν = 2 (AGM is idealized model)
  - Requires secure random nonce generation; deterministic nonces are insecure (unlike MuSig-DN)
  - Stateful signing: state must never be reused or secret key extraction becomes trivial
  - Overhead of ν-1 group elements broadcast per signer in round one
  
- Open questions / future work:
  - Whether weaker security assumptions suffice for two-round schemes
  - Applicability to threshold signatures (t-of-n) with same efficiency guarantees
  - Implementation and deployment in production systems (Bitcoin taproot adoption)
  - Post-quantum secure variants of the scheme

## Impact on our project

- Adopt/adapt? (yes/no) — notes: **YES**. MuSig2 is directly applicable to any n-of-n multi-signature authentication or authorization scenario. Its compatibility with standard Schnorr signatures, preprocessing support, and concurrent-session security make it the natural choice over MuSig for modern deployments. If threshold (t-of-n) signatures are needed, FROST based on similar linear-combination-of-nonces ideas may be preferred.

- Pitfalls to avoid:
  - Do not use deterministic nonce derivation; must implement cryptographically secure RNG for nonces
  - Ensure proper state management to avoid nonce reuse across signing sessions
  - Validate that all ν nonces are received and aggregated correctly before proceeding to round two
  - In key aggregation, verify proper computation of coefficients a_i = H_agg(L, X_i) for all keys
  - Be aware that security model assumes plain public-key model (no proof-of-possession); rogue-key attacks require key aggregation coefficients

- Changes to evaluation / scope:
  - Consider n-of-n vs. t-of-n requirements early; MuSig2 optimizes for n-of-n, while FROST handles thresholds
  - If preprocessing is critical (non-interactive signing), MuSig2 is substantially better than MuSig
  - Benchmark actual signing latency and communication overhead; ν = 2 provides optimal practical tradeoff
  - Evaluate compatibility with target platform (blockchain integration, PKI systems, distributed authorization)

## Practical notes

- Implementation hints / libraries mentioned:
  - Paper provides full pseudocode for Sign, Sign', Sign'', SignAgg, SignAgg', KeyAgg algorithms
  - Three hash functions needed: H_agg, H_non, H_sig (can be instantiated via domain separation from single hash)
  - MuSig2* variant optimizes KeyAgg by setting IsSecond(L, X) coefficient to 1
  - Partial verification available: check g^{s_i} = R̂_i X_i^{a_i c} per signer for accountability
  - Optional aggregator node reduces broadcast from quadratic to linear in number of signers

- Datasets / benchmarks used:
  - Security analysis based on group of order p (e.g., secp256k1 for Bitcoin)
  - Comparison tables show exponentiation counts for KeyGen, KeyAgg, Sign, Ver
  - Table 1 compares MuSig2 variants against MuSig, MSDL-pop, mBCJ, MuSig-DN, FROST, DWMS

- Figures / tables to capture (IDs):
  - Table 1 (page 4): Comprehensive comparison of multi-signature schemes on rounds, exponentiations, domains, security
  - Figure 4 (page 15): Full pseudocode of MuSig2 algorithms
  - Figure 6 (page 21): Execution tree diagram of algorithm D (ROM proof structure)
  - Figures 8-13 (pages 30-34): Games and procedures for AGM+ROM proof of MuSig2[ν=2]

## Short quote

> "MuSig2 is the first multi-signature scheme that simultaneously i) is secure under concurrent signing sessions, ii) supports key aggregation, iii) outputs ordinary Schnorr signatures, iv) needs only two communication rounds, and v) has similar signer complexity as ordinary Schnorr signatures. Furthermore, it is the first scheme in the pure DL setting that supports preprocessing of all but one rounds, effectively enabling a non-interactive signing process without forgoing security under concurrent sessions."

## Citation (copy-paste)

```bibtex
@inproceedings{Nick2021MuSig2,
  author    = {Jonas Nick and Tim Ruffing and Yannick Seurin},
  title     = {MuSig2: Simple Two-Round Schnorr Multi-Signatures},
  booktitle = {CRYPTO 2021, Part I},
  year      = {2021},
  doi       = {10.1007/978-3-030-84242-0_7}
}
```

**Short format**: Nick, Ruffing, Seurin. "MuSig2: Simple Two-Round Schnorr Multi-Signatures." CRYPTO 2021.
