# Paper

- Title: FROST: Flexible Round-Optimized Schnorr Threshold Signatures
- Authors: Chelsea Komlo, Ian Goldberg
- Year: 2020
- URL / DOI: https://eprint.iacr.org/2020/852

---

## Quick summary (1–2 lines)

- One-line summary: FROST is a two-round Schnorr threshold signature scheme that reduces network communication overhead while supporting unrestricted parallelism and flexible t-of-n threshold configurations without limiting signing concurrency.

## Why it matters

- Connection to our project (e.g., authentication, proxy, usability): FROST directly addresses distributed authentication and key management in resource-constrained environments. It enables threshold-based authorization where t out of n participants must cooperate to produce a valid signature, critical for secure multi-party protocols without a single point of failure. The two-round optimization and asynchronous capability make it practical for network-limited or offline-capable deployments.
- Key takeaway: FROST enables practical threshold signing without sacrificing security, concurrent signing, or requiring all participants to be online simultaneously—making it deployable in real-world distributed systems where participants may be offline or on unreliable networks.

## What they did

- Methods / system / experiment (short bullets)
  - Built upon Pedersen's Distributed Key Generation (DKG) protocol to generate long-lived secret shares without a trusted dealer
  - Introduced a two-stage signing protocol: (1) preprocessing stage where participants generate and publish nonce/commitment pairs independently, (2) single-round signing stage where participants compute responses and a signature aggregator combines them
  - Used additive secret sharing and share conversion to generate nonces non-interactively during signing
  - Employed binding technique via hash functions to prevent Wagner's attack (Drivers et al. attack on concurrent Schnorr multisignatures)
  - Implemented in Rust using Ristretto over Curve25519 for group operations
  - Proved security against chosen-message attacks using generalized forking algorithm reduction to discrete logarithm problem

- Main results / claims
  - FROST achieves single-round signing (or two-round with preprocessing) compared to three or more rounds required by prior Schnorr threshold schemes
  - Supports unrestricted parallelism of signing operations—number of concurrent signings is not limited
  - Requires only threshold t participants (where t ≤ n) instead of all n participants for signing operations
  - Avoids Wagner's birthday attack without limiting concurrency, unlike prior schemes that traded off robustness for efficiency
  - Secure against chosen-message attacks assuming discrete logarithm hardness and adversary controls fewer than t participants
  - Signatures indistinguishable from standard Schnorr signatures for backward compatibility and privacy

## Challenges and solutions

- Challenge: Prior Schnorr threshold schemes require 3+ communication rounds during signing, creating network bottlenecks for resource-constrained or asynchronous deployments
  - Solution: FROST separates key generation from signing and uses preprocessing to allow single-round signing. Nonce/commitment pairs generated offline and published asynchronously mean final signing requires only one coordinated message exchange

- Challenge: Two-round Schnorr multisignature schemes (Drivers et al.) are vulnerable to Wagner's birthday attack when multiple concurrent signing operations are allowed
  - Solution: FROST binds each participant's response to the specific message, participant set, and their commitments using binding values computed via hash function H₁(i, m, B). This prevents reuse of signature shares across different signing operations

- Challenge: Robust DKG schemes require all participants to be actively engaged throughout, limiting practical deployment where participants may be offline or on unreliable networks
  - Solution: FROST trades robustness for efficiency—assumes misbehaving participants are rare and can be detected and excluded. The protocol aborts on misbehavior, but implementations can re-run with a reduced participant set, avoiding expensive byzantine consensus

- Challenge: Ensuring consistent view of commitments in distributed key generation without a trusted dealer
  - Solution: Requires participants to broadcast commitment values and assume infrastructure ensures consistent distribution (e.g., centralized server or consensus mechanism), or apply techniques like commit-and-reveal

## Limitations / open questions

- Limitations noticed:
  - FROST is not robust—if any participant misbehaves, the protocol aborts and must be restarted. This assumes misbehavior is rare in practice, which may not hold in adversarial settings
  - Requires at least t < n/2 security threshold to prevent the adversary from controlling the DKG output (weaker than robust schemes)
  - Preprocessing stage requires agreed-upon location for publishing commitments, introducing potential bottleneck or single point of failure depending on implementation
  - Not provably secure against ROS-solver attack (though authors claim current version is not affected); ROS vulnerability remains open for other threshold schemes using similar techniques
  - Signature aggregator role (semi-trusted) must be trusted to report misbehavior and publish final signature correctly

- Open questions / future work:
  - How to implement publishing of commitments in fully decentralized settings without central role?
  - Can robustness be added without reverting to 3+ round protocols?
  - Extension to threshold schemes over other pairing-based assumptions (currently focuses on discrete log)
  - Standardization status and RFC development (mentioned RFC 9591 context)

## Impact on our project

- Adopt/adapt? (yes/no) — notes: YES. FROST is directly applicable to threshold authentication scenarios. If the project requires multi-party authorization where no single entity holds the signing key, FROST provides a practical, efficient alternative to prior schemes. The single-round signing and asynchronous preprocessing fit well with proxy-based or decentralized authentication architectures.

- Pitfalls to avoid:
  - Do not assume FROST is robust—design authentication system to gracefully handle protocol aborts when misbehaving participants are detected
  - Do not rely on preprocessing stage without ensuring reliable, consistent commitment publication mechanism
  - Do not use threshold t >= n/2 expecting same security guarantees as robust schemes; validate threat model carefully
  - Do not deploy signature aggregator as untrusted entity without additional verification layer

- Changes to evaluation / scope:
  - If evaluating threshold authentication, benchmark FROST against robust alternatives (Stinson-Strobl, Genarro et al.) on round count and network overhead
  - Test performance with offline/asynchronous participants to validate practical applicability claims
  - Measure commitment publishing latency if implementing decentralized variant
  - Consider ROS-solver implications if deployed in contexts with high concurrent signing volume

## Practical notes

- Implementation hints / libraries mentioned:
  - Authors' Rust implementation using Ristretto (https://github.com/crysp.uwaterloo.ca/software/frost)
  - Uses curve25519 for group operations
  - Requires hash functions for binding values: H₁ (binding values), H₂ (challenge), H₃ (hash to scalar)
  - Preprocessing stage can cache π nonce/commitment pairs per participant for up to π concurrent signing operations

- Datasets / benchmarks used:
  - No explicit benchmarking against competing schemes in paper (security proof is primary contribution)
  - Implementation notes suggest performance evaluation would benefit from comparison with Genarro et al. DKG, Stinson-Strobl robust signatures, and MuSig2 on:
    - Number of communication rounds
    - Total network bytes transmitted
    - Computational cost per participant
    - Latency with varying network conditions

- Figures / tables to capture (IDs):
  - Figure 1: KeyGen protocol (DKG with Pedersen's scheme + rogue-key attack protection)
  - Figure 2: Preprocessing protocol (nonce/commitment generation for single-use pairs)
  - Figure 3: Sign protocol (single-round signing with signature aggregator)
  - Section 2.5: Wagner's algorithm attack visualization and how FROST avoids it
  - Theorem 6.1: EUF-CMA security bound for FROST-Interactive

## Short quote

> "FROST improves upon prior work in Schnorr threshold schemes by providing a single-round signing variant with a preprocessing stage that is agnostic to the choice of the signing coalition. Further, the number of signing participants in FROST is required to be simply some t ≤ n, while remaining secure against the Drivers attack and misbehaving participants who do not correctly follow the protocol."

## Citation (copy-paste)

- Citation snippet (BibTeX):

```bibtex
@inproceedings{komlo2020frost,
  title={{FROST}: {F}lexible Round-Optimized Schnorr Threshold Signatures},
  author={Komlo, Chelsea and Goldberg, Ian},
  booktitle={Selected Areas in Cryptography (SAC)},
  year={2020},
  organization={Springer}
}
```

- MLA: Komlo, Chelsea, and Ian Goldberg. "FROST: Flexible Round-Optimized Schnorr Threshold Signatures." *Selected Areas in Cryptography*, 2020.
