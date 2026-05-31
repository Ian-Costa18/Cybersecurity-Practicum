# Paper

- Title: A Multiparty Computation Approach to Threshold ECDSA
- Authors: Jack Doerner, Yashvanth Kondi, Eysa Lee, abhi shelat
- Year: 2018-2019
- URL / DOI: Published at 39th IEEE Symposium on Security and Privacy (2018) and 40th IEEE Symposium on Security and Privacy (2019)

---

## Quick summary (1–2 lines)

- One-line summary: DKLS proposes MPC-based protocols for threshold ECDSA that avoid external cryptographic assumptions (like Paillier), using only the Computational Diffie-Hellman assumption underlying ECDSA itself, achieving practical efficiency with log(t) + 6 communication rounds.

## Why it matters

- Connection to our project (e.g., authentication, proxy, usability): Directly addresses threshold cryptographic signing for distributed authentication systems; enables multi-sig wallet security without relying on homomorphic encryption; practical for 2FA scenarios with low-powered devices.
- Key takeaway: Threshold ECDSA can be made practical and standardizable through MPC techniques without adding cryptographic assumptions beyond those ECDSA already requires.

## What they did

- Methods / system / experiment (short bullets)
  - Designed two main protocols: general t-of-n multiparty threshold ECDSA (requiring log(t) + 6 rounds) and optimized 2-of-2 scheme (2 rounds total)
  - Used semi-honest Oblivious Transfer (OT) multiplications instead of Paillier homomorphic encryption
  - Introduced novel "consistency check" mechanism: parties verify consistent inputs supplied to multipliers by combining shares with secret key in the exponent, relying on CDH hardness in the elliptic curve group
  - Implemented in Rust using NIST secp256k1 curve; instantiated using same hash function as ECDSA
  - Benchmarked across three settings: LAN (Google Cloud Platform), WAN (16 global datacenters), and low-power devices (Raspberry Pi)

- Main results / claims
  - 2-party signing wall-clock time within factor of 18 of local ECDSA signatures (just over 3 milliseconds)
  - t-party setup: 31.6 ms with 20 parties (LAN); up to 31.6 seconds with 256 parties
  - t-party signing: logarithmic growth with t; 20-party signing achieves 305 ms (2018 LN18 protocol required 5 seconds)
  - Low-power: Raspberry Pi 2-of-2 signing in 52.6 ms; 2-of-3 in 162 ms
  - Outperforms prior work (GG18, GG20, Lindell's protocol) by orders of magnitude in wall-clock time for both LAN and WAN settings

## Challenges and solutions

- Challenge: Standard threshold ECDSA schemes (pre-2018) required external cryptographic primitives (Paillier homomorphic encryption) causing poor performance and introducing unrelated hardness assumptions
  - Solution: Redesigned protocols around OT-based multiplication with a novel consistency check in the exponent, eliminating Paillier entirely

- Challenge: Secure multi-party multiplication is computationally expensive; generic MPC over arithmetic circuits has high overhead
  - Solution: Constructed specialized two-party OT-based multiplication protocol (Gilboa with hardening), then composed it for multi-party setting

- Challenge: OT-based multiplication vulnerable to selective failure attacks where OT sender learns bits of receiver's secret
  - Solution: Encode receiver's input randomly so attacker must learn more than statistical security parameter bits to determine encoded input

## Limitations / open questions

- Limitations noticed:
  - Requires log(t) + 6 rounds for general t-of-n case (not constant-round like some newer work)
  - Homomorphic encryption approaches (GG18, LN18) more communication-efficient despite slower wall-clock time
  - Setup phase still significant cost; improvements via Bar-Ilian/Beaver inversion possible but not implemented
  - WAN benchmarks at disadvantage relative to other works due to communication round costs

- Open questions / future work:
  - Whether constant-round threshold ECDSA is achievable without Paillier-like assumptions
  - Application to threshold cryptosystems beyond ECDSA
  - Further optimization of setup protocol (mentioned Bar-Ilian/Beaver inversion work in progress)

## Impact on our project

- Adopt/adapt? (yes/no) — notes: Yes - foundational for practical threshold authentication. DKLS directly addresses our multi-sig authentication use case. The consistency check mechanism via CDH in exponent is particularly elegant and avoids Paillier assumptions.
- Pitfalls to avoid:
  - Do not overlook communication round complexity; wall-clock time depends heavily on network latency
  - OT-based multiplication requires careful encoding to prevent information leakage
  - Setup and signing phases have different scaling characteristics; separate benchmarking needed
  - Low-power device performance not guaranteed without careful implementation (e.g., BLAKE2 vs SHA-256 choice matters on embedded systems)

- Changes to evaluation / scope:
  - Should benchmark both setup and signing separately in any deployment scenario
  - WAN latency (66.5 - 348 ms round-trips) will dominate over LAN; design must account for this
  - Two-party protocols significantly more practical than general t-of-n; prioritize 2FA scenarios if feasible

## Practical notes

- Implementation hints / libraries mentioned:
  - Rust implementation; uses secp256k1 (NIST standardized curve)
  - Oblivious Transfer extensions via Keller, Orsini, Scholl (KOS15) and Chou/Orlandi (CO15)
  - BLAKE2 hash function for low-power devices (preferred over SHA-256)
  - SHA-256 for general implementations

- Datasets / benchmarks used:
  - LAN: Google Cloud Platform n1-highmem-8 nodes (South Carolina datacenter), 5-10 Gbits/sec bandwidth, ~0.3 ms latency
  - WAN: 16 Google Cloud zones globally (US, EU, Asia-Pacific); longest leg 348 ms (Belgium-Mumbai)
  - Low-power: Raspberry Pi 3B+ (4 cores, 1.4 GHz ARM), connected via ethernet

- Figures / tables to capture (IDs):
  - Table 1: LAN benchmark parameters (n/t range, round counts, sample counts)
  - Table 2: WAN wall-clock times in milliseconds (parties/zones, signing rounds, times, setup times)
  - Table 3: Raspberry Pi benchmarks (2-of-2 signing: 52.6 ms; 3-of-3: 162 ms)
  - Figure 1: n-party setup wall-clock times (exponential growth, ~3000 ms at 256 parties)
  - Figure 2: t-party signing wall-clock times (logarithmic growth, 10-300 ms range)
  - Figure 3: World map of WAN benchmark locations with latency annotations

## Short quote

> "Our threshold ECDSA scheme achieves the best wall-clock times of such schemes known to date, showing that being conservative in assumptions need not come at the cost of concrete efficiency."

## Citation (copy-paste)

```bibtex
@inproceedings{DKLS18,
  title={Secure Two-Party Threshold ECDSA from ECDSA Assumptions},
  author={Doerner, Jack and Kondi, Yashvanth and Lee, Eysa and shelat, abhi},
  booktitle={39th IEEE Symposium on Security and Privacy},
  year={2018}
}

@inproceedings{DKLS19,
  title={Threshold ECDSA from ECDSA Assumptions: The Multiparty Case},
  author={Doerner, Jack and Kondi, Yashvanth and Lee, Eysa and shelat, abhi},
  booktitle={40th IEEE Symposium on Security and Privacy},
  year={2019}
}
```

**Short form**: Doerner et al., "A Multiparty Computation Approach to Threshold ECDSA," IEEE S&P 2018-2019
