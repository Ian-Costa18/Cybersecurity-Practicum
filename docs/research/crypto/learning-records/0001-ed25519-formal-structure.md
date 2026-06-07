# Ed25519: Formal Structure and Security Properties

The user engaged with both the original Bernstein et al. (2011) paper and the Brendel et al. (2021) provable security paper in full. They now understand Ed25519 as a concrete instantiation of EdDSA over the twisted Edwards curve birationally equivalent to Curve25519, and can read the formal KGen/Sign/Vfy algorithm definitions from the papers directly.

**Evidence:** Engaged with full paper content including the formal parameter table, algorithm pseudocode (§2 of original paper), and the EUF-CMA/SUF-CMA theorem statements (Theorems 3/4 of Brendel et al.).

**Implications:** The next lesson can go straight to the security proof chain (ECDLP → IMP-PA → EUF-CMA via Fiat-Shamir) without re-establishing the algorithm definition. The variant comparison (Original vs IETF vs LibS) and the SUF-CMA distinction should be covered in the reference document, as they are directly relevant to which variant to specify in the ADR.
