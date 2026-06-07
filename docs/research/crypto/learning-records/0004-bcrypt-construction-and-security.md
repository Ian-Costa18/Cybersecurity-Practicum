# Bcrypt: Construction and Security Model

The user engaged with Provos & Mazières (USENIX FREENIX 1999), the original bcrypt paper,
covering the formal definition of a secure password function, the EksBlowfish and bcrypt
algorithms, the anti-bitslicing argument, and comparison with DES crypt and MD5 crypt.

**Evidence:** Source read in full on 2026-06-06. Lesson 0004 created.

**Formal security definition (§3):**
- Password distribution D has predictability R(D) = max_{s∈D} Pr(s)
- An attacker A is a randomized boolean circuit; cost = |A| (number of gates)
- F(s,t) is an ε-secure password function if:
  1. Finding any partial information about s from F(s,t) offers no advantage over guessing:
     Pr[success with F] − Pr[success without F] < (ε/2) · |A| · R(D)
  2. Finding second preimages (s' ≠ s with F(s,t) = F(s',t)) is as hard as guessing passwords:
     advantage < ε · |A| · R(D)
- No formal proof is given that bcrypt achieves ε-security — the paper says explicitly:
  "we cannot formally prove bcrypt ε-secure, any flaw would likely deal a serious blow to
  the well-studied blowfish encryption algorithm"
- Contrast with AES-256-GCM: GCM has tight formal reduction to AES PRP; bcrypt does not

**Design criteria derived from the definition:**
1. Strong one-way function of the password (preimage and second-preimage resistance)
2. Salt space large enough to defeat precomputation (lookup tables / rainbow tables)
3. Adaptable cost — the key innovation absent from DES crypt and MD5 crypt

**Eksblowfish algorithm (§4):**
- Base: Blowfish, a 64-bit block cipher, 16-round Feistel network using XOR and ⊕ mod 2^32
- Blowfish state: 18 32-bit P-array subkeys (P_1,...,P_18) + 4 S-boxes (S_1,...,S_4), 256×32-bit words each
- F(a,b,c,d) = ((S_1[a] ⊕ S_2[b]) + S_3[c]) ⊕ S_4[d]  [Feistel round function]
- EksBlowfishSetup(cost, salt, key):
  1. state ← InitState()         [load digits of π into P-array and S-boxes]
  2. state ← ExpandKey(state, salt, key)
  3. repeat 2^cost times:
       state ← ExpandKey(state, 0, salt)
       state ← ExpandKey(state, 0, key)
  4. return state
- ExpandKey XORs the key cyclically into the P-array, then blowfish-encrypts 64-bit blocks of the salt
  to replace P-array entries in pairs, then continues replacing S-box entries two at a time

**Bcrypt algorithm (§5, Figure 3):**
- bcrypt(cost, salt, pwd):
  1. state ← EksBlowfishSetup(cost, salt, pwd)
  2. ctext ← "OrpheanBeholderScryDoubt"   [192-bit magic value]
  3. repeat 64 times: ctext ← EncryptECB(state, ctext)
  4. return Concatenate(cost, salt, ctext)
- Output format: "$2a$" + cost + base64(128-bit salt) + base64(192-bit ctext)
- Salt: 128 bits (ensures 2^41-entry files have negligible collision probability; Section 6.2.1)
- Cost: at publication time, 6 for normal users, 8 for superuser; should be re-evaluated as hardware improves

**Anti-bitslicing argument (§6.2.3):**
- DES crypt and MD5 crypt are vulnerable to bitslicing — treating a CPU as N parallel 1-bit processors
- Bitslicing works when S-boxes are fixed and well-known (DES)
- Bcrypt S-boxes: 4 KB total, change constantly during computation, different for every (password, salt) pair
- Therefore bitslicing cannot be applied to bcrypt — attacker gets no speedup from this technique
- Anti-pipelining: S-boxes must be separate for every simultaneous execution (no sharing across instances)

**Comparison with alternatives (§6):**
- DES crypt: 12-bit salt (4,096 unique), fixed cost (25 DES encryptions), vulnerable to bitslicing
- MD5 crypt: larger password, 12–48 bit salt, but fixed cost — steadily weakens as hardware improves
- Both have fixed cost → protection against offline attack erodes monotonically over time
- Bcrypt: 128-bit salt, 2^cost adaptable iterations, immune to bitslicing

**Implications for the proxy:**
- bcrypt is used for login password verification only — not for key derivation
- enc_key comes from PBKDF2(password, salt, 600k, SHA-256) — different primitive, different role
- The distinction matters: bcrypt output is not key material; it is a verifier stored in the database
- ADR for bcrypt should cite: adaptable cost (the decisive criterion vs MD5/SHA-based alternatives),
  128-bit salt defeating precomputation, and immunity to bitslicing hardware attacks
- ADR should note the absence of a formal proof and justify the security argument (reduces to Blowfish)
- Argon2id comparison: Argon2id adds memory-hardness (GPU resistance); bcrypt has no memory-hard property.
  If the ADR must justify bcrypt over Argon2id, the argument is: widespread deployment, library maturity,
  and that for a low-volume system (approval proxy) memory-hardness provides marginal additional benefit
  compared to simply increasing the cost factor.
