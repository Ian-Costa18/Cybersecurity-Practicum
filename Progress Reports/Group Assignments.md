# Group Assignments Post

**Name:** Ian Barish
**Requesting Group:** 7
**Track:** CS InfoSec

**Project Description:**

Enterprise grade cryptocurrency wallets have long implemented multi-signature ("multi-sig") authentication, which requires two or more parties to sign an outbound transaction from a secure wallet before it is sent to the receiving party. This security mechanism ensures that before a transaction is sent, it is agreed upon by the group, rather than any one individual. But what if you want to require multiple parties to approve of a critical setting change or a login to a sensitive online account? No existing general-purpose web authentication system (think Duo or Authelia) requires multiple distinct people to cooperate before granting access.

My practicum project proposes a general-purpose multi-signature authentication web proxy that allows access to the requested resource only when multiple parties provide their secret keys. This may be used by organizations who want to ensure product updates are only sent to end users when approved by multiple parties, preventing any one developer from conducting a supply-chain attack, or separated parents who want to ensure both parties consent when accessing the child's college fund, preventing one from withdrawing funds without the other's approval.
