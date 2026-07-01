---
id: T14
title: "Network Path Bypass (Forward-Auth Pattern)"
stride: ["Elevation of Privilege"]
capability: [L1]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T14 — Network Path Bypass (Forward-Auth Pattern)

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1 (network-level access to the backend) |
| **What the attacker gains** | If the backend service is reachable without going through the proxy, the entire approval requirement is bypassed. The proxy cannot detect or block direct access to the backend. |
| **What they cannot do** | Access the proxy-enforced approval state — but if they can reach the backend directly, they do not need to. |
| **Current defenses** | None — this is explicitly a documented constraint. The system trusts operators to enforce network topology. |
| **Planned defenses** | Future Traefik plugin integration makes deployment easier and reduces misconfiguration risk. The constraint is architectural; full mitigation requires network-layer enforcement. |
| **Operator configuration** | Bind backend services to private network interfaces only (e.g., `127.0.0.1` or a private VPC CIDR). Add firewall rules that allow inbound connections to the backend only from the proxy host IP. Regularly audit firewall rules. Test that direct access from outside the proxy is blocked. Do not expose backend services on public-facing interfaces even temporarily. |
