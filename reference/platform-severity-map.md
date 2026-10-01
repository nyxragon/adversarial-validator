# Platform severity map — anchor to the system the program actually uses

Determine the target platform from the finding's stated program. Anchor severity to that platform's
system. When the platform is not stated, default to CVSS 3.1 and say so.

| Platform | Primary system | Notes for the validator |
|---|---|---|
| **Bugcrowd** | VRT → P1 (Critical) … P5 (Informational) | Quote the exact VRT line (see `bugcrowd-vrt-flat.txt`, built via `scripts/build_vrt.py`). The VRT already encodes the triager's default bucket. Many entries are P5. Framing (Non-Brute-Force vs Brute-Force, etc.) moves the bucket — judge impact, not wording. Provide a CVSS vector as support. |
| **HackerOne** | CVSS 3.1 | H1 uses the CVSS 3.1 calculator for severity. Produce the full vector + band. |
| **Intigriti** | CVSS 3.1 → 5 bands | Bands: Exceptional / Critical / High / Medium / Low. Map the CVSS score to the band; Intigriti leans on demonstrated impact over theoretical reachability. |
| **YesWeHack** | CVSS 3.1 | Full vector + band. |
| **Synack / Cobalt / Intigriti-pentest** | CVSS 3.1 | Full vector + band. |
| **Coordinated disclosure / CVE / GitHub Security Advisory** | CVSS 3.1 | GHSA advisory form takes a CVSS 3.1 vector directly. Produce the vector; the GHSA maps it to the Critical/High/Medium/Low label. |
| **unknown / not stated** | CVSS 3.1 (default) | Produce the vector and state the platform was not stated. |

## CVSS score → band (shared by most platforms)

| Score | Band |
|---|---|
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.1 – 3.9 | Low |
| 0.0 | None / Informational |

## Bugcrowd VRT priority ↔ rough CVSS equivalence (orientation only — the VRT line wins)

| VRT | Rough CVSS | Typical |
|---|---|---|
| P1 | 9.0 – 10.0 | RCE, full ATO, auth bypass to admin |
| P2 | 7.0 – 8.9 | Stored XSS to session theft, SSRF to internal, IDOR to PII |
| P3 | 4.0 – 6.9 | CSRF on sensitive action, most reflected XSS |
| P4 | 0.1 – 3.9 | low-impact misconfig, self-XSS-adjacent, enumeration |
| P5 | 0.0 | informational, no reward |

Do not reverse-map CVSS to a VRT priority and call it done — on Bugcrowd, the quoted VRT line is the
anchor and the CVSS vector is supporting evidence.
