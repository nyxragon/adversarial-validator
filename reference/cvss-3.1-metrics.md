# CVSS 3.1 base metrics — quick reference

Build the vector, then read the score off it. **The vector is the claim; the number is arithmetic.**
Vector form: `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`

| Metric | Values | Pick the higher-impact value only when the evidence shows it |
|---|---|---|
| **AV** Attack Vector | N (network) / A (adjacent) / L (local) / P (physical) | N only if reachable over the internet/routed network |
| **AC** Attack Complexity | L (low) / H (high) | H only if a real, attacker-uncontrolled condition must hold |
| **PR** Privileges Required | N (none) / L (low) / H (high) | N = unauthenticated; L = any logged-in user; H = admin |
| **UI** User Interaction | N (none) / R (required) | R if a victim must click/view something |
| **S** Scope | U (unchanged) / C (changed) | C only if the vuln breaks out of its security authority (e.g. one tenant affects another, app compromises host) |
| **C** Confidentiality | N / L / H | H = total or sensitive data read |
| **I** Integrity | N / L / H | H = total or critical data/write |
| **A** Availability | N / L / H | H = full DoS / shutdown |

## Score → severity band (CVSS 3.1)

| Score | Band |
|---|---|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

## Discipline

- **Scope (S:C) is the most-abused metric.** Only mark it Changed when the impacted component is a
  *different* security authority than the vulnerable one (cross-tenant, sandbox escape, app→host).
  SSRF that reads another service, stored XSS that runs in another user's session, and cross-org
  access are classic S:C cases — but confirm the authority boundary is actually crossed.
- **Do not inflate C/I/A to H by default.** `H` means total or a critical subset, not "some".
- **Recompute, never copy a claimed score.** If the hunter asserted a number, derive the vector
  yourself from the demonstrated impact and compare. A mismatch is itself a finding about the report.

Authoritative calculator: https://www.first.org/cvss/calculator/3.1
