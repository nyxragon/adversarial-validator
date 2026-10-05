<div align="center">

# 🛡️ Adversarial Finding Validator

**An isolated AI subagent that tries to kill your security finding before a triager does.**

[![License: MIT](https://img.shields.io/badge/License-MIT-1f6feb?style=flat-square)](LICENSE)
&nbsp;![Version](https://img.shields.io/badge/version-0.1.0-8957e5?style=flat-square)
&nbsp;![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-d97757?style=flat-square)
&nbsp;![Verdicts](https://img.shields.io/badge/verdicts-SUBMIT%20·%20PROVE%20·%20INVESTIGATE%20·%20DISCARD-2ea043?style=flat-square)

[Demo](#demo) &nbsp;·&nbsp; [Install](#install) &nbsp;·&nbsp; [Usage](#usage) &nbsp;·&nbsp; [How it works](#how-it-works) &nbsp;·&nbsp; [Configuration](#configuration)

</div>

Your bug-hunting model is also your worst reviewer: show it your reasoning and it agrees. The Adversarial
Finding Validator reviews the finding the way an unbiased triager would — a separate Claude Code subagent
that judges it on the evidence alone, never your hypothesis, so it inherits none of your optimism and is
free to disprove you. Four verdicts, a severity it computes rather than one you assert, and a kill counts
as a result.

---

## Demo

Feed it the evidence for an SSRF you think is a High. It answers:

```text
VERDICT:   PROVE
PLATFORM:  Bugcrowd (VRT, with CVSS support)
SEVERITY:  demonstrated: P5  Server Security Misconfiguration > SSRF > External - Low impact
           CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L = 4.0 Medium  (Bugcrowd's own vector; score from score.py)
           ceiling:      P2  Server Security Misconfiguration > SSRF > Internal Secrets Exposure  (if the read is shown)
PROOF:     proofcheck PASS for the external fetch (OOB HTTP hit, nonce bound); INCOMPLETE for the internal read.
GATE:      #9 fails. The server fetches an attacker-controlled external host, but reaching a
           restricted internal target (the priority rests on it) is not shown.
FP CHECK:  Ruled out reflected-marker and DNS-only. A real HTTP GET was received server-side.
DEDUP:     dedup.py -> NO-PUBLIC-MATCH for this endpoint.
REASON:    The SSRF primitive is proven live, so it anchors to the external line today. The P2
           ceiling depends on reaching internal secrets, which the evidence does not demonstrate.
NEXT:      Point the fetch at the metadata IP and capture the credential arriving at your
           listener. Produce that and it becomes SUBMIT at the P2 line.
```

Confirmed the bug, refused the unearned P2, split the proven priority from the ceiling, and named the
one thing left to prove.

---

## Install

Requires [Claude Code](https://claude.com/claude-code).

```bash
claude plugin marketplace add nyxragon/adversarial-validator
claude plugin install adversarial-validator@nyxragon-plugins
```

<details>
<summary>Other ways to run it</summary>

```bash
# load for a single session, no install
claude --plugin-dir /path/to/adversarial-validator
```

```bash
# optional: build the Bugcrowd VRT table for VRT anchoring (works without it)
python3 scripts/build_vrt.py                 # newest tagged release (default)
python3 scripts/build_vrt.py --version 1.18  # pin a specific release
python3 scripts/build_vrt.py --list-versions # see what is available
```

</details>

---

## Usage

Give it evidence, not your argument:

```text
/adversarial-validator:validate
  the exact request and response, with status and body markers
  the baseline that proves the response is not a catch-all
  the real attacker trigger path
  what concrete data or state change was demonstrated
  the target platform, and any dedup already done
```

Or launch the agent directly: `@agent-adversarial-validator:finding-validator`

---

## How it works

| | Verdict | Meaning | Next step |
|:--:|---|---|---|
| ✅ | **SUBMIT** | Proven, reproducible, real impact, in scope. | Report it at the anchored severity. |
| 🔬 | **PROVE** | A real bug; only the demonstration is missing. | Produce the one proof it names. |
| 🔎 | **INVESTIGATE** | Plausible, but something load-bearing is unknown. | Resolve the one open question. |
| 🗑️ | **DISCARD** | Not a valid finding. | Drop it, with the reason recorded. |

Every verdict carries:

- **A computed severity.** A per-metric-cited vector; `score.py` (CVSS 3.1 and 4.0) returns the number.
- **Platform anchoring.** Bugcrowd gets the exact VRT line + Bugcrowd's authored CVSS/CWE; everyone else
  a CVSS vector. `vrt_diff.py` re-anchors a finding scored against an older VRT.
- **A false-positive screen** by name, plus `proofcheck.py` to check the oracle artifact is self-consistent.
- **Grounded dedup.** `dedup.py` over NVD + GHSA + your ledger, fails open (unreachable ≠ novel).
- **No true-positive suppression.** DISCARD needs a refutation artifact; "no impact seen" floors at
  INVESTIGATE; high-blast-radius classes must survive the validator attacking its own DISCARD.

<details>
<summary>What the false-positive screen catches</summary>

- A proxy or client error page served as a `200`
- Catch-all responses that answer identically for an invented path
- WAF or edge refusals mistaken for application behaviour
- Reflected markers (your own request echoed back)
- Versions read from a filename rather than file contents
- Oracles run without a negative control
- Always-informational classes (missing headers, self-XSS, DNS-only SSRF, open redirect with no chain)
  are rejected unless chained to real impact

</details>

---

## Configuration

- Severity follows the platform you state, defaulting to CVSS 3.1.
- The Bugcrowd VRT table is built by `scripts/build_vrt.py` and read from `reference/`. It defaults to the
  newest tagged release; pin one with `--version 1.18`, track the edge with `--version master`, or
  `--list-versions`. From inside Claude Code: `/vrt`, `/vrt 1.18`, `/vrt master`, `/vrt list`.
- The agent runs on `model: opus`; set it to `sonnet` in `agents/finding-validator.md` if you lack Opus access.

**The deterministic toolbelt** (`scripts/`, pure stdlib, each self-tests with `--self-test`):

| Tool | Does |
|---|---|
| `score.py` | CVSS 3.1 + 4.0 base score from a vector |
| `build_vrt.py` | build the flat + enriched VRT (official CVSS/CWE) at any version |
| `vrt_diff.py` | how a VRT line moved between two releases |
| `proofcheck.py` | check a per-class (or generic) oracle artifact is present and self-consistent |
| `dedup.py` | grounded prior-art (NVD + GHSA + your ledger), fails open |
| `ledger.py` | append-only validation ledger for own-history dedup |
| `sarif_ingest.py` | turn Semgrep/CodeQL/nuclei SARIF into bounty-gate finding stubs |

`benchmarks/run.py` is a reproducible validation benchmark over the deterministic spine.

---

## Contributing

PRs that extend coverage are welcome: a new instrument-artifact pattern for the false-positive screen,
a platform's severity mapping in `reference/platform-severity-map.md`, a `proofcheck.py` schema for a
bug class not yet covered, or a case for the validation benchmark. Open an issue first for anything that
changes what a verdict means.

## License

[MIT](LICENSE).
