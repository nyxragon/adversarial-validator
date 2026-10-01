<div align="center">

# 🛡️ Adversarial Finding Validator

**An isolated AI subagent that tries to kill your security finding before a triager does.**

[![License: MIT](https://img.shields.io/badge/License-MIT-1f6feb?style=flat-square)](LICENSE)
&nbsp;![Version](https://img.shields.io/badge/version-0.1.0-8957e5?style=flat-square)
&nbsp;![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-d97757?style=flat-square)
&nbsp;![Verdicts](https://img.shields.io/badge/verdicts-SUBMIT%20·%20PROVE%20·%20INVESTIGATE%20·%20DISCARD-2ea043?style=flat-square)

[🧪 Demo](#-demo) &nbsp;·&nbsp; [📦 Install](#-install) &nbsp;·&nbsp; [⌨️ Usage](#%EF%B8%8F-usage) &nbsp;·&nbsp; [🧠 How it works](#-how-it-works) &nbsp;·&nbsp; [⚙️ Configuration](#%EF%B8%8F-configuration)

</div>

AI-assisted vulnerability hunting has a signal problem: the same model that finds a bug will cheerfully
agree it is real the moment you ask. The result is a flood of false positives and mis-scored reports
that is dragging down bug-bounty and coordinated-disclosure triage. The **Adversarial Finding Validator**
is the counterweight: a Claude Code subagent that runs with **no hunting context**, sees only the
evidence (never your hypothesis), and returns one of four verdicts with a severity it derives itself.

> [!IMPORTANT]
> The isolation is the whole point. A validator that knows your theory rubber-stamps it, so this one
> is never told why you think the bug is real. It is built to prove you wrong.

---

## 🧪 Demo

Feed it the evidence for an SSRF you think is a High. It answers:

```text
VERDICT:   PROVE
PLATFORM:  Bugcrowd (VRT, with CVSS support)
SEVERITY:  P2  Server Security Misconfiguration > SSRF > Internal High Impact   (if the read is shown)
           demonstrated so far: P4  Server Security Misconfiguration > SSRF > External
           CVSS support: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 2.7 Low
GATE:      #9 fails. The server fetches an attacker-controlled external host, but reaching a
           restricted internal target (the priority rests on it) is not shown.
FP CHECK:  Ruled out reflected-marker and DNS-only. A real HTTP GET and POST were received
           server-side, not just a DNS callback.
DEDUP:     No prior public disclosure found for this endpoint.
REASON:    The SSRF primitive is proven live. P2 depends on reaching internal secrets, which the
           evidence does not demonstrate; today it anchors to the external-SSRF line.
NEXT:      Point the fetch at the metadata IP and capture the credential arriving at your
           listener. Produce that and it becomes SUBMIT at the P2 line.
```

It confirmed the bug, refused to hand you an unearned P2, split the proven priority from the ceiling,
and named the one thing left to prove. That is the whole loop.

---

## 🎯 Why

> [!NOTE]
> AI-assisted hunting floods triage with false positives and mis-scored reports. Valid-rates are
> dropping and programs have shut down over it.

- **You cannot validate your own finding.** Ask an LLM "is this real?" with your reasoning attached and
  it agrees with you.
- **Reports die on severity, not just validity.** A Critical that recomputes to Medium gets downgraded;
  an impact that was never demonstrated gets closed. This catches both before you send.
- **It is a decision, not an opinion.** You get SUBMIT / PROVE / INVESTIGATE / DISCARD and the single
  next step, not a paragraph of hedging.

---

## 📦 Install

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
python3 scripts/build_vrt.py
```

</details>

---

## ⌨️ Usage

> [!TIP]
> Give it **evidence, not your argument**. If you plead your case, you defeat the isolation that makes
> it work.

```text
/adversarial-validator:validate
  the exact request and response, with status and body markers
  the baseline that proves the response is not a catch-all
  the real attacker trigger path
  what concrete data or state change was demonstrated
  the target platform, and any dedup already done
```

Or launch the agent directly: `@agent-adversarial-validator:finding-validator`

**Typical flow**

- A fresh finding returns **PROVE** with the one proof to produce. You produce it, re-run, and it
  becomes **SUBMIT**.
- A bug you called Critical returns with a recomputed vector one band lower, so you file it right
  instead of getting downgraded.
- A "bug" that only reads your own request back returns **DISCARD**, with the artifact named.

---

## 🧠 How it works

A dedicated subagent, handed the evidence only and told to assume you were wrong and find out why.

| | Verdict | Meaning | Next step |
|:--:|---|---|---|
| ✅ | **SUBMIT** | Proven, reproducible, real impact, in scope. | Report it at the anchored severity. |
| 🔬 | **PROVE** | A real bug; only the demonstration is missing. | Produce the one proof it names. |
| 🔎 | **INVESTIGATE** | Plausible, but something load-bearing is unknown. | Resolve the one open question. |
| 🗑️ | **DISCARD** | Not a valid finding. | Drop it, with the reason recorded. |

Every verdict carries:

- **A severity it derives, not one you assert.** It computes a CVSS 3.1 vector and, for Bugcrowd,
  quotes the exact VRT line. *The vector is the claim; the number is arithmetic.* It corrects
  over-scored and under-scored reports alike.
- **Platform-aware anchoring.** Bugcrowd uses the VRT; HackerOne, Intigriti, YesWeHack and Synack use
  CVSS 3.1; coordinated disclosure, CVE and GitHub advisories use CVSS 3.1.
- **A false-positive screen** that rules out, by name, the artifacts that fake a positive.

<details>
<summary>What the false-positive screen catches</summary>

- A proxy or client error page served as a `200`
- Catch-all responses that answer identically for an invented path
- WAF or edge refusals mistaken for application behaviour
- Reflected markers (your own request echoed back)
- Versions read from a filename rather than file contents
- Oracles run without a negative control
- Always-informational classes (missing headers, self-XSS, DNS-only SSRF, open redirect with no
  chain) are rejected unless chained to real impact

</details>

---

## ⚙️ Configuration

- Severity follows the platform you state, and defaults to CVSS 3.1 when none is given.
- The Bugcrowd VRT table is built locally by `scripts/build_vrt.py` and read from `reference/`.
- The agent runs on `model: opus`.

> [!NOTE]
> No Opus access on your plan? Set `model:` to `sonnet` in `agents/finding-validator.md`.

---

## 🤝 Contributing

The false-positive catalog and the platform map are meant to grow. A missed artifact or an unmapped
platform makes a good PR.

## 📄 License

[MIT](LICENSE). The Bugcrowd VRT is Bugcrowd's, fetched at build time rather than redistributed here.
