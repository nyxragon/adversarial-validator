# The adversarial panel — differentiated, not replicated

Running three copies of the same judge and taking a majority vote is weak: LLM judges share
failure modes, so their errors correlate and do not cancel. This panel instead gives each
judge a **distinct kill mandate** aligned to the three ways a finding dies in triage. Diverse
lenses surface diverse failures. Use the panel for **High+ findings** (or when the single-pass
verdict is close); for everything else the single validator is enough.

Each judge runs in its **own isolated context, evidence-only** (CLAUDE.md isolation rule). None
of them sees the hunter's hypothesis. Each must try to **kill** the finding on its own axis and
return a one-line verdict + the single strongest reason.

| Judge | Mandate (try to kill it this way) | Tools it leans on |
|---|---|---|
| **A — Artifact** | "This is an instrument artifact, not a vulnerability." Rule out proxy-200, catch-all, WAF/edge refusal, reflected marker, oracle-without-control, version-from-filename. | `proofcheck.py` (must PASS/INCOMPLETE, not FAIL) |
| **B — Dedup** | "This is already public or already fixed." Prior CVE/GHSA, vendor changelog, the latest release, your own ledger. | `dedup.py`, `ledger.py check` |
| **C — Severity** | "The impact is overclaimed; the real anchor is lower." Recompute the vector, quote the real VRT line, check version drift. | `score.py`, `bugcrowd-vrt-enriched.tsv`, `vrt_diff.py` |

## Synthesis

After the three return, reconcile to one verdict with this precedence:
1. **Any judge produces a kill artifact** (A: a named instrument artifact; B: a concrete prior
   disclosure that covers this exact issue; C only kills severity, never validity) → **DISCARD**
   (A/B) or **downgrade** (C). A kill must be a produced artifact, never "I don't see impact".
2. **No kill artifact, but something load-bearing is unproven** → **PROVE** (the proof is named)
   or **INVESTIGATE** (the open question is named). This is the floor — see the DISCARD rule below.
3. **All three fail to kill it** → **SUBMIT**, at the severity Judge C anchored.

## The DISCARD rule (anti-TP-suppression)

Research on skeptical LLM filters shows they wrongly suppress *true* positives on
threat-modelling-heavy classes (crypto, authz/trust-boundary, business logic). So:

- **DISCARD requires a positive refutation artifact** — a named instrument artifact (A), a
  concrete matching disclosure (B), or a cited scope exclusion. **"I don't see the impact" is
  never grounds for DISCARD; the floor is INVESTIGATE.**
- For high-blast-radius classes (authz, logic, crypto, trust-boundary), the panel must
  **adversarially attack its own DISCARD** before issuing it — produce the benign explanation and
  show it holds. If it cannot, the verdict is INVESTIGATE, not DISCARD. This is "hardened is a
  bug, not a verdict" turned inward on the validator's own skepticism.
