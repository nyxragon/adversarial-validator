---
description: Run the adversarial finding-validator subagent on a candidate finding before writing any report or attaching any severity. Grounds severity in Bugcrowd VRT or CVSS 3.1 instead of intuition. Usage: /validate <finding file or description>
---

# /validate — settle it before the triager does

Launch the **`finding-validator`** subagent (Agent tool, `subagent_type: "finding-validator"`).

It reviews your finding the way an **independent triager** would — on the evidence alone, blind to your
reasoning, so it cannot inherit your optimism. Do **not** paste your own argument for why the finding is
good; give it the **evidence only**:

- the exact request(s) and response(s), with status, size, and body markers
- the baseline/control that proves the response is not a catch-all or an instrument artifact
- what a real attacker's trigger path is (not a hand-built page / console / curl against your own repro)
- what concrete data or state change was demonstrated
- the target platform (Bugcrowd / HackerOne / Intigriti / YesWeHack / CVD / CVE), and any dedup done

The validator computes severity deterministically (`score.py`, CVSS 3.1 **and** 4.0), quotes the
exact Bugcrowd VRT line plus Bugcrowd's own vector (`bugcrowd-vrt-enriched.tsv`), checks any oracle
result against a per-class proof schema (`proofcheck.py`), and grounds dedup against NVD/GHSA and
your ledger (`dedup.py`). For a **High+ finding** it can run the differentiated adversarial panel
(`reference/panel-lenses.md`). It never does CVSS arithmetic by hand and never DISCARDs on "I don't
see impact" alone.

## It returns

```
VERDICT:   SUBMIT | PROVE | INVESTIGATE | DISCARD
PLATFORM:  <stated platform, or default CVSS 3.1>
SEVERITY:  <vector> = <score> <band> (tool-computed, per-metric cited)  |  Bugcrowd: P<n> "<VRT line>"
PROOF:     proofcheck result (PASS / INCOMPLETE=PROVE-lead / FAIL=kill)
GATE:      which gate questions fail
FP CHECK:  which instrument artifact was ruled out, and how
DEDUP:     NO-PUBLIC-MATCH / POSSIBLE-DUP / INCONCLUSIVE
REASON:    the single most important reason for the verdict
NEXT:      the one proof (PROVE) or open question (INVESTIGATE) to resolve
```

## What each verdict means next

- **SUBMIT** → write the report now, and only at the severity the validator anchored.
- **PROVE** → it is a real vulnerability; produce the single proof named in `NEXT` (fire the oracle /
  show the live repro / demonstrate reachability), then re-run validate — it becomes SUBMIT.
- **INVESTIGATE** → it is not yet established as real; resolve the open question in `NEXT` first.
- **DISCARD** → not a valid finding; record the reason so it is not re-run.

**Never** state a severity the validator did not anchor to a VRT line or a CVSS vector.
