#!/usr/bin/env python3
"""
Validation benchmark runner. The field benchmarks vulnerability *detection*; this benchmarks
*validation* — labelled (evidence -> correct outcome) cases, weighted toward the hard ones:
real bugs that look fake, fake bugs that look real (instrument artifacts), and mis-scored
severity. It exercises the deterministic spine (proofcheck + score) so the result is
reproducible without invoking an LLM. Cases live in benchmarks/cases/*.json.

Case schema:
    {"name": "...", "kind": "proof"|"severity", "input": {...}, "expect": "...", "note": "..."}
  proof    -> input is a proofcheck evidence dict; expect in PASS/INCOMPLETE/FAIL
  severity -> input is {"vector": "CVSS:.../..."}; expect is "<score> <band>"

Usage: python3 benchmarks/run.py
Exit code is the number of failing cases (0 = all pass).
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import proofcheck          # noqa: E402
import score as scoremod   # noqa: E402


def run_case(c: dict) -> tuple[bool, str]:
    kind = c["kind"]
    if kind == "proof":
        verdict, _, _ = proofcheck.run(c["input"])
        return verdict == c["expect"], verdict
    if kind == "severity":
        s, _, _ = scoremod.score(c["input"]["vector"])
        got = f"{s} {scoremod.band(s)}"
        return got == c["expect"], got
    return False, f"unknown kind {kind}"


def main() -> int:
    cases = []
    for path in sorted(glob.glob(os.path.join(HERE, "cases", "*.json"))):
        with open(path, encoding="utf-8") as fh:
            cases.append(json.load(fh))
    if not cases:
        print("no cases found in benchmarks/cases/", file=sys.stderr)
        return 1

    fails = 0
    by_kind: dict[str, list[int]] = {}
    print(f"Validation benchmark — {len(cases)} cases\n")
    for c in cases:
        ok, got = run_case(c)
        fails += not ok
        by_kind.setdefault(c["kind"], [0, 0])
        by_kind[c["kind"]][0] += ok
        by_kind[c["kind"]][1] += 1
        mark = "ok  " if ok else "FAIL"
        print(f"  [{mark}] {c['name']:28} expect {c['expect']:14} got {got:14}  {c.get('note','')}")
    print()
    for k, (p, t) in sorted(by_kind.items()):
        print(f"  {k:9}: {p}/{t}")
    print(f"\n{'PASS' if not fails else 'FAIL'}: {len(cases) - fails}/{len(cases)} cases")
    return fails


if __name__ == "__main__":
    raise SystemExit(main())
