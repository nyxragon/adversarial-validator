#!/usr/bin/env python3
"""
Turn scanner output (SARIF from Semgrep / CodeQL / nuclei / others) into finding stubs
framed for the *bounty gate*, not the CI gate. A SAST triager asks "should this block the
PR?". The validator asks a different question no other tool answers: "is this scanner hit
worth a researcher's time to weaponise and submit?" This normalises each result so you can
run it through /validate with that question.

Usage:
    python3 scripts/sarif_ingest.py results.sarif                 # human-readable stubs
    python3 scripts/sarif_ingest.py results.sarif --format json   # machine-readable
    cat results.sarif | python3 scripts/sarif_ingest.py -

Each stub carries: tool, ruleId, message, location (file:line or URL), scanner severity, and
the bounty-gate questions left to answer (reachability / impact / dedup). Identical
rule+location pairs are de-duplicated.
"""
import argparse
import json
import sys

GATE = ["reachable by a real attacker (not just present in code)?",
        "concrete impact beyond 'this sink is dangerous'?",
        "not a known dupe / already fixed (run dedup.py)?"]


def _loc(result: dict) -> str:
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation", {})
        uri = (phys.get("artifactLocation", {}) or {}).get("uri")
        line = (phys.get("region", {}) or {}).get("startLine")
        if uri:
            return f"{uri}:{line}" if line else uri
    return "<no location>"


def ingest(doc: dict) -> list[dict]:
    stubs: list[dict] = []
    seen: set[tuple] = set()
    for run in doc.get("runs", []):
        tool = (((run.get("tool") or {}).get("driver") or {}).get("name")) or "scanner"
        # map ruleId -> default level from rules metadata (CodeQL/Semgrep style)
        rule_level = {}
        for r in ((run.get("tool") or {}).get("driver") or {}).get("rules", []):
            lvl = ((r.get("defaultConfiguration") or {}).get("level")
                   or (r.get("properties") or {}).get("security-severity"))
            if r.get("id"):
                rule_level[r["id"]] = lvl
        for res in run.get("results", []):
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "?"
            loc = _loc(res)
            key = (tool, rid, loc)
            if key in seen:
                continue
            seen.add(key)
            msg = ((res.get("message") or {}).get("text") or "").strip().replace("\n", " ")
            sev = res.get("level") or rule_level.get(rid) or "warning"
            stubs.append({"tool": tool, "ruleId": rid, "location": loc,
                          "scanner_severity": sev, "message": msg[:300],
                          "bounty_gate_open": GATE})
    return stubs


def main() -> int:
    ap = argparse.ArgumentParser(description="Normalise SARIF into bounty-gate finding stubs.")
    ap.add_argument("file", help="SARIF file, or '-' for stdin")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    args = ap.parse_args()
    try:
        raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    stubs = ingest(doc)
    if args.format == "json":
        print(json.dumps(stubs, indent=2))
        return 0
    if not stubs:
        print("No results in SARIF.")
        return 0
    print(f"{len(stubs)} finding stub(s) — run each through /validate asking "
          f"'is this worth weaponising & submitting?'\n")
    for i, s in enumerate(stubs, 1):
        print(f"[{i}] {s['tool']}  {s['ruleId']}  ({s['scanner_severity']})")
        print(f"    where: {s['location']}")
        print(f"    what:  {s['message']}")
        print(f"    bounty gate still open: {'; '.join(GATE)}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
