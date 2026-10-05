#!/usr/bin/env python3
"""
A zero-infra, append-only validation ledger — the 20% of a vuln-management DB a solo
researcher actually needs, with none of the server. Every verdict is one JSONL line. It
powers own-history dedup (so you never re-report your own gadget) and seeds the benchmark.

It is per-researcher state, NOT shipped with the plugin. Location (first that applies):
    $AV_LEDGER  >  ~/.adversarial-validator/ledger.jsonl

Usage:
    python3 scripts/ledger.py add  --class idor --target acme.com --title "IDOR in /orders" \\
                                   --verdict SUBMIT --severity "P2" --vrt "...>IDOR>..." [--marker ...]
    python3 scripts/ledger.py add  --file record.json        # or pipe JSON on stdin with --file -
    python3 scripts/ledger.py check --class idor --target acme.com [--marker /orders]
    python3 scripts/ledger.py list [--target acme.com] [--limit 20]

`check` reports prior ledger entries whose signature (class+target+marker) matches — i.e.
"have I already validated/filed this?" — so the validator can flag an own-dup before a report.
"""
import argparse
import hashlib
import json
import os
import sys
import time

LEDGER = os.environ.get("AV_LEDGER") or os.path.expanduser("~/.adversarial-validator/ledger.jsonl")


def _sig(cls: str, target: str, marker: str) -> str:
    raw = f"{(cls or '').lower()}|{(target or '').lower()}|{(marker or '').lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _load() -> list[dict]:
    if not os.path.exists(LEDGER):
        return []
    out = []
    with open(LEDGER, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def add(rec: dict) -> dict:
    rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    rec["sig"] = _sig(rec.get("class", ""), rec.get("target", ""), rec.get("marker", ""))
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    with open(LEDGER, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description="Append-only validation ledger.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="append a verdict record")
    a.add_argument("--file", help="read a JSON record from a file, or '-' for stdin")
    for f in ("class", "target", "title", "verdict", "severity", "vrt", "marker", "platform", "evidence_sha"):
        a.add_argument(f"--{f}")

    c = sub.add_parser("check", help="find prior entries matching class+target(+marker)")
    c.add_argument("--class", dest="cls", required=True)
    c.add_argument("--target", required=True)
    c.add_argument("--marker", default="")

    ls = sub.add_parser("list", help="list recent entries")
    ls.add_argument("--target")
    ls.add_argument("--limit", type=int, default=20)

    args = ap.parse_args()

    if args.cmd == "add":
        if args.file:
            raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
            rec = json.loads(raw)
        else:
            rec = {k: v for k, v in vars(args).items()
                   if v is not None and k not in ("cmd", "file")}
            if "cls" in rec:
                rec["class"] = rec.pop("cls")
        rec = add(rec)
        print(f"recorded {rec['sig']}  {rec.get('verdict','?')}  {rec.get('class','?')}  {rec.get('title','')}")
        print(f"ledger: {LEDGER}")
        return 0

    if args.cmd == "check":
        sig = _sig(args.cls, args.target, args.marker)
        rows = _load()
        exact = [r for r in rows if r.get("sig") == sig]
        same_ct = [r for r in rows if r.get("class", "").lower() == args.cls.lower()
                   and args.target.lower() in (r.get("target", "").lower())]
        if exact:
            print(f"OWN-DUP: {len(exact)} prior entr{'y' if len(exact)==1 else 'ies'} with the same signature ({sig}):")
            for r in exact:
                print(f"  {r.get('ts','?')}  {r.get('verdict','?')}  {r.get('severity','')}  {r.get('title','')}")
            return 2
        if same_ct:
            print(f"RELATED: no exact match, but {len(same_ct)} prior {args.cls} finding(s) on this target:")
            for r in same_ct[:10]:
                print(f"  {r.get('ts','?')}  {r.get('verdict','?')}  {r.get('title','')}  [{r.get('marker','')}]")
            return 1
        print(f"NO-OWN-DUP: nothing in the ledger for {args.cls} on {args.target} (sig {sig}).")
        return 0

    if args.cmd == "list":
        rows = _load()
        if args.target:
            rows = [r for r in rows if args.target.lower() in r.get("target", "").lower()]
        for r in rows[-args.limit:]:
            print(f"{r.get('ts','?')}  {r.get('verdict','?'):11} {r.get('severity',''):6} "
                  f"{r.get('class',''):8} {r.get('title','')}  [{r.get('target','')}]")
        print(f"\n{len(rows)} entr{'y' if len(rows)==1 else 'ies'}  ({LEDGER})")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
