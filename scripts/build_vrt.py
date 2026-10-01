#!/usr/bin/env python3
"""
Build reference/bugcrowd-vrt-flat.txt from Bugcrowd's official Vulnerability Rating
Taxonomy (VRT), flattened to one line per leaf:

    P<priority><TAB><Category > Sub > Specific>

The validator greps this file to quote an exact VRT line when scoring a Bugcrowd finding.
We do NOT redistribute the VRT in this repo; we fetch it from Bugcrowd's published,
open-source taxonomy so the data stays authoritative and correctly attributed.

Source:  https://github.com/bugcrowd/vulnerability-rating-taxonomy
License:  the VRT is Bugcrowd's; see their repository for its terms.

Usage:   python3 scripts/build_vrt.py
         python3 scripts/build_vrt.py --source /path/to/vulnerability-rating-taxonomy.json
"""
import argparse
import json
import os
import sys
import urllib.request

VRT_URL = (
    "https://raw.githubusercontent.com/bugcrowd/"
    "vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json"
)
OUT = os.path.join(os.path.dirname(__file__), "..", "reference", "bugcrowd-vrt-flat.txt")


def load(source: str | None) -> dict:
    if source:
        with open(source, "r", encoding="utf-8") as fh:
            return json.load(fh)
    print(f"Fetching VRT from {VRT_URL}", file=sys.stderr)
    with urllib.request.urlopen(VRT_URL, timeout=30) as resp:  # noqa: S310 (official host)
        return json.loads(resp.read().decode("utf-8"))


def prio(node: dict) -> str:
    p = node.get("priority")
    return f"P{p}" if isinstance(p, int) else "P?"  # null/varies -> P?


def walk(nodes: list, trail: list[str], out: list[str]) -> None:
    for node in nodes:
        name = node.get("name") or node.get("id") or "?"
        path = trail + [name]
        children = node.get("children")
        if children:
            walk(children, path, out)
        else:
            out.append(f"{prio(node)}\t{' > '.join(path)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", help="local vulnerability-rating-taxonomy.json instead of fetching")
    args = ap.parse_args()

    data = load(args.source)
    content = data.get("content", data if isinstance(data, list) else [])
    lines: list[str] = []
    walk(content, [], lines)
    if not lines:
        print("ERROR: no VRT entries parsed — the schema may have changed.", file=sys.stderr)
        return 1

    out_path = os.path.normpath(OUT)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} VRT entries to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
