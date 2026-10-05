#!/usr/bin/env python3
"""
Build reference/bugcrowd-vrt-flat.txt from Bugcrowd's official Vulnerability Rating
Taxonomy (VRT), flattened to one line per leaf:

    P<priority><TAB><Category > Sub > Specific>

The validator greps this file to quote an exact VRT line when scoring a Bugcrowd finding.
We do NOT redistribute the VRT in this repo; we fetch it from Bugcrowd's published,
open-source taxonomy so the data stays authoritative and correctly attributed.

Version identity is the git TAG, not a field inside the JSON: the taxonomy file itself
carries only a `metadata.release_date`. Bugcrowd tags each release as `v<major>.<minor>[.<patch>]`
(e.g. v1.19.1) and keeps the rolling edge on `master`.

Source:  https://github.com/bugcrowd/vulnerability-rating-taxonomy
License:  the VRT is Bugcrowd's; see their repository for its terms.

Usage:
    python3 scripts/build_vrt.py                    # newest tagged release (default)
    python3 scripts/build_vrt.py --version 1.18     # a specific release (v-prefix optional)
    python3 scripts/build_vrt.py --version master    # the rolling, pre-release edge
    python3 scripts/build_vrt.py --list-versions     # print available releases and exit
    python3 scripts/build_vrt.py --source taxonomy.json   # build from a local file
"""
import argparse
import json
import os
import re
import sys
import urllib.request

REPO = "bugcrowd/vulnerability-rating-taxonomy"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{ref}/vulnerability-rating-taxonomy.json"
TAGS_API = "https://api.github.com/repos/{repo}/tags?per_page=100"
OUT = os.path.join(os.path.dirname(__file__), "..", "reference", "bugcrowd-vrt-flat.txt")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "adversarial-validator-build-vrt"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (official hosts only)
        return resp.read()


def _ver_key(tag: str) -> tuple:
    """Sort key for a 'v1.19.1'-style tag: (1, 19, 1). Unparseable tags sort first."""
    nums = re.findall(r"\d+", tag)
    return tuple(int(n) for n in nums) if nums else ()


def list_tags() -> list[str]:
    """All release tags, newest first. Raises on network/API failure."""
    data = json.loads(_get(TAGS_API.format(repo=REPO)).decode("utf-8"))
    tags = [t["name"] for t in data if isinstance(t, dict) and t.get("name")]
    return sorted(tags, key=_ver_key, reverse=True)


def resolve_ref(version: str) -> str:
    """Turn a --version value into a git ref (branch or tag) to fetch from."""
    v = version.strip()
    if v in ("master", "main", "HEAD"):
        return v
    if v == "latest":
        tags = list_tags()
        if not tags:
            raise RuntimeError("no release tags found on GitHub")
        return tags[0]
    # a specific release: accept '1.18', 'v1.18', '1.18.0' — normalise to a 'v' tag
    return v if v.startswith("v") else f"v{v}"


def load_remote(ref: str) -> dict:
    url = RAW_URL.format(repo=REPO, ref=ref)
    print(f"Fetching VRT @ {ref} from {url}", file=sys.stderr)
    try:
        return json.loads(_get(url).decode("utf-8"))
    except urllib.error.HTTPError as e:  # noqa: PERF203
        if e.code == 404:
            raise SystemExit(
                f"ERROR: no VRT found at ref '{ref}' (HTTP 404).\n"
                f"       Run `python3 {sys.argv[0]} --list-versions` to see valid releases."
            )
        raise


def load_local(source: str) -> dict:
    with open(source, "r", encoding="utf-8") as fh:
        return json.load(fh)


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
    ap = argparse.ArgumentParser(
        description="Flatten Bugcrowd's VRT to reference/bugcrowd-vrt-flat.txt.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--version",
        default="latest",
        metavar="REF",
        help="VRT release to build: 'latest' (newest tag, default), a release like "
        "'1.18' / 'v1.18', or 'master' for the rolling edge.",
    )
    ap.add_argument(
        "--list-versions",
        action="store_true",
        help="print the available VRT releases (newest first) and exit.",
    )
    ap.add_argument("--source", help="build from a local vulnerability-rating-taxonomy.json instead of fetching")
    args = ap.parse_args()

    if args.list_versions:
        try:
            tags = list_tags()
        except Exception as e:  # noqa: BLE001
            print(f"ERROR: could not list versions: {e}", file=sys.stderr)
            return 1
        print(f"Available Bugcrowd VRT releases (newest first), plus 'master':\n")
        print("  master  (rolling, pre-release edge)")
        for t in tags:
            print(f"  {t}")
        return 0

    if args.source:
        data = load_local(args.source)
        ref_label = f"local:{os.path.basename(args.source)}"
    else:
        ref = resolve_ref(args.version)
        data = load_remote(ref)
        ref_label = f"{REPO}@{ref}"

    content = data.get("content", data if isinstance(data, list) else [])
    release_date = ""
    if isinstance(data, dict):
        release_date = (data.get("metadata") or {}).get("release_date", "") or ""

    lines: list[str] = []
    walk(content, [], lines)
    if not lines:
        print("ERROR: no VRT entries parsed — the schema may have changed.", file=sys.stderr)
        return 1

    header = [
        "# Bugcrowd Vulnerability Rating Taxonomy (flattened) — one `P<n><TAB>category path` per line.",
        "# Built by adversarial-validator/scripts/build_vrt.py; the VRT is Bugcrowd's (not redistributed here).",
        f"# source: {ref_label}" + (f"   release_date: {release_date}" if release_date else ""),
    ]

    out_path = os.path.normpath(OUT)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(header) + "\n")
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} VRT entries ({ref_label}) to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
