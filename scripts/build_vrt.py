#!/usr/bin/env python3
"""
Build the local Bugcrowd Vulnerability Rating Taxonomy (VRT) reference files from
Bugcrowd's official, open-source taxonomy. Two outputs:

    reference/bugcrowd-vrt-flat.txt       P<priority><TAB><Category > Sub > Specific>
    reference/bugcrowd-vrt-enriched.tsv   id<TAB>P<TAB>name path<TAB>cvss_v3<TAB>cvss_v4<TAB>cwe

The flat file is what the validator greps to quote an exact VRT line. The enriched TSV
adds Bugcrowd's OWN authored CVSS v3.1 and v4.0 vectors and the CWE per node, joined from
the taxonomy's official mapping files — so the validator can cite Bugcrowd's suggested
vector instead of deriving one blind. It also writes:

    reference/bugcrowd-vrt-deprecated.json   old-node -> {version: new-node}  (for vrt_diff.py)

The VRT is Bugcrowd's; we do NOT redistribute it, we fetch it. Version identity is the git
TAG (v1.2 … newest); the JSON itself carries only metadata.release_date.

Usage:
    python3 scripts/build_vrt.py                    # newest tagged release (default)
    python3 scripts/build_vrt.py --version 1.18     # a specific release (v-prefix optional)
    python3 scripts/build_vrt.py --version master    # the rolling, pre-release edge
    python3 scripts/build_vrt.py --list-versions     # print available releases and exit
    python3 scripts/build_vrt.py --no-mappings       # flat file only, skip CVSS/CWE/deprecated
    python3 scripts/build_vrt.py --source taxonomy.json   # build from a local file (flat only)

Source: https://github.com/bugcrowd/vulnerability-rating-taxonomy
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO = "bugcrowd/vulnerability-rating-taxonomy"
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
TAGS_API = "https://api.github.com/repos/{repo}/tags?per_page=100"
REF_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "reference"))
OUT_FLAT = os.path.join(REF_DIR, "bugcrowd-vrt-flat.txt")
OUT_ENRICHED = os.path.join(REF_DIR, "bugcrowd-vrt-enriched.tsv")
OUT_DEPRECATED = os.path.join(REF_DIR, "bugcrowd-vrt-deprecated.json")

MAPPINGS = {  # output key -> (path in repo, leaf field)
    "cvss_v3": ("mappings/cvss_v3/cvss_v3.json", "cvss_v3"),
    "cvss_v4": ("mappings/cvss_v4/cvss_v4.json", "cvss_v4"),
    "cwe": ("mappings/cwe/cwe.json", "cwe"),
}
DEPRECATED_PATH = "deprecated-node-mapping.json"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "adversarial-validator-build-vrt"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (official hosts only)
        return resp.read()


def _ver_key(tag: str) -> tuple:
    nums = re.findall(r"\d+", tag)
    return tuple(int(n) for n in nums) if nums else ()


def list_tags() -> list[str]:
    data = json.loads(_get(TAGS_API.format(repo=REPO)).decode("utf-8"))
    tags = [t["name"] for t in data if isinstance(t, dict) and t.get("name")]
    return sorted(tags, key=_ver_key, reverse=True)


def resolve_ref(version: str) -> str:
    v = version.strip()
    if v in ("master", "main", "HEAD"):
        return v
    if v == "latest":
        tags = list_tags()
        if not tags:
            raise RuntimeError("no release tags found on GitHub")
        return tags[0]
    return v if v.startswith("v") else f"v{v}"


def fetch_json(ref: str, path: str, required: bool = True) -> dict | None:
    url = RAW.format(repo=REPO, ref=ref, path=path)
    try:
        return json.loads(_get(url).decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            if required:
                raise SystemExit(
                    f"ERROR: not found at ref '{ref}' (HTTP 404): {path}\n"
                    f"       Run `python3 {sys.argv[0]} --list-versions` to see valid releases."
                )
            return None
        raise


def leaf_values(data: dict | None, field: str) -> dict[str, str]:
    """Flatten a mapping tree to {dotted-id-path: field-value} for leaf nodes."""
    out: dict[str, str] = {}
    if not data:
        return out
    content = data.get("content", data if isinstance(data, list) else [])

    def walk(nodes, trail):
        for n in nodes:
            nid = n.get("id") or n.get("name") or "?"
            path = trail + [nid]
            ch = n.get("children")
            if ch:
                walk(ch, path)
            else:
                val = n.get(field)
                if isinstance(val, list):
                    val = ";".join(str(x) for x in val if x is not None) or None
                if val:
                    out[".".join(path)] = str(val)

    walk(content, [])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build the Bugcrowd VRT reference files (flat + enriched).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--version", default="latest", metavar="REF",
                    help="release to build: 'latest' (default), '1.18'/'v1.18', or 'master'.")
    ap.add_argument("--list-versions", action="store_true", help="print available releases and exit.")
    ap.add_argument("--no-mappings", action="store_true", help="flat file only; skip CVSS/CWE/deprecated mappings.")
    ap.add_argument("--source", help="build the flat file from a local taxonomy JSON (no mappings).")
    args = ap.parse_args()

    if args.list_versions:
        try:
            tags = list_tags()
        except Exception as e:  # noqa: BLE001
            print(f"ERROR: could not list versions: {e}", file=sys.stderr)
            return 1
        print("Available Bugcrowd VRT releases (newest first), plus 'master':\n")
        print("  master  (rolling, pre-release edge)")
        for t in tags:
            print(f"  {t}")
        return 0

    # Load the main taxonomy
    if args.source:
        with open(args.source, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        ref_label = f"local:{os.path.basename(args.source)}"
        ref = None
        do_mappings = False
    else:
        ref = resolve_ref(args.version)
        print(f"Fetching VRT @ {ref}", file=sys.stderr)
        data = fetch_json(ref, "vulnerability-rating-taxonomy.json")
        ref_label = f"{REPO}@{ref}"
        do_mappings = not args.no_mappings

    release_date = ""
    if isinstance(data, dict):
        release_date = (data.get("metadata") or {}).get("release_date", "") or ""

    # Load mappings (best effort — older releases may lack cvss_v4)
    maps: dict[str, dict[str, str]] = {k: {} for k in MAPPINGS}
    map_status: list[str] = []
    if do_mappings:
        for key, (path, field) in MAPPINGS.items():
            print(f"Fetching mapping {key} @ {ref}", file=sys.stderr)
            md = fetch_json(ref, path, required=False)
            maps[key] = leaf_values(md, field)
            map_status.append(f"{key}:{len(maps[key]) if md else 'absent'}")

    # Walk the main taxonomy, tracking BOTH the name path and the dotted id path
    content = data.get("content", data if isinstance(data, list) else [])
    flat: list[str] = []
    enriched: list[str] = []

    def walk(nodes, name_trail, id_trail):
        for n in nodes:
            name = n.get("name") or n.get("id") or "?"
            nid = n.get("id") or n.get("name") or "?"
            names = name_trail + [name]
            ids = id_trail + [nid]
            ch = n.get("children")
            if ch:
                walk(ch, names, ids)
            else:
                p = n.get("priority")
                prio = f"P{p}" if isinstance(p, int) else "P?"
                name_path = " > ".join(names)
                dotted = ".".join(ids)
                flat.append(f"{prio}\t{name_path}")
                if do_mappings:
                    v3 = maps["cvss_v3"].get(dotted, "-")
                    v4 = maps["cvss_v4"].get(dotted, "-")
                    cwe = maps["cwe"].get(dotted, "-")
                    enriched.append(f"{dotted}\t{prio}\t{name_path}\t{v3}\t{v4}\t{cwe}")

    walk(content, [], [])
    if not flat:
        print("ERROR: no VRT entries parsed — the schema may have changed.", file=sys.stderr)
        return 1

    prov = (f"# source: {ref_label}" + (f"   release_date: {release_date}" if release_date else ""))
    hdr = [
        "# Bugcrowd Vulnerability Rating Taxonomy (flattened) — one `P<n><TAB>category path` per line.",
        "# Built by adversarial-validator/scripts/build_vrt.py; the VRT is Bugcrowd's (not redistributed here).",
        prov,
    ]
    with open(OUT_FLAT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hdr) + "\n" + "\n".join(flat) + "\n")
    print(f"Wrote {len(flat)} entries ({ref_label}) to {OUT_FLAT}")

    if do_mappings:
        ehdr = [
            "# Bugcrowd VRT, enriched — columns: id<TAB>priority<TAB>name path<TAB>cvss_v3<TAB>cvss_v4<TAB>cwe",
            "# cvss_v3/cvss_v4 are Bugcrowd's OWN authored vectors for the node ('-' if none); cwe is the mapped CWE.",
            prov + f"   mappings: {', '.join(map_status)}",
        ]
        with open(OUT_ENRICHED, "w", encoding="utf-8") as fh:
            fh.write("\n".join(ehdr) + "\n" + "\n".join(enriched) + "\n")
        print(f"Wrote {len(enriched)} enriched rows to {OUT_ENRICHED}")

        dep = fetch_json(ref, DEPRECATED_PATH, required=False)
        if dep is not None:
            with open(OUT_DEPRECATED, "w", encoding="utf-8") as fh:
                json.dump(dep, fh, indent=0)
            print(f"Wrote deprecated-node map ({len(dep)} entries) to {OUT_DEPRECATED}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
