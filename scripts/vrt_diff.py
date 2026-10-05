#!/usr/bin/env python3
"""
Show how a Bugcrowd VRT node moved between two taxonomy versions — the one thing a
researcher validating an older finding actually needs: "my bug was scored against VRT
1.14; where is that line now, and did its priority change?"

Bugcrowd reclassifies, renames, and deprecates nodes between releases. This follows the
official deprecated-node-mapping chain from the FROM version to the TO version and reports
the priority and name-path on each side, flagging RENAMED / REPRIORITISED / DEPRECATED.

Usage:
    python3 scripts/vrt_diff.py --from 1.14 --to 1.19.1 ssrf.internal
    python3 scripts/vrt_diff.py --from 1.11 --to latest "SSRF"
    python3 scripts/vrt_diff.py --from 1.15 --to 1.19.1 broken_access_control.idor.modify_view_sensitive_information_guid

QUERY is a dotted VRT id (exact or suffix) or a case-insensitive substring of the name path.
Fetches both taxonomies live from Bugcrowd (no local build needed).
"""
import argparse
import sys

from build_vrt import resolve_ref, fetch_json, DEPRECATED_PATH  # noqa: E402


def taxonomy_index(ref: str) -> dict[str, tuple[str, str]]:
    """Fetch a VRT version and return {dotted-id: (priority, name path)} for leaves."""
    data = fetch_json(ref, "vulnerability-rating-taxonomy.json")
    content = data.get("content", data if isinstance(data, list) else [])
    idx: dict[str, tuple[str, str]] = {}

    def walk(nodes, names, ids):
        for n in nodes:
            nm = n.get("name") or n.get("id") or "?"
            nid = n.get("id") or n.get("name") or "?"
            nn, ii = names + [nm], ids + [nid]
            ch = n.get("children")
            if ch:
                walk(ch, nn, ii)
            else:
                p = n.get("priority")
                idx[".".join(ii)] = (f"P{p}" if isinstance(p, int) else "P?", " > ".join(nn))

    walk(content, [], [])
    return idx


def _ver_tuple(v: str) -> tuple:
    return tuple(int(x) for x in v.lstrip("v").split(".") if x.isdigit())


def migrate(node_id: str, dep: dict, upto: str) -> tuple[str, list[str]]:
    """Follow the deprecated-node chain from node_id, applying only remaps introduced
    at or before the target version. Returns (final_id, trail of 'old -(ver)-> new')."""
    upto_t = _ver_tuple(upto) if upto not in ("master", "main", "HEAD") else (9999,)
    trail: list[str] = []
    seen: set[str] = set()
    cur = node_id
    while cur in dep and cur not in seen:
        seen.add(cur)
        ver, new = next(iter(dep[cur].items()))   # each entry is a single {version: new}
        if _ver_tuple(ver) > upto_t:
            break
        trail.append(f"{cur} -({ver})-> {new}")
        cur = new
    return cur, trail


def resolve_query(q: str, idx: dict[str, tuple[str, str]]) -> list[str]:
    if q in idx:
        return [q]
    if "." in q:
        hits = [i for i in idx if i == q or i.endswith("." + q) or q in i]
    else:
        ql = q.lower()
        hits = [i for i in idx if ql in idx[i][1].lower() or ql in i.lower()]
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=__doc__)
    ap.add_argument("--from", dest="src", required=True, metavar="VER", help="original VRT version (e.g. 1.14)")
    ap.add_argument("--to", dest="dst", default="latest", metavar="VER", help="target version (default: latest)")
    ap.add_argument("query", help="dotted VRT id (exact/suffix) or substring of the name path")
    args = ap.parse_args()

    src_ref, dst_ref = resolve_ref(args.src), resolve_ref(args.dst)
    print(f"Fetching VRT {src_ref} and {dst_ref} …", file=sys.stderr)
    src_idx = taxonomy_index(src_ref)
    dst_idx = taxonomy_index(dst_ref)
    dep = fetch_json(dst_ref, DEPRECATED_PATH, required=False) or {}

    hits = resolve_query(args.query, src_idx)
    if not hits:
        print(f"No node in {src_ref} matched '{args.query}'. Try a broader substring.", file=sys.stderr)
        return 1
    if len(hits) > 12:
        print(f"'{args.query}' matched {len(hits)} nodes in {src_ref}; showing first 12 — narrow the query:",
              file=sys.stderr)
        hits = hits[:12]

    for nid in hits:
        src_prio, src_name = src_idx[nid]
        final_id, trail = migrate(nid, dep, dst_ref.lstrip("v"))
        print(f"\nFROM  {src_ref}   {src_prio}  {src_name}")
        print(f"      id: {nid}")
        if final_id in dst_idx:
            dst_prio, dst_name = dst_idx[final_id]
            flags = []
            if final_id != nid:
                flags.append("RENAMED/MOVED")
            if dst_prio != src_prio:
                flags.append(f"REPRIORITISED {src_prio}->{dst_prio}")
            if not flags:
                flags.append("UNCHANGED")
            print(f"TO    {dst_ref}   {dst_prio}  {dst_name}   [{', '.join(flags)}]")
            print(f"      id: {final_id}")
        elif final_id == "other" or (trail and trail[-1].endswith("other")):
            print(f"TO    {dst_ref}   DEPRECATED -> folded into a generic/'other' bucket (no direct successor)")
        elif nid in dst_idx:
            print(f"TO    {dst_ref}   {dst_idx[nid][0]}  {dst_idx[nid][1]}   [UNCHANGED]")
        else:
            # final_id landed on a non-leaf category that the target version re-split.
            children = sorted(i for i in dst_idx if i.startswith(final_id + "."))
            if children:
                print(f"TO    {dst_ref}   COLLAPSED into category '{final_id}', re-split into "
                      f"{len(children)} sub-nodes — pick the one matching your evidence:")
                for c in children:
                    cp, cn = dst_idx[c]
                    print(f"        {cp}  {cn.split(' > ')[-1]}   ({c.split('.')[-1]})")
            else:
                print(f"TO    {dst_ref}   node not found and no deprecation chain resolved it (manual check needed)")
        for step in trail:
            print(f"        chain: {step}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
