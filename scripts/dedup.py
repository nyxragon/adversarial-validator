#!/usr/bin/env python3
"""
Grounded prior-art check for a candidate finding — turns the validator's dedup gate from
"does the model recall this being public?" into checked queries against real disclosure
surfaces, plus your own validation ledger. It does NOT decide true duplication; it surfaces
candidates for the human/agent to judge, and it fails OPEN (a query that cannot run leaves the
question inconclusive, never a false "novel").

Sources:
  - NVD CVE keyword search (services.nvd.nist.gov)
  - GitHub Security Advisories by affected package (api.github.com/advisories), when --package given
  - your local ledger (scripts/ledger.py) — have I already filed this?

Usage:
    python3 scripts/dedup.py --vendor casdoor --keyword "ldap takeover"
    python3 scripts/dedup.py --vendor shuffle --keyword ssrf --package shuffle --ecosystem pip
    python3 scripts/dedup.py --vendor acme --keyword idor --class idor --target acme.com   # also checks ledger

Verdict: NO-PUBLIC-MATCH / POSSIBLE-DUP (review the listed items) / INCONCLUSIVE (a source was unreachable).
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={q}&resultsPerPage=15"
GH_ADV = "https://api.github.com/advisories?affects={pkg}&per_page=15"


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "adversarial-validator-dedup",
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def nvd(vendor: str, keyword: str):
    q = urllib.parse.quote(f"{vendor} {keyword}".strip())
    try:
        data = _get(NVD.format(q=q))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        return None, str(e)
    out = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append((c.get("id", "?"), c.get("published", "")[:10], desc[:160]))
    return out, None


def ghsa(pkg: str):
    try:
        data = _get(GH_ADV.format(pkg=urllib.parse.quote(pkg)))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        return None, str(e)
    out = [(a.get("ghsa_id", "?"), (a.get("published_at") or "")[:10], (a.get("summary") or "")[:160])
           for a in (data if isinstance(data, list) else [])]
    return out, None


def main() -> int:
    ap = argparse.ArgumentParser(description="Grounded prior-art / dedup check.")
    ap.add_argument("--vendor", required=True)
    ap.add_argument("--keyword", required=True, help="bug class / component, e.g. 'ssrf login userinfo'")
    ap.add_argument("--package", help="package name for GitHub advisory lookup")
    ap.add_argument("--ecosystem", help="(unused placeholder for future ecosystem filtering)")
    ap.add_argument("--class", dest="cls", help="bug class for local ledger check")
    ap.add_argument("--target", help="target for local ledger check")
    args = ap.parse_args()

    inconclusive = False
    print(f"PRIOR-ART for: {args.vendor} / {args.keyword}\n")

    nvd_hits, nvd_err = nvd(args.vendor, args.keyword)
    if nvd_err:
        inconclusive = True
        print(f"NVD: UNREACHABLE ({nvd_err}) — inconclusive, treat as OPEN")
    else:
        print(f"NVD: {len(nvd_hits)} CVE(s) matched the keywords")
        for cid, pub, desc in nvd_hits[:10]:
            print(f"  {cid}  {pub}  {desc}")
    print()

    if args.package:
        gh_hits, gh_err = ghsa(args.package)
        if gh_err:
            inconclusive = True
            print(f"GHSA: UNREACHABLE ({gh_err}) — inconclusive")
        else:
            print(f"GHSA: {len(gh_hits)} advisory(ies) affecting '{args.package}'")
            for gid, pub, summ in gh_hits[:10]:
                print(f"  {gid}  {pub}  {summ}")
        print()

    if args.cls and args.target:
        try:
            import ledger  # noqa: PLC0415
            sig = ledger._sig(args.cls, args.target, "")
            own = [r for r in ledger._load()
                   if r.get("class", "").lower() == args.cls.lower()
                   and args.target.lower() in r.get("target", "").lower()]
            print(f"OWN LEDGER: {len(own)} prior {args.cls} finding(s) on {args.target} (sig {sig})")
            for r in own[:10]:
                print(f"  {r.get('ts','?')}  {r.get('verdict','?')}  {r.get('title','')}")
            print()
        except Exception as e:  # noqa: BLE001
            print(f"OWN LEDGER: could not read ({e})\n")

    total_public = (len(nvd_hits) if nvd_hits else 0)
    if args.package and 'gh_hits' in dir() and gh_hits:
        total_public += len(gh_hits)
    if inconclusive:
        verdict = "INCONCLUSIVE (a source was unreachable — the dedup question stays OPEN)"
    elif total_public > 0:
        verdict = "POSSIBLE-DUP (public items matched — review them against your finding before filing)"
    else:
        verdict = "NO-PUBLIC-MATCH (no CVE/GHSA matched; still not a guarantee of novelty)"
    print(f"VERDICT: {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
