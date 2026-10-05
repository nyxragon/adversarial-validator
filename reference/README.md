# Reference data

The validator reads these at runtime via `${CLAUDE_PLUGIN_ROOT}/reference/...`.

| File | Purpose | Shipped? |
|---|---|---|
| `cvss-3.1-metrics.md` | CVSS 3.1 base-metric reference + score bands | yes |
| `platform-severity-map.md` | which severity system each bug-bounty platform uses | yes |
| `bugcrowd-vrt-flat.txt` | flattened Bugcrowd VRT, one `P<n><TAB>path` per line | **no — build it** |

## Building the Bugcrowd VRT file

The Bugcrowd Vulnerability Rating Taxonomy is **Bugcrowd's** data, so this MIT repo does not
redistribute it. Generate it locally from Bugcrowd's official, open-source taxonomy:

```bash
python3 scripts/build_vrt.py                 # newest tagged release (default)
python3 scripts/build_vrt.py --version 1.18  # pin a specific release (v-prefix optional)
python3 scripts/build_vrt.py --version master # the rolling, pre-release edge
python3 scripts/build_vrt.py --list-versions # print available releases and exit
```

This writes `reference/bugcrowd-vrt-flat.txt`. Bugcrowd's version identity is the git **tag**
(`v1.2` … `v1.19.1`), not a field inside the JSON — the taxonomy file itself carries only a
`metadata.release_date`. The build defaults to the newest tag and stamps the chosen version into a
`#`-prefixed header at the top of the file (the validator greps `P<n>` lines, so the header is inert).

The validator degrades gracefully without the file: for Bugcrowd findings it will anchor to a CVSS
3.1 vector and note that the VRT line could not be quoted.

- Source: https://github.com/bugcrowd/vulnerability-rating-taxonomy
- The VRT is Bugcrowd's; see their repository for its license and terms.
