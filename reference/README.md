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
python3 scripts/build_vrt.py
```

This writes `reference/bugcrowd-vrt-flat.txt`. The validator degrades gracefully without it: for
Bugcrowd findings it will anchor to a CVSS 3.1 vector and note that the VRT line could not be quoted.

- Source: https://github.com/bugcrowd/vulnerability-rating-taxonomy
- The VRT is Bugcrowd's; see their repository for its license and terms.
