# Adversarial Finding Validator

A Claude Code plugin that **tries to kill your security finding before a triager does.**

It ships a subagent, `finding-validator`, that runs in an **isolated context with no hunting
history** — so it never inherits the optimism of whoever found the bug. You hand it the *evidence*,
not your theory; it hands back a blunt verdict, a severity anchored to the right system, and the one
reason the finding would be closed.

Most "ask an LLM to review my bug" setups fail the same way: the model sees the hunter's reasoning and
rationalizes it into a yes. This fixes that structurally — the validator is a separate agent, fed
evidence only, told to assume you were wrong and find out why.

> Prior art: the isolated "disprove-bot" idea is well established in offensive-AI work (rez0's separate
> validation bot, XBOW's validators, Project Zero's Big Sleep / Naptime oracle-first loop). This plugin
> packages that discipline with multi-platform severity anchoring and a false-positive catalog.

## The four verdicts

| Verdict | Meaning | What you do |
|---|---|---|
| **SUBMIT** | Proven, reproducible, real impact, in scope. | Write the report, at the anchored severity. |
| **PROVE** | It **is** a real vulnerability; only the demonstration is missing. | Produce the one proof it names (fire the oracle / show the live repro / demonstrate reachability), then it's SUBMIT. |
| **INVESTIGATE** | Plausible but **not yet established as real** — something load-bearing is unknown. | Resolve the one open question it names. |
| **DISCARD** | Not a valid finding (no impact, not reachable, always-rejected class, or an instrument artifact). | Drop it; record why so it isn't re-run. |

`PROVE` is deliberately **not** a weak verdict — it affirms the bug is real and just needs its demo.
That distinction (real-but-undemonstrated vs. maybe-real) is the whole point.

## Example

Hand it the evidence for an SSRF you think is a High, and it comes back:

```
VERDICT:   PROVE
PLATFORM:  HackerOne — CVSS 3.1
SEVERITY:  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 7.1 High  (if the read is shown)
           currently demonstrated: external-only fetch -> C:L ≈ 2.7 Low
GATE:      #9 fails — the server fetches an external host you control, but reaching a
           RESTRICTED internal target (the impact the severity rests on) is not shown.
FP CHECK:  Ruled out reflected-marker and DNS-only — a real HTTP GET+POST was received
           server-side, not just a DNS callback.
DEDUP:     No public CVE/advisory found for this endpoint.
REASON:    The SSRF primitive is proven live, but the whole severity depends on reaching
           internal/metadata, which the evidence does not demonstrate.
NEXT:      Point the fetch at the metadata IP and capture the credential arriving at your
           listener. Produce that and it is SUBMIT.
```

It affirmed the bug, refused to hand you an unearned High, separated the proven severity from the
ceiling, and told you the single thing to do next. That is the whole loop.

## Severity, anchored to the platform

The validator never states a severity it can't derive. It detects the target platform and anchors to
that platform's system:

- **Bugcrowd** → the exact **VRT** line (P1–P5), quoted, plus a supporting CVSS vector.
- **HackerOne / Intigriti / YesWeHack / Synack / Cobalt** → a full **CVSS 3.1** vector + band.
- **Coordinated disclosure / CVE / GitHub Security Advisory** → a full **CVSS 3.1** vector.
- **Platform not stated** → defaults to CVSS 3.1 and says so.

Universal rule: it computes the CVSS vector itself. *The vector is the claim; the number is arithmetic.*

## What it refuses to be fooled by

Before believing any evidence, it rules out the instrument artifacts that routinely fake a positive:
a proxy/client error page served as `200`, catch-all responses, CDN/WAF refusals mistaken for app
behaviour, silent egress bans, reflected markers, versions read from a filename, and oracles run
without a negative control. (See `agents/finding-validator.md` §3.)

## Install

Requires [Claude Code](https://claude.com/claude-code). This repo is itself a plugin marketplace.

```bash
# add the marketplace (once), then install
claude plugin marketplace add nyxragon/adversarial-validator
claude plugin install adversarial-validator@nyxragon-plugins
```

Or load it ad-hoc for one session without installing:

```bash
claude --plugin-dir /path/to/adversarial-validator
```

Then build the Bugcrowd VRT data (optional, for Bugcrowd findings — the plugin works without it):

```bash
python3 scripts/build_vrt.py
```

## Use

Invoke the slash command with evidence only:

```
/adversarial-validator:validate <paste the request/response, baseline, attacker path, impact, platform>
```

…or launch the agent directly: `@agent-adversarial-validator:finding-validator`.

**Give it evidence, not your reasoning:** the exact request(s)/response(s) with status + body markers,
the baseline that proves it isn't a catch-all, the real attacker trigger path, the concrete data or
state change demonstrated, the platform, and any dedup you've done. If you argue your case, you defeat
the isolation that makes it useful.

## Configuration

The agent is set to `model: opus` (complex adversarial reasoning benefits from the strongest model).
If your plan doesn't include Opus, edit `agents/finding-validator.md` and change `model:` to `sonnet`.

## Layout

```
adversarial-validator/
├── .claude-plugin/
│   ├── plugin.json          # plugin manifest
│   └── marketplace.json     # makes this repo installable as a marketplace
├── agents/
│   └── finding-validator.md # the validator (the product)
├── commands/
│   └── validate.md          # thin launcher for the agent
├── reference/
│   ├── cvss-3.1-metrics.md
│   ├── platform-severity-map.md
│   └── README.md            # how to build the VRT file
├── scripts/
│   └── build_vrt.py         # fetch + flatten Bugcrowd's official VRT
├── LICENSE                  # MIT
└── README.md
```

## Contributing

The false-positive catalog and the platform map are meant to grow. If an instrument artifact fooled
you, or a platform uses a severity system that isn't mapped, open a PR.

## License

MIT — see [LICENSE](LICENSE). The Bugcrowd VRT is Bugcrowd's and is fetched, not redistributed here.
