---
description: Build or pin the Bugcrowd VRT table the validator scores against. Pick the newest release, a specific version, the rolling edge, or list what is available. Usage: /vrt [version | list]
argument-hint: "[latest | 1.18 | master | list]"
allowed-tools: Bash
---

# /vrt — set the Bugcrowd VRT version

Build `reference/bugcrowd-vrt-flat.txt` (what the `finding-validator` greps to quote an exact VRT
line) from Bugcrowd's official taxonomy. Version identity is the git **tag** (`v1.2` … newest), not a
field in the JSON.

Run **exactly one** `Bash` call against `${CLAUDE_PLUGIN_ROOT}/scripts/build_vrt.py`, choosing the
flag from the argument the user passed — `$ARGUMENTS`:

- **empty** → `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/build_vrt.py"`  (newest tagged release)
- **`list`** or **`versions`** → `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/build_vrt.py" --list-versions`
  then stop — this only lists, it does not build.
- **a version** (`1.18`, `v1.18`, `latest`, `master`) → `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/build_vrt.py" --version "$ARGUMENTS"`

Do not invent any other flags; `--version` and `--list-versions` are the only ones. If the build
reports a 404, the version does not exist — run `--list-versions` and show the user the valid set.

## After it runs

Report, briefly:
- which version was built (the script prints `source: …@v<tag>   release_date: …`), and the entry count, **or** the list of available releases for `list`;
- that the validator will now anchor Bugcrowd findings to that version.

Do not read the file back or dump its contents — the one-line build summary is the confirmation.
