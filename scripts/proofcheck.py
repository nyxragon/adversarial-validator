#!/usr/bin/env python3
"""
Deterministic proof-schema checker for a candidate finding's oracle result.

The adversarial validator is a reasoning gate, not an exploit engine — so the strongest
thing it can do about proof is *demand a deterministic oracle artifact and verify it is
present and self-consistent* before any LLM reasoning runs. This is the portable analog of
XBOW's "verify with something other than an LLM": you hand in the oracle output as a small
JSON evidence package, and this checks it against the per-class schema. It does NOT touch a
target and it does NOT judge severity — it answers one question: is there a valid proof here?

    PASS       — a complete, self-consistent oracle artifact for this class is present.
    INCOMPLETE — the artifact is missing a required element (this is a PROVE lead, not a kill).
    FAIL       — the artifact contradicts itself or matches a known instrument artifact (kill it).

Usage:
    python3 scripts/proofcheck.py evidence.json
    cat evidence.json | python3 scripts/proofcheck.py -
    python3 scripts/proofcheck.py --template idor      # print the evidence schema for a class
    python3 scripts/proofcheck.py --self-test

Classes: idor, ssrf, xss_reflected, xss_stored, sqli_time, race.
Exit code: 0 = PASS, 1 = INCOMPLETE, 2 = FAIL, 3 = usage/parse error.
"""
import json
import sys

OK, MISS, FAIL = "ok", "missing", "fail"


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


# ---- universal instrument-artifact screen (runs for every class) ---------------------

def _artifact_checks(e: dict) -> list[tuple[str, str]]:
    out = []
    if e.get("marker_reflected") is True:
        out.append((FAIL, "marker is the request reflected back — not a target-produced signal"))
    if e.get("baseline_identical") is True:
        out.append((FAIL, "an invented/never-deployed baseline returned the same response — catch-all"))
    if e.get("edge_blocked") is True:
        out.append((FAIL, "response was an edge/WAF refusal, not application behaviour — question stays open"))
    return out


# ---- per-class schemas ----------------------------------------------------------------

def _idor(e):
    out = []
    owner = e.get("owner_hash")
    att = e.get("attacker_hashes") or []
    ctrl = e.get("control_status")
    if not owner:
        out.append((MISS, "owner_hash (what the victim sees for their own object)"))
    if not isinstance(att, list) or len(att) < 3:
        out.append((MISS, "attacker_hashes: >=3 cross-session reads of the victim object"))
    elif not owner:
        pass
    elif all(h == owner for h in att):
        out.append((OK, f"attacker received the victim's data in all {len(att)} sessions (hash == owner_hash)"))
    else:
        out.append((FAIL, "attacker response hashes do not all equal the owner's — not the same object/data"))
    if ctrl in (401, 403, 404):
        out.append((OK, f"negative control held (unauthorized/invented id -> {ctrl})"))
    elif ctrl is None:
        out.append((MISS, "control_status: attacker reads an invented/unauthorized id (expect 401/403/404)"))
    else:
        out.append((FAIL, f"negative control returned {ctrl}, not 401/403/404 — the 200 may be a catch-all"))
    return out


def _ssrf(e):
    out = []
    payload = e.get("payload_url") or ""
    nonce = e.get("oob_nonce")
    proto = (e.get("oob_protocol") or "").lower()
    if not nonce:
        out.append((MISS, "oob_nonce (unique token planted in the payload URL)"))
    elif nonce in payload:
        out.append((OK, "OOB nonce is present in the attacker-controlled payload URL"))
    else:
        out.append((FAIL, "oob_nonce does not appear in payload_url — cannot bind the callback to this request"))
    if e.get("oob_received") is not True:
        out.append((MISS, "oob_received: your self-hosted listener actually logged the interaction"))
    elif proto == "dns":
        out.append((FAIL, "DNS-only callback — proves resolution, not an HTTP fetch (rejected alone)"))
    elif proto in ("http", "https"):
        out.append((OK, f"server-side {proto.upper()} request received at your listener with the nonce"))
    else:
        out.append((MISS, "oob_protocol: 'http'/'https' (a real fetch), not 'dns'"))
    return out


def _xss_reflected(e):
    out = []
    nonce = e.get("nonce")
    if e.get("dialog_fired") is not True:
        out.append((MISS, "dialog_fired: a real headless browser observed the dialog"))
    elif nonce and e.get("dialog_text") == nonce:
        out.append((OK, "headless browser fired a dialog whose text equals the planted nonce"))
    elif not nonce:
        out.append((MISS, "nonce + dialog_text to prove the dialog is yours, not an incidental alert"))
    else:
        out.append((FAIL, "dialog_text does not match the planted nonce"))
    if _num(e.get("repetitions")) and _num(e.get("repetitions")) >= 3:
        out.append((OK, "reproduced >=3 times"))
    else:
        out.append((MISS, "repetitions: reproduce the dialog >=3 times"))
    if e.get("control_dialog") is True:
        out.append((FAIL, "a same-length benign control also fired a dialog — reflection is not the cause"))
    return out


def _xss_stored(e):
    out = []
    if e.get("cross_user_delivery") is True:
        out.append((OK, "payload was delivered to and rendered for a different user"))
    else:
        out.append((MISS, "cross_user_delivery: proven delivery to another user, not just your own view"))
    trig = (e.get("trigger") or "").lower()
    if trig in ("natural", "victim-side", "victim_side"):
        out.append((OK, "execution occurs on a natural victim action"))
    elif trig in ("console", "curl", "self"):
        out.append((FAIL, "trigger is console/curl/self — proves the payload valid, not reachable (PROVE lead)"))
    else:
        out.append((MISS, "trigger: 'natural' victim action (console/curl is not reachability)"))
    return out


def _sqli_time(e):
    out = []
    samples = [s for s in (e.get("samples") or []) if _num(s) is not None]
    inj = _num(e.get("injected_delay_s"))
    p = _num(e.get("p_value"))
    ctrl = _num(e.get("control_delay_s"))
    if len(samples) >= 8:
        out.append((OK, f"{len(samples)} timing samples collected (n>=8)"))
    else:
        out.append((MISS, "samples: >=8 observed delays for the injected sleep"))
    if p is not None and p < 0.01:
        out.append((OK, f"difference is significant (p={p} < 0.01)"))
    elif p is None:
        out.append((MISS, "p_value: Welch t-test vs the control, expect < 0.01"))
    else:
        out.append((FAIL, f"p_value={p} is not < 0.01 — timing difference is not significant"))
    if samples and inj:
        mean = sum(_num(s) for s in samples) / len(samples)
        if mean >= 0.7 * inj:
            out.append((OK, f"mean observed delay {mean:.2f}s >= 0.7x injected {inj}s"))
        else:
            out.append((FAIL, f"mean observed delay {mean:.2f}s < 0.7x injected {inj}s — sleep did not land"))
    elif not inj:
        out.append((MISS, "injected_delay_s: the sleep duration you injected"))
    if ctrl is not None and ctrl > 0.7 * (inj or 1):
        out.append((FAIL, f"control (no injection) also delayed {ctrl}s — the delay is not injection-caused"))
    return out


def _race(e):
    out = []
    conc = _num(e.get("concurrent_successes"))
    ctrl = _num(e.get("control_sequential_successes"))
    if conc is not None and conc > 1:
        out.append((OK, f"{int(conc)} successes under single-packet/concurrent delivery (limit breached > once)"))
    elif conc is None:
        out.append((MISS, "concurrent_successes: how many times the limited action succeeded concurrently"))
    else:
        out.append((FAIL, "only one concurrent success — no limit was actually breached"))
    if ctrl == 0:
        out.append((OK, "sequential control (@200ms) produced no breach"))
    elif ctrl is None:
        out.append((MISS, "control_sequential_successes: sequential replay should yield 0"))
    else:
        out.append((FAIL, f"sequential control also succeeded {int(ctrl)}x — not a race"))
    return out


SCHEMAS = {
    "idor": _idor, "bola": _idor, "bfla": _idor,
    "ssrf": _ssrf, "xss_reflected": _xss_reflected, "xss_stored": _xss_stored,
    "sqli_time": _sqli_time, "race": _race,
}

TEMPLATES = {
    "idor": {"class": "idor", "owner_hash": "<sha256 of victim's own view>",
             "attacker_hashes": ["<sha>", "<sha>", "<sha>"], "control_status": 404},
    "ssrf": {"class": "ssrf", "payload_url": "http://<nonce>.oob.example",
             "oob_nonce": "<nonce>", "oob_protocol": "http", "oob_received": True},
    "xss_reflected": {"class": "xss_reflected", "nonce": "<nonce>", "dialog_fired": True,
                      "dialog_text": "<nonce>", "repetitions": 3, "control_dialog": False},
    "xss_stored": {"class": "xss_stored", "cross_user_delivery": True, "trigger": "natural"},
    "sqli_time": {"class": "sqli_time", "injected_delay_s": 5,
                  "samples": [4.9, 5.1, 5.0, 4.8, 5.2, 5.0, 4.9, 5.1], "control_delay_s": 0.1, "p_value": 0.003},
    "race": {"class": "race", "concurrent_successes": 3, "attempts": 20, "control_sequential_successes": 0},
}


def run(e: dict) -> tuple[str, str, list[tuple[str, str]]]:
    cls = (e.get("class") or "").lower()
    if cls not in SCHEMAS:
        return "FAIL", cls, [(FAIL, f"unknown class '{cls}'; known: {', '.join(sorted(set(SCHEMAS)))}")]
    checks = _artifact_checks(e) + SCHEMAS[cls](e)
    if any(s == FAIL for s, _ in checks):
        verdict = "FAIL"
    elif any(s == MISS for s, _ in checks):
        verdict = "INCOMPLETE"
    else:
        verdict = "PASS"
    return verdict, cls, checks


def _print(verdict, cls, checks) -> None:
    glyph = {OK: "ok", MISS: "--", FAIL: "XX"}
    print(f"PROOF: {verdict}")
    print(f"CLASS: {cls}")
    print("CHECKS:")
    for s, label in checks:
        print(f"  [{glyph[s]}] {label}")
    if verdict == "PASS":
        print("ORACLE: a complete, self-consistent proof artifact is present.")
    elif verdict == "INCOMPLETE":
        print("ORACLE: this is a PROVE lead — produce the missing element(s) above, do not DISCARD.")
    else:
        print("ORACLE: the artifact is self-contradictory or an instrument artifact — this is a kill.")


_SELF_TEST = [
    ({"class": "idor", "owner_hash": "ab", "attacker_hashes": ["ab", "ab", "ab"], "control_status": 404}, "PASS"),
    ({"class": "idor", "owner_hash": "ab", "attacker_hashes": ["ab", "cd", "ab"], "control_status": 404}, "FAIL"),
    ({"class": "idor", "owner_hash": "ab", "attacker_hashes": ["ab", "ab", "ab"], "control_status": 200}, "FAIL"),
    ({"class": "idor", "owner_hash": "ab", "attacker_hashes": ["ab"], "control_status": 404}, "INCOMPLETE"),
    ({"class": "ssrf", "payload_url": "http://n1.oob", "oob_nonce": "n1", "oob_protocol": "http", "oob_received": True}, "PASS"),
    ({"class": "ssrf", "payload_url": "http://n1.oob", "oob_nonce": "n1", "oob_protocol": "dns", "oob_received": True}, "FAIL"),
    ({"class": "ssrf", "payload_url": "http://x.oob", "oob_nonce": "n1", "oob_protocol": "http", "oob_received": True}, "FAIL"),
    ({"class": "xss_reflected", "nonce": "z9", "dialog_fired": True, "dialog_text": "z9", "repetitions": 3, "control_dialog": False}, "PASS"),
    ({"class": "xss_reflected", "nonce": "z9", "dialog_fired": True, "dialog_text": "z9", "repetitions": 3, "control_dialog": True}, "FAIL"),
    ({"class": "xss_stored", "cross_user_delivery": True, "trigger": "console"}, "FAIL"),
    ({"class": "xss_stored", "cross_user_delivery": True, "trigger": "natural"}, "PASS"),
    ({"class": "sqli_time", "injected_delay_s": 5, "samples": [4.9, 5.1, 5, 4.8, 5.2, 5, 4.9, 5.1], "p_value": 0.003, "control_delay_s": 0.1}, "PASS"),
    ({"class": "sqli_time", "injected_delay_s": 5, "samples": [0.1, 0.2, 0.1, 0.1, 0.2, 0.1, 0.1, 0.1], "p_value": 0.5, "control_delay_s": 0.1}, "FAIL"),
    ({"class": "race", "concurrent_successes": 3, "control_sequential_successes": 0}, "PASS"),
    ({"class": "race", "concurrent_successes": 3, "control_sequential_successes": 2}, "FAIL"),
    ({"class": "ssrf", "payload_url": "http://n1.oob", "oob_nonce": "n1", "oob_protocol": "http", "oob_received": True, "marker_reflected": True}, "FAIL"),
]


def self_test() -> int:
    bad = 0
    for ev, expect in _SELF_TEST:
        got, _, _ = run(ev)
        ok = got == expect
        bad += not ok
        print(f"  [{'ok' if ok else 'FAIL'}] {ev.get('class'):14} expect {expect:10} got {got}")
    print(f"{'PASS' if not bad else 'FAIL'}: {len(_SELF_TEST) - bad}/{len(_SELF_TEST)} fixtures correct")
    return 1 if bad else 0


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[0] == "--self-test":
        return self_test()
    if argv[0] == "--template":
        if len(argv) < 2 or argv[1] not in TEMPLATES:
            print(f"usage: --template <{'|'.join(TEMPLATES)}>", file=sys.stderr)
            return 3
        print(json.dumps(TEMPLATES[argv[1]], indent=2))
        return 0
    try:
        raw = sys.stdin.read() if argv[0] == "-" else open(argv[0], encoding="utf-8").read()
        e = json.loads(raw)
    except (OSError, json.JSONDecodeError) as ex:
        print(f"ERROR: {ex}", file=sys.stderr)
        return 3
    verdict, cls, checks = run(e)
    _print(verdict, cls, checks)
    return {"PASS": 0, "INCOMPLETE": 1, "FAIL": 2}[verdict]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
