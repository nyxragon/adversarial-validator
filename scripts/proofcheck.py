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

This checks the MECHANICS of a proof, not the vulnerability — Claude does all the vuln
reasoning. The per-class schemas (idor, ssrf, ssrf_read, xss_reflected, xss_stored,
sqli_time, race, rce, auth_bypass) are conveniences; any other/novel class falls back to
'generic', which encodes the invariant they all share: a server-sourced marker (not the
request reflected) + a negative control that held + reproduced. So an unlisted class still
gets a deterministic sanity-check, and a template never limits what can be validated — a
mismatch or a missing template is not a refutation.

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
    if ctrl is None:
        out.append((MISS, "control_status: attacker reads an invented/unauthorized id (expect a 4xx deny)"))
    elif 400 <= ctrl < 500:
        out.append((OK, f"negative control held (invented/unauthorized id -> {ctrl}, differs from the 200 hit)"))
    elif 200 <= ctrl < 300:
        out.append((FAIL, f"negative control also returned {ctrl} — same as the hit, so the 200 may be a catch-all"))
    else:
        out.append((FAIL, f"negative control returned {ctrl}; expected a 4xx deny that differs from the hit"))
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
    # rendered != executed: demand an observed execution oracle, not just injection
    if e.get("executed") is True and e.get("nonce") and e.get("execution_marker") == e.get("nonce"):
        out.append((OK, "code execution observed (headless/browser oracle fired the planted nonce)"))
    elif e.get("executed") is True and not e.get("nonce"):
        out.append((MISS, "nonce + execution_marker: prove the fire is yours, not an incidental script"))
    else:
        out.append((MISS, "executed: injection may be shown, but code execution is not observed (rendered != executed)"))
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


def _rce(e):
    out = []
    nonce = e.get("cmd_nonce")
    text = e.get("output") or ""
    if not nonce:
        out.append((MISS, "cmd_nonce: a unique token your injected command emits"))
    elif nonce in text:
        out.append((OK, "command output contains the attacker-chosen nonce"))
    else:
        out.append((FAIL, "cmd_nonce does not appear in the output — not a confirmed execution"))
    sm = e.get("server_only_marker")
    if not sm:
        out.append((MISS, "server_only_marker: output the attacker could NOT supply (uid=, hostname, kernel)"))
    elif sm in text:
        out.append((OK, f"server-only marker present ('{sm}') — genuine execution, not a reflected echo"))
    else:
        out.append((FAIL, "server_only_marker not found in the output"))
    if _num(e.get("repetitions")) and _num(e.get("repetitions")) >= 2:
        out.append((OK, "reproduced >=2 times (nonce/marker vary per run)"))
    else:
        out.append((MISS, "repetitions: reproduce >=2 times"))
    return out


def _auth_bypass(e):
    out = []
    if e.get("unauth_or_forged") is True:
        out.append((OK, "request carried no valid credential (unauthenticated or forged/unsigned token)"))
    else:
        out.append((MISS, "unauth_or_forged: show the request used no valid session or a forged token"))
    pm = e.get("privileged_marker")
    if not pm:
        out.append((MISS, "privileged_marker: a server-set field proving privileged identity (admin:true, victim username)"))
    elif e.get("marker_server_set") is False:
        out.append((FAIL, "privileged_marker is attacker-supplied (in the token/request) — not proof the server granted it"))
    else:
        out.append((OK, f"server granted a privileged identity ('{pm}') from server state, not attacker input"))
    if e.get("control_rejected") is True:
        out.append((OK, "the correctly-validating sibling/path rejects the same input (negative control holds)"))
    else:
        out.append((MISS, "control_rejected: show the proper validation path rejects the forged/absent credential"))
    return out


def _ssrf_read(e):
    """Response-read SSRF: the internal response body is returned to the attacker
    (strictly stronger than an OOB callback, which the 'ssrf' schema covers)."""
    out = []
    marker = e.get("internal_marker")
    if not marker:
        out.append((MISS, "internal_marker: a target-specific string from the internal response (cluster_uuid, metadata field)"))
    elif e.get("marker_in_request"):
        out.append((FAIL, "internal_marker also appears in the request — cannot distinguish from reflection"))
    else:
        out.append((OK, "internal response content was returned to the attacker, with a marker not in the request"))
    ctrl = e.get("control_status")
    if ctrl is None:
        out.append((MISS, "control_status: an invalid/benign host should differ (e.g. 500/timeout), proving a real fetch"))
    elif 200 <= ctrl < 300:
        out.append((FAIL, f"invalid-host control also returned {ctrl} — the success may not be a real outbound fetch"))
    else:
        out.append((OK, f"invalid-host control differs ({ctrl}) — the success is a genuine outbound fetch"))
    return out


def _generic(e):
    """Class-agnostic proof principle, for ANY vuln with no specific template above.
    The specific schemas are conveniences; this is the invariant they all encode, so a
    novel/unlisted class still gets a deterministic sanity-check instead of none. Claude
    still does all the vuln reasoning — this only checks the mechanics of the proof."""
    out = []
    marker = e.get("marker")
    if not marker:
        out.append((MISS, "marker: a target-specific value that proves the effect (server-sourced, not a status code)"))
    elif e.get("marker_in_request") or e.get("marker_attacker_supplied"):
        out.append((FAIL, "marker is attacker-supplied / in the request — indistinguishable from reflection"))
    else:
        out.append((OK, "a server-sourced marker proves the effect (attacker could not have supplied it)"))
    if e.get("negative_control_held") is True:
        out.append((OK, "a negative control (invented/benign input) differed in the same run"))
    elif e.get("negative_control_held") is False:
        out.append((FAIL, "the negative control did NOT differ — the result may be a catch-all/instrument artifact"))
    else:
        out.append((MISS, "negative_control_held: run an invented/benign control that must NOT fire, same run"))
    if _num(e.get("repetitions")) and _num(e.get("repetitions")) >= 2:
        out.append((OK, "reproduced >=2 times"))
    else:
        out.append((MISS, "repetitions: reproduce >=2 times"))
    return out


SCHEMAS = {
    "idor": _idor, "bola": _idor, "bfla": _idor,
    "ssrf": _ssrf, "ssrf_read": _ssrf_read, "ssrf-read": _ssrf_read,
    "xss_reflected": _xss_reflected, "xss_stored": _xss_stored,
    "sqli_time": _sqli_time, "race": _race,
    "rce": _rce, "auth_bypass": _auth_bypass, "auth-bypass": _auth_bypass, "authbypass": _auth_bypass,
    "generic": _generic, "other": _generic,
}

TEMPLATES = {
    "idor": {"class": "idor", "owner_hash": "<sha256 of victim's own view>",
             "attacker_hashes": ["<sha>", "<sha>", "<sha>"], "control_status": 404},
    "ssrf": {"class": "ssrf", "payload_url": "http://<nonce>.oob.example",
             "oob_nonce": "<nonce>", "oob_protocol": "http", "oob_received": True},
    "xss_reflected": {"class": "xss_reflected", "nonce": "<nonce>", "dialog_fired": True,
                      "dialog_text": "<nonce>", "repetitions": 3, "control_dialog": False},
    "xss_stored": {"class": "xss_stored", "cross_user_delivery": True, "trigger": "natural",
                   "executed": True, "nonce": "<nonce>", "execution_marker": "<nonce>"},
    "sqli_time": {"class": "sqli_time", "injected_delay_s": 5,
                  "samples": [4.9, 5.1, 5.0, 4.8, 5.2, 5.0, 4.9, 5.1], "control_delay_s": 0.1, "p_value": 0.003},
    "race": {"class": "race", "concurrent_successes": 3, "attempts": 20, "control_sequential_successes": 0},
    "rce": {"class": "rce", "cmd_nonce": "<nonce>", "output": "<nonce> uid=0(root) host=abc123",
            "server_only_marker": "uid=0(root)", "repetitions": 2},
    "auth_bypass": {"class": "auth_bypass", "unauth_or_forged": True, "privileged_marker": "admin:true",
                    "marker_server_set": True, "control_rejected": True},
    "ssrf_read": {"class": "ssrf_read", "internal_marker": "<cluster_uuid>", "marker_in_request": False,
                  "control_status": 500},
    "generic": {"class": "generic", "marker": "<server-sourced value proving the effect>",
                "marker_in_request": False, "negative_control_held": True, "repetitions": 2},
}


def run(e: dict) -> tuple[str, str, list[tuple[str, str]]]:
    cls = (e.get("class") or "").lower()
    schema = SCHEMAS.get(cls, _generic)   # novel/unlisted class -> the generic proof principle, not a hard error
    checks = _artifact_checks(e) + schema(e)
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
    ({"class": "idor", "owner_hash": "ab", "attacker_hashes": ["ab", "ab", "ab"], "control_status": 400}, "PASS"),
    ({"class": "idor", "owner_hash": "ab", "attacker_hashes": ["ab", "cd", "ab"], "control_status": 404}, "FAIL"),
    ({"class": "idor", "owner_hash": "ab", "attacker_hashes": ["ab", "ab", "ab"], "control_status": 200}, "FAIL"),
    ({"class": "idor", "owner_hash": "ab", "attacker_hashes": ["ab"], "control_status": 404}, "INCOMPLETE"),
    ({"class": "ssrf", "payload_url": "http://n1.oob", "oob_nonce": "n1", "oob_protocol": "http", "oob_received": True}, "PASS"),
    ({"class": "ssrf", "payload_url": "http://n1.oob", "oob_nonce": "n1", "oob_protocol": "dns", "oob_received": True}, "FAIL"),
    ({"class": "ssrf", "payload_url": "http://x.oob", "oob_nonce": "n1", "oob_protocol": "http", "oob_received": True}, "FAIL"),
    ({"class": "xss_reflected", "nonce": "z9", "dialog_fired": True, "dialog_text": "z9", "repetitions": 3, "control_dialog": False}, "PASS"),
    ({"class": "xss_reflected", "nonce": "z9", "dialog_fired": True, "dialog_text": "z9", "repetitions": 3, "control_dialog": True}, "FAIL"),
    ({"class": "xss_stored", "cross_user_delivery": True, "trigger": "console"}, "FAIL"),
    ({"class": "xss_stored", "cross_user_delivery": True, "trigger": "natural"}, "INCOMPLETE"),  # injection only, no execution
    ({"class": "xss_stored", "cross_user_delivery": True, "trigger": "natural",
      "executed": True, "nonce": "z9", "execution_marker": "z9"}, "PASS"),
    ({"class": "sqli_time", "injected_delay_s": 5, "samples": [4.9, 5.1, 5, 4.8, 5.2, 5, 4.9, 5.1], "p_value": 0.003, "control_delay_s": 0.1}, "PASS"),
    ({"class": "sqli_time", "injected_delay_s": 5, "samples": [0.1, 0.2, 0.1, 0.1, 0.2, 0.1, 0.1, 0.1], "p_value": 0.5, "control_delay_s": 0.1}, "FAIL"),
    ({"class": "race", "concurrent_successes": 3, "control_sequential_successes": 0}, "PASS"),
    ({"class": "race", "concurrent_successes": 3, "control_sequential_successes": 2}, "FAIL"),
    ({"class": "ssrf", "payload_url": "http://n1.oob", "oob_nonce": "n1", "oob_protocol": "http", "oob_received": True, "marker_reflected": True}, "FAIL"),
    # rce
    ({"class": "rce", "cmd_nonce": "q7", "output": "q7 uid=0(root) host=abc", "server_only_marker": "uid=0(root)", "repetitions": 2}, "PASS"),
    ({"class": "rce", "cmd_nonce": "q7", "output": "q7 echoed back only", "server_only_marker": "uid=0(root)", "repetitions": 2}, "FAIL"),
    ({"class": "rce", "cmd_nonce": "q7", "output": "q7 uid=0(root)", "server_only_marker": "uid=0(root)", "repetitions": 1}, "INCOMPLETE"),
    # auth_bypass
    ({"class": "auth_bypass", "unauth_or_forged": True, "privileged_marker": "admin:true", "marker_server_set": True, "control_rejected": True}, "PASS"),
    ({"class": "auth_bypass", "unauth_or_forged": True, "privileged_marker": "admin:true", "marker_server_set": False, "control_rejected": True}, "FAIL"),
    ({"class": "auth_bypass", "unauth_or_forged": True, "privileged_marker": "admin:true", "marker_server_set": True}, "INCOMPLETE"),
    # ssrf_read (response-read)
    ({"class": "ssrf_read", "internal_marker": "JwZL0BLq", "marker_in_request": False, "control_status": 500}, "PASS"),
    ({"class": "ssrf_read", "internal_marker": "JwZL0BLq", "marker_in_request": True, "control_status": 500}, "FAIL"),
    ({"class": "ssrf_read", "internal_marker": "JwZL0BLq", "marker_in_request": False, "control_status": 200}, "FAIL"),
    # generic principle + novel/unlisted class falling back to it
    ({"class": "generic", "marker": "srv-xyz", "marker_in_request": False, "negative_control_held": True, "repetitions": 2}, "PASS"),
    ({"class": "generic", "marker": "srv-xyz", "marker_in_request": True, "negative_control_held": True, "repetitions": 2}, "FAIL"),
    ({"class": "prototype_pollution", "marker": "polluted-7f", "marker_in_request": False, "negative_control_held": True, "repetitions": 2}, "PASS"),
    ({"class": "some_novel_class", "marker": "m1", "marker_in_request": False, "negative_control_held": False, "repetitions": 2}, "FAIL"),
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
