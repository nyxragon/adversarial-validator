#!/usr/bin/env python3
"""
Deterministic CVSS calculator (v3.1 and v4.0) — pure stdlib, no pip dependency.

Why this exists: the validator must never *assert* a CVSS number. The vector is the
claim (a judgement, one metric at a time); the number is arithmetic off it. Letting the
LLM do that arithmetic introduces an error class we can delete outright. The agent emits
a vector; THIS computes the score. The vector stays the claim, the number becomes verified.

v3.1 implements the FIRST specification formula directly. v4.0 ports FIRST's official
reference algorithm (MacroVector lookup + interpolation) against the official lookup
tables vendored in cvss4_tables.py (BSD-2-Clause, data only).

Usage:
    python3 scripts/score.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    python3 scripts/score.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    python3 scripts/score.py --self-test
    echo "CVSS:4.0/..." | python3 scripts/score.py -

Output (one line): <score> <band>  (CVSS vX.Y)\t<normalised vector>
Version is taken from the CVSS:x.y prefix; with no prefix it is inferred from the metrics.
"""
import math
import os
import sys

# ======================================================================================
# Shared
# ======================================================================================

def band(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def _split_metrics(vector: str) -> dict[str, str]:
    v = vector.strip()
    if v.upper().startswith("CVSS:"):
        v = v.split("/", 1)[1] if "/" in v else ""
    out: dict[str, str] = {}
    for part in v.split("/"):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"malformed metric '{part}' (expected KEY:VALUE)")
        k, val = part.split(":", 1)
        out[k.strip().upper()] = val.strip().upper()
    return out


# ======================================================================================
# CVSS v3.1  (closed-form, FIRST spec section 7.4)
# ======================================================================================

_AV31 = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC31 = {"L": 0.77, "H": 0.44}
_UI31 = {"N": 0.85, "R": 0.62}
_PR31_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR31_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA31 = {"H": 0.56, "L": 0.22, "N": 0.00}
_REQ31 = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
_CH31 = {"AV": set(_AV31), "AC": set(_AC31), "PR": {"N", "L", "H"}, "UI": set(_UI31),
         "S": {"U", "C"}, "C": set(_CIA31), "I": set(_CIA31), "A": set(_CIA31)}


def _roundup31(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss31_score(vector: str) -> tuple[float, str]:
    all_m = _split_metrics(vector)
    m = {k: all_m[k] for k in _REQ31 if k in all_m}
    missing = [k for k in _REQ31 if k not in m]
    if missing:
        raise ValueError(f"missing v3.1 base metric(s): {', '.join(missing)}")
    for k in _REQ31:
        if m[k] not in _CH31[k]:
            raise ValueError(f"bad value '{m[k]}' for {k}; allowed: {sorted(_CH31[k])}")
    changed = m["S"] == "C"
    pr = (_PR31_C if changed else _PR31_U)[m["PR"]]
    iss = 1 - (1 - _CIA31[m["C"]]) * (1 - _CIA31[m["I"]]) * (1 - _CIA31[m["A"]])
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else 6.42 * iss
    expl = 8.22 * _AV31[m["AV"]] * _AC31[m["AC"]] * pr * _UI31[m["UI"]]
    if impact <= 0:
        score = 0.0
    elif changed:
        score = _roundup31(min(1.08 * (impact + expl), 10))
    else:
        score = _roundup31(min(impact + expl, 10))
    norm = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _REQ31)
    return round(score, 1), norm


# ======================================================================================
# CVSS v4.0  (ported from FIRST's cvss_score.js; tables vendored in cvss4_tables.py)
# ======================================================================================

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from cvss4_tables import CVSS4_LOOKUP, MAX_SEVERITY, MAX_COMPOSED
    _HAVE_V4 = True
except Exception:  # noqa: BLE001
    _HAVE_V4 = False

_AV4 = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_PR4 = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI4 = {"N": 0.0, "P": 0.1, "A": 0.2}
_AC4 = {"L": 0.0, "H": 0.1}
_AT4 = {"N": 0.0, "P": 0.1}
_VC4 = {"H": 0.0, "L": 0.1, "N": 0.2}
_SC4 = {"H": 0.1, "L": 0.2, "N": 0.3}
_SI4 = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_CR4 = {"H": 0.0, "M": 0.1, "L": 0.2}
_LEVELS4 = {"AV": _AV4, "PR": _PR4, "UI": _UI4, "AC": _AC4, "AT": _AT4,
            "VC": _VC4, "VI": _VC4, "VA": _VC4, "SC": _SC4, "SI": _SI4, "SA": _SI4,
            "CR": _CR4, "IR": _CR4, "AR": _CR4}
_BASE4 = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
_CH4 = {"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"},
        "PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
        "VC": {"H", "L", "N"}, "VI": {"H", "L", "N"}, "VA": {"H", "L", "N"},
        "SC": {"H", "L", "N"}, "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"}}


def _m4(sel: dict, metric: str):
    v = sel.get(metric)
    if metric == "E" and (v is None or v == "X"):
        return "A"
    if metric in ("CR", "IR", "AR") and (v is None or v == "X"):
        return "H"
    mod = sel.get("M" + metric)
    if mod is not None and mod != "X":
        return mod
    return v


def _macro_vector(s: dict) -> str:
    av, pr, ui = _m4(s, "AV"), _m4(s, "PR"), _m4(s, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = "1"
    else:
        eq1 = "2"
    eq2 = "0" if (_m4(s, "AC") == "L" and _m4(s, "AT") == "N") else "1"
    vc, vi, va = _m4(s, "VC"), _m4(s, "VI"), _m4(s, "VA")
    if vc == "H" and vi == "H":
        eq3 = "0"
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = "1"
    else:
        eq3 = "2"
    sc, si, sa = _m4(s, "SC"), _m4(s, "SI"), _m4(s, "SA")
    if _m4(s, "MSI") == "S" or _m4(s, "MSA") == "S":
        eq4 = "0"
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = "1"
    else:
        eq4 = "2"
    e = _m4(s, "E")
    eq5 = {"A": "0", "P": "1", "U": "2"}[e]
    cr, ir, ar = _m4(s, "CR"), _m4(s, "IR"), _m4(s, "AR")
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = "0"
    else:
        eq6 = "1"
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _extract(metric: str, s: str) -> str:
    rest = s[s.index(metric) + len(metric) + 1:]
    return rest[:rest.index("/")] if "/" in rest else rest


def _eq_maxes(mv: str, eq: int):
    return MAX_COMPOSED["eq" + str(eq)][mv[eq - 1]]


def cvss40_score(vector: str) -> tuple[float, str]:
    if not _HAVE_V4:
        raise ValueError("cvss4_tables.py not found — cannot score CVSS 4.0 (run build_vrt.py or restore the file)")
    all_m = _split_metrics(vector)
    missing = [k for k in _BASE4 if k not in all_m]
    if missing:
        raise ValueError(f"missing v4.0 base metric(s): {', '.join(missing)}")
    for k in _BASE4:
        if all_m[k] not in _CH4[k]:
            raise ValueError(f"bad value '{all_m[k]}' for {k}; allowed: {sorted(_CH4[k])}")
    sel = dict(all_m)
    for k in ("E", "CR", "IR", "AR"):
        sel.setdefault(k, "X")
    norm = "CVSS:4.0/" + "/".join(f"{k}:{all_m[k]}" for k in _BASE4)

    if all(_m4(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0, norm

    mv = _macro_vector(sel)
    value = CVSS4_LOOKUP[mv]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in mv)

    def low(e1, e2, e3, e4, e5, e6):
        return CVSS4_LOOKUP.get(f"{e1}{e2}{e3}{e4}{e5}{e6}")

    s1 = low(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    s2 = low(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 1 and eq6 == 1:
        s36 = low(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 0 and eq6 == 1:
        s36 = low(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 1 and eq6 == 0:
        s36 = low(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 == 0 and eq6 == 0:
        left = low(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        right = low(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        cands = [c for c in (left, right) if c is not None]
        s36 = max(cands) if cands else None
    else:
        s36 = low(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    s4 = low(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    s5 = low(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    eq1_maxes = _eq_maxes(mv, 1)
    eq2_maxes = _eq_maxes(mv, 2)
    eq36_maxes = MAX_COMPOSED["eq3"][mv[2]][mv[5]]
    eq4_maxes = _eq_maxes(mv, 4)
    eq5_maxes = _eq_maxes(mv, 5)
    max_vectors = [a + b + c + d + e for a in eq1_maxes for b in eq2_maxes
                   for c in eq36_maxes for d in eq4_maxes for e in eq5_maxes]

    sd = {}
    for mx in max_vectors:
        sd = {k: _LEVELS4[k][_m4(sel, k)] - _LEVELS4[k][_extract(k, mx)] for k in _LEVELS4}
        if all(d >= 0 for d in sd.values()):
            break

    cur_eq1 = sd["AV"] + sd["PR"] + sd["UI"]
    cur_eq2 = sd["AC"] + sd["AT"]
    cur_eq36 = sd["VC"] + sd["VI"] + sd["VA"] + sd["CR"] + sd["IR"] + sd["AR"]
    cur_eq4 = sd["SC"] + sd["SI"] + sd["SA"]

    step = 0.1
    ms1 = MAX_SEVERITY["eq1"][str(eq1)] * step
    ms2 = MAX_SEVERITY["eq2"][str(eq2)] * step
    ms36 = MAX_SEVERITY["eq3eq6"][str(eq3)][str(eq6)] * step
    ms4 = MAX_SEVERITY["eq4"][str(eq4)] * step

    n, total = 0, 0.0
    for avail, cur, msev in ((s1, cur_eq1, ms1), (s2, cur_eq2, ms2),
                             (s36, cur_eq36, ms36), (s4, cur_eq4, ms4)):
        if avail is not None:
            n += 1
            total += (value - avail) * (cur / msev)
    if s5 is not None:          # eq5 percentage is always 0
        n += 1
    mean = (total / n) if n else 0.0

    value -= mean
    value = max(0.0, min(10.0, value))
    return math.floor(value * 10 + 0.5) / 10.0, norm


# ======================================================================================
# Dispatch + CLI
# ======================================================================================

def score(vector: str) -> tuple[float, str, str]:
    """Return (score, normalised_vector, version_label)."""
    head = vector.strip().upper()
    if head.startswith("CVSS:4"):
        s, norm = cvss40_score(vector)
        return s, norm, "CVSS v4.0"
    if head.startswith("CVSS:3"):
        s, norm = cvss31_score(vector)
        return s, norm, "CVSS v3.1"
    metrics = _split_metrics(vector)
    if "VC" in metrics or "VI" in metrics or "VA" in metrics:   # v4-only metrics
        s, norm = cvss40_score(vector)
        return s, norm, "CVSS v4.0"
    s, norm = cvss31_score(vector)
    return s, norm, "CVSS v3.1"


_SELF_TEST_31 = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # classic reflected XSS
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.7),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.3),
]
# v4: all-max (lookup+zero-distance), no-impact shortcut, and a vector that *is* its own
# macrovector max (distance 0 => score equals the lookup entry) exercising the full machinery.
_SELF_TEST_40 = [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ("CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 1.0),  # mv 212201 -> lookup 1
]


def self_test() -> int:
    bad = 0
    for vec, expected in _SELF_TEST_31:
        got, _ = cvss31_score(vec)
        ok = abs(got - expected) < 1e-9
        bad += not ok
        print(f"  [{'ok' if ok else 'FAIL'}] {vec}  exp {expected}  got {got}")
    if _HAVE_V4:
        for vec, expected in _SELF_TEST_40:
            got, _ = cvss40_score(vec)
            ok = abs(got - expected) < 1e-9
            bad += not ok
            print(f"  [{'ok' if ok else 'FAIL'}] {vec}  exp {expected}  got {got}")
    else:
        print("  [skip] CVSS 4.0 (cvss4_tables.py not importable)")
    total = len(_SELF_TEST_31) + (len(_SELF_TEST_40) if _HAVE_V4 else 0)
    print(f"{'PASS' if not bad else 'FAIL'}: {total - bad}/{total} vectors correct")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[0] == "--self-test":
        return self_test()
    vec = sys.stdin.read() if argv[0] == "-" else argv[0]
    try:
        s, norm, ver = score(vec)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    print(f"{s} {band(s)}  ({ver})\t{norm}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
