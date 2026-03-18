#!/usr/bin/env python3
"""JWT Manual Vulnerability Hunting — Spec Edge Case Differential Testing.

Generates 30 hand-crafted JWT tokens targeting RFC edge cases,
runs each against 6 HMAC library targets, and reports differentials.

Usage:
    python targets/jwt_manual_test.py [--filter T01,T02,...] [--verbose]
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time

# ── Constants ────────────────────────────────────────────────────────────
SECRET = b"secret"
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP_PATH = os.path.join("C:/Users/dmbs3", f"_jwt_manual_{os.getpid()}.tmp")

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

HMAC_TARGETS = [
    ("jsonwebtoken", "node",   "targets/jwt_node_jsonwebtoken.js"),
    ("jose4",        "node",   "targets/jwt_node_jose4.js"),
    ("fast-jwt",     "node",   "targets/jwt_node_fastjwt.js"),
    ("PyJWT",        "python", "targets/jwt_python_pyjwt.py"),
    ("python-jose",  "python", "targets/jwt_python_jose.py"),
    ("jwcrypto",     "python", "targets/jwt_python_jwcrypto.py"),
]

COMPARE_FIELDS = [
    "signature_valid", "signature_error", "sub", "iss", "aud",
    "claim_types", "exp_state", "nbf_state", "iat_state", "time_valid",
    "effective_alg", "header_alg", "crit_processed", "resolved_kid",
    "b64_mode", "duplicate_claim_keys", "duplicate_header_keys", "typ",
]


# ── JWT Builder ──────────────────────────────────────────────────────────
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(signing_input: bytes, alg: str = "HS256") -> str:
    digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg in digest_map:
        return _b64url(hmac.new(SECRET, signing_input, digest_map[alg]).digest())
    return ""


def make_jwt(header: dict, payload: dict, alg: str = "HS256") -> str:
    """Build a properly signed JWT from dicts."""
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    sig = _sign(signing_input, alg)
    return f"{h}.{p}.{sig}"


def make_jwt_raw(header_json: str, payload_json: str, alg: str = "HS256") -> str:
    """Build JWT from raw JSON strings — preserves duplicate keys, formatting."""
    h = _b64url(header_json.encode("utf-8"))
    p = _b64url(payload_json.encode("utf-8"))
    signing_input = f"{h}.{p}".encode("ascii")
    sig = _sign(signing_input, alg)
    return f"{h}.{p}.{sig}"


# ── Target Runner ────────────────────────────────────────────────────────
def run_target(target_tuple: tuple, jwt_token: str) -> dict | None:
    name, runtime, script = target_tuple
    script_path = os.path.join(PROJECT_DIR, script)
    try:
        with open(TMP_PATH, "w", encoding="utf-8") as f:
            f.write(jwt_token)
        cmd = (["node", script_path, TMP_PATH] if runtime == "node"
               else ["python", script_path, TMP_PATH])
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
            cwd=PROJECT_DIR, encoding="utf-8", errors="replace",
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
        return {"_error": f"exit={result.returncode}", "_stderr": result.stderr[:200]}
    except subprocess.TimeoutExpired:
        return {"_error": "timeout"}
    except (json.JSONDecodeError, OSError) as e:
        return {"_error": str(e)[:200]}
    finally:
        try:
            os.unlink(TMP_PATH)
        except OSError:
            pass


# ── Type Normalization (suppress string/str, array/list, int/number FPs) ──
_TYPE_ALIASES = {
    "str": "string", "int": "number", "float": "number",
    "list": "array", "bool": "boolean", "NoneType": "null",
}


def _normalize_value(field: str, value):
    """Normalize values to suppress cross-language type name differences."""
    if field == "claim_types" and isinstance(value, dict):
        return {k: _TYPE_ALIASES.get(v, v) for k, v in value.items()}
    return value


# ── Differential Analyzer ────────────────────────────────────────────────
def find_differentials(results: dict, fields: list[str]) -> list[dict]:
    valid = {n: r for n, r in results.items() if r and "_error" not in r}
    if len(valid) < 2:
        return []
    diffs = []
    for field in fields:
        values = {}
        for name, r in valid.items():
            v = _normalize_value(field, r.get(field))
            values[name] = v
        unique = set()
        for v in values.values():
            unique.add(json.dumps(v, sort_keys=True, default=str))
        if len(unique) > 1:
            diffs.append({"field": field, "values": values, "unique": len(unique)})
    return diffs


# ── Test Cases ───────────────────────────────────────────────────────────
def build_test_cases() -> list[dict]:
    now = int(time.time())
    cases = []

    def add(tid, category, desc, jwt, fields=None):
        cases.append({
            "id": tid, "category": category, "description": desc,
            "jwt": jwt, "compare_fields": fields or COMPARE_FIELDS,
        })

    # ── Tier 1: High probability ──

    # T01-T03: iss URL confusion
    add("T01", "iss_url", "iss with URL fragment (#evil)",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "iss": "https://auth.example.com#evil-fragment"}))

    add("T02", "iss_url", "iss with userinfo injection (@evil)",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "iss": "https://evil@auth.example.com"}))

    add("T03", "iss_url", "iss with query string (?redirect=evil)",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "iss": "https://auth.example.com?redirect=evil.com"}))

    # T04-T06: aud edge cases
    add("T04", "aud", "aud array with empty string element",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "aud": ["api-server", ""]}))

    add("T05", "aud", "aud array with whitespace element",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "aud": ["api-server", " "]}))

    add("T06", "aud", "aud as single empty string",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "aud": ""}))

    # T07-T11: Timestamp boundaries
    add("T07", "time", "exp = current time (boundary)",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "exp": now}))

    add("T08", "time", "exp as float (fractional seconds)",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "exp": now + 3600.5}))

    add("T09", "time", "exp beyond JS MAX_SAFE_INTEGER",
        make_jwt_raw('{"alg":"HS256"}', '{"sub":"user1","exp":99999999999999999}'))

    add("T10", "time", "temporal inversion: iat>exp, nbf=0",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "iat": now + 999999, "exp": 1, "nbf": 0}))

    add("T11", "time", "negative nbf (before epoch)",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "nbf": -1}))

    # T12-T13: Algorithm case sensitivity
    add("T12", "alg_case", "alg lowercase: hs256",
        make_jwt_raw('{"alg":"hs256"}', '{"sub":"user1"}'))

    add("T13", "alg_case", "alg mixed case: Hs256",
        make_jwt_raw('{"alg":"Hs256"}', '{"sub":"user1"}'))

    # T14-T17: sub type coercion
    add("T14", "type_coerce", "sub = 0 (falsy integer)",
        make_jwt({"alg": "HS256"}, {"sub": 0, "iss": "test"}))

    add("T15", "type_coerce", "sub = true (boolean)",
        make_jwt_raw('{"alg":"HS256"}', '{"sub":true,"iss":"test"}'))

    add("T16", "type_coerce", "sub = array",
        make_jwt({"alg": "HS256"}, {"sub": ["admin", "user"], "iss": "test"}))

    add("T17", "type_coerce", "sub = empty string",
        make_jwt({"alg": "HS256"}, {"sub": "", "iss": "test"}))

    # ── Tier 2: Spec interpretation differences ──

    # T18-T19: crit header
    add("T18", "crit", "crit with unknown-but-present extension",
        make_jwt({"alg": "HS256", "crit": ["x-custom"], "x-custom": True}, {"sub": "user1"}))

    add("T19", "crit", "empty crit array",
        make_jwt({"alg": "HS256", "crit": []}, {"sub": "user1"}))

    # T20: header-payload claim overlap
    add("T20", "overlap", "sub in both header and payload (different values)",
        make_jwt_raw('{"alg":"HS256","sub":"header-admin"}', '{"sub":"payload-user"}'))

    # T21-T23: kid injection
    add("T21", "kid", "kid with embedded JSON (path traversal)",
        make_jwt({"alg": "HS256", "kid": '{"key":"../../admin-key"}'}, {"sub": "user1"}))

    add("T22", "kid", "kid with null byte",
        make_jwt_raw('{"alg":"HS256","kid":"key-id\\u0000evil-suffix"}', '{"sub":"user1"}'))

    add("T23", "kid", "kid extremely long (4096 chars)",
        make_jwt({"alg": "HS256", "kid": "A" * 4096}, {"sub": "user1"}))

    # T24: b64:false
    add("T24", "b64", "b64:false with crit:[b64]",
        make_jwt({"alg": "HS256", "b64": False, "crit": ["b64"]}, {"sub": "user1"}))

    # T25-T26: Duplicate keys
    add("T25", "dup_key", "duplicate sub in payload (first=user, last=admin)",
        make_jwt_raw('{"alg":"HS256"}', '{"sub":"first-user","role":"viewer","sub":"last-admin"}'))

    add("T26", "dup_key", "duplicate alg in header (HS256 then HS384)",
        make_jwt_raw('{"alg":"HS256","typ":"JWT","alg":"HS384"}', '{"sub":"user1"}'))

    # T27: typ variants
    add("T27", "typ", "non-standard typ: at+jwt (RFC 9068)",
        make_jwt({"alg": "HS256", "typ": "at+jwt"}, {"sub": "user1"}))

    # T28: Unicode
    add("T28", "unicode", "sub with zero-width space (invisible char)",
        make_jwt({"alg": "HS256"}, {"sub": "user\u200b1"}))

    # T29: Deep nesting
    add("T29", "nesting", "deeply nested JSON object claim",
        make_jwt({"alg": "HS256"}, {"sub": "user1", "data": {"a": {"b": {"c": {"d": {"e": "deep"}}}}}}))

    # T30: alg=none baseline
    h = _b64url(b'{"alg":"none"}')
    p = _b64url(b'{"sub":"admin"}')
    add("T30", "alg_none", "alg=none with empty signature (classic bypass)", f"{h}.{p}.")

    return cases


# ── Reporter ─────────────────────────────────────────────────────────────
def print_result(tc: dict, results: dict, diffs: list[dict], verbose: bool):
    has_diff = len(diffs) > 0
    rejected = [n for n, r in results.items() if r and "_error" in r]
    parsed = [n for n, r in results.items() if r and "_error" not in r]

    status_str = f"{RED}DIFFERENTIAL ({len(diffs)} fields){RESET}" if has_diff else f"{GREEN}UNIFORM{RESET}"
    print(f"\n{BOLD}[{tc['id']}]{RESET} {tc['description']}")
    print(f"  {status_str}  |  Parsed: {len(parsed)}  Rejected: {len(rejected)}")

    if rejected and verbose:
        for n in rejected:
            err = results[n].get("_error", "?") if results[n] else "None"
            print(f"    {DIM}{n}: {err}{RESET}")

    if has_diff:
        for diff in diffs:
            field = diff["field"]
            # Skip noisy fields unless verbose
            if not verbose and field in ("signature_error",):
                continue
            print(f"  {YELLOW}>> {field}{RESET}:")
            for tname, value in diff["values"].items():
                val_str = repr(value)
                if len(val_str) > 80:
                    val_str = val_str[:77] + "..."
                print(f"     {CYAN}{tname:15s}{RESET} = {val_str}")

    # Highlight security-relevant differentials
    sec_fields = {"signature_valid", "effective_alg", "header_alg", "sub", "iss", "aud", "crit_processed", "b64_mode"}
    sec_diffs = [d for d in diffs if d["field"] in sec_fields]
    if sec_diffs:
        fields_str = ", ".join(d["field"] for d in sec_diffs)
        print(f"  {RED}{BOLD}!! SECURITY-RELEVANT: {fields_str}{RESET}")


def print_summary(all_results: list[tuple]):
    total = len(all_results)
    diff_tests = [(tc, diffs) for tc, _, diffs in all_results if diffs]
    uniform = total - len(diff_tests)

    print(f"\n{'=' * 70}")
    print(f"{BOLD}SUMMARY{RESET}: {total} tests | "
          f"{RED}{len(diff_tests)} differential{RESET} | "
          f"{GREEN}{uniform} uniform{RESET}")

    if diff_tests:
        print(f"\n{BOLD}Differential tests:{RESET}")
        for tc, diffs in diff_tests:
            fields = [d["field"] for d in diffs]
            sec_fields = {"signature_valid", "effective_alg", "header_alg", "sub", "iss", "aud", "crit_processed", "b64_mode"}
            has_sec = any(f in sec_fields for f in fields)
            marker = f"{RED}[SEC]{RESET} " if has_sec else ""
            print(f"  {marker}{tc['id']}: {', '.join(fields)}")


# ── Main ─────────────────────────────────────────────────────────────────
def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    filter_ids = None
    for arg in sys.argv[1:]:
        if arg.startswith("--filter"):
            continue
        if arg.startswith("T"):
            filter_ids = set(arg.split(","))

    # Also check --filter=T01,T02 form
    for arg in sys.argv[1:]:
        if arg.startswith("--filter="):
            filter_ids = set(arg.split("=", 1)[1].split(","))

    test_cases = build_test_cases()
    if filter_ids:
        test_cases = [tc for tc in test_cases if tc["id"] in filter_ids]

    print(f"{BOLD}JWT Manual Vulnerability Hunting{RESET}")
    print(f"Targets: {', '.join(t[0] for t in HMAC_TARGETS)}")
    print(f"Tests: {len(test_cases)}")
    print(f"{'=' * 70}")

    all_results = []
    for tc in test_cases:
        results = {}
        for target in HMAC_TARGETS:
            results[target[0]] = run_target(target, tc["jwt"])

        fields = tc.get("compare_fields", COMPARE_FIELDS)
        diffs = find_differentials(results, fields)
        print_result(tc, results, diffs, verbose)
        all_results.append((tc, results, diffs))

    print_summary(all_results)
    return 1 if any(d for _, _, d in all_results) else 0


if __name__ == "__main__":
    sys.exit(main())
