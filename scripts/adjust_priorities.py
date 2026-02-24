"""Analyze corpus and auto-adjust priorities for XSS fuzzing."""
import requests
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://localhost:8005/api"
SESSION_ID = int(sys.argv[1]) if len(sys.argv) > 1 else 25


def analyze_xss_potential(text: str, size: int, depth: int) -> tuple[float, int]:
    """Score a corpus entry for XSS potential. Returns (boost, score)."""
    score = 0

    # Event handlers (working in modern browsers, not javascript: URIs)
    for kw in ["onfocus", "onerror", "onload", "onclick", "onmouseover",
               "ontoggle", "onbeforeinput", "onanimationend", "onautocomplete"]:
        if kw in text.lower():
            score += 3

    # mXSS patterns (namespace confusion, parser differential)
    for kw in ["<math", "<svg", "<foreignObject", "<mtext",
               "<malignmark", "<mglyph", "annotation-xml"]:
        if kw in text:
            score += 2

    # DOM confusion / structure attacks
    for kw in ["<form", "<table", "<template", "<noscript",
               "<details", "<select", "<textarea", "<!--"]:
        if kw in text:
            score += 1

    # Content-type / charset confusion
    for kw in ["charset=", "Shift_JIS", "UTF-7", "windows-1252", "ISO-2022"]:
        if kw in text:
            score += 2

    # Mutation-XSS specific (DOMPurify bypass patterns)
    for kw in ["<style", "expression(", "url(", "<image", "<audio src"]:
        if kw in text:
            score += 1

    # Bloat penalty
    if size > 5000:
        score -= 4
    elif size > 3000:
        score -= 2

    # Depth bonus (evolved from interesting parents)
    if depth >= 2:
        score += 1

    # Map score to boost
    if score >= 6:
        boost = 10.0
    elif score >= 4:
        boost = 5.0
    elif score >= 2:
        boost = 2.0
    elif score <= -2:
        boost = 0.1
    else:
        boost = 1.0

    return boost, score


def main():
    s = requests.get("{}/sessions/{}".format(BASE, SESSION_ID)).json()
    print(
        "Session {}: {}  execs={}  eps={}  corpus={}  findings={}  edges={}".format(
            SESSION_ID, s["status"], s["total_execs"], s["execs_per_sec"],
            s["corpus_size"], s["unique_findings"], s["total_edges"],
        )
    )

    if s["status"] != "running":
        print("Session not running, skipping adjustments")
        return

    corpus = requests.get(
        "{}/corpus".format(BASE), params={"session_id": SESSION_ID, "per_page": 200}
    ).json()
    print("\nCorpus entries in DB: {}".format(len(corpus)))

    print("\n--- Priority Adjustments ---")
    for e in corpus:
        prev = requests.get("{}/corpus/{}/preview".format(BASE, e["id"])).json()
        text = prev.get("preview", "")
        boost, score = analyze_xss_potential(text, e["size_bytes"], e["depth"])

        r = requests.patch(
            "{}/corpus/{}/priority".format(BASE, e["id"]),
            json={"boost": boost},
        )
        data = r.json()
        fwd = data.get("forwarded_to_fuzzer", False)
        print(
            "  seed={:>3}  boost={:>5.1f}  score={:>2}  fwd={}  {}".format(
                e["seed_id"], boost, score, fwd, text[:70],
            )
        )

    # Show findings
    findings = requests.get(
        "{}/findings".format(BASE), params={"session_id": SESSION_ID, "per_page": 50}
    ).json()
    items = findings.get("items", [])
    print("\nFindings: {}".format(len(items)))
    for f in items:
        print("  [{}] {}  oracle={}".format(f["severity"], f["title"][:70], f["oracle_name"]))


if __name__ == "__main__":
    main()
