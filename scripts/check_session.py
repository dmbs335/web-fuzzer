"""Check session status and corpus for live priority adjustment."""
import requests
import sys
import json

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://localhost:8005/api"
SESSION_ID = int(sys.argv[1]) if len(sys.argv) > 1 else 25


def main():
    s = requests.get(f"{BASE}/sessions/{SESSION_ID}").json()
    print(
        f"Session {SESSION_ID}: {s['status']}  "
        f"execs={s['total_execs']}  eps={s['execs_per_sec']}  "
        f"corpus={s['corpus_size']}  findings={s['unique_findings']}  "
        f"edges={s['total_edges']}"
    )
    print()

    corpus = requests.get(
        f"{BASE}/corpus", params={"session_id": SESSION_ID, "per_page": 200}
    ).json()
    print(f"Corpus entries in DB: {len(corpus)}")
    for e in corpus:
        prev = requests.get(f"{BASE}/corpus/{e['id']}/preview").json()
        text = prev.get("preview", "")[:140]
        print(
            f"  id={e['id']} seed={e['seed_id']:>3} "
            f"depth={e['depth']} energy={e['energy']:.1f} "
            f"size={e['size_bytes']}B"
        )
        print(f"    {text}")
        print()

    findings = requests.get(
        f"{BASE}/findings", params={"session_id": SESSION_ID, "per_page": 50}
    ).json()
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(
            f"  [{f['severity']}] {f['title'][:80]}  "
            f"oracle={f['oracle_name']}"
        )


if __name__ == "__main__":
    main()
