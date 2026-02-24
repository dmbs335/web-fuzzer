"""URL Parser Confusion Matrix — Post-session analysis.

Fetches findings from the orchestrator API and generates:
  1. Parser-pair confusion matrix (severity heatmap)
  2. Attack category breakdown per parser pair
  3. URL component disagreement matrix
  4. Top inputs per CRITICAL finding pattern

Usage:
  python analyze_matrix.py --session 50
  python analyze_matrix.py --session 50 --format html --output report.html
  python analyze_matrix.py --session 50 --format csv --output matrix.csv
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import Counter, defaultdict
from typing import Any

API_BASE = "http://localhost:8005/api"


def _set_api_base(url: str):
    global API_BASE
    API_BASE = url

# Target names by ref_index — must match the session's diff_cmds order
TARGET_NAMES = {
    -1: "urllib",        # primary
    0: "rfc3986",
    1: "WHATWG",
    2: "legacy",
    3: "curl",
    4: "java-URI",
    5: "java-URL",
    # extend if more targets
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_SYMBOL = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}


def fetch_findings(session_id: int) -> list[dict]:
    """Fetch all findings for a session from the orchestrator API."""
    findings = []
    page = 1
    while True:
        url = f"{API_BASE}/findings?session_id={session_id}&per_page=200&page={page}"
        resp = urllib.request.urlopen(url)
        data = json.loads(resp.read())
        items = data.get("items", data) if isinstance(data, dict) else data
        if not items:
            break
        findings.extend(items)
        total_pages = data.get("pages", 1) if isinstance(data, dict) else 1
        if page >= total_pages:
            break
        page += 1
    return findings


def fetch_session(session_id: int) -> dict:
    """Fetch session info."""
    url = f"{API_BASE}/sessions/{session_id}"
    resp = urllib.request.urlopen(url)
    return json.loads(resp.read())


def parse_metadata(f: dict) -> dict:
    """Extract metadata dict from finding."""
    raw = f.get("metadata", "{}")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {}
    return raw or {}


def build_target_names(session: dict) -> dict[int, str]:
    """Build target name map from session config."""
    names = dict(TARGET_NAMES)  # copy defaults
    diff_cmds = session.get("diff_cmds", "[]")
    if isinstance(diff_cmds, str):
        try:
            diff_cmds = json.loads(diff_cmds)
        except (json.JSONDecodeError, ValueError):
            diff_cmds = []

    # Override with short names derived from commands
    name_map = {
        "url_python_urllib": "urllib",
        "url_python_rfc3986": "rfc3986",
        "url_node_whatwg": "WHATWG",
        "url_node_legacy": "legacy",
        "url_curl": "curl",
        "url_java_uri": "java-URI",
        "UrlJavaUri": "java-URI",
        "url_java_url": "java-URL",
        "UrlJavaUrl": "java-URL",
        "url_go_net_url": "go-url",
        "url_rust_url": "rust-url",
        "url_php": "php",
        "url_wget": "wget",
    }
    for i, cmd in enumerate(diff_cmds):
        for key, short in name_map.items():
            if key in cmd:
                names[i] = short
                break
        else:
            names[i] = f"ref[{i}]"
    return names


# ── Matrix builders ──────────────────────────────────────────

def build_pair_severity_matrix(
    findings: list[dict], names: dict[int, str]
) -> dict[str, Counter]:
    """Parser pair → severity counter."""
    matrix: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        meta = parse_metadata(f)
        ref_i = meta.get("ref_index")
        if ref_i is None:
            continue
        sev = f.get("severity", "?").lower()
        pair_key = f"urllib → {names.get(ref_i, f'ref[{ref_i}]')}"
        matrix[pair_key][sev] += 1
    return dict(matrix)


def build_pair_category_matrix(
    findings: list[dict], names: dict[int, str]
) -> dict[str, Counter]:
    """Parser pair → category counter."""
    matrix: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        meta = parse_metadata(f)
        ref_i = meta.get("ref_index")
        if ref_i is None:
            continue
        cat = meta.get("category", meta.get("strategy", "unknown"))
        pair_key = f"urllib → {names.get(ref_i, f'ref[{ref_i}]')}"
        matrix[pair_key][cat] += 1
    return dict(matrix)


def build_component_matrix(
    findings: list[dict], names: dict[int, str]
) -> dict[str, Counter]:
    """Parser pair → differing URL component counter."""
    matrix: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        meta = parse_metadata(f)
        ref_i = meta.get("ref_index")
        if ref_i is None:
            continue
        diff_fields = meta.get("diff_fields", [])
        pair_key = f"urllib → {names.get(ref_i, f'ref[{ref_i}]')}"
        for field in diff_fields:
            matrix[pair_key][field] += 1
    return dict(matrix)


def build_category_component_matrix(
    findings: list[dict],
) -> dict[str, Counter]:
    """Category → differing component counter."""
    matrix: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        meta = parse_metadata(f)
        cat = meta.get("category", meta.get("strategy", "unknown"))
        diff_fields = meta.get("diff_fields", [])
        for field in diff_fields:
            matrix[cat][field] += 1
    return dict(matrix)


def collect_critical_patterns(
    findings: list[dict], names: dict[int, str]
) -> list[dict]:
    """Collect CRITICAL findings with deduplication by pattern type."""
    criticals = []
    for f in findings:
        if f.get("severity", "").lower() != "critical":
            continue
        meta = parse_metadata(f)
        ref_i = meta.get("ref_index", "?")
        inp = f.get("input_preview", "")[:100]
        criticals.append({
            "pair": f"urllib → {names.get(ref_i, f'ref[{ref_i}]')}",
            "category": meta.get("category", "?"),
            "diff_fields": meta.get("diff_fields", []),
            "primary_host": str(meta.get("primary_host", ""))[:40],
            "ref_host": str(meta.get("ref_host", ""))[:40],
            "input": inp,
            "is_duplicate": f.get("is_duplicate", False),
        })
    return criticals


# ── Formatters ───────────────────────────────────────────────

def _pad(s: str, width: int) -> str:
    """Pad string to width, handling wide chars roughly."""
    visible = len(s)
    return s + " " * max(0, width - visible)


def format_matrix_text(
    title: str,
    matrix: dict[str, Counter],
    col_keys: list[str] | None = None,
) -> str:
    """Format a matrix as aligned text table."""
    if not matrix:
        return f"\n{title}\n  (no data)\n"

    # Determine columns
    if col_keys is None:
        col_set: set[str] = set()
        for ctr in matrix.values():
            col_set.update(ctr.keys())
        col_keys = sorted(col_set)

    if not col_keys:
        return f"\n{title}\n  (no columns)\n"

    # Column widths
    row_label_width = max(len(k) for k in matrix) + 2
    col_widths = {c: max(len(c), 4) + 2 for c in col_keys}

    lines = [f"\n{'=' * 70}", title, "=" * 70]

    # Header
    header = _pad("", row_label_width)
    for c in col_keys:
        header += _pad(c, col_widths[c])
    header += _pad("TOTAL", 8)
    lines.append(header)
    lines.append("-" * len(header))

    # Rows sorted by total descending
    sorted_rows = sorted(matrix.items(), key=lambda x: sum(x[1].values()), reverse=True)
    for row_key, ctr in sorted_rows:
        row = _pad(row_key, row_label_width)
        total = 0
        for c in col_keys:
            val = ctr.get(c, 0)
            total += val
            cell = str(val) if val > 0 else "·"
            row += _pad(cell, col_widths[c])
        row += _pad(str(total), 8)
        lines.append(row)

    # Column totals
    footer = _pad("TOTAL", row_label_width)
    grand = 0
    for c in col_keys:
        col_total = sum(ctr.get(c, 0) for ctr in matrix.values())
        grand += col_total
        footer += _pad(str(col_total), col_widths[c])
    footer += _pad(str(grand), 8)
    lines.append("-" * len(header))
    lines.append(footer)

    return "\n".join(lines)


def format_criticals_text(criticals: list[dict]) -> str:
    """Format CRITICAL findings as a readable list."""
    if not criticals:
        return "\nNo CRITICAL findings.\n"

    unique = [c for c in criticals if not c["is_duplicate"]]
    lines = [
        f"\n{'=' * 70}",
        f"CRITICAL SSRF Findings ({len(unique)} unique / {len(criticals)} total)",
        "=" * 70,
    ]

    # Group by pattern (pair + category)
    groups: dict[str, list[dict]] = defaultdict(list)
    for c in unique:
        key = f"{c['pair']} | {c['category']}"
        groups[key].append(c)

    for group_key, items in sorted(groups.items(), key=lambda x: -len(x[1])):
        lines.append(f"\n  {group_key} ({len(items)} findings)")
        for item in items[:5]:  # show max 5 per group
            p = item["primary_host"][:25]
            r = item["ref_host"][:25]
            inp = item["input"][:70]
            fields = ",".join(item["diff_fields"])
            lines.append(f"    host: {p} vs {r}  [{fields}]")
            lines.append(f"    input: {inp}")
        if len(items) > 5:
            lines.append(f"    ... and {len(items) - 5} more")

    return "\n".join(lines)


def format_summary(session: dict, findings: list[dict]) -> str:
    """Session summary header."""
    sev_count = Counter(f.get("severity", "?").lower() for f in findings)
    unique_count = sum(1 for f in findings if not f.get("is_duplicate", False))
    dup_count = sum(1 for f in findings if f.get("is_duplicate", False))

    lines = [
        "=" * 70,
        f"SESSION {session['id']}: {session.get('name', '?')}",
        "=" * 70,
        f"  Status:    {session.get('status', '?')}",
        f"  Execs:     {session.get('total_execs', 0):,}  ({session.get('execs_per_sec', 0):.1f}/s)",
        f"  Corpus:    {session.get('corpus_size', 0):,}",
        f"  Edges:     {session.get('peak_edges', 0):,}",
        f"  Elapsed:   {session.get('elapsed_seconds', 0):.0f}s",
        f"  Findings:  {len(findings)} total ({unique_count} unique, {dup_count} duplicates)",
        "",
        "  By Severity:",
    ]
    for sev in SEV_ORDER:
        cnt = sev_count.get(sev, 0)
        if cnt > 0:
            bar = "█" * min(cnt, 50)
            lines.append(f"    {sev:8s}  {cnt:3d}  {bar}")
    return "\n".join(lines)


# ── HTML output ──────────────────────────────────────────────

def format_html(
    session: dict,
    findings: list[dict],
    names: dict[int, str],
    pair_sev: dict,
    pair_cat: dict,
    comp_matrix: dict,
    cat_comp: dict,
    criticals: list[dict],
) -> str:
    """Generate full HTML report."""

    def _html_matrix(title: str, matrix: dict[str, Counter], col_keys: list[str] | None = None) -> str:
        if not matrix:
            return f"<h3>{title}</h3><p>No data</p>"
        if col_keys is None:
            col_set: set[str] = set()
            for ctr in matrix.values():
                col_set.update(ctr.keys())
            col_keys = sorted(col_set)

        rows_sorted = sorted(matrix.items(), key=lambda x: sum(x[1].values()), reverse=True)
        max_val = max((ctr.get(c, 0) for _, ctr in rows_sorted for c in col_keys), default=1) or 1

        html = f'<h3>{title}</h3>\n<table>\n<tr><th></th>'
        for c in col_keys:
            html += f'<th>{c}</th>'
        html += '<th>Total</th></tr>\n'

        for row_key, ctr in rows_sorted:
            html += f'<tr><td class="row-label">{row_key}</td>'
            total = 0
            for c in col_keys:
                val = ctr.get(c, 0)
                total += val
                intensity = val / max_val if max_val else 0
                if val == 0:
                    html += '<td class="zero">·</td>'
                else:
                    r = int(255 * (1 - intensity * 0.7))
                    g = int(255 * (1 - intensity * 0.3))
                    b = int(255 * (1 - intensity * 0.7))
                    html += f'<td style="background:rgb({r},{g},{b});font-weight:bold">{val}</td>'
            html += f'<td class="total">{total}</td></tr>\n'

        html += '</table>\n'
        return html

    sev_count = Counter(f.get("severity", "?").lower() for f in findings)
    unique_count = sum(1 for f in findings if not f.get("is_duplicate", False))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>URL Parser Confusion Matrix — Session {session['id']}</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 2rem; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
  h2 {{ color: #79c0ff; margin-top: 2rem; }}
  h3 {{ color: #d2a8ff; }}
  table {{ border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }}
  th, td {{ padding: 6px 12px; border: 1px solid #30363d; text-align: center; }}
  th {{ background: #161b22; color: #8b949e; font-weight: 600; }}
  .row-label {{ text-align: left; font-weight: 600; color: #58a6ff; background: #161b22; white-space: nowrap; }}
  .zero {{ color: #484f58; }}
  .total {{ font-weight: bold; background: #161b22; }}
  .summary {{ background: #161b22; padding: 1rem 1.5rem; border-radius: 8px; border: 1px solid #30363d; }}
  .summary dt {{ font-weight: 600; color: #8b949e; }}
  .summary dd {{ margin: 0 0 0.5rem 0; font-size: 1.1rem; }}
  .sev-critical {{ color: #f85149; font-weight: bold; }}
  .sev-high {{ color: #db6d28; font-weight: bold; }}
  .sev-medium {{ color: #d29922; }}
  .sev-low {{ color: #8b949e; }}
  .finding-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 0.8rem 1rem; margin: 0.5rem 0; }}
  .finding-card .host {{ font-family: monospace; font-size: 0.9rem; }}
  .finding-card .input {{ font-family: monospace; font-size: 0.8rem; color: #8b949e; word-break: break-all; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  .badge-critical {{ background: #f8514922; color: #f85149; border: 1px solid #f8514944; }}
  .badge-high {{ background: #db6d2822; color: #db6d28; border: 1px solid #db6d2844; }}
</style>
</head>
<body>
<h1>URL Parser Confusion Matrix</h1>
<h2>Session {session['id']}: {session.get('name', '')}</h2>

<div class="summary">
<dl>
  <dt>Executions</dt><dd>{session.get('total_execs', 0):,} ({session.get('execs_per_sec', 0):.1f}/s)</dd>
  <dt>Elapsed</dt><dd>{session.get('elapsed_seconds', 0):.0f}s</dd>
  <dt>Findings</dt><dd>{len(findings)} total ({unique_count} unique)</dd>
  <dt>Severity</dt><dd>
    <span class="sev-critical">CRITICAL: {sev_count.get('critical', 0)}</span> &nbsp;
    <span class="sev-high">HIGH: {sev_count.get('high', 0)}</span> &nbsp;
    <span class="sev-medium">MEDIUM: {sev_count.get('medium', 0)}</span> &nbsp;
    <span class="sev-low">LOW: {sev_count.get('low', 0)}</span>
  </dd>
</dl>
</div>

<h2>1. Parser Pair × Severity</h2>
<p>Primary target (urllib) vs each reference — number of findings by severity.</p>
{_html_matrix("", pair_sev, SEV_ORDER)}

<h2>2. Parser Pair × Attack Category</h2>
<p>What type of confusion exists between each parser pair.</p>
{_html_matrix("", pair_cat)}

<h2>3. Parser Pair × URL Component</h2>
<p>Which URL components are parsed differently by each parser pair.</p>
{_html_matrix("", comp_matrix)}

<h2>4. Category × URL Component</h2>
<p>Which URL components are involved in each attack category.</p>
{_html_matrix("", cat_comp)}

<h2>5. CRITICAL SSRF Findings</h2>
"""

    unique_crits = [c for c in criticals if not c["is_duplicate"]]
    groups: dict[str, list[dict]] = defaultdict(list)
    for c in unique_crits:
        key = f"{c['pair']} | {c['category']}"
        groups[key].append(c)

    for group_key, items in sorted(groups.items(), key=lambda x: -len(x[1])):
        html += f'<h3>{group_key} ({len(items)})</h3>\n'
        for item in items[:10]:
            p = item["primary_host"][:35]
            r = item["ref_host"][:35]
            inp = item["input"][:100]
            fields = ", ".join(item["diff_fields"])
            html += f"""<div class="finding-card">
  <span class="badge badge-critical">CRITICAL</span>
  <span class="host">{_esc(p)}</span> vs <span class="host">{_esc(r)}</span>
  <span style="color:#484f58;font-size:0.8rem">[{fields}]</span>
  <div class="input">{_esc(inp)}</div>
</div>\n"""
        if len(items) > 10:
            html += f'<p style="color:#8b949e">... and {len(items) - 10} more</p>\n'

    html += """
</body>
</html>"""
    return html


def _esc(s: str) -> str:
    """Escape HTML entities."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ── CSV output ───────────────────────────────────────────────

def format_csv(
    pair_sev: dict[str, Counter],
    pair_cat: dict[str, Counter],
    comp_matrix: dict[str, Counter],
) -> str:
    """Generate CSV with all matrices as separate sections."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)

    def _write_matrix(title: str, matrix: dict[str, Counter], col_keys: list[str] | None = None):
        if col_keys is None:
            col_set: set[str] = set()
            for ctr in matrix.values():
                col_set.update(ctr.keys())
            col_keys = sorted(col_set)

        writer.writerow([])
        writer.writerow([title])
        writer.writerow(["Parser Pair"] + col_keys + ["Total"])
        for row_key, ctr in sorted(matrix.items(), key=lambda x: -sum(x[1].values())):
            vals = [ctr.get(c, 0) for c in col_keys]
            writer.writerow([row_key] + vals + [sum(vals)])

    _write_matrix("Pair x Severity", pair_sev, SEV_ORDER)
    _write_matrix("Pair x Category", pair_cat)
    _write_matrix("Pair x Component", comp_matrix)

    return buf.getvalue()


# ── Main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="URL Parser Confusion Matrix Analysis")
    parser.add_argument("--session", type=int, required=True, help="Session ID to analyze")
    parser.add_argument("--format", choices=["text", "html", "csv"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output file (default: stdout)")
    parser.add_argument("--api", type=str, default=API_BASE,
                        help=f"Orchestrator API base URL (default: {API_BASE})")
    args = parser.parse_args()

    _set_api_base(args.api)

    print(f"Fetching session {args.session}...", file=sys.stderr)
    session = fetch_session(args.session)

    print("Fetching findings...", file=sys.stderr)
    findings = fetch_findings(args.session)
    print(f"  {len(findings)} findings loaded", file=sys.stderr)

    names = build_target_names(session)
    print(f"  Targets: {', '.join(names.values())}", file=sys.stderr)

    # Build matrices
    pair_sev = build_pair_severity_matrix(findings, names)
    pair_cat = build_pair_category_matrix(findings, names)
    comp_matrix = build_component_matrix(findings, names)
    cat_comp = build_category_component_matrix(findings)
    criticals = collect_critical_patterns(findings, names)

    # Format output
    if args.format == "html":
        output = format_html(session, findings, names, pair_sev, pair_cat,
                             comp_matrix, cat_comp, criticals)
    elif args.format == "csv":
        output = format_csv(pair_sev, pair_cat, comp_matrix)
    else:
        parts = [
            format_summary(session, findings),
            format_matrix_text("1. PARSER PAIR × SEVERITY", pair_sev, SEV_ORDER),
            format_matrix_text("2. PARSER PAIR × ATTACK CATEGORY", pair_cat),
            format_matrix_text("3. PARSER PAIR × URL COMPONENT", comp_matrix),
            format_matrix_text("4. CATEGORY × URL COMPONENT", cat_comp),
            format_criticals_text(criticals),
        ]
        output = "\n".join(parts)

    # Write output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"\nReport saved to: {args.output}", file=sys.stderr)
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(output)


if __name__ == "__main__":
    main()
