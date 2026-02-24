import json, os

sessions = [50, 51, 52, 53, 54]
base = "C:/Users/dmbs3/fuzzer-orchestrator/backend/data/sessions"

# Collect data per session
session_data = {}
for sid in sessions:
    findings_dir = f"{base}/{sid}/findings"
    fingerprints = []
    severities = []
    categories = []

    if os.path.exists(findings_dir):
        for finding_dir in sorted(os.listdir(findings_dir)):
            info_path = os.path.join(findings_dir, finding_dir, "info.json")
            if os.path.isfile(info_path):
                with open(info_path) as f:
                    d = json.load(f)
                fp = d.get('fingerprint', 'NONE')
                sev = d.get('severity', 'unknown')
                cat = d.get('metadata', {}).get('category', 'unknown')
                fingerprints.append(fp)
                severities.append(sev)
                categories.append(cat)

    session_data[sid] = {
        'fingerprints': fingerprints,
        'unique_fps': set(fingerprints),
        'severities': severities,
        'categories': categories,
        'count': len(fingerprints)
    }

# Report.json data
report_data = {}
for sid in sessions:
    with open(f"{base}/{sid}/report.json") as f:
        report_data[sid] = json.load(f)

print("=" * 100)
print("CROSS-SESSION TREND ANALYSIS: URL DIFFERENTIAL FUZZING (Sessions 50-54)")
print("=" * 100)

# === PER-SESSION SUMMARY ===
print("\n" + "=" * 100)
print("1. PER-SESSION SUMMARY")
print("=" * 100)
print(f"{'Session':<10} {'Duration(s)':<14} {'Executions':<13} {'Exec/s':<10} {'Total Findings':<16} {'Unique FPs':<12}")
print("-" * 75)
for sid in sessions:
    r = report_data[sid]
    sd = session_data[sid]
    dur = r['elapsed_seconds']
    execs = r['total_executions']
    eps = r['executions_per_second']
    total = sd['count']
    unique = len(sd['unique_fps'])
    print(f"S{sid:<9} {dur:<14.1f} {execs:<13} {eps:<10.1f} {total:<16} {unique}")

# === SEVERITY DISTRIBUTION ===
print("\n" + "=" * 100)
print("2. SEVERITY DISTRIBUTION PER SESSION (from findings on disk)")
print("=" * 100)
sev_order = ['critical', 'high', 'medium', 'low']
print(f"{'Session':<10} {'Critical':<12} {'High':<12} {'Medium':<12} {'Low':<12}")
print("-" * 58)
for sid in sessions:
    sd = session_data[sid]
    sev_counts = {}
    for s in sev_order:
        sev_counts[s] = sd['severities'].count(s)
    print(f"S{sid:<9} {sev_counts['critical']:<12} {sev_counts['high']:<12} {sev_counts['medium']:<12} {sev_counts['low']:<12}")

# === CATEGORY DISTRIBUTION ===
print("\n" + "=" * 100)
print("3. CATEGORY DISTRIBUTION PER SESSION")
print("=" * 100)
all_cats = set()
for sid in sessions:
    all_cats.update(session_data[sid]['categories'])
cat_order = sorted(all_cats)
header = f"{'Session':<10}"
for c in cat_order:
    header += f" {c:<22}"
print(header)
print("-" * (10 + 22 * len(cat_order)))
for sid in sessions:
    sd = session_data[sid]
    row = f"S{sid:<9}"
    for c in cat_order:
        cnt = sd['categories'].count(c)
        row += f" {cnt:<22}"
    print(row)

# === CUMULATIVE UNIQUE FINDINGS ===
print("\n" + "=" * 100)
print("4. CUMULATIVE UNIQUE FINDINGS (Union of Fingerprints)")
print("=" * 100)
cumulative = set()
cumulative_counts = []
new_per_session = []
for sid in sessions:
    sd = session_data[sid]
    prev_size = len(cumulative)
    new_fps = sd['unique_fps'] - cumulative
    cumulative = cumulative | sd['unique_fps']
    new_count = len(new_fps)
    cumulative_counts.append(len(cumulative))
    new_per_session.append(new_count)

print(f"{'After Session':<16} {'Session Unique':<16} {'New Unique FPs':<18} {'Cumulative Unique':<20} {'Growth Rate':<14}")
print("-" * 84)
for i, sid in enumerate(sessions):
    sd = session_data[sid]
    sess_count = len(sd['unique_fps'])
    new_c = new_per_session[i]
    cum_c = cumulative_counts[i]
    if i == 0:
        growth = "baseline"
    else:
        pct = (new_c / cumulative_counts[i-1]) * 100 if cumulative_counts[i-1] > 0 else 0
        growth = f"+{pct:.1f}%"
    print(f"S{sid:<15} {sess_count:<16} {new_c:<18} {cum_c:<20} {growth:<14}")

# === DIMINISHING RETURNS ===
print("\n" + "=" * 100)
print("5. DIMINISHING RETURNS ANALYSIS")
print("=" * 100)
print(f"{'Session':<10} {'Unique in Session':<20} {'New (never seen)':<20} {'Already Known':<16} {'Novelty Rate':<14}")
print("-" * 80)
seen_so_far = set()
for sid in sessions:
    sd = session_data[sid]
    unique_in_sess = len(sd['unique_fps'])
    new_fps = sd['unique_fps'] - seen_so_far
    already = unique_in_sess - len(new_fps)
    novelty = (len(new_fps) / unique_in_sess * 100) if unique_in_sess > 0 else 0
    print(f"S{sid:<9} {unique_in_sess:<20} {len(new_fps):<20} {already:<16} {novelty:.1f}%")
    seen_so_far = seen_so_far | sd['unique_fps']

# === FINDING STABILITY ===
print("\n" + "=" * 100)
print("6. FINDING STABILITY (Fingerprint Recurrence)")
print("=" * 100)

# Count how many sessions each fingerprint appears in
# Only count sessions that have findings (exclude S51 which has 0)
active_sessions = [s for s in sessions if session_data[s]['count'] > 0]
num_active = len(active_sessions)

fp_session_count = {}
fp_sessions_map = {}
for sid in active_sessions:
    for fp in session_data[sid]['unique_fps']:
        if fp not in fp_session_count:
            fp_session_count[fp] = 0
            fp_sessions_map[fp] = []
        fp_session_count[fp] += 1
        fp_sessions_map[fp].append(sid)

# Distribution of recurrence
recurrence_dist = {}
for count in range(1, num_active + 1):
    recurrence_dist[count] = sum(1 for fp, c in fp_session_count.items() if c == count)

print(f"\nActive sessions with findings: {active_sessions} ({num_active} sessions)")
print(f"Total unique fingerprints across all sessions: {len(fp_session_count)}")
print(f"\n{'Appears in N sessions':<25} {'Count':<10} {'Percentage':<12}")
print("-" * 47)
for n in range(num_active, 0, -1):
    cnt = recurrence_dist.get(n, 0)
    pct = cnt / len(fp_session_count) * 100
    label = f"All {num_active} sessions" if n == num_active else f"{n} session{'s' if n > 1 else ''}"
    print(f"{label:<25} {cnt:<10} {pct:.1f}%")

# Robust findings (in all active sessions)
print(f"\n--- ROBUST FINDINGS (appear in ALL {num_active} active sessions) ---")
robust_fps = [fp for fp, c in fp_session_count.items() if c == num_active]
print(f"Count: {len(robust_fps)}")

# Get details for robust fingerprints
if robust_fps:
    robust_details = []
    for fp in sorted(robust_fps):
        for sid in active_sessions:
            sd = session_data[sid]
            if fp in sd['unique_fps']:
                idx = sd['fingerprints'].index(fp)
                sev = sd['severities'][idx]
                cat = sd['categories'][idx]
                robust_details.append((fp, sev, cat))
                break

    print(f"\n{'Fingerprint':<20} {'Severity':<12} {'Category':<24}")
    print("-" * 56)
    sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    robust_details.sort(key=lambda x: (sev_rank.get(x[1], 9), x[2]))
    for fp, sev, cat in robust_details:
        print(f"{fp:<20} {sev:<12} {cat:<24}")

# Findings appearing in 3+ sessions
print(f"\n--- FREQUENT FINDINGS (appear in 3+ of {num_active} sessions) ---")
frequent_fps = [fp for fp, c in fp_session_count.items() if c >= 3]
print(f"Count: {len(frequent_fps)}")

# One-off findings
print(f"\n--- ONE-OFF FINDINGS (appear in exactly 1 session) ---")
oneoff_fps = [fp for fp, c in fp_session_count.items() if c == 1]
print(f"Count: {len(oneoff_fps)}")
print(f"\n{'Session':<10} {'One-off Findings':<18} {'% of Session Unique':<22}")
print("-" * 50)
for sid in active_sessions:
    unique_in = len(session_data[sid]['unique_fps'])
    cnt = sum(1 for fp in session_data[sid]['unique_fps'] if fp_session_count[fp] == 1)
    pct = cnt / unique_in * 100 if unique_in > 0 else 0
    print(f"S{sid:<9} {cnt:<18} {pct:.1f}%")

# Category breakdown of one-offs
print(f"\n  One-off findings by category:")
oneoff_cats = {}
for fp in oneoff_fps:
    for sid in active_sessions:
        sd = session_data[sid]
        if fp in sd['unique_fps']:
            idx = sd['fingerprints'].index(fp)
            cat = sd['categories'][idx]
            oneoff_cats[cat] = oneoff_cats.get(cat, 0) + 1
            break
for cat in sorted(oneoff_cats.keys(), key=lambda c: -oneoff_cats[c]):
    print(f"    {cat}: {oneoff_cats[cat]}")

# === COVERAGE PLATEAU ===
print("\n" + "=" * 100)
print("7. COVERAGE PLATEAU ANALYSIS")
print("=" * 100)
print("\nMarginal discovery rate (new fingerprints per session):")
print(f"{'Transition':<20} {'New FPs Added':<16} {'Cumulative Total':<18} {'Marginal %':<14}")
print("-" * 68)
for i, sid in enumerate(sessions):
    new_c = new_per_session[i]
    cum_c = cumulative_counts[i]
    if i == 0:
        label = f"S{sid} (first)"
        marginal = "100.0%"
    else:
        label = f"S{sessions[i-1]}->S{sid}"
        marginal = f"{new_c / cum_c * 100:.1f}%" if cum_c > 0 else "N/A"
    print(f"{label:<20} {new_c:<16} {cum_c:<18} {marginal:<14}")

# Linear vs diminishing - only active sessions
print("\n--- Growth Pattern (Active Sessions Only) ---")
active_new = [(sessions[i], new_per_session[i]) for i in range(len(sessions)) if session_data[sessions[i]]['count'] > 0]
print(f"New fingerprints per active session: {[f'S{s}={n}' for s, n in active_new]}")

if len(active_new) >= 2:
    first_half = active_new[:len(active_new)//2]
    second_half = active_new[len(active_new)//2:]
    avg_first = sum(n for _, n in first_half) / len(first_half)
    avg_second = sum(n for _, n in second_half) / len(second_half)
    print(f"Average new FPs (first half:  S{first_half[0][0]}-S{first_half[-1][0]}): {avg_first:.1f}")
    print(f"Average new FPs (second half: S{second_half[0][0]}-S{second_half[-1][0]}): {avg_second:.1f}")
    ratio = avg_second / avg_first if avg_first > 0 else 0
    print(f"Second-half / First-half ratio: {ratio:.2f}")
    if ratio < 0.5:
        print("VERDICT: Strong diminishing returns - discovery rate dropped by >50%")
    elif ratio < 0.7:
        print("VERDICT: Clear diminishing returns - discovery rate declining significantly")
    elif ratio < 0.9:
        print("VERDICT: Moderate diminishing returns - discovery rate slowing")
    else:
        print("VERDICT: Near-linear growth - still discovering at similar rates")

# Projected saturation
total_unique = len(fp_session_count)
print(f"\nTotal unique fingerprints discovered across all sessions: {total_unique}")
# Check if last session still found new things
last_active = active_new[-1]
print(f"Last session (S{last_active[0]}) still found {last_active[1]} new fingerprints")
if last_active[1] > 10:
    print("CONCLUSION: Coverage has NOT plateaued - significant new findings still emerging")
elif last_active[1] > 3:
    print("CONCLUSION: Coverage is approaching a plateau but not fully saturated")
else:
    print("CONCLUSION: Coverage appears to have plateaued")

# === CATEGORY COVERAGE ACROSS SESSIONS ===
print("\n" + "=" * 100)
print("8. CUMULATIVE CATEGORY COVERAGE")
print("=" * 100)
cumul_cats = {}
for sid in sessions:
    sd = session_data[sid]
    for fp, cat in zip(sd['fingerprints'], sd['categories']):
        if cat not in cumul_cats:
            cumul_cats[cat] = set()
        cumul_cats[cat].add(fp)

print(f"\n{'Category':<24} {'Unique FPs':<14} {'% of Total':<12}")
print("-" * 50)
for cat in sorted(cumul_cats.keys(), key=lambda c: -len(cumul_cats[c])):
    cnt = len(cumul_cats[cat])
    pct = cnt / total_unique * 100
    print(f"{cat:<24} {cnt:<14} {pct:.1f}%")

# Cumulative category growth
print(f"\n--- Category Discovery Over Time ---")
cat_cumul = {}
print(f"{'Session':<10}", end="")
for cat in cat_order:
    print(f" {cat[:18]:<20}", end="")
print()
print("-" * (10 + 20 * len(cat_order)))
for sid in sessions:
    sd = session_data[sid]
    for fp, cat in zip(sd['fingerprints'], sd['categories']):
        if cat not in cat_cumul:
            cat_cumul[cat] = set()
        cat_cumul[cat].add(fp)
    row = f"S{sid:<9}"
    for cat in cat_order:
        cnt = len(cat_cumul.get(cat, set()))
        row += f" {cnt:<20}"
    print(row)

print("\n" + "=" * 100)
print("END OF CROSS-SESSION TREND ANALYSIS")
print("=" * 100)
