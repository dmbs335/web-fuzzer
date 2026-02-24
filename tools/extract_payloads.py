"""Extract and group all S57 payloads by category."""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import json, os, collections

FINDINGS_DIR = r"C:\Users\dmbs3\fuzzer-orchestrator\backend\data\sessions\57\findings"
REF_NAMES = {0: 'WHATWG', 1: 'legacy', 2: 'rfc3986', 3: 'curl', -1: 'N/A'}
SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

groups = collections.defaultdict(list)

for d in sorted(os.listdir(FINDINGS_DIR)):
    info_path = os.path.join(FINDINGS_DIR, d, 'info.json')
    input_path = os.path.join(FINDINGS_DIR, d, 'input')
    if not os.path.isfile(info_path):
        continue
    info = json.load(open(info_path, encoding='utf-8'))
    meta = info.get('metadata', {})
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except:
            meta = {}
    try:
        inp = open(input_path, 'rb').read()
        inp_str = inp.decode('utf-8', errors='replace')
    except:
        inp_str = '(unreadable)'

    cat = meta.get('category', 'unknown')
    sev = info.get('severity', '?')
    ref_idx = meta.get('ref_index', -1)
    p_host = str(meta.get('primary_host', ''))[:60]
    r_host = str(meta.get('ref_host', ''))[:60]
    p_port = str(meta.get('primary_port', ''))
    r_port = str(meta.get('ref_port', ''))
    p_path = str(meta.get('primary_path', ''))[:60]
    r_path = str(meta.get('ref_path', ''))[:60]

    groups[cat].append({
        'input': inp_str[:250],
        'sev': sev,
        'ref': ref_idx,
        'p_host': p_host, 'r_host': r_host,
        'p_port': p_port, 'r_port': r_port,
        'p_path': p_path, 'r_path': r_path,
    })

for cat, items in sorted(groups.items(), key=lambda x: -len(x[1])):
    print(f'\n{"=" * 90}')
    print(f' [{cat.upper()}] -- {len(items)} findings')
    print(f'{"=" * 90}')

    seen = set()
    shown = 0
    for it in sorted(items, key=lambda x: SEV_ORDER.get(x['sev'], 9)):
        key = it['input'][:50].encode('ascii', 'replace')
        if key in seen:
            continue
        seen.add(key)
        if shown >= 25:
            print(f'  ... +{len(items) - shown} more similar patterns')
            break

        sev_tag = {'critical': 'CRIT', 'high': 'HIGH', 'medium': ' MED', 'low': ' LOW'}.get(it['sev'], '    ')
        ref = REF_NAMES.get(it['ref'], '?')
        inp_clean = it['input'][:110].replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        print(f'  [{sev_tag}] vs {ref:7s} | {inp_clean}')

        if it['p_host'] and it['r_host'] and it['p_host'] != it['r_host']:
            print(f'                       host: "{it["p_host"]}" vs "{it["r_host"]}"')
        if it['p_port'] and it['r_port'] and it['p_port'] != it['r_port']:
            print(f'                       port: "{it["p_port"]}" vs "{it["r_port"]}"')
        if it['p_path'] and it['r_path'] and it['p_path'] != it['r_path']:
            ph = it['p_path'][:50]
            rh = it['r_path'][:50]
            print(f'                       path: "{ph}" vs "{rh}"')
        shown += 1
