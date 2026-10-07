#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop346 (docs 10.93): the vote road and the tenure handover per leg, from the validators' logs (bench-<tag>/node*-v.log). usage: voteroad346.py <tag> ...
Proposal to quorum: per view the time from `proposal sent view=V` to `block committed! view=V` in the same (leader's) log, median / p90 / max over the three 30 s windows' views; the interval between
consecutive proposals and, for views that are multiples of 1024 (the leader tenure), the interval across the handover against the median interval; the timeout certificates (`TC formed`) and the
views that timed out; ParentUnknown lines anywhere. For the handover views the layer's `seal-first build phases` of the same blocks (number = the view's `chain started number=N`+1) with
gap_before_exec, parent_fields_ms, rename_fallbacks and rename_record_waits."""
import glob, re, statistics as st, sys
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
ansi = re.compile(r'\x1b\[[0-9;]*m')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
for tag in sys.argv[1:]:
    prop, com, started, tcs, pu, timed = {}, {}, {}, 0, 0, 0
    for f in sorted(glob.glob(f'{B}/bench-{tag}/node*-v.log')):
        for l in open(f, errors='replace'):
            l = ansi.sub('', l)
            if 'proposal sent view=' in l:
                m = re.search(r'proposal sent view=(\d+)', l); prop[int(m[1])] = (ts(l), f)
            elif 'block committed! view=' in l:
                m = re.search(r'block committed! view=(\d+)', l)
                if m: com.setdefault((int(m[1]), f), ts(l))
            elif 'chain started number=' in l:
                m = re.search(r'chain started number=(\d+) .* view=(\d+)', l)
                if m: started[int(m[2])] = int(m[1])
            if 'TC formed' in l: tcs += 1
            if 'ParentUnknown' in l: pu += 1
            if 'view timed out' in l and 'leader=true' in l: timed += 1
    d = [(com[(v, f)] - t) * 1e3 for v, (t, f) in prop.items() if (v, f) in com and 0 < com[(v, f)] - t < 2]
    views = sorted(prop); iv = [(prop[b][0] - prop[a][0]) * 1e3 for a, b in zip(views, views[1:]) if b == a + 1]
    print(f'== {tag}: {len(prop)} proposals; proposal -> quorum (leader\'s commit) median {st.median(d) if d else float("nan"):.1f} / p90 {pct(d, .9):.1f} / max {max(d or [0]):.1f} ms; proposal interval median {st.median(iv) if iv else float("nan"):.1f} / p90 {pct(iv, .9):.1f} ms; TC formed lines {tcs}; leader views timed out {timed}; ParentUnknown lines {pu}')
    mi = st.median(iv) if iv else 0
    for v in [x for x in views if x % 1024 == 0 and x > 0]:
        around = [(w, (prop[w][0] - prop[w - 1][0]) * 1e3) for w in range(v - 1, v + 4) if w in prop and w - 1 in prop]
        print(f'   handover at view {v}: proposal intervals (view, ms) {[(w, round(x)) for w, x in around]} against the median {mi:.0f} ms')
    el = f'{B}/bench-{tag}/node0-el.log'
    try:
        nums = {started[v] + 1: v for v in started if v % 1024 in (0, 1, 2, 3) and v > 0}
        rows = {}
        for l in open(el, errors='replace'):
            l = ansi.sub('', l)
            if 'seal-first build phases number=' in l:
                m = re.search(r'number=(\d+)', l)
                if m and int(m[1]) in nums: rows[int(m[1])] = dict(re.findall(r'(\w+)=(\S+)', l))
        for n in sorted(rows):
            d = rows[n]; print(f'     block {n} (view {nums[n]}): ' + ', '.join(f'{k} {d.get(k, "-")}' for k in ('sealed_at_ms', 'gap_before_exec_ms', 'parent_fields_ms', 'rename_fallbacks', 'rename_record_waits', 'carried_depth')))
    except Exception as e: print('   (no build lines:', e, ')')
