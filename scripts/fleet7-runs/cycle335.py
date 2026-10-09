#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop335 (docs 10.82): where a cycle goes at the leader. usage: cycle335.py <tag> ...   (tag = e.g. loop335P70)
E=1: validator 0 leads every view of a leg (tenure 1024); its log and the layer's (`node0-el.log`) carry the whole chain. Over the three 30 s windows
(from the first full canonical block, as analyze334.py), for every proposed block H (key: its hash) and its child build H2:
  chain, per build (medians / p90 ms): `chain started` (the child build begins, parent = H, trigger seal) -> `frame build sealed` -> `build on the sealed
  block answered on the early seal` -> `built ahead on the sealed own block` -> `block body prepared` -> `proposal sent`; the release (next `chain started`)
  against the early-seal answer; the seal-to-seal cadence (chain start to the next chain start) and the cycle (proposal to proposal).
  consensus, per block: proposal -> each key's `sending vote to leader` (median per key, the slowest key, how many of the votes waited for execution
  validation against found the block already validated), the leader's R1 and R2 collect (`block committed!` line), proposal -> commit, commit -> each key's
  `received Decide`, and the commit against the release two builds on (negative: the commit is off the chain).
  repeated per key: `vote log sync was slow` lines per node per block and their ms, `commit forkchoice answered` per node (count per block, elapsed
  median / p90), the layer's own `Forkchoice updated` lines per canonical block, `forest lock held` lines and ms."""
import bisect, re, statistics as st, sys
from collections import defaultdict
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
def mp(x): return f'{st.median(x):.1f}/{pct(x, .9):.1f}' if x else '-'
def read(path):
    try: return [ansi.sub('', l) for l in open(path, errors='replace')]
    except OSError: return []
def nxt(sorted_ts, t):
    i = bisect.bisect_right(sorted_ts, t); return sorted_ts[i] if i < len(sorted_ts) else None
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'; print(f'== {tag}')
    el = read(f'{root}/node0-el.log'); v0 = read(f'{root}/node0-v.log')
    canon = [ts(l) for l in el if 'Block added to canonical chain' in l and re.search(r' txs=(\d+)', l) and int(re.search(r' txs=(\d+)', l)[1]) >= 100000]
    if not canon: print('  no full block'); continue
    t0 = canon[0]; t1 = t0 + 90
    cs, body, prop, commit, pts = {}, {}, {}, {}, {}
    view_of = {}
    for l in v0:
        if 'chain started number=' in l:
            m = re.search(r'parent=(0x\w+)', l)
            if m: cs[m[1]] = ts(l)
        elif 'block body prepared block_hash=' in l: body[re.search(r'block_hash=(0x\w+)', l)[1]] = ts(l)
        elif 'proposal sent view=' in l:
            d = dict(KV.findall(l)); prop[d['block']] = (ts(l), d); view_of[int(d['view'])] = d['block']
        elif 'block committed! view=' in l:
            d = dict(KV.findall(l)); commit[d['block_hash']] = (ts(l), l)
    cs_sorted = sorted(cs.values())
    cs_by_t = {t: h for h, t in cs.items()}
    fs = sorted(ts(l) for l in el if 'frame build sealed' in l)
    ea = sorted(ts(l) for l in el if 'answered on the early seal' in l)
    ba = sorted(ts(l) for l in el if 'built ahead on the sealed own block' in l)
    R = defaultdict(list)
    for t_cs in cs_sorted:
        if not (t0 <= t_cs < t1): continue
        t_cs2 = nxt(cs_sorted, t_cs)
        if t_cs2 is None: continue
        h2 = cs_by_t[t_cs2]; h = cs_by_t[t_cs]
        t_fs = nxt(fs, t_cs); t_ea = nxt(ea, t_fs) if t_fs else None; t_ba = nxt(ba, t_ea) if t_ea else None
        if not (t_fs and t_ea and t_ba and h2 in body and h2 in prop): continue
        if t_fs > t_cs2 + 0.02: continue
        R['chain start -> frame build sealed'].append((t_fs - t_cs) * 1e3)
        R['frame sealed -> early-seal answered'].append((t_ea - t_fs) * 1e3)
        R['early-seal answered -> next chain start (release)'].append((t_cs2 - t_ea) * 1e3)
        R['seal-to-seal cadence (chain start -> next chain start)'].append((t_cs2 - t_cs) * 1e3)
        R['early-seal answered -> built ahead on the sealed own block'].append((t_ba - t_ea) * 1e3)
        R['built ahead -> body prepared'].append((body[h2] - t_ba) * 1e3)
        R['body prepared -> proposal sent (tick / vote-log sync wait)'].append((prop[h2][0] - body[h2]) * 1e3)
        R['early-seal answered -> proposal sent'].append((prop[h2][0] - t_ea) * 1e3)
        if h in prop: R['cycle (proposal -> next proposal)'].append((prop[h2][0] - prop[h][0]) * 1e3)
        if h2 in commit and h in commit: R['commit(H2) minus release two builds on: see below'] += []
        c = commit.get(h)
        nn = nxt(cs_sorted, t_cs2)
        if c and nn: R['commit of H minus the release of the build two on (negative = off the chain)'].append((c[0] - nn) * 1e3)
    n = len(R['cycle (proposal -> next proposal)'])
    print(f'  chain (leader, {n} blocks over the 3 windows; median/p90 ms)')
    for k, x in R.items():
        if x: print(f'    {k:75s} {mp(x)}')
    tb = [d for t, d in prop.values() if t0 <= t < t1]
    print(f'  proposals tick-bound {sum(1 for d in tb if d.get("tick_bound") == "true")} of {len(tb)}; take_sealed_us median {st.median(float(d.get("take_sealed_us", 0)) for d in tb):.0f}, publish_us {st.median(float(d.get("publish_us", 0)) for d in tb):.0f}, preamble_us {st.median(float(d.get("preamble_us", 0)) for d in tb):.0f}, tick_late_us median/p90 {mp([float(d.get("tick_late_us", 0)) for d in tb])}')
    # consensus
    pr_t = {int(d['view']): t for t, d in prop.values()}
    votes = defaultdict(dict); gated = defaultdict(dict); decide = defaultdict(dict); synced = defaultdict(list); fcu = defaultdict(list); fcu_n = defaultdict(int)
    for i in range(7):
        for l in read(f'{root}/node{i}-v.log'):
            if 'sending vote to leader view=' in l:
                votes[int(re.search(r'view=(\d+)', l)[1])][i] = ts(l)
            elif 'import-gated vote: waiting for execution validation view=' in l: gated[int(re.search(r'view=(\d+)', l)[1])][i] = 'waited'
            elif 'import-gated vote: block already execution-validated view=' in l: gated[int(re.search(r'view=(\d+)', l)[1])][i] = 'validated'
            elif 'received Decide, committing block view=' in l: decide[int(re.search(r'view=(\d+)', l)[1])][i] = ts(l)
            elif 'vote log sync was slow' in l:
                m = re.search(r'sync_ms=(\d+)', l)
                if m and t0 <= ts(l) < t1: synced[i].append(int(m[1]))
            elif 'commit forkchoice answered' in l and t0 <= ts(l) < t1:
                m = re.search(r'elapsed_ms=(\d+)', l); fcu[i].append(int(m[1])); fcu_n[i] += 1
    W = [v for v in sorted(pr_t) if t0 <= pr_t[v] < t1]
    perkey = defaultdict(list); slow = []; waited = validated = 0; dec = defaultdict(list)
    for v in W:
        vv = votes.get(v, {})
        for i, t in vv.items(): perkey[i].append((t - pr_t[v]) * 1e3)
        if len(vv) >= 5: slow.append(max((t - pr_t[v]) * 1e3 for t in vv.values()))
        for i, g in gated.get(v, {}).items():
            if g == 'waited': waited += 1
            else: validated += 1
        h = view_of.get(v); c = commit.get(h)
        if c:
            for i, t in decide.get(v, {}).items(): dec[i].append((t - c[0]) * 1e3)
    print('  consensus (per view; ms after the proposal unless stated)')
    print('    vote sent per key, median: ' + ' '.join(f'k{i}={st.median(perkey[i]):.1f}' for i in sorted(perkey)) + f'; slowest key median/p90 {mp(slow)}')
    print(f'    votes that waited for execution validation {waited}, found the block already validated {validated} (all keys, {len(W)} views)')
    cm = [(commit[view_of[v]][0] - pr_t[v]) * 1e3 for v in W if v in view_of and view_of[v] in commit]
    r1 = [float(m[1]) for v in W if view_of.get(v) in commit for m in [re.search(r'R1_collect=(\d+)ms', commit[view_of[v]][1])] if m]
    r2 = [float(m[1]) for v in W if view_of.get(v) in commit for m in [re.search(r'R2_collect=(\d+)ms', commit[view_of[v]][1])] if m]
    pa = [float(m[1]) for v in W if view_of.get(v) in commit for m in [re.search(r'proposal=@(\d+)ms', commit[view_of[v]][1])] if m]
    print(f'    proposal -> commit median/p90 {mp(cm)}; leader R1 collect {mp(r1)}, R2 collect {mp(r2)}; the view\'s own proposal at @{mp(pa)} ms after its start')
    print('    commit -> Decide per key, median: ' + ' '.join(f'k{i}={st.median(dec[i]):.1f}' for i in sorted(dec)))
    nb = max(1, len(W))
    print('  repeated per key (over the 3 windows)')
    print('    vote-log sync slow lines per node: ' + ' '.join(f'k{i}={len(synced[i])} (median {st.median(synced[i]):.0f} ms)' for i in sorted(synced) if synced[i]) + f'; views {nb}')
    print('    commit forkchoice answered, per node: ' + ' '.join(f'k{i}={fcu_n[i]} (elapsed median/p90 {mp(fcu[i])})' for i in sorted(fcu)) + f'; views {nb}')
    fc = sum(1 for l in el if ('Forkchoice updated' in l) and t0 <= ts(l) < t1)
    fl = [l for l in el if 'forest lock held' in l and t0 <= ts(l) < t1]
    flms = [float(m[1]) for l in fl for m in [re.search(r' ms=(\d+)', l)] if m]
    print(f"    the layer's `Forkchoice updated` lines {fc} for {len([c for c in canon if t0 <= c < t1])} canonical blocks; `forest lock held` lines {len(fl)} (ms median/p90 {mp(flms)})")
