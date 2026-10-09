#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop346 (docs 10.86): markdown rows for the report from the runners' outputs. usage: table346.py <out file>... (prefix loop346)."""
import re, sys, os
L = []
for f in sys.argv[1:]: L += open(f, errors='replace').read().split('\n')
legs, order, cur, win, sect = {}, [], None, 0, None
for l in L:
    m = re.match(r'(loop346\w+) win([123]) tps=([\d,]+) txs=([\d,]+) blocks= (\d+) .*full\(>=95%\)=(\d+)/(\d+)', l)
    if m:
        t = m[1][7:]; d = legs.setdefault(t, {'w': {}, 'feed': {}, 'lock': {}, 'pr': {}}); d['w'][int(m[2])] = (int(m[3].replace(',', '')), int(m[4].replace(',', '')), int(m[5]), int(m[6]), int(m[7]))
        if t not in order: order.append(t)
    m = re.match(r'== (loop346\w+)(:| )', l)
    if m:
        cur = m[1][7:]; win = 0; sect = 'feed' if 'feed check' in l else 'lock' if 'lanes lock' in l else 'pr' if 'pruner (per block' in l else 'an'
        legs.setdefault(cur, {'w': {}, 'feed': {}, 'lock': {}, 'pr': {}})
    m = re.match(r'  window (\d)', l)
    if m: win = int(m[1])
    if not cur or cur not in legs: continue
    d = legs[cur]
    if sect == 'feed':
        m = re.search(r'acq_us (\d+) \(max (\d+)\); gate_us (\d+); reply_us (\d+); slots_busy (\d+)%; delivered median ([\d,]+)/s max ([\d,]+)/s; queue at builds median ([\d,]+) min ([\d,]+)', l)
        if m and win: d['feed'][win] = m.groups()
        m = re.search(r'flood.log.*median ([\d,]+)/s max ([\d,]+)/s; reply latency median ([\d.]+) ms max ([\d.]+)', l)
        if m: d['fl'] = m.groups()
    elif sect == 'lock':
        m = re.search(r'lock duty ([\d.]+)% \(max ([\d.]+)\); holds/5s ([\d,]+); longest hold ([\d.]+) ms median, ([\d.]+) ms max by (\S+) .*lock wait ([\d.]+) ms/5s, longest ([\d.]+) ms; drains/5s ([\d,]+) of (\d+) tx, mean (\d+) us, max ([\d.]+) ms', l)
        if m and win: d['lock'][win] = m.groups()
        m = re.search(r'prune \((\d+) blocks\): prune_ms (\d+)/(\d+); fold ([\d.]+) ms, lock ([\d.]+) ms, remove\(hold\) ([\d.]+) ms, free ([\d.]+) ms; frames_swept (\d+); coalesced on (\d+) of (\d+); prune_wait_ms (\d+)/(\d+); pruner busy (\d+)% of a thread, lock held by it ([\d.]+)%', l)
        if m and win: d['pr'][win] = m.groups()
    else:
        if win == 1:
            for k, pat in (('cyc', r'cycle mean/median/p90 ([\d./]+) ms'), ('seal', r'sealed_at median/p90/p99 ([\d/]+)'), ('pe', r'par_exec (\d+/\d+)'), ('cores', r'execution layer cores busy ([\d.]+)'), ('vote', r'slowest key vote delay median/p90 ([\d./]+)')):
                m = re.search(pat, l)
                if m and k not in d: d[k] = m[1]
            m = re.search(r'binding wait \(tick / quorum / seal share.*tick (\d+)%.*seal (\d+)%', l)
            if m and 'bind' not in d: d['bind'] = m[1] + '/' + m[2]
        m = re.search(r'layer RSS [\d.]+ -> [\d.]+ G \(max ([\d.]+)\)', l)
        if m: d['rss'] = max(d.get('rss', 0), float(m[1]))
        m = re.search(r'engine own-import total_ms per block median/p90/max (\d+/\d+)', l)
        if m and 'imp' not in d: d['imp'] = m[1]
print('| leg | win1 | win2 | win3 | round | blocks | full % | cycle w1 mean/med/p90 | sealed_at | par_exec | tick/seal % | cores | peak RSS | own-import | vote |'); print('|' + ' --- |' * 15)
for t in order:
    d = legs[t]; w = d['w']
    if len(w) < 3: continue
    print(f"| {t} | {w[1][0]:,} | {w[2][0]:,} | {w[3][0]:,} | {sum(w[i][1] for i in w) / 1e6:.1f}M | {w[1][2]}/{w[2][2]}/{w[3][2]} | {100 * w[1][3] / w[1][4]:.0f}/{100 * w[2][3] / w[2][4]:.0f}/{100 * w[3][3] / w[3][4]:.0f} | {d.get('cyc')} | {d.get('seal')} | {d.get('pe')} | {d.get('bind')} | {d.get('cores')} | {d.get('rss')} | {d.get('imp')} | {d.get('vote')} |")
print('\n| leg | acq ms | gate ms w1/w2/w3 | delivered med (max) w1/w2/w3 | queue med; min w1/w2/w3 | flood reply ms | lock duty % | longest hold ms (holder) | lock wait ms/5s | drain tx / mean us / max ms | prune_ms med | prune hold ms | pruner busy % | lock by prune % |'); print('|' + ' --- |' * 14)
for t in order:
    d = legs[t]
    if not d['feed'] or not d['lock']: continue
    f = d['feed']; k = d['lock']; p = d['pr']
    print(f"| {t} | {f[1][0]}-{max(f[i][1] for i in f)} | {'/'.join(str(round(int(f[i][2]) / 1000, 1)) for i in f)} | {' / '.join(f[i][5] + ' (' + f[i][6] + ')' for i in f)} | {' / '.join(f[i][7] + '; ' + f[i][8] for i in f)} | {d.get('fl', ['','','-'])[2]} | {'/'.join(k[i][0] for i in k)} | {'/'.join(k[i][4] for i in k)} ({os.path.basename(k[1][5])}) | {'/'.join(k[i][6] for i in k)} | {k[1][9]} / {k[1][10]} / {k[1][11]} | {'/'.join(p[i][1] for i in p)} | {'/'.join(p[i][5] for i in p)} | {'/'.join(p[i][12] for i in p)} | {'/'.join(p[i][13] for i in p)} |")
# loop346 additions: the persistence per window and the seal-start / plan report
print('\n| leg | persisted/canonical w1 / w2 / w3 | ms per block w1 / w2 / w3 | sf_transactions ms | qmdb_persisted ms | in-memory start -> end (max) w1 / w2 / w3 | lag growth blocks/min w1 / w2 / w3 |'); print('|' + ' --- |' * 7)
pr, pl, cur = {}, {}, None
for l in L:
    m = re.match(r'== (loop346\w+): persistence per window', l)
    if m: cur = m[1][7:]; pr[cur] = []; continue
    m = re.match(r'== (loop346\w+): seal start', l)
    if m: cur = m[1][7:]; pl[cur] = []; continue
    if cur in pr and l.startswith('  window'):
        m = re.search(r'persisted (\d+) blocks of (\d+) canonical \((\d+)%\); ([\d.]+) ms/block persistence \(sf_transactions ([\d.]+), qmdb_persisted ([\d.]+)\); in-memory blocks (\d+) -> (\d+) \(max (\d+)\); lag latest-persisted (\d+) -> (\d+) blocks = ([+-][\d.]+) blocks/min', l)
        if m: pr[cur].append(m.groups())
    elif cur in pl and l.startswith('  window'):
        pl[cur].append(l.strip())
    elif cur in pl and l.strip().startswith('plan_ahead'):
        pl[cur].append(l.strip())
for t in order:
    r = pr.get(t)
    if not r or len(r) < 3: continue
    print(f"| {t} | {' / '.join(x[2] + '%' for x in r)} | {' / '.join(x[3] for x in r)} | {'/'.join(x[4] for x in r)} | {'/'.join(x[5] for x in r)} | {' / '.join(x[6] + '->' + x[7] + ' (' + x[8] + ')' for x in r)} | {' / '.join(x[11] for x in r)} |")
print('\nplan / start lines (window 2):')
for t in order:
    r = pl.get(t)
    if r and len(r) >= 4: print(f'  {t}: {r[2][:400]}'); print(f'      {r[3][:200]}')
