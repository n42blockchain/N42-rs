#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Anatomy of a block's cycle over the pacing tick, from a three-node round's logs.

    fleet7-excess-anatomy.py <round-dir> [<round-dir> ...]

Window 1, every block V: cycle = P(V) - P(V-1) is split into consecutive segments
that sum to it exactly:

  tick        100 ms nominal pacing (the constant part)
  late        preamble Tp(V) minus (P(V-1) + 100 ms): the timer firing late, or the
              preamble held for the previous commit (quorum overshoot, split out)
  start_lag   Tp -> build request, inside the wait for the sealed header
  queue       request -> transactions taken from the queue (`queue_ms`)
  build       queue -> the build's block sealed (`build_ms`)
  encode      the 26 MB answer encoded (`encode_ms`)
  delivery    EL's `built ahead on the sealed own block` line -> the proposer's
              take_sealed returns (the answer crossing to the proposer)
  send        sealed header (or preamble) -> proposal on the wire (sign, publish)

`take_sealed_us` is the wait [Tp, H]; the build's own timeline (request = line time
minus `total_ms`, then queue, build, encode, delivery) is clipped into it, so the
pieces sum to it. The unclipped chain (previous send -> request -> ... -> hand-off)
is reported separately for blocks whose wait was binding (take > 3 ms). Also reported: the previous block's quorum path
(Qc - P = first follower's receipt + check + vote-to-commit transit), the group
comparison (<= 110 ms, middle, slowest 10%), autocorrelation, leadership, and the
cross-node coincidence of the stages. Reuses the parser of fleet7-depth-replay.py.
"""
import importlib.util
import os
import statistics as st
import sys
from collections import Counter

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('dr', os.path.join(here, 'fleet7-depth-replay.py'))
dr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dr)

TICK = 0.100


def pearson(a, b):
    ma, mb = st.mean(a), st.mean(b)
    num = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    den = (sum((x - ma) ** 2 for x in a) * sum((y - mb) ** 2 for y in b)) ** .5
    return num / den if den else 0.0


def acf(x, k):
    m = st.mean(x)
    return sum((x[i] - m) * (x[i + k] - m) for i in range(len(x) - k)) / sum((v - m) ** 2 for v in x)


def stats(x):
    return f'{st.median(x):6.1f} {st.mean(x):6.1f} {dr.pct(x, .9):6.1f}'


def analyse(root):
    D = dr.collect(root)
    W = dr.window_views(D)
    m = dr.measure(D, W)
    P, Tp, Qc, Pd = D['P'], D['Tp'], D['Qc'], D['Pd']
    ba = {}
    for t, l in dr.lines(f'{root}/node{D["ldr"]}-el.log'):
        if 'built ahead on the sealed own block' in l:
            d = dr.kv(l)
            d['t'] = t
            ba[int(d['number']) + 1] = d
    rows = []
    for v in W[1:]:
        s = m['seal'][v]
        cyc = P[v] - P[v - 1]
        take = s['take']
        H = s['H']
        late_all = Tp[v] - (P[v - 1] + TICK)
        qover = max(0.0, min(Qc[v - 1] + 0.0065 - (P[v - 1] + TICK), late_all)) if late_all > 0 else 0.0
        lo, hi = Tp[v], Tp[v] + take
        cl = lambda t: min(max(t, lo), hi)
        b = ba[v]
        tb, enc, que = b['t'], b['encode_ms'] / 1e3, b['queue_ms'] / 1e3
        # Since loop318 the line is logged AFTER the write and `total_ms` includes it; the old boundary (the line
        # before the write) is `answer_write_start_us`. Older logs have no such field and the line time is it.
        r0 = tb - b['total_ms'] / 1e3
        if 'answer_write_start_us' in b:
            # the log parser's clock is not the unix clock: shift by the write's own duration from the line time
            tb = b['t'] - (b['answer_write_end_us'] - b['answer_write_start_us']) / 1e6
            if b.get('answer_encode_start_us'):
                enc = (b['answer_write_start_us'] - b['answer_encode_start_us']) / 1e6
        pts = [lo, cl(r0), cl(r0 + que), cl(tb - enc), cl(tb), hi]
        send = P[v] - hi
        seg = {'late (timer)': late_all - qover, 'late (quorum overshoot)': qover,
               'start_lag': pts[1] - pts[0], 'queue': pts[2] - pts[1], 'build': pts[3] - pts[2],
               'encode': pts[4] - pts[3], 'delivery': pts[5] - pts[4], 'send': send}
        assert abs(TICK + sum(seg.values()) - cyc) < 1e-6
        first = min(D['fol'], key=lambda n: m['fo'][n][v - 1]['vote'])
        f = m['fo'][first][v - 1]
        q = {'receipt': f['n'], 'check': f['vote'] - f['b'], 'transit': Qc[v - 1] - f['vote']}
        rows.append({'v': v, 'cyc': cyc * 1e3, 'seg': {k: x * 1e3 for k, x in seg.items()},
                     'trig': Pd[v]['build_start_trigger'], 'take': take * 1e3,
                     'chain': {'req_after_prev_send': (r0 - P[v - 1]) * 1e3, 'queue': que * 1e3,
                               'build': b['build_ms'], 'encode': enc * 1e3,
                               'delivery': (H - tb) * 1e3, 'prev_send_to_hand': (H - P[v - 1]) * 1e3},
                     'q': {k: x * 1e3 for k, x in q.items()}, 'qcp': (Qc[v - 1] - P[v - 1]) * 1e3})
    return D, W, m, rows


def report(root):
    D, W, m, rows = analyse(root)
    cyc = [r['cyc'] for r in rows]
    mean = st.mean(cyc)
    print(f'== {os.path.basename(root)}: {len(rows)} blocks, leader node{D["ldr"]}, cycle mean {mean:.1f} '
          f'median {st.median(cyc):.1f} p90 {dr.pct(cyc, .9):.1f}; excess over 100 ms = {mean - 100:.1f}')
    print('segment                    median   mean    p90   share of excess   (ms)')
    names = list(rows[0]['seg'])
    for k in names:
        x = [r['seg'][k] for r in rows]
        print(f'  {k:24} {stats(x)}   {st.mean(x) / (mean - 100) * 100:6.1f}%')
    for trig in ('seal', 'send'):
        g = [r for r in rows if r['trig'] == trig]
        print(f'  build trigger {trig}: {len(g)} blocks ({len(g) / len(rows) * 100:.0f}%), cycle mean {st.mean(r["cyc"] for r in g):.1f} '
              f'median {st.median(r["cyc"] for r in g):.1f}')
    g = [r for r in rows if r['take'] > 3]
    print(f'  chain of the {len(g)} blocks whose sealed-header wait was binding (take > 3 ms), unclipped, median/mean/p90:')
    for k in ('req_after_prev_send', 'queue', 'build', 'encode', 'delivery', 'prev_send_to_hand'):
        print(f'    {k:22} {stats([r["chain"][k] for r in g])}')
    g2 = [r for r in rows if r['take'] > 3 and r['trig'] == 'send']
    if g2:
        print(f'    of which trigger send ({len(g2)}): prev_send_to_hand ' + stats([r['chain']['prev_send_to_hand'] for r in g2]))
    print('  previous block quorum path (inside the tick wait unless it overshoots):')
    for k in ('receipt', 'check', 'transit'):
        x = [r['q'][k] for r in rows]
        print(f'    {k:22} {stats(x)}')
    x = [r['qcp'] for r in rows]
    print(f'    {"Qc - P":22} {stats(x)}')
    lo = [r for r in rows if r['cyc'] <= 110]
    top = sorted(cyc)[int(len(cyc) * .9)]
    hi = [r for r in rows if r['cyc'] >= top]
    mid = [r for r in rows if 110 < r['cyc'] < top]
    print(f'groups: <=110 ms n={len(lo)}, middle n={len(mid)}, slowest 10% (>= {top:.0f} ms) n={len(hi)}; mean of each segment')
    print(f'  {"":26}' + ''.join(f'{g:>10}' for g in ('<=110', 'middle', 'slowest')))
    print(f'  {"cycle":26}' + ''.join(f'{st.mean([r["cyc"] for r in g]):10.1f}' for g in (lo, mid, hi)))
    for k in names:
        print(f'  {k:26}' + ''.join(f'{st.mean([r["seg"][k] for r in g]):10.1f}' for g in (lo, mid, hi)))
    print(f'  {"Qc - P":26}' + ''.join(f'{st.mean([r["qcp"] for r in g]):10.1f}' for g in (lo, mid, hi)))
    # fixed offset: how often is each segment above 5 ms
    print('  share of blocks with the segment above 5 ms: ' + ', '.join(
        f'{k} {sum(1 for r in rows if r["seg"][k] > 5) / len(rows) * 100:.0f}%' for k in names))
    c = [r['cyc'] for r in rows]
    print('  cycle autocorrelation lag 1/2/3: ' + ' '.join(f'{acf(c, k):+.2f}' for k in (1, 2, 3)))
    slow = [i for i, r in enumerate(rows) if r['cyc'] >= top]
    print(f'  P(slow | previous slow) {sum(1 for i in slow if i > 0 and rows[i - 1]["cyc"] >= top) / max(1, len(slow)):.2f} '
          f'(base rate 0.10); P(slow | previous fast <=110) '
          f'{sum(1 for i in slow if i > 0 and rows[i - 1]["cyc"] <= 110) / max(1, sum(1 for i in range(1, len(rows)) if rows[i - 1]["cyc"] <= 110)):.2f}')
    alt = sum(1 for a, b in zip(c, c[1:]) if (a <= 110) != (b <= 110)) / (len(c) - 1)
    print(f'  consecutive blocks on opposite sides of 110 ms: {alt * 100:.0f}%')
    # cross-node: stages of the followers and of the leader for slow vs all blocks
    print('  cross-node stages, slow blocks vs all (median ms; ratio):')
    sl = {r['v'] for r in hi}
    stages = {}
    for n in D['fol']:
        fo = m['fo'][n]
        stages[f'node{n} check'] = {v: fo[v]['c'] * 1e3 for v in W}
        stages[f'node{n} exec'] = {v: fo[v]['x'] * 1e3 for v in W}
        stages[f'node{n} root'] = {v: (fo[v]['F'] - fo[v]['EE']) * 1e3 for v in W}
        stages[f'node{n} fields lag'] = {v: (fo[v]['F'] - fo[v]['b']) * 1e3 for v in W}
    stages['leader par'] = {v: m['seal'][v]['par'] * 1e3 for v in W}
    stages['leader handoff h'] = {v: m['seal'][v]['h'] * 1e3 for v in W}
    for k, d in stages.items():
        allv = [d[v] for v in W[1:]]
        sv = [d[v] for v in W[1:] if v in sl]
        sv1 = [d[v - 1] for v in W[1:] if v in sl]
        print(f'    {k:20} all {st.median(allv):6.1f}  slow {st.median(sv):6.1f} ({st.median(sv) / st.median(allv):.2f}x)  '
              f'slow-1 {st.median(sv1):6.1f} ({st.median(sv1) / st.median(allv):.2f}x)')
    ns = D['fol']
    if len(ns) == 2:
        for stg in ('check', 'exec', 'root'):
            a = [stages[f'node{ns[0]} {stg}'][v] for v in W]
            b = [stages[f'node{ns[1]} {stg}'][v] for v in W]
            print(f'    correlation of {stg} between node{ns[0]} and node{ns[1]} over blocks: {pearson(a, b):+.2f}')
    # same-block slowness vs the other nodes: slow means above the node's own p90 for the stage
    for stg in ('check', 'exec', 'root'):
        a = stages[f'node{ns[0]} {stg}']
        b = stages[f'node{ns[1]} {stg}']
        pa, pb = dr.pct(list(a.values()), .9), dr.pct(list(b.values()), .9)
        both = sum(1 for v in W if a[v] > pa and b[v] > pb)
        one = sum(1 for v in W if (a[v] > pa) != (b[v] > pb))
        print(f'    {stg}: above own p90 on both followers {both}, on exactly one {one} (independent expectation both {len(W) * .01:.1f})')
    # leadership over the whole leg
    L = {}
    for n in [D['ldr']] + D['fol']:
        pass
    return D, rows


def leadership(root):
    props = Counter()
    ranges = {}
    import glob
    for p in sorted(glob.glob(f'{root}/node*-v.log')):
        n = int(p.split('node')[-1].split('-')[0])
        vs = [int(dr.kv(l)['view']) for t, l in dr.lines(p) if 'proposal sent view=' in l]
        if vs:
            ranges[n] = (len(vs), min(vs), max(vs))
    sf = Counter()
    for p in sorted(glob.glob(f'{root}/node*-el.log')):
        n = int(p.split('node')[-1].split('-')[0])
        sf[n] = sum(1 for t, l in dr.lines(p) if 'seal-first build phases' in l)
    print('  proposals per node (count, first view, last view):', ranges, ' seal-first builds:', dict(sf))


if __name__ == '__main__':
    for r in sys.argv[1:]:
        report(r)
        leadership(r)
        print()
