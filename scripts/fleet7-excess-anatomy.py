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


def binding(root):
    """Which wait binds each proposal, and the last voter's path from receipt to vote.

    Tick: the preamble came at P(V-1) + 100 ms and nothing else was later. Seal: the
    proposer waited for the sealed header (take_sealed > 3 ms). Quorum: the preamble
    came within 10 ms of the previous commit and more than 3 ms after the tick. The
    throttle (unpersisted blocks soft 48 / hard 80) is reported from the in-memory
    maximum in the round table, not from a log line: it never engages below 48.
    The quorum waits for every vote (the straggler grace), so the last voter binds.
    """
    D, W, m, rows = analyse(root)
    P, Tp, Qc = D['P'], D['Tp'], D['Qc']
    asm, land = {}, {}
    for n in D['fol']:
        a, ld = {}, {}
        for t, l in dr.lines(f'{root}/node{n}-el.log'):
            if 'compact body assembled from the queue' in l:
                d = dr.kv(l)
                a[int(d['number'])] = t - d['assemble_ms'] / 1e3
            elif 'Block added to canonical chain' in l:
                ld[int(dr.kv(l)['number'])] = t
        asm[n], land[n] = a, ld
    cls = {}
    for r in rows:
        v = r['v']
        if r['take'] > 3:
            c = 'seal'
        elif Tp[v] - Qc[v - 1] < 0.010 and Tp[v] > P[v - 1] + 0.103:
            c = 'quorum'
        else:
            c = 'tick'
        r['bind'] = c
        cls.setdefault(c, []).append(r)
    mean = st.mean(r['cyc'] for r in rows)
    print(f'-- binding wait per block ({os.path.basename(root)}); cycle mean {mean:.1f}')
    for c, g in sorted(cls.items(), key=lambda kv: -len(kv[1])):
        print(f'   {c:7} {len(g) / len(rows) * 100:5.1f}% of blocks, mean cycle {st.mean(r["cyc"] for r in g):6.1f}, '
              f'median {st.median(r["cyc"] for r in g):6.1f}')
    # last voter's path, for every block (the quorum waits for it) and per binding class
    parts = {k: [] for k in ('receipt', 'wait_for_engine', 'assemble_check', 'to_vote_sent', 'transit', 'qc_minus_p')}
    last = Counter()
    gate = []
    byc = {}
    for r in rows:
        v = r['v'] - 1  # the previous block, whose quorum gates this proposal
        vs = {n: D['fo'][n]['vote'][v] for n in D['fol']}
        n = max(vs, key=vs.get)
        last[n] += 1
        b = D['fo'][n]['b'][v]
        a = asm[n].get(v - 1)
        if a is None:
            continue
        k = v - 1
        d = {'receipt': b - P[v], 'wait_for_engine': a - b, 'assemble_check': vs[n] - a,
             'transit': Qc[v] - vs[n], 'qc_minus_p': Qc[v] - P[v]}
        d['to_vote_sent'] = 0.0
        for kk, x in d.items():
            parts[kk].append(x * 1e3)
        if k - 2 in land[n]:
            gate.append((a - land[n][k - 2]) * 1e3)
        r['d'] = d
        r['lastvoter'] = n
        byc.setdefault(r['bind'], []).append((n, d))
    print('   last voter of the previous block:', dict(last))
    print('   last voter, receipt to Qc (ms, median / mean / p90):')
    for kk in ('receipt', 'wait_for_engine', 'assemble_check', 'transit', 'qc_minus_p'):
        print(f'     {kk:16} {stats(parts[kk])}')
    if gate:
        print(f'   assembly start minus the voter\'s engine landing of block n-2: min {min(gate):.1f} '
              f'p10 {dr.pct(gate, .1):.1f} median {st.median(gate):.1f} p90 {dr.pct(gate, .9):.1f} ms (never negative: '
              f'{sum(1 for x in gate if x < 0)} of {len(gate)} below 0)')
    print('   quorum path by binding class (mean ms): ' + '; '.join(
        f'{c}: wait_for_engine {st.mean(d["wait_for_engine"] for n, d in g) * 1e3:.0f}, Qc-P {st.mean(d["qc_minus_p"] for n, d in g) * 1e3:.0f}'
        for c, g in byc.items()))
    # engine landing latency per follower
    for n in D['fol']:
        x = [(land[n][v - 1] - D['fo'][n]['b'][v]) * 1e3 for v in W if v - 1 in land[n]]
        di = D['fo'][n]['di']
        print(f'   node{n}: engine landing minus body arrival median {st.median(x):.0f} p90 {dr.pct(x, .9):.0f}; '
              f'parent_engine_wait_ms median {st.median(di[v]["parent_engine_wait_ms"] for v in W):.0f}; '
              f'fields_ready median {st.median(di[v]["fields_ready_ms"] for v in W):.0f}')
    # counterfactual: the slower follower's check path as fast as the faster follower's
    fast = min(D['fol'], key=lambda n: st.median(D['fo'][n]['vote'][v] - D['fo'][n]['b'][v] for v in W))
    gq = st.median(Tp[r['v']] - Qc[r['v'] - 1] for r in rows if r['bind'] == 'quorum') if cls.get('quorum') else 0.007
    tr = st.median(Qc[v] - max(D['fo'][n]['vote'][v] for n in D['fol']) for v in W)
    late = st.mean(r['seg']['late (timer)'] for r in rows) / 1e3
    send = st.mean(r['seg']['send'] for r in rows) / 1e3
    cf = []
    for r in rows:
        v = r['v'] - 1
        q = max(D['fo'][n]['b'][v] - P[v] + (D['fo'][fast]['vote'][v] - D['fo'][fast]['b'][v]) for n in D['fol']) + tr
        base = 0.100 + late
        seal = r['take'] / 1e3 + 0.0 if r['take'] > 3 else 0.0
        cf.append((max(base, q + gq, seal + (P[r['v']] - r['seg']['send'] / 1e3 - Tp[r['v']] + Tp[r['v']] - P[r['v'] - 1]) if False else base, q + gq) + send) * 1e3)
    print(f'   counterfactual, every follower\'s vote path as fast as node{fast}\'s (quorum gap {gq * 1e3:.1f} ms, '
          f'commit transit {tr * 1e3:.1f} ms, seal wait left as measured where binding): mean cycle '
          f'{st.mean(max(c, r["cyc"] if r["bind"] == "seal" else 0) for c, r in zip(cf, rows)):.1f} ms')
    tl = [D['Pd'][r['v']]['tick_late_us'] / 1e3 for r in rows]
    print(f'   timer: tick_late_us median {st.median(tl):.2f} mean {st.mean(tl):.2f} p90 {dr.pct(tl, .9):.2f} ms; '
          f'preamble minus nominal tick (late, all causes) mean {st.mean(r["seg"]["late (timer)"] + r["seg"]["late (quorum overshoot)"] for r in rows):.1f}; '
          f'send overhead mean {st.mean(r["seg"]["send"] for r in rows):.2f} ms')
    top = sorted(r['cyc'] for r in rows)[int(len(rows) * .9)]
    hi = [r for r in rows if r['cyc'] >= top]
    print(f'   slowest 10% (>= {top:.0f} ms, n={len(hi)}): binding ' +
          ', '.join(f'{c} {sum(1 for r in hi if r["bind"] == c)}' for c in ('tick', 'quorum', 'seal')) +
          f'; previous-block Qc-P mean {st.mean(r["qcp"] for r in hi):.0f} against {st.mean(r["qcp"] for r in rows):.0f} overall')
    hd = [r['d'] for r in hi if 'd' in r]
    ad = [r['d'] for r in rows if 'd' in r]
    for kk in ('wait_for_engine', 'assemble_check', 'transit'):
        print(f'     last voter {kk:16} slowest 10% mean {st.mean(d[kk] for d in hd) * 1e3:6.1f}  all blocks {st.mean(d[kk] for d in ad) * 1e3:6.1f}')
    print(f'     last voter is node{max(D["fol"], key=lambda n: sum(1 for r in hi if r.get("lastvoter") == n))} in '
          f'{max(sum(1 for r in hi if r.get("lastvoter") == n) for n in D["fol"])} of {len(hi)}; slow blocks with the previous block also slow: '
          f'{sum(1 for i, r in enumerate(rows) if r in hi and i and rows[i - 1] in hi)}')
    return D, W, rows


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    for r in args:
        if '--binding' in sys.argv:
            binding(r)
            print()
            continue
        report(r)
        leadership(r)
        print()
