#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Replay the deferral depth D on a three-node bench round, from its logs only.

    fleet7-depth-replay.py [--md] [round-dir ...]

Default round directories are the judged legs of loop316 (NEW, FOFF, NEWb) under
/data/blockchain/rust-fleet3-bench. Reads node<i>-v.log and node<i>-el.log (ANSI
stripped on the fly); runs nothing else.

Header N carries the execution result of block N-D. The model recomputes each
block's proposal and quorum time of window 1 (the 30 s after the first full body)
under that rule, keeping every measured duration and delay:

  leader   seal(V)  = start(V) + max(par(V), R(V-D) - start(V)) + c
           start(V) = seal(V-1) + e(V)              (the chained build-ahead)
           R(V)     = max(start(V) + state_ready(V), R(V-1))   (serial)
           ready(V) = seal(V) + h(V)                (hand-off until the proposer holds it)
           P(V)     = max(P(V-1) + tick, Qc(V-1) + gq, ready(V)) + o
  follower b(V)     = P(V) + n(V)                   (body arrival, measured offset)
           vote(V)  = max(b(V) + c(V), F(V-D) + g)  (check, then the parent-D result)
           ES(V)    = max(b(V) + road_end(V), EE(V-1)) + s ; EE = ES + x(V)
           F(V)     = max(EE(V), F(V-1)) + rt(V)    (execution, then the root; serial)
  quorum   Qc(V)    = min over followers vote(V) + transit    (leader + one follower)

Per-block durations (par, state_ready, e, h, n, c, road_end, x, rt) are the logs'
own; the gating constants (tick, gq, o, c, s, g, transit) are medians. D = 1 must
reproduce the measured mean cycle or the model is not used.
"""

import datetime
import glob
import os
import random
import re
import statistics as st
import sys

ROOT = '/data/blockchain/rust-fleet3-bench'
LEGS = ['NEW', 'FOFF', 'NEWb']
TX = 163000
CL = re.compile(r'\x1b\[[0-9;]*m')
STAMP = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+)Z')
KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def ts(line):
    m = STAMP.match(line)
    return datetime.datetime.fromisoformat(m.group(1)).timestamp() if m else None


def kv(line):
    d = {}
    for k, v in KV.findall(line):
        v = v.strip('"')
        try:
            d[k] = float(v)
        except ValueError:
            d[k] = v
    return d


def lines(path):
    for raw in open(path, errors='ignore'):
        raw = CL.sub('', raw)
        t = ts(raw)
        if t is not None:
            yield t, raw


def pct(x, p):
    x = sorted(x)
    return x[min(int(len(x) * p), len(x) - 1)]


def med(x):
    return st.median(x) if x else 0.0


# --------------------------------------------------------------------------
# Extraction


def collect(root):
    """Per-view tables of the leader and the followers for one round."""
    nodes = sorted(int(m.group(1)) for p in glob.glob(f'{root}/node*-v.log')
                   if (m := re.search(r'node(\d+)-v\.log', p)))
    nodes = [n for n in nodes if os.path.getsize(f'{root}/node{n}-v.log') > 0]
    props, full = {}, {}
    vlog = {n: list(lines(f'{root}/node{n}-v.log')) for n in nodes}
    for n in nodes:
        for t, l in vlog[n]:
            if 'proposal sent view=' in l:
                d = kv(l)
                props.setdefault(n, {})[int(d['view'])] = (t, d)
            elif 'block body prepared' in l and (kv(l).get('bytes', 0) > 500_000 or kv(l).get('compact_bytes', 0) > 5_000):  # elided bodies have bytes=0
                full.setdefault(n, []).append(t)
    t0 = min(full[n][0] for n in full)  # first full body, any leader
    ldr = min(full, key=lambda n: full[n][0])  # window 1 sits in this leader's tenure
    fol = [n for n in nodes if n != ldr]
    D = {'ldr': ldr, 'fol': fol, 't0': t0}
    pre, qc = {}, {}
    for t, l in vlog[ldr]:
        if 'proposal preamble view=' in l:
            pre[int(kv(l)['view'])] = t
        elif 'block committed!' in l:
            qc[int(kv(l)['view'])] = t
    D['P'] = {v: x[0] for v, x in props[ldr].items()}
    D['Pd'] = {v: x[1] for v, x in props[ldr].items()}
    D['Tp'], D['Qc'] = pre, qc
    seal = {}
    for t, l in lines(f'{root}/node{ldr}-el.log'):
        if 'seal-first build phases' in l:
            d = kv(l)
            d['st'] = t - d['total_ms'] / 1e3
            seal[int(d['number']) + 1] = d  # view = number + 1
    D['seal'] = seal
    D['fo'] = {}
    for n in fol:
        b, vt, road, di = {}, {}, {}, {}
        for t, l in vlog[n]:
            if 'import starting block_hash' in l:
                b[kv(l)['block_hash']] = t
            elif 'sending vote to leader' in l:
                d = kv(l)
                vt[int(d['view'])] = (t, d['block_hash'])
        for t, l in lines(f'{root}/node{n}-el.log'):
            if ' vote road number=' in l:
                d = kv(l)
                road[int(d['number']) + 1] = d
            elif 'direct import: executed here' in l:
                d = kv(l)
                di[int(d['number']) + 1] = d
        D['fo'][n] = {
            'b': {v: b[h] for v, (t, h) in vt.items() if h in b},
            'vote': {v: t for v, (t, h) in vt.items()},
            'road': road, 'di': di}
    return D


def window_views(D):
    P, t0 = D['P'], D['t0']
    need = lambda v: (v in D['Tp'] and v in D['seal'] and v in D['Qc'] and
                      all(v in D['fo'][n]['b'] and v in D['fo'][n]['di'] and
                          v in D['fo'][n]['road'] and v in D['fo'][n]['vote']
                          for n in D['fol']))
    W = [v for v in sorted(P) if t0 <= P[v] <= t0 + 30]
    # contiguous run with every table present
    run, best = [], []
    for v in W:
        if need(v) and (not run or v == run[-1] + 1):
            run.append(v)
        else:
            if len(run) > len(best):
                best = run
            run = [v] if need(v) else []
    best = best if len(best) >= len(run) else run
    return best[1:]  # the first block of the run is kept only as a predecessor


# --------------------------------------------------------------------------
# Per-block measured quantities and constants


def measure(D, W):
    """Per-view measured durations and the median gating constants."""
    P, Tp, Qc, seal, Pd = D['P'], D['Tp'], D['Qc'], D['seal'], D['Pd']
    m = {'seal': {}, 'fo': {n: {} for n in D['fol']}}
    for v in W:
        s, sp = seal[v], seal[v - 1]
        S = s['st'] + s['sealed_at_ms'] / 1e3
        Sp = sp['st'] + sp['sealed_at_ms'] / 1e3
        H = Tp[v] + Pd[v]['take_sealed_us'] / 1e6
        m['seal'][v] = {
            'S': S, 'H': H, 'st': s['st'], 'par': s['par_ms'] / 1e3,
            'sr': s['state_ready_ms'] / 1e3, 'e': s['st'] - Sp, 'h': H - S,
            'R': s['st'] + s['state_ready_ms'] / 1e3,
            'take': Pd[v]['take_sealed_us'] / 1e6}
    for n in D['fol']:
        f = D['fo'][n]
        for v in W:
            b = f['b'][v]
            di, rd = f['di'][v], f['road'][v]
            m['fo'][n][v] = {
                'b': b, 'n': b - P[v], 'vote': f['vote'][v],
                'c': f['vote'][v] - b - rd['parent_wait_ms'] / 1e3,
                'ES': b + di['exec_start_ms'] / 1e3, 'EE': b + di['exec_end_ms'] / 1e3,
                'F': b + di['fields_ready_ms'] / 1e3, 'rend': di['road_end_ms'] / 1e3,
                'x': (di['exec_end_ms'] - di['exec_start_ms']) / 1e3}
    # a follower's measured (b, EE, F) for the view before the window, for seeding
    return m


def constants(D, W, m):
    P, Tp, Qc = D['P'], D['Tp'], D['Qc']
    tk, gq, o, cc, tr, s_, rt, g = [], [], [], [], [], [], [], []
    for v in W[1:]:
        ms = m['seal'][v]
        o.append(P[v] - max(Tp[v], ms['H']))
        gq.append(Tp[v] - Qc[v - 1])
        if ms['take'] < 0.001 and Tp[v] - Qc[v - 1] > 0.02:
            tk.append(Tp[v] - P[v - 1])
        sl, sp = D['seal'][v], D['seal'][v - 1]
        Rprev = sp['st'] + sp['state_ready_ms'] / 1e3
        cc.append(sl['sealed_at_ms'] / 1e3 - max(sl['par_ms'] / 1e3, Rprev - sl['st']))
        tr.append(Qc[v] - min(m['fo'][n][v]['vote'] for n in D['fol']))
        for n in D['fol']:
            a, b_ = m['fo'][n][v], m['fo'][n].get(v - 1)
            if b_:
                s_.append(a['ES'] - max(a['b'] + a['rend'], b_['EE']))
                rt.append(a['F'] - max(a['EE'], b_['F']))
                g.append(a['vote'] - b_['F'])
    gqs = sorted(gq)
    return {
        'tick': med(tk), 'gq': gqs[len(gqs) // 20], 'o': med(o), 'cc': med(cc),
        'tr': med(tr), 's': med(s_), 'g': 0.001,
        'e_seal': med([m['seal'][v]['e'] for v in W[1:] if m['seal'][v]['e'] < 0.02])}


# --------------------------------------------------------------------------
# The replay


def simulate(D, W, m, K, depth, seed=None, voters=None, slot_free=False):
    """Returns the simulated tables. Blocks W[:SEED] keep their measured times."""
    SEED = 4
    P, Tp, Qc = D['P'], D['Tp'], D['Qc']
    ms, fo = m['seal'], m['fo']
    Pn, S, R, Qn = {}, {}, {}, {}
    Fn = {n: {} for n in D['fol']}
    EEn = {n: {} for n in D['fol']}
    vn = {n: {} for n in D['fol']}
    rng = random.Random(seed) if seed is not None else None
    pool = [(fo[n][v]['n'], fo[n][v]['c']) for n in D['fol'] for v in W]
    for i, v in enumerate(W):
        if i < SEED:
            Pn[v], S[v], R[v], Qn[v] = P[v], ms[v]['S'], ms[v]['R'], Qc[v]
            for n in D['fol']:
                Fn[n][v], EEn[n][v], vn[n][v] = fo[n][v]['F'], fo[n][v]['EE'], fo[n][v]['vote']
            continue
        e, h = ms[v]['e'], ms[v]['h']
        if slot_free:  # a build may start at the previous seal, never waiting for the previous send
            e = min(e, K['e_seal'])
        st_ = S[v - 1] + e
        R[v] = max(st_ + ms[v]['sr'], R[v - 1])
        Rd = R[v - depth] if (v - depth) in R else ms[v - depth]['R'] if (v - depth) in ms else R[W[0]]
        S[v] = st_ + max(ms[v]['par'], Rd - st_) + K['cc']
        H = S[v] + h
        Tpn = max(Pn[v - 1] + K['tick'], Qn[v - 1] + K['gq'])
        Pn[v] = max(Tpn, H) + K['o']
        votes = []
        for n in D['fol']:
            a = fo[n][v]
            b = Pn[v] + a['n']
            Fd = Fn[n].get(v - depth)
            if Fd is None:
                Fd = fo[n][v - depth]['F'] if (v - depth) in fo[n] else 0
            vn[n][v] = max(b + a['c'], Fd + K['g'])
            ES = max(b + a['rend'], EEn[n][v - 1]) + K['s']
            EEn[n][v] = ES + a['x']
            Fn[n][v] = max(EEn[n][v], Fn[n][v - 1]) + (a['F'] - max(a['EE'], fo[n][v - 1]['F']))
            votes.append(vn[n][v])
        if voters:  # an n-voter fleet: the k-th fastest of `voters` iid follower votes
            draws = sorted(Pn[v] + sum(rng.choice(pool)) for _ in range(voters[0]))
            Qn[v] = draws[voters[1] - 1] + K['tr']
        else:
            Qn[v] = min(votes) + K['tr']
    return {'P': Pn, 'F': Fn, 'Q': Qn, 'R': R}


def cycles(P, W, start=4):
    vs = W[start - 1:]
    return [(P[b] - P[a]) * 1e3 for a, b in zip(vs, vs[1:])]


def slope(xs):
    n = len(xs)
    mx, my = (n - 1) / 2, sum(xs) / n
    return sum((i - mx) * (y - my) for i, y in enumerate(xs)) / sum((i - mx) ** 2 for i in range(n))


# --------------------------------------------------------------------------
# Gating classes at D = 1, from the measured round


def classify(D, W, m, K):
    P, Tp, Qc = D['P'], D['Tp'], D['Qc']
    out = {}
    for v in W[1:]:
        ms = m['seal'][v]
        sl, sp = D['seal'][v], D['seal'][v - 1]
        Rrel = sp['st'] + sp['state_ready_ms'] / 1e3 - sl['st']
        exc = (P[v] - P[v - 1]) * 1e3
        if ms['take'] > 0.003:
            if Rrel > sl['par_ms'] / 1e3:
                c = 'leader seal: its own parent result'
            elif ms['e'] > 0.02:
                c = 'leader seal: build waits for the previous send (one-ahead slot)'
            else:
                c = 'leader seal: own build (par)'
        elif Tp[v] - Qc[v - 1] < 0.008 and Tp[v] > P[v - 1] + K['tick'] + 0.003:
            c = 'quorum of N-1 (vote path)'
        else:
            c = 'pacing tick'
        out.setdefault(c, []).append(exc)
    # follower parent-result gating of the quorum vote, over all blocks
    fg = 0
    for v in W[1:]:
        first = min(D['fol'], key=lambda n: m['fo'][n][v]['vote'])
        a, b_ = m['fo'][first][v], m['fo'][first][v - 1]
        if a['vote'] - b_['F'] < 0.005:
            fg += 1
    return out, fg


def run_leg(root, tag, rows):
    D = collect(root)
    W = window_views(D)
    m = measure(D, W)
    K = constants(D, W, m)
    meas = [(D['P'][b] - D['P'][a]) * 1e3 for a, b in zip(W[3:], W[4:])]
    res = {}
    for d in (1, 2, 3):
        sim = simulate(D, W, m, K, d)
        cy = cycles(sim['P'], W)
        lag = {n: [(sim['F'][n][v] - sim['P'][v]) * 1e3 for v in W[4:]] for n in D['fol']}
        res[d] = {
            'mean': st.mean(cy), 'med': st.median(cy), 'p90': pct(cy, .9), 'cy': cy,
            'lag_mean': st.mean(st.mean(x) for x in lag.values()),
            'lag_slope': st.mean(slope(x) for x in lag.values()),
            'lag_p90': pct([y for x in lag.values() for y in x], .9)}
        sf = simulate(D, W, m, K, d, slot_free=True)
        res[d]['sf'] = st.mean(cycles(sf['P'], W))
        for tag2, tick2 in (('t50', 0.05), ('t0', 0.0)):
            K2 = dict(K, tick=K['tick'] - (0.1 - tick2) if tick2 else 0.0)
            s2 = simulate(D, W, m, K2, d, slot_free=True)
            lg = [slope([(s2['F'][n][v] - s2['P'][v]) * 1e3 for v in W[4:]]) for n in D['fol']]
            res[d][tag2] = (st.mean(cycles(s2['P'], W)), st.mean(lg))
        mc = []
        for seed in range(20):
            s7 = simulate(D, W, m, K, d, seed=seed, voters=(6, 4))
            mc.append(st.mean(cycles(s7['P'], W)))
        res[d]['mc7'] = st.mean(mc)
    cls, fgate = classify(D, W, m, K)
    svc = [m['fo'][n][v]['x'] * 1e3 for n in D['fol'] for v in W]
    rtt = [(m['fo'][n][v]['F'] - m['fo'][n][v]['EE']) * 1e3 for n in D['fol'] for v in W]
    lagm = [(m['fo'][n][v]['F'] - D['P'][v]) * 1e3 for n in D['fol'] for v in W[3:]]
    lagm_slope = st.mean(slope([(m['fo'][n][v]['F'] - D['P'][v]) * 1e3 for v in W[3:]]) for n in D['fol'])
    info = {
        'tag': tag, 'ldr': D['ldr'], 'n': len(W), 'K': K, 'meas': meas, 'res': res, 'cls': cls,
        'fgate': fgate, 'exec_mean': st.mean(svc), 'root_mean': st.mean(rtt),
        'lag_meas_mean': st.mean(lagm), 'lag_meas_slope': lagm_slope,
        'rbound': sum(1 for v in W[1:] if
                      D['seal'][v - 1]['st'] + D['seal'][v - 1]['state_ready_ms'] / 1e3 - D['seal'][v]['st']
                      > D['seal'][v]['par_ms'] / 1e3),
        'nvote': 2 * (len(W) - 1)}
    rows.append(info)
    return info


def report(rows):
    print('Per leg, window 1 (blocks, leader node, measured mean cycle, D=1 model error):')
    for r in rows:
        mm = st.mean(r['meas'])
        e1 = (r['res'][1]['mean'] / mm - 1) * 100
        print(f"  {r['tag']:5} n={r['n']} leader=node{r['ldr']} measured mean {mm:.1f} ms "
              f"median {st.median(r['meas']):.1f} p90 {pct(r['meas'], .9):.1f}; "
              f"model D=1 mean {r['res'][1]['mean']:.1f} ({e1:+.1f}%)")
    print()
    print('Cycle (ms) and implied TPS (163,000 tx per block), 3-node quorum (2 of 3):')
    print('  leg   D  mean  median  p90   TPS(mean)  vs D=1   7-node mean (5 of 7)')
    for r in rows:
        mm = st.mean(r['meas'])
        print(f"  {r['tag']:5} measured {mm:6.1f} {st.median(r['meas']):6.1f} {pct(r['meas'], .9):6.1f} "
              f"{TX / mm * 1e3 / 1e6:6.3f}M")
        base = r['res'][1]['mean']
        for d in (1, 2, 3):
            x = r['res'][d]
            print(f"  {'':5} {d}  {x['mean']:6.1f} {x['med']:6.1f} {x['p90']:6.1f} "
                  f"{TX / x['mean'] * 1e3 / 1e6:6.3f}M  {(x['mean'] / base - 1) * 100:+5.1f}%   {x['mc7']:6.1f}")
    print()
    print('Extrapolation, one-ahead build slot lifted (a build starts at the previous seal, e = measured seal-trigger median):')
    for r in rows:
        print(f"  {r['tag']:5} " + '  '.join(
            f"D={d}: {r['res'][d]['sf']:6.1f} ms {TX / r['res'][d]['sf'] * 1e3 / 1e6:5.3f}M" for d in (1, 2, 3)))
    print()
    print('Sensitivity, slot lifted and the pacing tick shortened (cycle ms / follower execution-lag slope ms per block):')
    for r in rows:
        for k, name in (('t50', 'tick -50 ms'), ('t0', 'no tick')):
            print(f"  {r['tag']:5} {name:11} " + '  '.join(
                f"D={d}: {r['res'][d][k][0]:6.1f} / {r['res'][d][k][1]:+6.2f}" for d in (1, 2, 3)))
    print()
    print('Gating at D=1 (share of blocks; mean cycle of the class, ms):')
    for r in rows:
        tot = sum(len(v) for v in r['cls'].values())
        print(f"  {r['tag']}")
        for k, v in sorted(r['cls'].items(), key=lambda kv: -len(kv[1])):
            print(f"    {k:58} {len(v) / tot * 100:5.1f}%  mean cycle {st.mean(v):6.1f}")
        print(f"    seal gated by the leader's own parent result (R-bound, any size): "
              f"{r['rbound']}/{r['n'] - 1}; quorum vote within 5 ms of the voter's parent result: "
              f"{r['fgate']}/{r['n'] - 1}")
    print()
    print('Execution lag (follower F(V) - proposal P(V), ms) and its growth per block:')
    for r in rows:
        print(f"  {r['tag']:5} measured mean {r['lag_meas_mean']:.0f} slope {r['lag_meas_slope']:+.3f} ms/block; "
              f"exec {r['exec_mean']:.0f} + root {r['root_mean']:.0f} ms per block")
        for d in (1, 2, 3):
            x = r['res'][d]
            print(f"        D={d}: mean {x['lag_mean']:.0f} p90 {x['lag_p90']:.0f} slope {x['lag_slope']:+.3f} ms/block")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    dirs = [(os.path.basename(a), a) for a in args] or [(l, f'{ROOT}/bench-loop316{l}') for l in LEGS]
    rows = []
    for tag, d in dirs:
        run_leg(d, tag, rows)
    report(rows)


if __name__ == '__main__':
    main()
