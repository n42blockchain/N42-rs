#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import re, sys, statistics, datetime, os

ROOT = "/data/blockchain/rust-fleet7-bench"
ANSI = re.compile(r'\x1b\[[0-9;]*m')
TS = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)')

def parse_ts(s):
    # 2026-09-21T02:31:20.245860Z
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")

def strip(line):
    return ANSI.sub('', line)

def load(path):
    with open(path, errors='replace') as f:
        return [strip(l) for l in f]

def kv(line, key, cast=int):
    m = re.search(key + r'=("?)([^ "]+)\1', line)
    if not m:
        return None
    v = m.group(2)
    try:
        return cast(v)
    except ValueError:
        return v

FIELDS_VOTE_ROAD = ['number','txs','request','recv_ms','decode_ms','senders_ms','parent_wait_ms','check_ms','total_ms']
FIELDS_LBP = ['view','ahead','fcu_ms','build_ms','seal_ms','total_ms']
FIELDS_PRE = ['view','header_ms','attrs_ms','from_el']
FIELDS_COMMIT = ['view']  # + proposal/R1/R2/total parsed specially
FIELDS_DIRECT = ['number','txs','convert_ms','header_ms','senders_ms','exec_ms','checks_ms','root_ms','hashed_ms','total_ms']

def leg_dir(name):
    return os.path.join(ROOT, name)

def parse_leg(name):
    d = leg_dir(name)
    nodes = {}
    for n in range(7):
        v = load(os.path.join(d, f"node{n}-v.log"))
        e = load(os.path.join(d, f"node{n}-el.log"))
        nodes[n] = {'v': v, 'el': e}
    return nodes

def ts_of(line):
    m = TS.match(line)
    return parse_ts(m.group(1)) if m else None

def collect(nodes):
    data = {n: {
        'bp': [],       # (ts,)
        'pre': {},      # view -> (ts, header_ms, attrs_ms)
        'lbp': {},      # view -> (ts, fcu, build, seal, total)
        'commit': {},   # view -> (ts, proposal_ms, r1, r2, total, votes)
        'body_recv': [],# (ts,) block body received (any)
        'vote_road': [],# (ts, number, txs, request, recv, decode, senders, parent_wait, check, total)
        'direct': [],   # (ts, number, txs, convert, header, senders, exec, checks, root, hashed, total)
        'own_handed': [], # (ts, number)
    } for n in range(7)}

    for n in range(7):
        for line in nodes[n]['v']:
            t = ts_of(line)
            if t is None:
                continue
            if 'block body prepared' in line:
                data[n]['bp'].append(t)
            elif 'proposal preamble' in line:
                view = kv(line, 'view')
                data[n]['pre'][view] = (t, kv(line,'header_ms'), kv(line,'attrs_ms'))
            elif 'leader build path' in line:
                view = kv(line, 'view')
                data[n]['lbp'][view] = (t, kv(line,'fcu_ms'), kv(line,'build_ms'), kv(line,'seal_ms'), kv(line,'total_ms'))
            elif 'consensus_timing=leader' in line:
                view = kv(line, 'view')
                m = re.search(r'proposal=@(\d+)ms R1_collect=(\d+)ms R2_collect=(\d+)ms total=(\d+)ms votes=(\d+)\+(\d+)', line)
                bh = kv(line, 'block_hash', str)
                if m:
                    data[n]['commit'][view] = (t, int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)), bh)
            elif 'block body received' in line:
                data[n]['body_recv'].append((t, kv(line,'block_hash', str)))
        for line in nodes[n]['el']:
            t = ts_of(line)
            if t is None:
                continue
            if 'vote road' in line:
                data[n]['vote_road'].append((t, kv(line,'number'), kv(line,'txs'), kv(line,'request',str),
                                              kv(line,'recv_ms'), kv(line,'decode_ms'), kv(line,'senders_ms'),
                                              kv(line,'parent_wait_ms'), kv(line,'check_ms'), kv(line,'total_ms')))
            elif 'direct import: executed here, handed' in line or \
                 "direct import: answered before the engine's own pass" in line:
                data[n]['direct'].append((t, kv(line,'number'), kv(line,'txs'), kv(line,'convert_ms'),
                                           kv(line,'header_ms'), kv(line,'senders_ms'), kv(line,'exec_ms'),
                                           kv(line,'checks_ms'), kv(line,'root_ms'), kv(line,'hashed_ms'),
                                           kv(line,'total_ms')))
            elif 'own block handed to the engine as executed' in line:
                data[n]['own_handed'].append((t, kv(line,'number')))
    return data

def median(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None

def analyze_leg(name):
    nodes = parse_leg(name)
    data = collect(nodes)

    # block number -> txs, via vote_road (any follower)
    num_txs = {}
    num_time = {}  # earliest vote_road ts per number (rough)
    for n in range(7):
        for (t, num, txs, *_rest) in data[n]['vote_road']:
            if num is None: continue
            num_txs.setdefault(num, txs)
            if num not in num_time or t < num_time[num]:
                num_time[num] = t

    if not num_txs:
        return None, f"no vote_road lines in {name}"

    full_nums = sorted(n_ for n_, txs in num_txs.items() if txs is not None and txs >= 150000)
    if not full_nums:
        return None, f"no full blocks (txs>=150000) in {name}"
    t_start = num_time[full_nums[0]]
    t_end = t_start + datetime.timedelta(seconds=30)
    window_nums = [n_ for n_ in full_nums if t_start <= num_time[n_] < t_end]

    # leader identity per block number: from own_handed events
    leader_of = {}
    for n in range(7):
        for (t, num) in data[n]['own_handed']:
            if num is None: continue
            leader_of[num] = n

    # view == block number, confirmed empirically: PRE(view) -> LBP(view) -> BP(view)
    # form one tight cluster (E, F both a few ms) for the SAME view/number. Find BP
    # by taking the nearest "block body prepared" event on/after LBP(view).ts, on the
    # SAME node. A gap > 200ms means this view's block never got a >1MB BP line
    # (not a full block, or BP missing) -- skip it.
    num_bp_ts = {}   # (leader,view) -> bp ts
    leader_view_num = {}  # (leader,view) -> block number == view, kept explicit for clarity
    for ld in range(7):
        bps = sorted(data[ld]['bp'])
        for view, (lbp_ts, fcu, build_ms, seal, E) in data[ld]['lbp'].items():
            import bisect
            i = bisect.bisect_left(bps, lbp_ts)
            if i >= len(bps):
                continue
            bp_ts = bps[i]
            if (bp_ts - lbp_ts).total_seconds() > 0.2:
                continue
            num_bp_ts[(ld, view)] = bp_ts

    results = []
    for ld in range(7):
        views = sorted(v for (l, v) in num_bp_ts if l == ld)
        for view in views:
            nxt = view + 1
            if (ld, nxt) not in num_bp_ts:
                continue
            bp_v = num_bp_ts[(ld, view)]
            bp_v1 = num_bp_ts[(ld, nxt)]
            if not (t_start <= bp_v < t_end):
                continue
            # this block (view) must actually be a full one per vote_road txs
            if num_txs.get(view, 0) is None or num_txs.get(view, 0) < 150000:
                continue
            if num_txs.get(nxt, 0) is None or num_txs.get(nxt, 0) < 150000:
                continue
            cycle = (bp_v1 - bp_v).total_seconds() * 1000
            commit_v = data[ld]['commit'].get(view)
            commit_v1 = data[ld]['commit'].get(nxt)
            lbp_v1 = data[ld]['lbp'].get(nxt)
            pre_v1 = data[ld]['pre'].get(nxt)
            if not (commit_v and commit_v1 and lbp_v1):
                continue
            B = commit_v[2]  # R1_collect (view's own proposal -> R1 quorum)
            X = commit_v1[1]  # proposal_ms for view+1 (== D+E+F of view+1)
            E = lbp_v1[4]     # total_ms of leader build path, view+1
            F = (bp_v1 - lbp_v1[0]).total_seconds() * 1000
            D = X - E - F
            C = cycle - B - D - E - F
            rec = dict(leader=ld, num=view, view=view, cycle=cycle, B=B, C=C, D=D, E=E, F=F, X=X,
                       pre_check=None)
            if pre_v1:
                rec['pre_check'] = (bp_v1 - pre_v1[0]).total_seconds()*1000  # should ~= E+F
            results.append(rec)

    return dict(results=results, window_nums=window_nums, t_start=t_start, t_end=t_end,
                leader_of=leader_of, full_nums=full_nums, num_txs=num_txs, data=data), None

def summarize(name):
    res, err = analyze_leg(name)
    if err:
        print(f"{name}: {err}")
        return None
    r = res['results']
    print(f"=== {name} ===  window1 full blocks: {len(res['window_nums'])}  matched cycles(A-F): {len(r)}  leaders in window: {sorted(set(res['leader_of'].get(n) for n in res['window_nums']))}")
    if not r:
        print("  no matched consecutive same-leader full-block pairs")
        return res
    for k in ['cycle','B','C','D','E','F']:
        vals = [x[k] for x in r]
        print(f"  {k:6s} n={len(vals):3d} median={statistics.median(vals):7.1f}  mean={statistics.mean(vals):7.1f}  min={min(vals):7.1f} max={max(vals):7.1f}")
    sums = [x['B']+x['C']+x['D']+x['E']+x['F'] for x in r]
    cycles = [x['cycle'] for x in r]
    diffs = [c-s for c,s in zip(cycles,sums)]
    print(f"  cycle - (B+C+D+E+F): median={statistics.median(diffs):.2f} mean={statistics.mean(diffs):.2f} (should be ~A, ~0-2ms)")
    precheck = [x['pre_check'] for x in r if x['pre_check'] is not None]
    if precheck:
        ef = [x['E']+x['F'] for x in r if x['pre_check'] is not None]
        d2 = [p-e for p,e in zip(precheck, ef)]
        print(f"  sanity (BP-PRE) - (E+F): median={statistics.median(d2):.2f}  (should be ~0)")
    return res

def follower_breakdown(name, res):
    data = res['data']
    t_start, t_end = res['t_start'], res['t_end']
    leader_of = res['leader_of']
    # hash -> number, from any leader's commit dict
    hash_num = {}
    for ld in range(7):
        for view, c in data[ld]['commit'].items():
            if len(c) > 7 and c[7]:
                hash_num[c[7]] = view
    # per-node vote_road restricted to window full blocks, keyed by number
    per_node_by_num = {n: {} for n in range(7)}
    for n in range(7):
        for (t, num, txs, req, recv, dec, snd, pw, chk, tot) in data[n]['vote_road']:
            if num is None or not (t_start <= t < t_end):
                continue
            if num_is_full(res, num):
                per_node_by_num[n][num] = (t, req, recv, dec, snd, pw, chk, tot)
    # per-node body_recv by hash -> ts (first occurrence in window +/- margin)
    per_node_recv_by_hash = {n: {} for n in range(7)}
    for n in range(7):
        for (t, h) in data[n]['body_recv']:
            if h and (t_start - datetime.timedelta(seconds=2)) <= t < (t_end + datetime.timedelta(seconds=2)):
                per_node_recv_by_hash[n].setdefault(h, t)

    print(f"--- {name}: per-follower vote-road (window1 full blocks) ---")
    ranks_per_block = {}
    for n in range(7):
        rows = per_node_by_num[n]
        if not rows:
            continue
        is_leader_count = sum(1 for num in rows if leader_of.get(num) == n)
        req_counts = {}
        for num, v in rows.items():
            req_counts[v[1]] = req_counts.get(v[1], 0) + 1
        def med(idx):
            vals = [v[idx] for v in rows.values()]
            return statistics.median(vals)
        # hand-off: need hash for each num -> reverse hash_num
        num_hash = {v: k for k, v in hash_num.items()}
        handoffs = []
        for num, v in rows.items():
            h = num_hash.get(num)
            recv_t = per_node_recv_by_hash[n].get(h) if h else None
            if recv_t is None:
                continue
            started_at = v[0] - datetime.timedelta(milliseconds=v[7])  # ts - total_ms
            handoffs.append((started_at - recv_t).total_seconds() * 1000)
        ho_med = statistics.median(handoffs) if handoffs else None
        print(f"  node{n} leader_on={is_leader_count:3d}/{len(rows):3d} req={req_counts} "
              f"n={len(rows):3d} handoff={ho_med if ho_med is None else round(ho_med,1)} "
              f"recv={med(2):.1f} decode={med(3):.1f} senders={med(4):.1f} parent_wait={med(5):.1f} "
              f"check={med(6):.1f} total={med(7):.1f}")
        for num, v in rows.items():
            ranks_per_block.setdefault(num, []).append((n, v[7]))
    # gating rank: for each block, sort followers (exclude leader) by total_ms, find 4th smallest
    gate_ranks = []
    for num, lst in ranks_per_block.items():
        ld = leader_of.get(num)
        followers = sorted((tot, n) for (n, tot) in lst if n != ld)
        if len(followers) >= 4:
            gate_ranks.append(followers[3])  # 4th fastest (0-indexed 3)
    if gate_ranks:
        vals = [g[0] for g in gate_ranks]
        from collections import Counter
        who = Counter(g[1] for g in gate_ranks)
        print(f"  4th-fastest-follower total_ms: n={len(vals)} median={statistics.median(vals):.1f} mean={statistics.mean(vals):.1f}  which node gates (count): {dict(who)}")
    # convert_ms from 'direct' entries (new_payload legs only, mostly)
    for n in range(7):
        rows = [d for d in data[n]['direct'] if d[1] is not None and t_start <= d[0] < t_end and num_is_full(res, d[1])]
        if rows:
            conv = statistics.median(d[3] for d in rows)
            header_ms = statistics.median(d[4] for d in rows)
            print(f"  node{n} convert_ms={conv:.1f} header_ms={header_ms:.1f} (direct-import path, n={len(rows)})")
    # gap check: vote_road total - named parts, vs convert_ms+header_ms
    gaps = []
    for n in range(7):
        rows = per_node_by_num[n]
        direct_by_num = {d[1]: d for d in data[n]['direct'] if d[1] is not None}
        for num, v in rows.items():
            named = v[2] + v[3] + v[4] + v[5] + v[6]  # recv+decode+senders+parent_wait+check
            gap = v[7] - named
            extra = None
            d = direct_by_num.get(num)
            if d:
                extra = d[3] + d[4]  # convert_ms + header_ms
            gaps.append((n, num, gap, extra))
    if gaps:
        g = statistics.median(x[2] for x in gaps)
        ex = [x[3] for x in gaps if x[3] is not None]
        print(f"  vote_road total - named parts: median gap={g:.1f}ms  vs convert_ms+header_ms median={statistics.median(ex):.1f}ms (n={len(ex)})" if ex else f"  vote_road total - named parts: median gap={g:.1f}ms")

def num_is_full(res, num):
    txs = res['num_txs'].get(num)
    return txs is not None and txs >= 150000

if __name__ == '__main__':
    legs = sys.argv[1:] or ['bench-loop190Y0b','bench-loop190Y0c','bench-loop190Y1b','bench-loop190Y1c']
    all_res = {}
    for leg in legs:
        all_res[leg] = summarize(leg)
        if all_res[leg]:
            follower_breakdown(leg, all_res[leg])
        print()
