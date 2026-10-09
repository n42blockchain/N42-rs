#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop350 (docs/E1_MANY_KEYS.md section 6): what a many-key leg adds to the ordinary report. usage: manykeys350.py <tag> [<valsample file>]

From bench-<tag>/node*-v.log (ANSI stripped), N and the quorum from the number of logs (q = N - (N-1)//3):

 1. The leader's `block committed!` lines: R1_collect / R2_collect / total (proposal to prepare QC, to commit QC, to commit) and the
    vote counts `votes=a+b` at the moment each QC formed.
 2. Vote collection per view, from the TRACED validators' `n42.h2.trace: recv kind="vote"` lines (fleet7.sh: F7_TRACE_VALIDATOR=0,1,2): for each
    view the traced validator proposed (`proposal sent view=V`): proposal -> first vote, first vote -> quorum (the (q-1)-th vote received; the
    leader's own is not received), quorum -> last vote, and proposal -> last vote (the slowest key's delay), then the same for `commit_vote`.
    The trace line names no voter, so "the slowest key" is the last arrival, not a key index; a `voter=` field on the line would name it.
    Votes still missing when the next view's proposal goes out are counted (`missing`).
 3. The straggler rule: the interval between the leader's consecutive proposals, and how many are >= 500 ms (a grace that ran out is 600 ms
    from the commit QC); `slow step` lines on the leaders (transport_ms + flush_ms > 30: the loop that polls the swarm, verifies votes and
    drives the engine was away from its queues that long) with the slowest handled event's kind.
 4. Gossip propagation: proposal sent (leader) -> `recv kind="proposal"` at each traced follower. Hop counts are not logged by
    gossipsub; the delay is the proxy.
 5. With a valsample350.py file: validators' CPU, RSS, threads and the libp2p connection count.
There is no field for the leader's vote-verification time: it is inside `transport_ms` / `handle_ms` of the `slow step` lines and the
R1/R2 collect times; docs/E1_MANY_KEYS.md names the field a code change should add (`verify_us`, `verify_count` on `block committed!`)."""
import glob, os, re, statistics as st, sys
from datetime import datetime, timezone

B = os.environ.get('F7_BENCH_ROOT', '/data/blockchain/rust-fleet7-bench')
ansi = re.compile(r'\x1b\[[0-9;]*m')


def ts(l):
    return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()


def pct(x, q):
    x = sorted(x)
    return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')


def dist(name, x, unit='ms'):
    if not x:
        return f'  {name}: none'
    return f'  {name}: n={len(x)} p50 {st.median(x):.1f} p90 {pct(x, .9):.1f} p99 {pct(x, .99):.1f} max {max(x):.1f} {unit}'


def main(tag, vs=None):
    leg = f'{B}/bench-{tag}'
    logs = sorted(glob.glob(f'{leg}/node*-v.log'), key=lambda p: int(re.search(r'node(\d+)-v', p)[1]))
    n = len(logs)
    q = n - (n - 1) // 3
    print(f'== {tag}: {n} validator logs, f={(n - 1) // 3}, quorum {q}')
    prop, commits, r1, r2, tot, v1, v2, slow = {}, [], [], [], [], [], [], []
    recv = {}   # (view, kind) -> {file: [times]}
    sent_at = {}
    traced = set()
    keys = ('n42.h2.trace', 'proposal sent', 'block committed!', 'slow step')
    vf = {k: [] for k in ('verify_us', 'verify_n', 'verify_batches', 'verify_fallbacks', 'inbound_queue_max', 'gossip_poll_us')}
    fq = {}   # file -> last cumulative straggler_waits, direct counters
    sw_us, views_led = [], {}
    for f in logs:
        for l in open(f, errors='replace'):
            if not any(k in l for k in keys):
                continue
            l = ansi.sub('', l)
            if 'n42.h2.trace:' in l:
                m = re.search(r'n42\.h2\.trace: (recv|send)\b.*?kind="?(\w+)"?.*?view=(\d+)', l) \
                    or re.search(r'n42\.h2\.trace: (recv|send)\b.*?view=(\d+).*?kind="?(\w+)"?', l)
                if m:
                    g = m.groups()
                    if g[0] == 'recv':
                        kind, view = (g[1], int(g[2])) if g[2].isdigit() else (g[2], int(g[1]))
                        recv.setdefault((view, kind), {}).setdefault(f, []).append(ts(l))
                        traced.add(f)
            elif 'proposal sent' in l:
                for k, pat in (('w', r'straggler_waits=(\d+)'), ('dr', r'direct_received=(\d+)'), ('dd', r'direct_duplicates=(\d+)'),
                               ('ds', r'direct_sent=(\d+)'), ('df', r'direct_fallbacks=(\d+)')):
                    mm = re.search(pat, l)
                    if mm:
                        fq.setdefault(f, {})[k] = int(mm[1])
                mm = re.search(r'straggler_wait_us=(\d+)', l)
                if mm:
                    sw_us.append(int(mm[1]))
                views_led[f] = views_led.get(f, 0) + 1
                m = re.search(r'proposal sent view=(\d+)', l)
                if m:
                    prop[int(m[1])] = (ts(l), f)
            elif 'block committed!' in l:
                for k in vf:
                    mm = re.search(k + r'=(\d+)', l)
                    if mm:
                        vf[k].append(int(mm[1]))
                m = re.search(r'R1_collect=(\d+)ms R2_collect=(\d+)ms total=(\d+)ms votes=(\d+)\+(\d+)', l)
                if m:
                    r1.append(int(m[1])); r2.append(int(m[2])); tot.append(int(m[3])); v1.append(int(m[4])); v2.append(int(m[5]))
            elif 'slow step' in l:
                m = re.search(r'transport_ms=(\d+) transport_events=(\d+) poll_ms=(\d+) handle_ms=(\d+) slowest_ms=(\d+) slowest_kind="?(\w*)"? outputs_ms=(\d+) flush_ms=(\d+)', l)
                if m:
                    slow.append((f, int(m[1]), int(m[4]), int(m[5]), m[6], int(m[8])))
    print('1. the leaders\' commit lines')
    print(dist('R1_collect (proposal -> prepare QC)', r1) + '')
    print(dist('R2_collect (prepare QC -> commit QC)', r2))
    print(dist('total (proposal -> commit)', tot))
    if v1:
        print(f'  votes at formation: R1 median {st.median(v1):.0f} max {max(v1)} (quorum {q}); R2 median {st.median(v2):.0f} max {max(v2)}')
    print('2. vote collection at the traced leaders (first vote -> quorum -> last vote)')
    if not recv:
        print('  no trace lines: the leg ran without F7_TRACE_VALIDATOR')
    for kind, label in (('vote', 'R1'), ('commit_vote', 'R2')):
        a, b, c, d, e, miss, nv = [], [], [], [], [], 0, 0
        for view, (tp, f) in prop.items():
            times = sorted(recv.get((view, kind), {}).get(f, []))
            if not times or f not in traced:
                continue
            nv += 1
            first, last = times[0], times[-1]
            quorum = times[q - 2] if len(times) >= q - 1 else None
            a.append((first - tp) * 1e3)
            if quorum is not None:
                b.append((quorum - first) * 1e3)
                c.append((last - quorum) * 1e3)
            d.append((last - tp) * 1e3)
            if len(times) < n - 1:
                miss += 1
        print(f' {label} ({kind}), {nv} views:')
        print(dist('  proposal -> first vote', a)); print(dist('  first vote -> quorum', b)); print(dist('  quorum -> last vote', c))
        print(dist('  proposal -> last vote (the slowest key)', d)); print(f'   views with fewer than {n - 1} votes received: {miss}')
    print('3. the straggler rule and the loop')
    views = sorted(prop)
    iv = [(prop[b][0] - prop[a][0]) * 1e3 for a, b in zip(views, views[1:]) if b == a + 1 and prop[a][1] == prop[b][1]]
    print(dist('proposal interval (same leader, consecutive views)', iv) + f'; >= 500 ms: {sum(1 for x in iv if x >= 500)}')
    if slow:
        by = {}
        for f, tm, hm, sm, kind, fl in slow:
            by.setdefault(kind or '-', []).append(tm + fl)
        print(f'  `slow step` lines: {len(slow)} (transport+flush > 30 ms); by slowest event kind: ' +
              ', '.join(f'{k}: {len(v)} (max {max(v)} ms)' for k, v in sorted(by.items(), key=lambda kv: -len(kv[1]))[:5]))
        print(f'  leaders\' lines: {sum(1 for s in slow if os.path.basename(s[0]) in {os.path.basename(p[1]) for p in prop.values()})}')
    else:
        print('  no `slow step` lines')
    print('4. gossip propagation (proposal sent -> received at a traced follower)')
    dl = []
    for view, (tp, f) in prop.items():
        for g, times in recv.get((view, 'proposal'), {}).items():
            if g != f:
                dl.append((min(times) - tp) * 1e3)
    print(dist('  proposal arrival delay', dl) if dl else '  no trace lines')
    print('4b. the new fields (docs/E1_MANY_KEYS.md section 6), leaders\' `block committed!` and `proposal sent` lines')
    for k in vf:
        x = vf[k]
        print(dist('  ' + k, [float(v) for v in x], 'us' if k.endswith('_us') else '') if x and k != 'verify_fallbacks' else
              (f'  verify_fallbacks: total {sum(x)} over {len(x)} blocks' if x else f'  {k}: none'))
    if fq:
        tw = sum(v.get('w', 0) for v in fq.values())
        nz = [x for x in sw_us if x > 0]
        print(f'  straggler_waits (cumulative per leader log, summed over {len(fq)} leaders): {tw}; waits with straggler_wait_us > 0: {len(nz)} of {len(sw_us)} proposals, '
              + (f'p50 {st.median(nz) / 1e3:.1f} p90 {pct(nz, .9) / 1e3:.1f} max {max(nz) / 1e3:.1f} ms, total {sum(nz) / 1e6:.2f} s' if nz else 'none'))
        dr = sum(v.get('dr', 0) for v in fq.values()); dd = sum(v.get('dd', 0) for v in fq.values())
        ds = sum(v.get('ds', 0) for v in fq.values()); df = sum(v.get('df', 0) for v in fq.values())
        led = sum(views_led.values())
        exp = led * 2 * (n - 1)
        print(f'  direct votes at the leaders: received {dr} (duplicates dropped {dd}); sent by those nodes {ds}, fallbacks to gossip {df}; '
              f'leaders led {led} views = {exp} vote messages expected (2 rounds x {n - 1}); direct share of those {100 * dr / exp if exp else 0:.1f}%')
    print('5. validators')
    if vs and os.path.exists(vs):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import valsample350
        valsample350.report(vs)
    else:
        print('  no valsample file')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
