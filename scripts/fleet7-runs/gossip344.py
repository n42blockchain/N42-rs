#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop344 (docs 10.91): the gossip leg's body arrival to vote, and the transport's complaints. usage: gossip344.py <tag> ...
Per validator log of the leg (bench-<tag>/node<i>-v.log): for every block hash the time of `block body received` / `compact block body received` and of `sending vote to leader`;
the difference (ms) median / p90 / max over the validators that voted, and the number of blocks with a body line and no vote line. Then the count and the first lines of any log line
(validators and layer) matching yamux|buffer of stream|window|connection closed|ConnectionClosed|InvalidFrame|too large|exceeds|reject|timed out|Timeout certificate|TC formed."""
import glob, os, re, statistics as st, sys
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
ansi = re.compile(r'\x1b\[[0-9;]*m'); H = re.compile(r'0x[0-9a-f]{64}')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
pat = re.compile(r'yamux|buffer of stream|window|connection closed|ConnectionClosed|InvalidFrame|too large|exceeds|rejected|timed out|TC formed|stream reset', re.I)
for tag in sys.argv[1:]:
    d = []; nobody = 0; nodes = 0; hits = []
    for f in sorted(glob.glob(f'{B}/bench-{tag}/node*-v.log')):
        body, vote = {}, {}
        for l in open(f, errors='replace'):
            if 'block body received' in l or 'compact block body received' in l:
                l = ansi.sub('', l); m = H.search(l)
                if m and m[0] not in body: body[m[0]] = ts(l)
            elif 'sending vote to leader' in l:
                l = ansi.sub('', l); m = H.search(l)
                if m and m[0] not in vote: vote[m[0]] = ts(l)
            if pat.search(l) and 'block body received' not in l and 'sending vote' not in l: hits.append((os.path.basename(f), ansi.sub('', l.rstrip())[:240]))
        if body: nodes += 1
        for h, t in body.items():
            if h in vote: d.append((vote[h] - t) * 1e3)
            else: nobody += 1
    print(f'== {tag}: {nodes} validators logged bodies; body arrival -> vote: n {len(d)}, median {st.median(d) if d else float("nan"):.1f} ms, p90 {sorted(d)[int(len(d) * .9)] if d else float("nan"):.1f}, max {max(d or [0]):.1f}; bodies without a vote line {nobody}')
    pats = {}
    for fn, l in hits:
        k = re.sub(r'0x[0-9a-f]+|\d+', 'N', l)[40:140]; pats.setdefault(k, [0, fn, l]); pats[k][0] += 1
    print(f'   transport / timeout lines: {len(hits)} in {len(pats)} distinct shapes' + ('' if hits else ' (none)'))
    for k, (n, fn, l) in sorted(pats.items(), key=lambda x: -x[1][0])[:6]: print(f'     x{n} {fn}: {l[:200]}')
    el = f'{B}/bench-{tag}/node0-el.log'
    if os.path.exists(el):
        c = sum(1 for l in open(el, errors='replace') if re.search(r'yamux|buffer of stream|connection closed', l, re.I)); print(f'   layer log yamux/closed lines: {c}')
