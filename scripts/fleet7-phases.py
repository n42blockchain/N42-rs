#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Where a block's cycle goes, from the fleet's own logs.

    fleet7-phases.py [fleet root]

Every phase of a full block, measured across all seven nodes and paired by block
hash, so the cycle is accounted for rather than left with a residual. A residual
collects every error in the terms above it: the first version of this analysis
attributed 173 ms to block-body propagation by subtraction, and measuring it
directly said 27.8 ms.

Full and empty blocks are reported separately because they differ by two orders
of magnitude and a combined median describes neither.

RUN THIS AT THE END OF A ROUND, and compare only whole rounds with whole rounds.
Sampled after window 2 one round's body p99 is 2.7 s; sampled over the whole of
the same round it is 39.8 s, because the last window is where supply runs out
and the stalls come back. Two samples covering different parts of a round put in
one table is a comparison of nothing, and it has been made twice here.
"""

import datetime
import glob
import re
import sys
from collections import defaultdict

ROOT = sys.argv[1] if len(sys.argv) > 1 else '/data/blockchain/rust-fleet7-bench'
CLEAN = re.compile(r'\x1b\[[0-9;]*m')
STAMP = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+)Z')
HASH = re.compile(r'(?:decide\.)?block_hash="?(0x[0-9a-f]+)"?')
BYTES = re.compile(r'bytes=(\d+)')
GAS = re.compile(r'gas_used=([\d.]+)([KMG])gas')
UNIT = {'K': 1e3, 'M': 1e6, 'G': 1e9}
# A body over half a megabyte is a full block of this tier; the empty ones are
# a couple of hundred bytes.
BIG_BODY = 500_000
BIG_GAS = 400e6


def stamp(line):
    m = STAMP.match(line)
    return datetime.datetime.fromisoformat(m.group(1)) if m else None


def report(name, samples, unit='ms'):
    if not samples:
        print(f'{name:38} no samples')
        return
    v = sorted(samples)
    n = len(v)
    print(
        f'{name:38} n={n:5} median={v[n // 2]:8.1f}{unit} '
        f'p90={v[int(n * 0.9)]:9.1f}{unit} p99={v[min(int(n * 0.99), n - 1)]:9.1f}{unit} '
        f'max={v[-1]:9.1f}{unit}'
    )


def main():
    published = {}
    received = defaultdict(list)
    leader_gap, barrier, quorum = [], [], []

    for path in sorted(glob.glob(f'{ROOT}/node*/v.log')):
        commit = None
        seen, voted = {}, {}
        for raw in open(path, errors='ignore'):
            line = CLEAN.sub('', raw)
            ts = stamp(line)
            if ts is None:
                continue
            h = HASH.search(line)
            key = h.group(1) if h else None
            if 'received Decide, committing block' in line:
                commit = ts
                if key and key in voted:
                    quorum.append((ts - voted[key]).total_seconds() * 1000)
            elif 'published block body' in line:
                size = int(BYTES.search(line).group(1)) if BYTES.search(line) else 0
                if key:
                    published[key] = (ts, size)
                if commit is not None and size > BIG_BODY:
                    gap = (ts - commit).total_seconds() * 1000
                    if 0 < gap < 30_000:
                        leader_gap.append(gap)
                commit = None
            elif 'block body received' in line and key:
                received[key].append((ts, path))
            elif key and 'waiting for execution validation' in line:
                seen.setdefault(key, ts)
            elif key and 'sending vote to leader' in line:
                voted[key] = ts
                if key in seen:
                    barrier.append((ts - seen[key]).total_seconds() * 1000)

    # The FIRST receipt per node, not every receipt.
    #
    # A body is delivered twice to some nodes, about fifty-eight seconds apart —
    # 56 of 1,259 (node, block) pairs in one round — and counting the second copy
    # as an arrival latency put a p90 of 57 seconds on a path whose real
    # distribution is 65% under a tenth of a second. That artefact was almost
    # published as a finding about slow gossip. A re-delivery is worth knowing
    # about, but it is not how long the body took to arrive.
    body_full, body_small = [], []
    for h, (t0, size) in published.items():
        arrivals = received.get(h, [])
        by_first = {}
        for t1, node in arrivals:
            if node not in by_first or t1 < by_first[node]:
                by_first[node] = t1
        for t1 in by_first.values():
            ms = (t1 - t0).total_seconds() * 1000
            if ms >= 0:
                (body_full if size > BIG_BODY else body_small).append(ms)

    build, imported = [], []
    for path in sorted(glob.glob(f'{ROOT}/node*/el.log')):
        job = recv = job_gap = None
        for raw in open(path, errors='ignore'):
            line = CLEAN.sub('', raw)
            ts = stamp(line)
            if ts is None:
                continue
            if 'New payload job created' in line:
                job = ts
            elif 'Received new payload' in line:
                recv = ts
                if job is not None:
                    job_gap = (ts - job).total_seconds() * 1000
                    job = None
            elif 'Block added to canonical chain' in line and recv is not None:
                g = GAS.search(line)
                gas = float(g.group(1)) * UNIT[g.group(2)] if g else 0
                if gas > BIG_GAS:
                    imported.append((ts - recv).total_seconds() * 1000)
                    if job_gap is not None:
                        build.append(job_gap)
                recv = job_gap = None

    print(f'--- full blocks ({ROOT}) ---')
    report('leader: commit -> body published', leader_gap)
    report('leader: payload build', build)
    report('body: published -> received', body_full)
    report('follower: import barrier', barrier)
    report('follower: payload -> canonical', imported)
    report('vote -> Decide', quorum)
    print()
    report('body: published -> received (small)', body_small)


if __name__ == '__main__':
    main()
