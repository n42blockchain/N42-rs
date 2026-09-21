#!/usr/bin/env python3
"""What the quorum actually waits for, per block.

`fleet7-phases.py` reports the median import barrier across all the
validators. A quorum certificate needs `n - f` votes with `f = (n - 1) / 3` --
five of seven, three of four -- so the leader waits for the **quorum-th** vote,
not the median one, and the `f` slowest importers do not hold the chain up at
all. Round 43 showed why that distinction matters: a leg whose median barrier
was 577 ms read the same 0.652 s cycle as one whose median was 480, which the
median cannot explain.

For every block hash this prints, across the fleet:

    votes      how many validators voted at all
    quorum-th  that vote's delay after the validator saw the block
               (`waiting for execution validation` -> `sending vote to leader`)
    median     the same delay at the median validator, for comparison
    slowest    the last one, which the chain never waits for

Usage: fleet7-quorum.py [fleet root or an archived round directory] [quorum]

The quorum is not a constant. Given neither it nor F7_NODES, it is computed
from the number of `node<i>` log files found, which is what the fleet's size
actually was. A four-node leg read with a quorum of five reports "no block
reached 5 votes" -- correct and useless -- and a seven-node leg read with
three reports a vote the chain never waited for.
"""

import datetime
import glob
import os
import re
import statistics
import sys

CLEAN = re.compile(r'\x1b\[[0-9;]*m')
STAMP = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+)Z')
HASH = re.compile(r'\b([0-9a-fx]{10,66})\b')

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
    'F7_ROOT', '/data/blockchain/rust-fleet7-bench')


def stamp(line):
    m = STAMP.match(line)
    return datetime.datetime.fromisoformat(m.group(1)) if m else None


def main():
    # block hash -> list of one delay per validator that voted
    delays = {}
    # The live fleet keeps `node<i>/v.log`; an archived round keeps
    # `node<i>-v.log` beside its round.txt. Read whichever is there.
    paths = sorted(glob.glob(f'{ROOT}/node*/v.log')) or sorted(glob.glob(f'{ROOT}/node*-v.log'))
    # The fleet's size, and from it the quorum: the argument first, then
    # F7_NODES, then the logs that are actually there.
    nodes = int(os.environ.get('F7_NODES', 0)) or len(paths)
    if not nodes:
        print(f'no node*/v.log under {ROOT}')
        return 1
    quorum = int(sys.argv[2]) if len(sys.argv) > 2 else nodes - (nodes - 1) // 3
    for path in paths:
        seen = {}
        for raw in open(path, errors='ignore'):
            line = CLEAN.sub('', raw)
            ts = stamp(line)
            if ts is None:
                continue
            h = HASH.search(line)
            key = h.group(1) if h else None
            if key is None:
                continue
            if 'waiting for execution validation' in line:
                seen.setdefault(key, ts)
            elif 'sending vote to leader' in line and key in seen:
                delays.setdefault(key, []).append((ts - seen.pop(key)).total_seconds() * 1000)

    full = [sorted(v) for v in delays.values() if len(v) >= quorum]
    if not full:
        print(f'no block reached {quorum} votes in {ROOT}')
        return 1

    def report(name, values):
        values = sorted(values)
        n = len(values)
        print(
            f'{name:<28} n={n:>5} median={statistics.median(values):>8.1f}ms '
            f'p90={values[int(n * 0.9)]:>8.1f}ms p99={values[min(n - 1, int(n * 0.99))]:>8.1f}ms '
            f'max={values[-1]:>8.1f}ms'
        )

    print(f'--- votes per block, quorum {quorum} of {nodes} ({ROOT}) ---')
    print(f'blocks with at least {quorum} votes: {len(full)}')
    report(f'the {quorum}th vote (the quorum)', [v[quorum - 1] for v in full])
    report('the median validator', [statistics.median(v) for v in full])
    report('the slowest validator', [v[-1] for v in full])
    report('the fastest validator', [v[0] for v in full])
    spread = [v[-1] - v[quorum - 1] for v in full]
    report('slowest minus quorum', spread)
    return 0


if __name__ == '__main__':
    sys.exit(main())
