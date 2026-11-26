#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""CPU per thread name of a process over an interval (/proc only; for hosts
where perf is not allowed). docs/EXPLORER_RPC_PERF.md.

  explorer-threads.py <pid> <seconds>
"""
import os
import re
import sys
import time
from collections import defaultdict


def sample(pid):
    out = {}
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            with open(f"/proc/{pid}/task/{tid}/stat") as f:
                raw = f.read()
        except OSError:
            continue
        name = raw[raw.index("(") + 1: raw.rindex(")")]
        parts = raw[raw.rindex(")") + 2:].split()
        out[tid] = (name, int(parts[11]) + int(parts[12]))
    return out


def main():
    pid, secs = int(sys.argv[1]), float(sys.argv[2])
    tick = os.sysconf("SC_CLK_TCK")
    a = sample(pid)
    time.sleep(secs)
    b = sample(pid)
    groups = defaultdict(lambda: [0.0, 0])
    for tid, (name, t) in b.items():
        key = re.sub(r"[-_ ]?\d+$", "", name)
        groups[key][0] += (t - a.get(tid, (name, 0))[1]) / tick / secs
        groups[key][1] += 1
    total = sum(v[0] for v in groups.values())
    print(f"total {total:.2f} cores over {secs:.0f} s")
    for k, (cores, n) in sorted(groups.items(), key=lambda x: -x[1][0])[:12]:
        if cores >= 0.05:
            print(f"  {k:<24} {cores:7.2f} cores  ({n} threads)")


if __name__ == "__main__":
    main()
