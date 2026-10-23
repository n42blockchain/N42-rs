#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2017-2025 N42 Contributors
"""Charge major-fault samples to the memory mapping they hit.

Input is the output of `perf record -e major-faults -c 1 -d` (read through
`perf script -F comm,tid,addr`) plus a copy of /proc/<pid>/maps taken at the
same time. Each sample's data address is looked up in the sorted mappings and
counted per mapping, per file path and per command name.

Usage:
  majfmap.py <perf.data> <maps.txt> [--script-file <file>] [--top N]
"""
import argparse
import bisect
import subprocess
import sys
from collections import Counter, defaultdict

UNMAPPED = "<unmapped>"


def parse_maps(path):
    """Return a list of (start, end, perms, path) sorted by start."""
    out = []
    with open(path) as f:
        for line in f:
            parts = line.split(None, 5)
            if len(parts) < 5 or "-" not in parts[0]:
                continue
            try:
                s, e = (int(x, 16) for x in parts[0].split("-"))
            except ValueError:
                continue
            name = parts[5].strip() if len(parts) > 5 else ""
            out.append((s, e, parts[1], name or "[anon]"))
    out.sort()
    return out


def parse_samples(lines):
    """Yield (comm, addr); tolerate junk lines. Last two fields: tid, addr."""
    for line in lines:
        f = line.split()
        if len(f) < 3:
            continue
        try:
            int(f[-2])
            addr = int(f[-1], 16)
        except ValueError:
            continue
        yield " ".join(f[:-2]), addr


def table(title, header, rows):
    print("\n" + title)
    print("  ".join(header))
    for r in rows:
        print("  ".join(str(c) for c in r))


def fmt_top(counter, n):
    return ", ".join(f"{k}={v}" for k, v in counter.most_common(n))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("perf_data")
    ap.add_argument("maps")
    ap.add_argument("--script-file")
    ap.add_argument("--top", type=int, default=25)
    a = ap.parse_args()

    maps = parse_maps(a.maps)
    starts = [m[0] for m in maps]
    if a.script_file:
        with open(a.script_file) as f:
            lines = f.read().splitlines()
    else:
        r = subprocess.run(
            ["perf", "script", "-i", a.perf_data, "-F", "comm,tid,addr"],
            capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("perf script failed: " + r.stderr.strip())
        lines = r.stdout.splitlines()

    by_map = Counter()                    # mapping index (or -1) -> count
    map_comm = defaultdict(Counter)       # mapping index -> comm counts
    by_comm = Counter()
    comm_map = defaultdict(Counter)       # comm -> mapping index counts
    total = 0
    for comm, addr in parse_samples(lines):
        i = bisect.bisect_right(starts, addr) - 1
        k = i if i >= 0 and addr < maps[i][1] else -1
        by_map[k] += 1
        map_comm[k][comm] += 1
        by_comm[comm] += 1
        comm_map[comm][k] += 1
        total += 1

    def label(k):
        if k < 0:
            return UNMAPPED
        s, e, p, n = maps[k]
        return f"{s:x}-{e:x} {n}"

    def pct(c):
        return f"{100.0 * c / total:.1f}%" if total else "0%"

    print(f"total samples: {total}")
    rows = []
    for k, c in by_map.most_common(a.top):
        if k < 0:
            rows.append((c, pct(c), "-", "-", UNMAPPED, ""))
        else:
            s, e, p, n = maps[k]
            rows.append((c, pct(c), p, f"{(e - s) / 1048576:.1f}MiB", n,
                         fmt_top(map_comm[k], 3)))
    table("by mapping:", ("count", "pct", "perms", "size", "path",
                          "top comms"), rows)

    rows = [(c, pct(c), cm, fmt_top(Counter({label(k): v for k, v in
                                             comm_map[cm].items()}), 2))
            for cm, c in by_comm.most_common(a.top)]
    table("by comm:", ("count", "pct", "comm", "top mappings"), rows)

    by_path = Counter()
    for k, c in by_map.items():
        by_path[UNMAPPED if k < 0 else maps[k][3]] += c
    table("by path:", ("count", "pct", "path"),
          [(c, pct(c), p) for p, c in by_path.most_common(a.top)])


if __name__ == "__main__":
    main()
