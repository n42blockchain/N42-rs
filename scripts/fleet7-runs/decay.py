#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""decay.py -- phase-by-phase cycle-growth analysis for a fleet7 bench leg.

Read-only. Single-threaded. Does not touch the repo or start any process.

Usage:
    python3 decay.py <bench_dir> <mem_file>

<bench_dir>  e.g. /data/blockchain/rust-fleet7-bench/bench-loop182P350a
             (node{0..6}-el.log, node{0..6}-v.log, flood.log, round.txt, cycles.txt)
<mem_file>   e.g. .../target/fleet-runs/mem-loop182P350a.txt
             (one line per 5s: el_rss, MemAvailable, Cached, Dirty, fleet_majflt,
             compact_stall, pgpgin -- local time, no date)

Splits the 90s of load (from the first full block, txs=163000) into three 30s
windows and reports the median/p90 of every numeric phase it can find, per
window, plus WARN/ERROR counts and a memory-sampler summary.
"""
import sys
import re
import glob
import statistics as st
from collections import defaultdict, Counter
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}\.\d+)Z')


def parse_ts(line):
    m = TS_RE.match(line)
    if not m:
        return None
    d, t = m.groups()
    return datetime.strptime(d + "T" + t, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


def read_stripped(path):
    with open(path, 'rb') as f:
        data = f.read().decode('utf-8', errors='replace')
    for line in data.split('\n'):
        if not line:
            continue
        yield ANSI_RE.sub('', line)


def kv_int(line, keys):
    out = {}
    for k in keys:
        m = re.search(r'\b' + re.escape(k) + r'=(-?\d+)\b', line)
        if m:
            out[k] = int(m.group(1))
    return out


def med(vals):
    return st.median(vals) if vals else None


def p90(vals):
    if not vals:
        return None
    s = sorted(vals)
    idx = min(len(s) - 1, int(round(0.9 * (len(s) - 1))))
    return s[idx]


def fmt(v):
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.1f}"
    return str(v)


BUILD_KEYS = ['setup_ms', 'par_ms', 'par_pull_ms', 'par_prep_ms', 'par_part_ms',
              'par_exec_ms', 'par_collect_ms', 'par_commit_ms', 'par_fold_ms',
              'tx_root_ms', 'parent_fields_ms', 'sealed_ms', 'sealed_at_ms',
              'merge_ms', 'state_ready_ms', 'roots_ms', 'finish_ms', 'total_ms']

IMPORT_KEYS = ['convert_ms', 'header_ms', 'senders_ms', 'exec_ms', 'checks_ms',
               'root_ms', 'hashed_ms', 'total_ms', 'senders_cached', 'state_ms',
               'carry_ms', 'mined_ms', 'insert_ms', 'engine_ms']

PARIMPORT_KEYS = ['partition_ms', 'groups_ms', 'merge_ms', 'finish_ms', 'groups']

OWNBLOCK_KEYS = ['handoff_ms', 'payload_ms', 'total_ms']

QMDB_KEYS = ['read_ms', 'total_ms', 'bytes']

QUEUE_KEYS = ['mined', 'queued', 'prune_ms']

INGEST_KEYS = ['frames', 'txs', 'rate', 'recover_ms_per_frame', 'pool_ms_per_frame',
               'recover_us_per_tx', 'busy_us_per_tx', 'slot_wait_us_per_tx',
               'slots_busy_pct', 'pool_us_per_tx', 'reply_us_per_frame',
               'gate_us_per_frame', 'chan_us_per_frame', 'acq_us_per_frame',
               'spawn_us_per_frame']

VOTESYNC_KEYS = ['vote', 'commit', 'sync_ms']

ENGSLOW_KEYS = ['took_ms', 'idle_before_ms']

CONSENSUS_RE = re.compile(
    r'block_hash=(0x[0-9a-f]+).*?consensus_timing=leader '
    r'proposal=@(\d+)ms R1_collect=(\d+)ms R2_collect=(\d+)ms total=(\d+)ms')


def normalize_msg(rest):
    s = re.sub(r'0x[0-9a-fA-F]+', 'HASH', rest)
    s = re.sub(r'\d+', 'N', s)
    return s.strip()[:140]


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    bench_dir, mem_file = sys.argv[1], sys.argv[2]

    el_logs = sorted(glob.glob(bench_dir.rstrip('/') + '/node*-el.log'))
    v_logs = sorted(glob.glob(bench_dir.rstrip('/') + '/node*-v.log'))

    # --- pass 0: hash -> txs map, from "Block added to canonical chain" (any node) ---
    hash_txs = {}
    canon_re = re.compile(r'Block added to canonical chain .*?hash=(0x[0-9a-f]+) .*?txs=(\d+)')
    for path in el_logs:
        for line in read_stripped(path):
            m = canon_re.search(line)
            if m:
                h, txs = m.group(1), int(m.group(2))
                hash_txs.setdefault(h, txs)

    # --- pass 1: find t0 = first full block (txs=163000) build or import line ---
    t0 = None
    start_re = re.compile(r'(seal-first build phases|direct import: executed here).*txs=(\d+)')
    for path in el_logs:
        for line in read_stripped(path):
            m = start_re.search(line)
            if m and int(m.group(2)) == 163000:
                ts = parse_ts(line)
                if ts and (t0 is None or ts < t0):
                    t0 = ts
                break  # first match per file is earliest in that file
    if t0 is None:
        print("no full (txs=163000) build/import line found -- cannot establish load start")
        sys.exit(1)

    win_bounds = [(t0, t0 + __import__('datetime').timedelta(seconds=30)),
                  (t0 + __import__('datetime').timedelta(seconds=30), t0 + __import__('datetime').timedelta(seconds=60)),
                  (t0 + __import__('datetime').timedelta(seconds=60), t0 + __import__('datetime').timedelta(seconds=90))]

    def win_of(ts):
        for i, (a, b) in enumerate(win_bounds):
            if a <= ts < b:
                return i
        return None

    # --- accumulators ---
    build = [defaultdict(list) for _ in range(3)]
    imp = [defaultdict(list) for _ in range(3)]
    parimp = [defaultdict(list) for _ in range(3)]
    ownblock = [defaultdict(list) for _ in range(3)]
    qmdb = [[] for _ in range(3)]
    queue = [defaultdict(list) for _ in range(3)]
    ingest = [defaultdict(list) for _ in range(3)]
    votesync = [defaultdict(list) for _ in range(3)]
    engslow = [[] for _ in range(3)]
    consensus = [defaultdict(list) for _ in range(3)]
    warns = [Counter() for _ in range(3)]

    def add_kv(acc_win, d):
        for k, v in d.items():
            acc_win[k].append(v)

    # --- pass 2: el.log lines ---
    for path in el_logs:
        for line in read_stripped(path):
            ts = parse_ts(line)
            if ts is None:
                continue
            w = win_of(ts)
            if w is None:
                continue

            if 'seal-first build phases' in line:
                txs_m = re.search(r'\btxs=(\d+)\b', line)
                if txs_m and int(txs_m.group(1)) == 163000:
                    add_kv(build[w], kv_int(line, BUILD_KEYS))

            elif 'direct import: executed here' in line and (
                    'handed to the engine as executed' in line or
                    "answered before the engine's own pass" in line):
                txs_m = re.search(r'\btxs=(\d+)\b', line)
                if txs_m and int(txs_m.group(1)) == 163000:
                    add_kv(imp[w], kv_int(line, IMPORT_KEYS))

            elif 'parallel import phases' in line:
                # only keep ones that line up with a full-block import (same window is enough,
                # groups>0 is a reasonable full-block proxy since empty blocks show groups=0)
                add_kv(parimp[w], kv_int(line, PARIMPORT_KEYS))

            elif 'own block imported by header' in line:
                add_kv(ownblock[w], kv_int(line, OWNBLOCK_KEYS))

            elif 'compacted the QMDB log into a new checkpoint' in line:
                d = kv_int(line, QMDB_KEYS)
                if 'total_ms' in d:
                    qmdb[w].append(d['total_ms'])

            elif 'canonical blocks pruned from the queue' in line:
                d = kv_int(line, QUEUE_KEYS)
                if d.get('mined') == 163000:
                    add_kv(queue[w], d)

            elif re.search(r'\bINFO ingest frames=', line):
                add_kv(ingest[w], kv_int(line, INGEST_KEYS))

            elif 'engine service loop: a slow branch' in line:
                d = kv_int(line, ENGSLOW_KEYS)
                if 'took_ms' in d:
                    engslow[w].append(d['took_ms'])

            if ' WARN ' in line or ' ERROR ' in line:
                msg = line.split('Z', 1)[1] if 'Z' in line else line
                msg = re.sub(r'^\s*(INFO|WARN|ERROR)\s*', '', msg)
                warns[w][normalize_msg(msg)] += 1

    # --- pass 3: v.log lines (already ANSI-stripped by read_stripped) ---
    for path in v_logs:
        for line in read_stripped(path):
            ts = parse_ts(line)
            if ts is None:
                continue
            w = win_of(ts)
            if w is None:
                continue

            m = CONSENSUS_RE.search(line)
            if m:
                h = m.group(1)
                if hash_txs.get(h) == 163000:
                    consensus[w]['proposal'].append(int(m.group(2)))
                    consensus[w]['R1_collect'].append(int(m.group(3)))
                    consensus[w]['R2_collect'].append(int(m.group(4)))
                    consensus[w]['total'].append(int(m.group(5)))

            if 'vote log sync was slow' in line:
                add_kv(votesync[w], kv_int(line, VOTESYNC_KEYS))

            if ' WARN ' in line or ' ERROR ' in line:
                msg = line.split('Z', 1)[1] if 'Z' in line else line
                msg = re.sub(r'^\s*(INFO|WARN|ERROR)\s*', '', msg)
                warns[w][normalize_msg(msg)] += 1

    # --- memory sampler ---
    mem_lines = []
    mem_re = re.compile(
        r'^(\d{2}:\d{2}:\d{2}) el_rss=([\d.]+)G .*?MemAvailable:([\d.]+)G Cached:([\d.]+)G '
        r'Dirty:([\d.]+)G.*?pgpgin=(\d+) fleet_majflt=(\d+) compact_stall=(\d+)')
    tz_ny = ZoneInfo('America/New_York') if ZoneInfo else None
    base_date = t0.date()
    for line in open(mem_file, encoding='utf-8', errors='replace'):
        m = mem_re.search(line)
        if not m:
            continue
        hms, el_rss, memavail, cached, dirty, pgpgin, majflt, cstall = m.groups()
        h, mi, s = (int(x) for x in hms.split(':'))
        local_dt = datetime(base_date.year, base_date.month, base_date.day, h, mi, s)
        if tz_ny:
            local_dt = local_dt.replace(tzinfo=tz_ny)
            utc_dt = local_dt.astimezone(timezone.utc)
        else:
            utc_dt = local_dt.replace(tzinfo=timezone.utc)  # fallback, likely wrong offset
        mem_lines.append((utc_dt, float(el_rss), float(memavail), float(cached),
                           float(dirty), int(pgpgin), int(majflt), int(cstall)))

    mem_win = [[] for _ in range(3)]
    for rec in mem_lines:
        w = win_of(rec[0])
        if w is not None:
            mem_win[w].append(rec)

    # ================= report =================
    print(f"bench_dir = {bench_dir}")
    print(f"mem_file  = {mem_file}")
    print(f"t0 (first full block, UTC) = {t0.isoformat()}")
    for i, (a, b) in enumerate(win_bounds):
        print(f"  w{i+1}: [{a.time()}, {b.time()})  UTC")
    print(f"hash->txs map size: {len(hash_txs)}")
    print()

    def report_group(name, data, keys=None):
        print(f"--- {name} ---")
        ks = keys or sorted({k for w in data for k in w.keys()})
        for k in ks:
            row = []
            for w in range(3):
                vals = data[w].get(k, [])
                row.append(f"n={len(vals)} med={fmt(med(vals))} p90={fmt(p90(vals))}")
            print(f"  {k:20s} w1[{row[0]}]  w2[{row[1]}]  w3[{row[2]}]")
        print()

    report_group("leader build (seal-first build phases, txs=163000)", build, BUILD_KEYS)
    report_group("follower import (direct import, txs=163000)", imp, IMPORT_KEYS)
    report_group("parallel import phases", parimp, PARIMPORT_KEYS)
    report_group("own block imported by header", ownblock, OWNBLOCK_KEYS)
    report_group("consensus (consensus_timing=leader, full blocks)", consensus,
                 ['proposal', 'R1_collect', 'R2_collect', 'total'])
    report_group("vote log sync was slow (sync_ms)", votesync, ['sync_ms'])
    report_group("ingest", ingest, INGEST_KEYS)
    report_group("tx queue (canonical blocks pruned from the queue, full blocks)", queue, QUEUE_KEYS)

    print("--- QMDB compaction total_ms (count, median, p90, max) ---")
    for w in range(3):
        vals = qmdb[w]
        print(f"  w{w+1}: n={len(vals)} med={fmt(med(vals))} p90={fmt(p90(vals))} max={fmt(max(vals) if vals else None)}")
    print()

    print("--- engine service loop slow-branch took_ms (count, median, p90, max) ---")
    for w in range(3):
        vals = engslow[w]
        print(f"  w{w+1}: n={len(vals)} med={fmt(med(vals))} p90={fmt(p90(vals))} max={fmt(max(vals) if vals else None)}")
    print()

    print("--- WARN/ERROR message counts per window ---")
    all_msgs = set()
    for w in warns:
        all_msgs |= set(w.keys())
    for msg in sorted(all_msgs):
        c = [warns[w][msg] for w in range(3)]
        if any(c):
            print(f"  w1={c[0]:3d} w2={c[1]:3d} w3={c[2]:3d}  {msg}")
    print()

    print("--- memory sampler per window ---")
    for w in range(3):
        recs = mem_win[w]
        if not recs:
            print(f"  w{w+1}: no samples")
            continue
        el_rss = [r[1] for r in recs]
        memavail = [r[2] for r in recs]
        cached = [r[3] for r in recs]
        dirty = [r[4] for r in recs]
        pgpgin = [r[5] for r in recs]
        majflt = [r[6] for r in recs]
        cstall = [r[7] for r in recs]
        print(f"  w{w+1}: n={len(recs)}  el_rss {el_rss[0]:.2f}G->{el_rss[-1]:.2f}G (d={el_rss[-1]-el_rss[0]:+.2f}G)  "
              f"MemAvailable min={min(memavail):.1f}G  Cached {cached[0]:.1f}->{cached[-1]:.1f}G  "
              f"Dirty min/max={min(dirty):.2f}/{max(dirty):.2f}G  "
              f"d_pgpgin={pgpgin[-1]-pgpgin[0]}  d_majflt={majflt[-1]-majflt[0]}  d_compact_stall={cstall[-1]-cstall[0]}")
    print()


if __name__ == '__main__':
    main()
