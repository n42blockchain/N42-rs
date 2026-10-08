#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop347 (docs/E1_MANY_KEYS.md): the validator processes' CPU, RSS, threads and libp2p connections.

    valsample347.py sample <out.tsv> [seconds=150] [interval=5]   append samples until the time is up
    valsample347.py report <out.tsv>                              one summary line a metric

Every `interval` seconds, for each process whose command line is the h2_validator of the fleet under F7_ROOT:
    <epoch> val <index> <cpu_ticks> <rss_kb> <threads>
and every sixth sample the connection census, read from /proc/net/tcp{,6}: an ESTABLISHED loopback socket
whose remote port is a validator's listen port is the dialling end of one connection, so their count is the
number of connections; per process, the sockets it owns (/proc/<pid>/fd) on either end:
    <epoch> conn <total connections> <min per process> <median> <max> <processes>
CPU is cumulative ticks of the whole process (all threads); the report differences first and last."""
import os, re, sys, time, statistics as st

ROOT = os.environ.get('F7_ROOT', '/data/blockchain/rust-fleet7-bench')
P2P_BASE = int(os.environ.get('F7_P2P_BASE', '19000'))
TICK = os.sysconf('SC_CLK_TCK')


def validators():
    out = {}
    for p in os.listdir('/proc'):
        if not p.isdigit():
            continue
        try:
            c = open(f'/proc/{p}/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace')
        except OSError:
            continue
        if 'h2_validator' in c and f'{ROOT}/' in c:
            m = re.search(r'--index (\d+)', c)
            if m:
                out[int(m[1])] = int(p)
    return out


def stat_of(pid):
    try:
        f = open(f'/proc/{pid}/stat').read()
        rest = f[f.rindex(')') + 2:].split()
        ticks = int(rest[11]) + int(rest[12])  # utime + stime
        threads = int(rest[17])
        rss = int(re.search(r'VmRSS:\s+(\d+)', open(f'/proc/{pid}/status').read())[1])
        return ticks, rss, threads
    except (OSError, ValueError, TypeError, IndexError):
        return None


def sockets(n):
    """inode -> (local port, remote port) of the ESTABLISHED sockets on the validators' ports."""
    ports = range(P2P_BASE, P2P_BASE + n)
    out = {}
    for fn in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            lines = open(fn).read().splitlines()[1:]
        except OSError:
            continue
        for l in lines:
            f = l.split()
            if f[3] != '01':
                continue
            lp, rp = int(f[1].rsplit(':', 1)[1], 16), int(f[2].rsplit(':', 1)[1], 16)
            if lp in ports or rp in ports:
                out[int(f[9])] = (lp, rp)
    return out


def census(vals):
    socks = sockets(len(vals))
    ports = range(P2P_BASE, P2P_BASE + len(vals))
    total = sum(1 for lp, rp in socks.values() if rp in ports)
    per = []
    for idx, pid in sorted(vals.items()):
        n = 0
        try:
            for fd in os.listdir(f'/proc/{pid}/fd'):
                try:
                    t = os.readlink(f'/proc/{pid}/fd/{fd}')
                except OSError:
                    continue
                if t.startswith('socket:[') and int(t[8:-1]) in socks:
                    n += 1
        except OSError:
            pass
        per.append(n)
    return total, per


def sample(out, secs, every):
    end = time.time() + secs
    k = 0
    with open(out, 'a', buffering=1) as f:
        while time.time() < end:
            t0 = time.time()
            vals = validators()
            for idx, pid in sorted(vals.items()):
                s = stat_of(pid)
                if s:
                    f.write(f'{t0:.1f}\tval\t{idx}\t{s[0]}\t{s[1]}\t{s[2]}\n')
            if k % 6 == 0 and vals:
                total, per = census(vals)
                per = sorted(per)
                f.write(f'{t0:.1f}\tconn\t{total}\t{per[0]}\t{per[len(per) // 2]}\t{per[-1]}\t{len(per)}\n')
            k += 1
            time.sleep(max(0.0, every - (time.time() - t0)))


def report(path):
    first, last, rss, thr = {}, {}, {}, {}
    conns = []
    for l in open(path):
        f = l.rstrip('\n').split('\t')
        if len(f) < 6:
            continue
        if f[1] == 'val':
            i, t = int(f[2]), float(f[0])
            first.setdefault(i, (t, int(f[3])))
            last[i] = (t, int(f[3]))
            rss.setdefault(i, []).append(int(f[4]) / 1e6)
            thr[i] = int(f[5])
        elif f[1] == 'conn':
            conns.append(tuple(int(x) for x in f[2:7]))
    if not first:
        print('valsample347: no samples')
        return
    cores = {i: (last[i][1] - first[i][1]) / TICK / max(1e-9, last[i][0] - first[i][0]) for i in first}
    tot = sum(cores.values())
    peak_rss = [max(v) for v in rss.values()]
    # the sum of RSS at each sample time is approximated by the sum of per-process peaks (an upper bound)
    print(f'validators n={len(cores)}: cpu total {tot:.2f} cores, per key mean {tot / len(cores):.3f} '
          f'median {st.median(cores.values()):.3f} max {max(cores.values()):.3f} (key {max(cores, key=cores.get)}) min {min(cores.values()):.3f}; '
          f'rss per key peak mean {st.mean(peak_rss):.3f} max {max(peak_rss):.3f} G, sum of peaks {sum(peak_rss):.1f} G; '
          f'threads per key mean {st.mean(thr.values()):.0f}, total {sum(thr.values())}')
    if conns:
        c = conns[-1]
        print(f'libp2p connections (last census of {len(conns)}): {c[0]} in all (a full mesh of {c[4]} is {c[4] * (c[4] - 1) // 2}); '
              f'sockets per process min {c[1]} median {c[2]} max {c[3]}')


if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'sample':
        sample(sys.argv[2], float(sys.argv[3]) if len(sys.argv) > 3 else 150, float(sys.argv[4]) if len(sys.argv) > 4 else 5)
    elif len(sys.argv) == 3 and sys.argv[1] == 'report':
        report(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)
