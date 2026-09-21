#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Read jemalloc (jeprof) heap dumps without symbolising the whole binary.

Usage:
  heap-read.py totals  <dir> <pid>                 # adjusted in-use per dump, ordered by mtime
  heap-read.py top     <dump> [--base <dump>] [-n N] [--min-pct P]
  heap-read.py syms    <binary> <dump> [--base <dump>] [-n N]
  heap-read.py groups  <binary> <dump> [<dump> ...]   # subsystem split per dump

Applies jeprof's sampling correction (heap_v2/<rate>): for a trace with n objects
and b bytes, scale = 1/(1-exp(-(b/n)/rate)).  `top`/`syms` print per-stack totals;
`syms` resolves the frames with one batched addr2line call.
"""
import sys, os, math, subprocess, collections

def parse(path):
    rate = None
    traces = []   # (count, bytes, [addrs])
    with open(path, 'r', errors='replace') as fh:
        cur = None
        for line in fh:
            if line.startswith('heap_v2/'):
                rate = int(line.strip().split('/')[1]); continue
            if line.startswith('MAPPED_LIBRARIES'): break
            if line.startswith('@'):
                cur = [int(x, 16) for x in line.split()[1:]]; continue
            s = line.strip()
            if s.startswith('t*:') and cur is not None:
                p = s.split(':')
                n = int(p[1]); b = int(p[2].split('[')[0])
                traces.append((n, b, tuple(cur))); cur = None
    return rate, traces

def adjust(n, b, rate):
    if n == 0 or b == 0: return 0.0, 0.0
    ratio = (b / n) / rate
    if ratio > 40: return float(n), float(b)
    scale = 1.0 / (1.0 - math.exp(-ratio))
    return n * scale, b * scale

def agg(path):
    rate, traces = parse(path)
    out = collections.defaultdict(lambda: [0.0, 0.0])
    for n, b, st in traces:
        an, ab = adjust(n, b, rate)
        out[st][0] += an; out[st][1] += ab
    return out

def gib(x): return x / (1 << 30)

def cmd_totals(d, pid):
    fs = [f for f in os.listdir(d) if f.startswith(f'heap.{pid}.') and f.endswith('.heap')]
    fs.sort(key=lambda f: os.path.getmtime(os.path.join(d, f)))
    import time
    for f in fs:
        a = agg(os.path.join(d, f))
        tot = sum(v[1] for v in a.values())
        raw = 0
        print(f"{time.strftime('%H:%M:%S', time.localtime(os.path.getmtime(os.path.join(d,f))))} {f} inuse={gib(tot):8.3f} GiB traces={len(a)}")

def diff(path, base):
    a = agg(path)
    if base:
        b = agg(base)
        for k, v in b.items():
            a[k][1] -= v[1]; a[k][0] -= v[0]
    return a

def cmd_top(path, base, n, minpct):
    a = diff(path, base)
    tot = sum(v[1] for v in a.values())
    rows = sorted(a.items(), key=lambda kv: -kv[1][1])
    print(f"total {gib(tot):.3f} GiB")
    for st, v in rows[:n]:
        if minpct and v[1] / tot * 100 < minpct: break
        print(f"{gib(v[1]):8.3f} GiB {v[1]/tot*100:5.1f}% objs={v[0]:.0f} " + ' '.join(hex(x) for x in st))

def cmd_syms(binary, path, base, n):
    a = diff(path, base)
    tot = sum(v[1] for v in a.values())
    rows = sorted(a.items(), key=lambda kv: -kv[1][1])[:n]
    addrs = []
    for st, _ in rows: addrs.extend(st)
    uniq = sorted(set(addrs))
    # the binary is non-PIE-loaded at a base; find it from MAPPED_LIBRARIES
    base_addr = 0
    with open(path, errors='replace') as fh:
        seen = False
        for line in fh:
            if line.startswith('MAPPED_LIBRARIES'): seen = True; continue
            if seen and binary.split('/')[-1] in line:
                base_addr = int(line.split('-')[0], 16); break
    off = [a2 - base_addr for a2 in uniq]
    sym = {}
    p2 = subprocess.run(['addr2line', '-f', '-C', '-e', binary] + [hex(x) for x in off],
                        capture_output=True, text=True)
    l2 = p2.stdout.splitlines()
    for i, a2 in enumerate(uniq):
        sym[a2] = (l2[2*i] if 2*i < len(l2) else '?', l2[2*i+1] if 2*i+1 < len(l2) else '?')
    print(f"total {gib(tot):.3f} GiB  (binary base {hex(base_addr)})")
    for i, (st, v) in enumerate(rows):
        print(f"\n#{i+1} {gib(v[1]):8.3f} GiB {v[1]/tot*100:5.1f}% objs={v[0]:.0f}")
        for a2 in st:
            f, l = sym.get(a2, ('?', '?'))
            print(f"    {f}   [{l}]")


RULES = [
 ('sender caches',                r'n42_tx_types::sender_cache|reth_evm::sender_recovery'),
 ('reth exec/cross-block cache',  r'reth_execution_cache|SavedCache|cached_state|PayloadProcessor'),
 ('QMDB forest/twig/ops/readview', r'twig_core|qmdb_compat|n42_qmdb|QmdbOperation|bmt_core|qmdb_state'),
 ('RocksDB (QMDB store)',         r'^rocksdb::'),
 ('ingest + network buffers',     r'n42_tx_ingest|libp2p|gossipsub|h2_net|n42_h2|jsonrpsee|hyper|discv5|reth_network|noise|yamux'),
 ('tx pool / tx queue',           r'n42_tx_queue|TxQueue|reth_transaction_pool'),
 ('bundle/exec build',            r'parallel_transfer|BundleState|BundleAccount|revm_|reth_revm|execute_transfers|default_n42_payload|reth_execution_types|reth_evm'),
 ('blocks held in memory',        r'convert_payload_to_block|payload_serve|BlockBody|SealedBlock|sealed_block|ExecutedBlock|follower_import|RecoveredBlock|alloy_consensus::block|N42TxEnvelope|reth_payload|ConsistentProvider|BlockchainProvider'),
 ('reth provider / engine',       r'reth_provider|reth_storage|reth_chain_state|reth_trie|reth_engine|reth_node'),
 ('tokio / rayon runtime',        r'^tokio::|^std::thread|rayon_core'),
]

def _base_of(path, binary):
    tail = binary.split('/')[-1]
    for line in open(path, errors='replace'):
        if tail in line and '-' in line.split()[0]:
            return int(line.split('-')[0], 16)
    return 0

def cmd_groups(binary, paths):
    import re as _re
    rules = [(n, _re.compile(p)) for n, p in RULES]
    parsed = {p: parse(p) for p in paths}
    bases = {p: _base_of(p, binary) for p in paths}
    offs = set()
    for p, (r, tr) in parsed.items():
        for n, b, st in tr: offs.update(a - bases[p] for a in st[:14])
    uniq = sorted(offs)
    out = subprocess.run(['addr2line', '-f', '-C', '-e', binary] + [hex(a) for a in uniq],
                         capture_output=True, text=True).stdout.splitlines()
    sym = {a: out[2*i] for i, a in enumerate(uniq) if 2*i < len(out)}
    def grp(st, bs):
        for a in st[:14]:
            f = sym.get(a - bs, '')
            for n, pat in rules:
                if pat.search(f): return n
        return 'other'
    res = {}
    for p, (r, tr) in parsed.items():
        g = collections.defaultdict(float)
        for n, b, st in tr:
            an, ab = adjust(n, b, r); g[grp(st, bases[p])] += ab
        res[p] = g
    keys = set()
    for g in res.values(): keys |= set(g)
    print('%-32s' % 'group' + ''.join('%12s' % p.split('/')[-1][:12] for p in paths))
    for k in sorted(keys, key=lambda k: -max(res[p].get(k, 0) for p in paths)):
        print('%-32s' % k + ''.join('%10.3f G' % (res[p].get(k, 0)/(1<<30)) for p in paths))
    print('%-32s' % 'TOTAL' + ''.join('%10.3f G' % (sum(res[p].values())/(1<<30)) for p in paths))

if __name__ == '__main__':
    c = sys.argv[1]
    if c == 'totals': cmd_totals(sys.argv[2], sys.argv[3])
    elif c == 'top':
        args = sys.argv[2:]; base = None; n = 40; mp = 0
        path = args[0]; i = 1
        while i < len(args):
            if args[i] == '--base': base = args[i+1]; i += 2
            elif args[i] == '-n': n = int(args[i+1]); i += 2
            elif args[i] == '--min-pct': mp = float(args[i+1]); i += 2
            else: i += 1
        cmd_top(path, base, n, mp)
    elif c == 'syms':
        args = sys.argv[2:]; base = None; n = 15
        binary, path = args[0], args[1]; i = 2
        while i < len(args):
            if args[i] == '--base': base = args[i+1]; i += 2
            elif args[i] == '-n': n = int(args[i+1]); i += 2
            else: i += 1
        cmd_syms(binary, path, base, n)
    elif c == 'groups': cmd_groups(sys.argv[2], sys.argv[3:])
    else: print(__doc__)
