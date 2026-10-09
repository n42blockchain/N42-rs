#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop318 per-leg metrics (docs 10.66). usage: analyze318.py <tag> [<tag> ...]
Window 1 blocks as in fleet7-excess-anatomy.py. Prints cycle, sealed_at, follower fields_ready, the answer's
encode/write/read/decode split from the new timestamps, answer_bytes, the two build-trigger modes and the on-demand
counts (EL logs: 'own block's body served on demand', 'compact body: asking for the transactions',
'compact body refused'; validator logs: 'elided block's body fetched from the execution layer')."""
import importlib.util, os, re, sys, statistics as st
B = '/data/blockchain/rust-fleet3-bench'
here = os.path.dirname(os.path.abspath(__file__))
sp = importlib.util.spec_from_file_location('an', os.path.join(here, '..', 'fleet7-excess-anatomy.py'))
an = importlib.util.module_from_spec(sp); sp.loader.exec_module(an)
dr = an.dr
ansi = re.compile(r'\x1b\[[0-9;]*m')
KV = re.compile(r'(\w+)=(\S+)')
def kvs(l): return {k: v.strip('"') for k, v in KV.findall(l)}
def pm(x):
    x = sorted(x)
    return f'{st.median(x):.1f}/{x[int(len(x) * .9)]:.1f}' if x else '-'
def count(path, pats):
    n = {p: 0 for p in pats}
    for l in open(path, errors='replace'):
        for p in pats:
            if p in l: n[p] += 1
    return n
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'
    D, W, m, rows = an.analyse(root)
    ldr = D['ldr']; vs = {r['v'] for r in rows}
    cyc = [r['cyc'] for r in rows]
    print(f'== {tag}: window-1 blocks {len(rows)}, cycle mean/median/p90 {st.mean(cyc):.1f}/{st.median(cyc):.1f}/{an.dr.pct(cyc, .9):.1f}')
    sealed, enc, wr, rd, dec, nbytes, elided = [], [], [], [], [], [], 0
    el = {}
    for l in open(f'{root}/node{ldr}-el.log', errors='replace'):
        l = ansi.sub('', l)
        if 'seal-first build phases' in l:
            d = kvs(l)
            if 'sealed_at_ms' in d and int(d.get('txs', 0)) >= 150000: sealed.append(float(d['sealed_at_ms']))
        if 'built ahead on the sealed own block' in l:
            d = kvs(l)
            if 'answer_write_start_us' in d: el[int(d['number']) + 1] = d
    for l in open(f'{root}/node{ldr}-v.log', errors='replace'):
        if 'proposal sent' not in l: continue
        d = kvs(ansi.sub('', l)); v = int(d['view'])
        if v in vs and v in el:
            e = el[v]; ws, es, we = (int(e[k]) for k in ('answer_write_start_us', 'answer_encode_start_us', 'answer_write_end_us'))
            enc.append((ws - es) / 1e3); wr.append((we - ws) / 1e3); nbytes.append(int(e['answer_bytes']) / 1e6)
            if e['elided'] == 'true': elided += 1
            re_, de = int(d.get('answer_read_end_us', 0)), int(d.get('answer_decode_end_us', 0))
            if re_ and de: rd.append((re_ - ws) / 1e3); dec.append((de - re_) / 1e3)
    print(f'  sealed_at ms median/p90 {pm(sealed)} (n={len(sealed)})')
    fl = []
    for n in D['fol']:
        for t, l in dr.lines(f'{root}/node{n}-el.log'):
            if 'direct import: executed here' in l and 'txs=163000' in l:
                fl.append(float(kvs(l)['fields_ready_ms']))
    print(f'  follower fields_ready ms median/p90 {pm(fl)} (n={len(fl)}, whole leg)')
    print(f'  answer (window 1, n={len(enc)}, elided {elided}): encode {pm(enc)}  write {pm(wr)}  read {pm(rd)} (n={len(rd)})  decode {pm(dec)}  answer_MB {pm(nbytes)}  [median/p90 ms]')
    sel = {k: [r['cyc'] for r in rows if r['trig'] == k] for k in ('seal', 'send')}
    print('  modes: ' + '  '.join(f'{k} {len(x)} ({len(x) / len(rows) * 100:.0f}%) mean {st.mean(x):.1f}' for k, x in sel.items() if x))
    ev = count(f'{root}/node{ldr}-el.log', ["own block's body served on demand", 'compact body: asking for the transactions', 'compact body refused'])
    tot = {p: 0 for p in ev}
    vt = {"elided block's body fetched from the execution layer": 0, 'peer asked for a block taken elided': 0}
    for i in range(3):
        for p, c in count(f'{root}/node{i}-el.log', list(ev)).items(): tot[p] += c
        for p, c in count(f'{root}/node{i}-v.log', list(vt)).items(): vt[p] += c
    print(f'  on demand, whole leg, all nodes: EL {tot}  validator {vt}')
