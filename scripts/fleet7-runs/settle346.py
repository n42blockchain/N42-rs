#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop346 (docs 10.93): the settlement tags of a depth-2 leg, read over RPC while the layer is still up (the flood is over: no block bodies are read, only the three tagged headers). usage: settle346.py <tag> [port 8700]
Prints latest / safe / finalized (number, hash) several times 2 s apart (the chain keeps producing empty blocks), the distance latest - safe and latest - finalized (the depth-2 chain should
show `safe` about two behind the tip and `finalized` behind it), and the count of -38002 / -38006 / invalid forkchoice / refused lines in the layer's log and the validators' logs.
Exit 0 = tags answer and finalized <= safe <= latest and no error lines, 1 otherwise."""
import glob, json, re, sys, time, urllib.request
tag = sys.argv[1]; port = int(sys.argv[2]) if len(sys.argv) > 2 else 8700
B = '/data/blockchain/rust-fleet7-bench'
def call(m, p):
    r = json.load(urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': m, 'params': p}).encode(), {'content-type': 'application/json'}), timeout=30))
    return r.get('result')
bad = []
for i in range(4):
    row = {}
    for t in ('latest', 'safe', 'finalized'):
        b = call('eth_getBlockByNumber', [t, False]); row[t] = (int(b['number'], 16), b['hash'][:12]) if b else None
    print(f'  {time.strftime("%H:%M:%S")} latest {row["latest"]}, safe {row["safe"]}, finalized {row["finalized"]}' + (f'; latest-safe {row["latest"][0] - row["safe"][0]}, latest-finalized {row["latest"][0] - row["finalized"][0]}' if row['safe'] and row['finalized'] else ''))
    if not (row['safe'] and row['finalized']) or not (row['finalized'][0] <= row['safe'][0] <= row['latest'][0]): bad.append('tag order / missing')
    time.sleep(2)
pat = re.compile(r'-3800[0-9]|invalid forkchoice|forkchoice.*(refus|invalid)|unknown ancestor|ParentUnknown', re.I)
hits = []
for f in [f'{B}/node0/el.log'] + sorted(glob.glob(f'{B}/node*/v.log')):
    try:
        for l in open(f, errors='replace'):
            if pat.search(l): hits.append((f.split('/')[-2], re.sub(r'\x1b\[[0-9;]*m', '', l.strip())[:200]))
    except OSError: pass
print(f'  settlement / forkchoice error lines (-3800x, invalid forkchoice, refused, ParentUnknown): {len(hits)}')
for h in hits[:6]: print('    ', h)
if hits: bad.append('error lines')
print('RESULT', 'BAD: ' + '; '.join(bad) if bad else 'ok')
sys.exit(1 if bad else 0)
