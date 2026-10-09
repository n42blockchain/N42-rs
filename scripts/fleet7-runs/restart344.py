#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop344 (docs 10.91): the kill-and-restart check on a leg's layer, run by the runner while the fleet of the leg is still up (E=1: one layer, node0's datadir).
usage: restart344.py <tag> [rpc port, default 8700]. Steps: (1) copy the layer's command line, environment, working directory and CPU list from /proc; (2) SIGTERM every validator and flood
process (the chain stops growing), wait; (3) read the head and the last 40 blocks' (number, hash, stateRoot) and, for a sender of the last full block, its balance and nonce at the last
ten blocks, over RPC; (4) SIGTERM the layer, wait for it to exit (its exit status and the last log lines are kept); (5) start the same command on the same datadir (same environment and
affinity), wait for the RPC; (6) compare, for every block number both runs know, hash and stateRoot, the head the restart came back at, and the account's balance / nonce at the restart's
head against the pre-restart reading at that number; (7) the restart's log lines matching panic|error|mismatch|corrupt|heal|unwind|inconsisten|rollback|replay|recover; (8) SIGTERM the restarted layer.
Prints a RESULT line: ok / BAD / INCOMPLETE."""
import glob, json, os, re, signal, subprocess, sys, time, urllib.request
tag = sys.argv[1]; port = int(sys.argv[2]) if len(sys.argv) > 2 else 8700
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
def call(m, p, t=60):
    r = json.load(urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': m, 'params': p}).encode(), {'content-type': 'application/json'}), timeout=t))
    if 'error' in r: raise RuntimeError(str(r['error'])[:200])
    return r['result']
def pids(pat):
    out = []
    for p in glob.glob('/proc/[0-9]*'):
        try: c = open(p + '/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace')
        except OSError: continue
        if re.search(pat, c) and 'restart344' not in c: out.append(int(p.split('/')[-1]))
    return out
def waitgone(ps, secs):
    end = time.time() + secs
    while time.time() < end:
        if not any(os.path.exists(f'/proc/{p}') for p in ps): return True
        time.sleep(1)
    return False
res = []; bad = []; warn = []
layer = [p for p in pids(r'/n4[2] node --chain') if f'{B}/node0/' in open(f'/proc/{p}/cmdline', 'rb').read().decode(errors='replace')]
if not layer: print('no layer'); sys.exit(2)
lp = layer[0]
cmd = open(f'/proc/{lp}/cmdline', 'rb').read().split(b'\0')[:-1]; env = dict(l.split(b'=', 1) for l in open(f'/proc/{lp}/environ', 'rb').read().split(b'\0') if b'=' in l)
cwd = os.readlink(f'/proc/{lp}/cwd'); cpus = re.search(r'Cpus_allowed_list:\s*(\S+)', open(f'/proc/{lp}/status').read())[1]
aff = set()
for part in cpus.split(','):
    a, _, b = part.partition('-'); aff.update(range(int(a), int(b or a) + 1))
print(f'layer pid {lp}, {len(cmd)} args, {len(env)} env vars, cwd {cwd}, {len(aff)} cpus')
others = pids(r'h2_validato[r]') + pids(r'tx_floo[d]')
for p in others:
    try: os.kill(p, signal.SIGTERM)
    except OSError: pass
print(f'SIGTERM to {len(others)} validator / flood processes; gone within 30 s: {waitgone(others, 30)}')
for p in others:
    if os.path.exists(f'/proc/{p}'): warn.append(f'process {p} survived SIGTERM'); 
time.sleep(5)
head = int(call('eth_blockNumber', []), 16)
pre = {}
for n in range(head, max(-1, head - 40), -1):
    b = call('eth_getBlockByNumber', [hex(n), False]); pre[n] = (b['hash'], b['stateRoot'], len(b['transactions']))
full = next((n for n in sorted(pre, reverse=True) if pre[n][2] > 0), None)
acct = None; bal = {}
if full is not None:
    tx = call('eth_getTransactionByBlockNumberAndIndex', [hex(full), '0x0']); acct = tx['from']
    for n in range(head, max(-1, head - 10), -1):
        try: bal[n] = (call('eth_getBalance', [acct, hex(n)]), call('eth_getTransactionCount', [acct, hex(n)]))
        except Exception as e: bal[n] = ('err', str(e)[:60])
print(f'pre-restart head {head} hash {pre[head][0][:18]} stateRoot {pre[head][1][:18]}; last block with transactions {full}; account {acct}, balance at the head {bal.get(head)}')
os.kill(lp, signal.SIGTERM); exited = waitgone([lp], 180); print(f'layer SIGTERM, exited within 180 s: {exited}')
if not exited: warn.append('layer did not exit on SIGTERM'); os.kill(lp, signal.SIGKILL); time.sleep(3)
log2 = f'{B}/node0/el-restart-{tag}.log'
pid = subprocess.Popen([c.decode() for c in cmd], env={k.decode(): v.decode(errors='replace') for k, v in env.items()}, cwd=cwd, stdout=open(log2, 'wb'), stderr=subprocess.STDOUT,
                       preexec_fn=lambda: os.sched_setaffinity(0, aff), start_new_session=True).pid
up = False; end = time.time() + 240
while time.time() < end:
    try: n2 = int(call('eth_blockNumber', [], 5), 16); up = True; break
    except Exception: time.sleep(2)
print(f'restarted pid {pid}; RPC up: {up}')
if up:
    time.sleep(5); n2 = int(call('eth_blockNumber', []), 16)
    print(f'restart head {n2} (pre-restart head {head}; {head - n2} blocks lower)')
    same = diff = 0
    for n in range(n2, max(-1, n2 - 40), -1):
        if n in pre:
            b = call('eth_getBlockByNumber', [hex(n), False])
            if (b['hash'], b['stateRoot']) == pre[n][:2]: same += 1
            else: diff += 1; bad.append(f'block {n}: hash / stateRoot differ after the restart')
    print(f'blocks compared (hash + stateRoot): {same + diff}, equal {same}, different {diff}')
    if n2 in pre and pre[n2][0] != call('eth_getBlockByNumber', [hex(n2), False])['hash']: bad.append('restart head hash differs')
    if acct and n2 in bal:
        post = (call('eth_getBalance', [acct, hex(n2)]), call('eth_getTransactionCount', [acct, hex(n2)]))
        print(f'account {acct} at block {n2}: before {bal[n2]}, after {post}')
        if post != bal[n2]: bad.append('account state at the restart head differs')
    elif acct: warn.append(f'no pre-restart account reading at block {n2}')
    if head - n2 > 40: warn.append('the restart came back more than 40 blocks lower')
txt = open(log2, errors='replace').read(); pat = re.compile(r'panic|error|mismatch|corrupt|heal|unwind|inconsisten|rollback|replay|recover', re.I)
ln = [re.sub(r'\x1b\[[0-9;]*m', '', l)[:220] for l in txt.splitlines() if pat.search(l)]
print(f'restart log: {len(txt.splitlines())} lines, {len(ln)} matching panic|error|mismatch|corrupt|heal|unwind|inconsisten|rollback|replay|recover'); [print('   ', l) for l in ln[:10]]
if any(re.search(r'panic|corrupt|mismatch', l, re.I) for l in ln): bad.append('restart log: panic / corrupt / mismatch')
try: os.kill(pid, signal.SIGTERM); waitgone([pid], 60)
except OSError: pass
print('RESULT', 'BAD: ' + '; '.join(bad) if bad else ('INCOMPLETE: ' + '; '.join(warn) if (warn or not up) else 'ok'))
sys.exit(1 if bad else 0)
