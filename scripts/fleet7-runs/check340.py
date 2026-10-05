#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop340 (docs 10.87): read-back of a leg's static-file data through the layer's RPC, run while the layer is still up, before the datadirs are wiped.
usage: check340.py <tag> [rpc port, default 8700]. Exit 0 = everything read right, 1 = something read wrong, 2 = the check could not complete (timeout / no answer).
1. The layer's log: any line about static-file consistency or healing beyond the start-up (lines matching heal|inconsisten|unwind|corrupt|NippyJar|mismatch, printed).
2. For the first full block of the leg, a middle one and the last one: eth_getBlockByNumber with full transactions and eth_getBlockReceipts: the transaction count equals the
   canonical-log count, the receipts' count equals it, every receipt's status is 1, cumulativeGasUsed rises and ends at the block's gasUsed, the receipts' transaction
   hashes equal the block's in order, and for the first / middle / last transaction (and two more) of each block the hash is recomputed from the fields
   (keccak256(0x50 || rlp([...fields, signature])), docs/spec/N42_TX_0x50.md), the Ed25519 signature is verified over the signing hash and `from` equals
   keccak256(alg || pubkey)[12:]. The raw JSON of the sampled transactions is saved to /data/n42-build/target-n42-rs/fleet-runs/check340-<tag>.json."""
import importlib.util, json, os, re, subprocess, sys, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__))
tag = sys.argv[1]; port = int(sys.argv[2]) if len(sys.argv) > 2 else 8700
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
measure = load('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
vec = load('altsig', os.path.join(HERE, '..', '..', 'docs', 'sigbench', 'altsig_vectors.py'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
bad, warn = [], []
def call(method, params, timeout=300):
    req = urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(), {'content-type': 'application/json'})
    r = json.load(urllib.request.urlopen(req, timeout=timeout))
    if 'error' in r: raise RuntimeError(str(r['error'])[:300])
    return r['result']
# 1. the log
log = f'{B}/node0/el.log'
pat = re.compile(r'heal|inconsisten|unwind|corrupt|nippyjar|mismatch', re.I)
hits = [l.rstrip()[:300] for l in open(log, errors='replace') if pat.search(l) and 'fields_mismatches=0' not in l and 'gas used mismatch' not in l]
hits = [l for l in hits if 'seal-first build phases' not in l]
print(f'log: {len(hits)} lines match heal|inconsisten|unwind|corrupt|NippyJar|mismatch (excluding the build lines\' counters)')
for l in hits[:8]: print('   ', re.sub(r'\x1b\[[0-9;]*m', '', l))
if any(re.search(r'heal|inconsisten|corrupt', l, re.I) for l in hits): bad.append('log: healing / inconsistency message')
canon = measure.log_blocks(log); full = [c for c in canon if c[2] >= 100000]
if not full: print('no full block'); sys.exit(2)
nums = [full[0][1], full[len(full) // 2][1], full[-1][1]]; counts = {c[1]: c[2] for c in canon}
print('blocks checked:', nums, 'transaction counts from the log:', [counts[n] for n in nums])
samples = {}
try:
    for n in nums:
        blk = call('eth_getBlockByNumber', [hex(n), True]); txs = blk['transactions']
        rc = call('eth_getBlockReceipts', [hex(n)])
        ok = len(txs) == counts[n] and len(rc) == len(txs)
        st = sum(1 for r in rc if r.get('status') in ('0x1', 1, True)); cum = [int(r['cumulativeGasUsed'], 16) for r in rc]
        mono = all(a < b for a, b in zip(cum, cum[1:])) and (not cum or cum[-1] == int(blk['gasUsed'], 16))
        same = all(t['hash'] == r['transactionHash'] for t, r in zip(txs, rc))
        print(f'block {n}: {len(txs)} txs (log {counts[n]}), {len(rc)} receipts, status ok {st}, cumulative gas rising and ending at gasUsed: {mono}, receipt hashes equal the block\'s in order: {same}')
        if not (ok and st == len(rc) and mono and same): bad.append(f'block {n}: count/status/gas/hash order')
        idx = sorted({0, len(txs) // 2, len(txs) - 1, len(txs) // 4, 3 * len(txs) // 4}); done = 0
        for i in idx:
            tx = txs[i]; samples[f'{n}:{i}'] = tx
            try:
                fl = lambda k, *alts: next(tx[a] for a in (k,) + alts if a in tx)
                body = dict(chainId=fl('chainId'), nonce=fl('nonce'), maxPriorityFeePerGas=fl('maxPriorityFeePerGas'), maxFeePerGas=fl('maxFeePerGas'), gasLimit=fl('gasLimit', 'gas'),
                            to=fl('to'), value=fl('value'), input=fl('input'), accessList=tx.get('accessList', []), algType=fl('algType', 'alg_type'), pubkey=fl('pubkey', 'publicKey'))
                sig = vec.unhex(fl('signature'))
                signing = vec.keccak256(b'\x50' + vec.rlp_list(vec.fields(body)))
                enc = b'\x50' + vec.rlp_list(vec.fields(body) + [vec.rlp_bytes(sig)])
                h = vec.keccak256(enc).hex(); okh = ('0x' + h) == tx['hash']
                Ed25519PublicKey.from_public_bytes(vec.unhex(body['pubkey'])).verify(sig, signing)
                sender = '0x' + vec.keccak256(bytes([vec.qty(body['algType'])]) + vec.unhex(body['pubkey']))[12:].hex()
                oks = sender.lower() == tx['from'].lower()
                done += 1
                if not (okh and oks): bad.append(f'block {n} tx {i}: hash recompute {okh}, sender {oks}')
                else: print(f'   tx {i}: hash recomputed ok, Ed25519 signature verifies, from = keccak(alg||pubkey)[12:]')
            except Exception as e:
                warn.append(f'block {n} tx {i}: could not recompute ({type(e).__name__}: {str(e)[:120]}); keys {sorted(tx)[:20]}')
except Exception as e:
    warn.append(f'rpc: {type(e).__name__}: {str(e)[:200]}')
json.dump(samples, open(f'{S}/check340-{tag}.json', 'w'))
for w in warn: print('WARN', w)
for b in bad: print('BAD', b)
print('RESULT', 'BAD' if bad else ('INCOMPLETE' if warn else 'ok'))
sys.exit(1 if bad else (2 if warn else 0))
