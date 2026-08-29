#!/usr/bin/env python3
"""Decode the committed QC gov5 embeds in each header's extra data and print its signer bitmap.

extra = "N42H" | view (u64 LE) | QC (SSZ: view u64, bytes blockHash, bytes aggSig, bytes signersBitmap) | seal (96)
bytes = u32 LE length + payload; signersBitmap = u16 LE count + bits (bit i = validator i signed).
usage: qc-evidence.py <rpc-url> <from> <to>
"""
import json, sys, urllib.request

def rpc(url, method, params):
    req = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), headers={"content-type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=10))["result"]

def read_bytes(b, off):
    n = int.from_bytes(b[off:off+4], "little"); off += 4
    return b[off:off+n], off + n

def decode_extra(extra):
    assert extra[:4] == b"N42H", extra[:4]
    view = int.from_bytes(extra[4:12], "little")
    payload = extra[12:]
    if len(payload) <= 96:
        return view, None
    qc = payload[:-96]
    off = 0
    qc_view = int.from_bytes(qc[off:off+8], "little"); off += 8
    block_hash, off = read_bytes(qc, off)
    agg, off = read_bytes(qc, off)
    bitmap, off = read_bytes(qc, off)
    count = int.from_bytes(bitmap[:2], "little")
    signers = [bool(bitmap[2 + i // 8] >> (i % 8) & 1) for i in range(count)]
    return view, (qc_view, block_hash.hex(), signers)

if __name__ == "__main__":
    url, lo, hi = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    for n in range(lo, hi + 1):
        blk = rpc(url, "eth_getBlockByNumber", [hex(n), False])
        if blk is None:
            print(n, "missing"); continue
        extra = bytes.fromhex(blk["extraData"][2:])
        view, qc = decode_extra(extra)
        if qc is None:
            print(f"{n} view={view} hash={blk['hash'][:18]} miner={blk['miner'][:10]} (no QC in extra)"); continue
        qc_view, qc_hash, signers = qc
        bits = "".join("1" if s else "0" for s in signers)
        print(f"{n} view={view} hash={blk['hash'][:18]} leader={blk['miner'][:10]} committedQC view={qc_view} for {qc_hash[:16]} signers={bits} votes={sum(signers)}/{len(signers)} slot6={'YES' if len(signers)>6 and signers[6] else 'no'}")
