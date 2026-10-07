import json
import os
import re
from pathlib import Path
import struct
import sys
import urllib.request


def rpc(port, method, params):
    body = json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}', data=body,
                                    headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def rlp(raw, pos=0):
    prefix = raw[pos]
    if prefix < 128:
        return raw[pos:pos + 1], pos + 1
    if prefix <= 183:
        size, start = prefix - 128, pos + 1
        return raw[start:start + size], start + size
    if prefix <= 191:
        n = prefix - 183
        size = int.from_bytes(raw[pos + 1:pos + 1 + n], 'big')
        start = pos + 1 + n
        return raw[start:start + size], start + size
    if prefix <= 247:
        size, start = prefix - 192, pos + 1
    else:
        n = prefix - 247
        size = int.from_bytes(raw[pos + 1:pos + 1 + n], 'big')
        start = pos + 1 + n
    end = start + size
    result = []
    while start < end:
        item, start = rlp(raw, start)
        result.append(item)
    assert start == end
    return result, end


root = Path(os.environ['F7_ROOT'])
base = int(os.environ['F7_HTTP_BASE'])
replay = Path(os.environ['F7_FLOOD_REPLAY'])
phase = sys.argv[2]
flood_log = (root / f'bench-{phase}/flood.log').read_text()
assert 'replay       : 32 files' in flood_log and 'every sender is at nonce 0' in flood_log
sign_seconds = [int(n) for n in re.findall(r', sign (\d+)s', flood_log)]
assert sign_seconds and all(n == 0 for n in sign_seconds), sign_seconds
rows = []
# Inspect actual node environments, not merely the launcher's intentions.
for i in range(7):
    pid = int((root / f'node{i}/el.pid').read_text().split()[0])
    entries = Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
    env = dict(entry.split(b'=', 1) for entry in entries if b'=' in entry)
    assert env.get(b'N42_INGEST_VERIFY') == b'all', (i, env.get(b'N42_INGEST_VERIFY'))
    assert not env.get(b'N42_FRAME_GATEWAYS'), i
    assert env.get(b'N42_FAST_TRANSFER') == b'1', i
    assert env.get(b'N42_FRAME_BLOCKS') == b'1', i
    cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    genesis_path = Path(cmdline[cmdline.index(b'--chain') + 1].decode())
    config = json.loads(genesis_path.read_text())['config']
    assert config['stateScheme'] == 'qmdb' and config['altSigTx'] and config['frameBlocks']
    node_log = re.sub(r'\x1b\[[0-9;]*m', '', (root / f'node{i}/el.log').read_text(errors='replace'))
    verified = [int(n) for n in re.findall(r'\bverified_at_ingest=(\d+)', node_log)]
    assert verified and max(verified) > 0, (i, 'missing ingest verification evidence')
    assert not re.search(r'\b(?:claimed|shard_claimed)=[1-9]', node_log), i
    rows.append(dict(node=i, pid=pid, verify='all', gateway_bypass=False,
                     fast_transfer=True, frame_blocks=True, verified_at_ingest=max(verified), state_scheme='qmdb', command=[a.decode() for a in cmdline if a]))

# Take independently stored signed bytes, verify replay identity, and ensure a
# signature mutation cannot be admitted through the ordinary RPC entrypoint.
with next(replay.glob('*.flood')).open('rb') as stream:
    header = stream.read(128)
    assert header[:8] == b'N42FLOOD' and header[12] == 1
    assert header[13:16] == b'\0\0\0'  # no claimed senders, legacy layout or gateway
    _, length = struct.unpack('<II', stream.read(8))
    frame = stream.read(length)
    count = struct.unpack_from('<I', frame)[0]
    assert 0 < count < 0x40000000
    tx_len = struct.unpack_from('<I', frame, 4)[0]
    raw = frame[8:8 + tx_len]
    assert raw[0] == 0x50
    fields, end = rlp(raw, 1)
    assert end == len(raw) and len(fields) == 12
    assert len(fields[-1]) == 64 and len(fields[-2]) == 32
    recipient = '0x' + fields[5].hex()
    value = int.from_bytes(fields[6], 'big')
    assert value > 0
    damaged = bytearray(raw)
    damaged[-1] ^= 1
    bad = rpc(base, 'eth_sendRawTransaction', ['0x' + damaged.hex()])
    assert 'error' in bad and not bad.get('result'), bad
    assert any(word in json.dumps(bad).lower() for word in ['signature', 'recover']), bad

balances = [int(rpc(base + i, 'eth_getBalance', [recipient, 'latest'])['result'], 16)
            for i in range(7)]
assert len(set(balances)) == 1 and balances[0] >= value, balances
height = min(int(rpc(base + i, 'eth_blockNumber', [])['result'], 16) for i in range(7))
# Full transaction/receipt reads happen only after the measured flood stopped.
found = None
for number in range(height, max(0, height - 100), -1):
    block = rpc(base, 'eth_getBlockByNumber', [hex(number), False])['result']
    candidates = [rpc(base, 'eth_getTransactionByHash', [h])['result'] for h in block['transactions'][:4]]
    candidates = [tx for tx in candidates if tx and int(tx['type'], 16) == 0x50]
    if candidates:
        tx = candidates[0]
        receipt = rpc(base, 'eth_getTransactionReceipt', [tx['hash']])['result']
        assert receipt is not None and int(receipt['status'], 16) == 1, receipt
        found = dict(block=number, tx=tx['hash'], type=tx['type'],
                     receipt_status=receipt['status'], gas_used=receipt['gasUsed'])
        break
assert found is not None, 'No mined 0x50 transaction found'
result = dict(nodes=rows, replay_sign_seconds=sign_seconds, malformed_signature_response=bad,
              recipient=recipient, recipient_balances=balances, mined_transaction=found)
Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
