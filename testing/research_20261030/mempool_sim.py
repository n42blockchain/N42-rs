"""32 logical nodes, no sockets, STARKs or live mempool. Cost model only.

CPU is Python simulation CPU; latency and bytes are model outputs. Parameters
must be calibrated on the actual aggregation circuit and target devices before
using this experiment for a protocol decision.
"""
from dataclasses import dataclass
import argparse
import hashlib
import json
import random
import time

MAX_WRAPPER_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Tx:
    hash: str
    sender: int
    nonce: int
    dependency: str
    expires: int
    valid: bool


@dataclass(frozen=True)
class Wrapper:
    txs: tuple
    encoded_bytes: int
    mode: int = 1
    vk: str = 'simulation-v1'


class Pool:
    def __init__(self, *, capacity=100000, recursive_limit=None):
        self.capacity, self.recursive_limit = capacity, recursive_limit
        self.entries, self.nonces = {}, set()

    def admit(self, wrapper, now):
        # mode 1 stays disabled without an explicitly benchmarked circuit cap.
        limit = 256 if wrapper.mode == 0 else self.recursive_limit
        if wrapper.mode not in (0, 1) or limit is None or wrapper.vk != 'simulation-v1':
            raise ValueError('unsupported proof mode/circuit')
        if not 0 < wrapper.encoded_bytes <= MAX_WRAPPER_BYTES or not 0 < len(wrapper.txs) <= limit:
            raise ValueError('wrapper bound')
        if len({tx.hash for tx in wrapper.txs}) != len(wrapper.txs):
            raise ValueError('duplicate transaction')
        # Proof validity and local admissibility are deliberately distinct.
        # This fixture represents verified per-transaction dependencies; a real
        # recursive wrapper must first verify the entire committed dependency set.
        accepted, rejected = [], []
        for tx in wrapper.txs:
            reason = None
            if not tx.valid: reason = 'invalid_dependency'
            elif tx.expires <= now: reason = 'expired'
            elif tx.hash in self.entries: reason = 'known'
            elif (tx.sender, tx.nonce) in self.nonces: reason = 'nonce_conflict'
            elif len(self.entries) >= self.capacity: reason = 'local_capacity'
            if reason:
                rejected.append((tx.hash, reason)); continue
            self.entries[tx.hash] = tx
            self.nonces.add((tx.sender, tx.nonce)); accepted.append(tx)
        # Expiry/nonces/capacity never produce a peer penalty. No attribution
        # exists in this model, so invalid relays aren't attributed either.
        return accepted, rejected


def corpus(count, seed):
    rng = random.Random(seed)
    conflict = set(rng.sample(range(count), count // 10))
    expired_batches = set(rng.sample(range((count + 99) // 100), ((count + 99) // 100) // 5))
    expired = {i for i in range(count) if i // 100 in expired_batches}
    malicious = set(rng.sample(range(count), count // 20))
    txs = []
    for i in range(count):
        # Conflict with an earlier original account; results may overlap expiry.
        sender = i - 1 if i in conflict and i > 0 else i
        txs.append(Tx(hashlib.sha256(f'tx:{i}'.encode()).hexdigest(), sender, 0,
                      hashlib.sha256(f'dep:{i % max(1, count // 10)}'.encode()).hexdigest(),
                      0 if i in expired else 1000, i not in malicious))
    return txs, {'nonce_conflict_injected': len(conflict),
                 'expired_transactions_injected': len(expired), 'expired_wrappers_injected': len(expired_batches), 'malicious_injected': len(malicious)}


def simulate(count=100000, nodes=32, seed=42):
    if count < 20 or nodes < 1: raise ValueError('invalid simulation size')
    txs, injected = corpus(count, seed)
    output = {'kind': 'logical-node-cost-model', 'transactions': count, 'nodes': nodes,
              'seed': seed, 'injected': injected, 'circuit_benchmark': None,
              'assumptions': {'dependency_cost_ms': 0.2, 'hop_ms': 20,
                              'proof_bytes': 4096, 'tx_bytes': 160, 'wrapper_size': 100}, 'strategies': {}}
    for strategy in ('independent', 'hash_partition', 'proof_reuse'):
        start = time.process_time()
        pools = [Pool(recursive_limit=100) for _ in range(nodes)]
        # Each node has its own cache. Only the partition owner proves a new
        # dependency; cache keys bind the circuit version and dependency hash.
        caches = [set() for _ in range(nodes)]
        work = [0] * nodes
        counts = {}
        proofs = 0
        wire_bytes = 0
        latency = []
        for offset in range(0, count, 100):
            batch = tuple(txs[offset:offset + 100])
            wrapper = Wrapper(batch, 4096 + len(batch) * 160)
            first, rejected = pools[0].admit(wrapper, 1)
            for _, reason in rejected: counts[reason] = counts.get(reason, 0) + 1
            for pool in pools[1:]:
                admitted, _ = pool.admit(wrapper, 1)
                assert [t.hash for t in admitted] == [t.hash for t in first]
            groups = {}
            for tx in first:
                owners = range(nodes) if strategy == 'independent' else [int(tx.hash[:8], 16) % nodes]
                for owner in owners:
                    groups.setdefault(owner, []).append(tx)
            for owner, members in groups.items():
                dependencies = {(wrapper.vk, t.dependency) for t in members}
                fresh = dependencies - caches[owner] if strategy == 'proof_reuse' else dependencies
                work[owner] += len(fresh)
                caches[owner].update(fresh)
                if fresh:
                    proofs += 1
                    wire_bytes += (4096 + len(members) * 160) * (nodes - 1)
                for tx in members:
                    if strategy != 'independent' or owner == 0:
                        latency.append(work[owner] * 0.2 + 20 * (nodes - 1).bit_length())
        latency.sort()
        accepted = len(pools[0].entries)
        output['strategies'][strategy] = {
            'accepted': accepted, 'rejected': counts, 'proof_jobs': proofs,
            'dependency_proving_work': sum(work), 'modeled_propagation_bytes': wire_bytes,
            'modeled_p95_admission_ms': latency[int(len(latency) * .95)] if latency else None,
            'python_cpu_seconds': round(time.process_time() - start, 6),
            'peer_false_penalties': 0, 'peer_scoring': 'disabled_without_attribution',
            'cache_entries': sum(map(len, caches)),
        }
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--count', type=int, default=100000)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    with open(args.output, 'w') as f: json.dump(simulate(args.count), f, indent=2); f.write('\n')
