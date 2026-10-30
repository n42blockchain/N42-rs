"""PQC migration state-machine laboratory. NOT a cryptographic implementation.

No production consensus imports this module. The injected verifier/sign callback
must be replaced and audited before any real keys are handled. Independent signer
journals cannot detect each other's leaves: one shared durable authority (or HSM)
is required. Never restore its database from a chain snapshot.
"""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass, asdict
import hashlib
import json
import sqlite3


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


@contextmanager
def transaction(path):
    db = sqlite3.connect(path, isolation_level=None, timeout=60)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('BEGIN IMMEDIATE')
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


class LeafJournal:
    """Reserve-before-sign with an independent monotonic fencing authority.

    The fence must NOT be restored with signer/chain backups. Two signers must
    share it. SQLite stands in for that external authority in this laboratory;
    restoring both stores is outside the model and unsafe for real XMSS keys.
    """
    def __init__(self, path, fence_path):
        if str(path) == str(fence_path):
            raise ValueError('independent fence required')
        self.path, self.fence_path = path, fence_path
        with transaction(path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS leaves '
                       '(key TEXT, leaf INTEGER, message BLOB, signature BLOB, PRIMARY KEY(key,leaf))')
        with transaction(fence_path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS fence '
                       '(key TEXT, leaf INTEGER, message BLOB, signature_hash BLOB, PRIMARY KEY(key,leaf))')

    def sign_once(self, key, leaf, message, signer):
        if not key or type(leaf) is not int or not 0 <= leaf < 2**32 or not isinstance(message, bytes):
            raise ValueError('invalid signer input')
        with transaction(self.fence_path) as fence:
            prior = fence.execute('SELECT * FROM fence WHERE key=? AND leaf=?', (key, leaf)).fetchone()
            if prior is not None:
                if prior['message'] != message:
                    raise ValueError('leaf reuse')
                with transaction(self.path) as db:
                    row = db.execute('SELECT * FROM leaves WHERE key=? AND leaf=?', (key, leaf)).fetchone()
                if row is None or row['message'] != message or row['signature'] is None or prior['signature_hash'] is None:
                    raise ValueError('rollback, burned or in-flight leaf; never re-sign')
                if hashlib.sha256(row['signature']).digest() != prior['signature_hash']:
                    raise ValueError('signature cache corrupted')
                return row['signature']
            fence.execute('INSERT INTO fence VALUES (?,?,?,NULL)', (key, leaf, message))
        with transaction(self.path) as db:
            db.execute('INSERT INTO leaves VALUES (?,?,?,NULL)', (key, leaf, message))
        signature = signer(message)
        if not isinstance(signature, bytes) or not signature:
            raise ValueError('invalid signature; leaf remains burned')
        with transaction(self.path) as db:
            db.execute('UPDATE leaves SET signature=? WHERE key=? AND leaf=?', (signature, key, leaf))
        with transaction(self.fence_path) as db:
            db.execute('UPDATE fence SET signature_hash=? WHERE key=? AND leaf=?',
                       (hashlib.sha256(signature).digest(), key, leaf))
        return signature


@dataclass(frozen=True)
class Registration:
    network: str
    role: str
    index: int
    algorithm: str
    key: str
    vrf_root: str | None
    previous_epoch: int | None
    epoch: int
    authority: str

    @property
    def message(self):
        return canonical(asdict(self))


class Registry:
    """N42-oriented model; not Ethereum SSZ or an EIP-8450 implementation.

    Authority is explicitly injected by a trusted genesis/test fixture. Frozen
    state has no signer-accessible unfreeze. Any recovery fork is a new decision.
    """
    def __init__(self, path, network, authorities, verify, algorithms=('test-pq-v1',)):
        self.path, self.network = path, network
        self.authorities, self.verify = dict(authorities), verify
        self.algorithms = frozenset(algorithms)
        with transaction(path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS registry '
                       '(role TEXT, idx INTEGER, body BLOB, PRIMARY KEY(role,idx))')
            db.execute('CREATE TABLE IF NOT EXISTS registry_undo '
                       '(block INTEGER, role TEXT, idx INTEGER, old BLOB)')
            db.execute('CREATE TABLE IF NOT EXISTS registry_meta '
                       '(id INTEGER PRIMARY KEY CHECK(id=1), head INTEGER, frozen INTEGER)')
            db.execute('INSERT OR IGNORE INTO registry_meta VALUES (1,0,0)')

    def apply_block(self, height, registrations, *, epoch):
        if not 1 <= len(registrations) <= 8:
            raise ValueError('registration block bound')
        with transaction(self.path) as db:
            meta = db.execute('SELECT * FROM registry_meta').fetchone()
            if meta['frozen'] or height != meta['head'] + 1:
                raise ValueError('frozen or non-contiguous block')
            for r, signature in registrations:
                if r.network != self.network or r.role not in ('validator', 'builder') or r.index < 0 or r.epoch != epoch:
                    raise ValueError('wrong domain')
                if r.authority != self.authorities.get((r.role, r.index)) or r.algorithm not in self.algorithms:
                    raise ValueError('unauthorized key or algorithm')
                if len(r.key) != 64 or len(bytes.fromhex(r.key)) != 32 or r.epoch < 0:
                    raise ValueError('invalid key')
                if r.role == 'validator':
                    if r.vrf_root is None or len(r.vrf_root) != 64 or len(bytes.fromhex(r.vrf_root)) != 32:
                        raise ValueError('validator VRF required')
                elif r.vrf_root is not None:
                    raise ValueError('builder has no VRF field')
                old = db.execute('SELECT body FROM registry WHERE role=? AND idx=?', (r.role, r.index)).fetchone()
                previous = json.loads(old['body']) if old else None
                if r.previous_epoch != (previous['epoch'] if previous else None):
                    raise ValueError('stale registration')
                if previous and (r.epoch < previous['epoch'] + 256 or r.key == previous['key']):
                    raise ValueError('rotation bound or unchanged key')
                if not self.verify(r, signature):
                    raise ValueError('invalid possession/authority proof')
                db.execute('INSERT INTO registry_undo VALUES (?,?,?,?)',
                           (height, r.role, r.index, old['body'] if old else None))
                db.execute('INSERT OR REPLACE INTO registry VALUES (?,?,?)', (r.role, r.index, r.message))
            db.execute('UPDATE registry_meta SET head=?', (height,))

    def rollback(self, target):
        with transaction(self.path) as db:
            head = db.execute('SELECT head FROM registry_meta').fetchone()[0]
            if type(target) is not int or not 0 <= target <= head:
                raise ValueError('invalid rollback')
            for row in db.execute('SELECT * FROM registry_undo WHERE block>? ORDER BY block DESC,rowid DESC', (target,)).fetchall():
                if row['old'] is None:
                    db.execute('DELETE FROM registry WHERE role=? AND idx=?', (row['role'], row['idx']))
                else:
                    db.execute('INSERT OR REPLACE INTO registry VALUES (?,?,?)', (row['role'], row['idx'], row['old']))
            db.execute('DELETE FROM registry_undo WHERE block>?', (target,))
            db.execute('UPDATE registry_meta SET head=?', (target,))
        # Deliberately do NOT rewind the independent signer journal.

    def freeze(self):
        with transaction(self.path) as db:
            db.execute('UPDATE registry_meta SET frozen=1')

    def digest(self):
        with transaction(self.path) as db:
            rows = [json.loads(r[0]) for r in db.execute('SELECT body FROM registry ORDER BY role,idx')]
        return hashlib.sha256(canonical(rows)).hexdigest()
