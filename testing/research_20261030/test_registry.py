from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import unittest
from pq_registry import LeafJournal, Registry, Registration


def fake_sign(message):
    # Deliberately public and forgeable. State-machine fixture only.
    return b'NOT-A-PQ-SIGNATURE:' + hashlib.sha256(message).digest()


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.j = LeafJournal(self.root / 'signer.db', self.root / 'external-fence.db')
        self.r = Registry(self.root / 'chain.db', 'n42-test',
                          {('validator', i): f'owner-{i}' for i in range(10000)},
                          lambda r, s: s == fake_sign(r.message))

    def registration(self, i=0):
        return Registration('n42-test', 'validator', i, 'test-pq-v1',
                            hashlib.sha256(str(i).encode()).hexdigest(), '00' * 32, None, 1, f'owner-{i}')

    def test_ten_thousand_and_reorg_replay(self):
        empty = self.r.digest()
        entries = []
        for i in range(10000):
            r = self.registration(i)
            entries.append((r, self.j.sign_once(r.key, 0, r.message, fake_sign)))
        for offset in range(0, len(entries), 8):
            self.r.apply_block(offset // 8 + 1, entries[offset:offset + 8], epoch=1)
        full = self.r.digest()
        self.r.rollback(0); self.assertEqual(self.r.digest(), empty)
        for offset in range(0, len(entries), 8):
            block = entries[offset:offset + 8]
            for r, sig in block:
                self.assertEqual(self.j.sign_once(r.key, 0, r.message,
                    lambda _: self.fail('must reuse cached signature')), sig)
                with self.assertRaises(ValueError):
                    self.j.sign_once(r.key, 0, b'changed', fake_sign)
            self.r.apply_block(offset // 8 + 1, block, epoch=1)
        self.assertEqual(self.r.digest(), full)

    def test_two_signers_and_crash_burn(self):
        other = LeafJournal(self.root / 'signer.db', self.root / 'external-fence.db')
        def sign(journal):
            try: return journal.sign_once('key', 0, b'message', fake_sign)
            except ValueError: return None  # in-flight reservation must fail closed
        with ThreadPoolExecutor(2) as pool:
            signatures = list(pool.map(sign, [self.j, other]))
        self.assertIn(fake_sign(b'message'), signatures)
        def fail(_): raise RuntimeError('signer died')
        with self.assertRaises(RuntimeError): self.j.sign_once('burn', 0, b'message', fail)
        with self.assertRaises(ValueError): other.sign_once('burn', 0, b'message', fake_sign)

    def test_signer_database_rollback_is_detected_by_independent_fence(self):
        import shutil
        shutil.copyfile(self.root / 'signer.db', self.root / 'backup.db')
        self.j.sign_once('rollback', 0, b'message', fake_sign)
        shutil.copyfile(self.root / 'backup.db', self.root / 'signer.db')
        with self.assertRaises(ValueError):
            self.j.sign_once('rollback', 0, b'message', lambda _: self.fail('re-signed'))
        with self.assertRaises(ValueError):
            self.j.sign_once('rollback', 0, b'other', lambda _: self.fail('re-signed'))

    def test_rotation_authority_replay_and_atomic_block(self):
        r = self.registration()
        self.r.apply_block(1, [(r, fake_sign(r.message))], epoch=1)
        initial = self.r.digest()
        for invalid in [r, replace(r, authority='attacker'), replace(r, network='other'),
                        replace(r, algorithm='unknown'), replace(r, epoch=256, previous_epoch=1, key='11'*32)]:
            with self.assertRaises(ValueError): self.r.apply_block(2, [(invalid, fake_sign(invalid.message))], epoch=257)
        valid = replace(r, epoch=257, previous_epoch=1, key='11'*32)
        with self.assertRaises(ValueError): self.r.apply_block(2, [(valid, fake_sign(valid.message)), (r, b'bad')], epoch=257)
        self.assertEqual(self.r.digest(), initial)
        self.r.apply_block(2, [(valid, fake_sign(valid.message))], epoch=257)
        self.r.rollback(1); self.assertEqual(self.r.digest(), initial)
        self.r.freeze(); self.r.rollback(0)
        with self.assertRaises(ValueError): self.r.apply_block(1, [(r, fake_sign(r.message))], epoch=1)

if __name__ == '__main__': unittest.main()
