import unittest
from mempool_sim import Pool, Wrapper, Tx, MAX_WRAPPER_BYTES, simulate

class MempoolTests(unittest.TestCase):
    def test_bounds_fail_before_admission(self):
        tx = Tx('tx', 1, 0, 'dep', 100, True)
        for w in [Wrapper((tx,), MAX_WRAPPER_BYTES + 1), Wrapper((tx,), 1, mode=2),
                  Wrapper((tx, tx), 1), Wrapper((tx,), 1, vk='wrong')]:
            p = Pool(recursive_limit=10)
            with self.assertRaises(ValueError): p.admit(w, 1)
            self.assertEqual(len(p.entries), 0)
        with self.assertRaises(ValueError): Pool().admit(Wrapper((tx,), 1), 1)

    def test_valid_dependencies_do_not_imply_admissible_transactions(self):
        txs = (Tx('a', 1, 0, 'a', 100, True), Tx('b', 1, 0, 'b', 100, True),
               Tx('c', 2, 0, 'c', 0, True), Tx('d', 3, 0, 'd', 100, False))
        accepted, rejected = Pool(recursive_limit=10).admit(Wrapper(txs, 100), 1)
        self.assertEqual([t.hash for t in accepted], ['a'])
        self.assertEqual([r for _, r in rejected], ['nonce_conflict', 'expired', 'invalid_dependency'])

    def test_three_strategies_accept_same_transactions(self):
        result = simulate(1000, 32)
        modes = result['strategies']
        self.assertEqual(len({m['accepted'] for m in modes.values()}), 1)
        self.assertGreater(modes['independent']['dependency_proving_work'], modes['hash_partition']['dependency_proving_work'])
        self.assertLessEqual(modes['proof_reuse']['dependency_proving_work'], modes['hash_partition']['dependency_proving_work'])
