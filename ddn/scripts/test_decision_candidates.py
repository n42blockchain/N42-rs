import unittest

from decision_candidates import sample_lines


class CandidateTests(unittest.TestCase):
    def test_samples_normal_and_abnormal_without_labels(self):
        records = sample_lines(["boot ok\n", "peer timeout\n", "normal block\n", "QMDB error\n"], "node", "run-a", 1)
        self.assertEqual(len(records), 2)
        self.assertEqual({r["candidate_bucket"] for r in records}, {"normal", "abnormal"})
        self.assertTrue(all("truth" not in r for r in records))


if __name__ == "__main__":
    unittest.main()
