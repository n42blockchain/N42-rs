import unittest

from decision_corpus import join_labels


class CorpusTests(unittest.TestCase):
    def test_adjudication_requires_exact_event_set(self):
        events = [{"id": "a", "source": "node", "text": "peer timeout", "observed_at_ms": 1}]
        labels = [{"id": "a", "truth": "NETWORK", "need_escalation": "YES", "incident_id": "incident-1"}]
        self.assertEqual(join_labels(events, labels)[0]["truth"], "NETWORK")
        with self.assertRaises(ValueError):
            join_labels(events, [])
        with self.assertRaises(ValueError):
            join_labels(events, labels + labels)


if __name__ == "__main__":
    unittest.main()
