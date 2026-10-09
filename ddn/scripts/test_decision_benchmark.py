import unittest

from decision_benchmark import LABELS, evaluate_predictions, rule_predict, validate_corpus


class DecisionBenchmarkTests(unittest.TestCase):
    def test_schema_rejects_duplicate_ids_and_bad_labels(self):
        event = {"id": "a", "source": "node", "text": "peer timeout", "observed_at_ms": 1,
                 "truth": "NETWORK", "need_escalation": "YES", "incident_id": "incident-1"}
        self.assertEqual(len(validate_corpus([event])), 1)
        with self.assertRaises(ValueError):
            validate_corpus([event, event])
        with self.assertRaises(ValueError):
            validate_corpus([{**event, "truth": "WALLET"}])

    def test_rules_cannot_suppress_critical_escalation(self):
        event = {"id": "a", "source": "node", "text": "consensus finality stalled", "observed_at_ms": 1}
        decision = rule_predict(event)
        self.assertEqual(decision["label"], "CONSENSUS")
        self.assertEqual(decision["need_escalation"], "YES")

    def test_equal_event_set_and_basic_metrics(self):
        corpus = [
            {"id": "a", "source": "node", "text": "peer timeout", "observed_at_ms": 1, "truth": "NETWORK", "need_escalation": "YES", "incident_id": "i1"},
            {"id": "b", "source": "ci", "text": "normal", "observed_at_ms": 2, "truth": "NORMAL", "need_escalation": "NO", "incident_id": "i2"},
        ]
        predictions = [
            {"id": "a", "label": "NETWORK", "need_escalation": "YES", "latency_ms": 10},
            {"id": "b", "label": "UNKNOWN", "need_escalation": "YES", "latency_ms": 20},
        ]
        result = evaluate_predictions(corpus, predictions)
        self.assertEqual(result["accuracy"], 0.5)
        self.assertEqual(result["unknown_rate"], 0.5)
        self.assertEqual(result["recall"]["NETWORK"], 1.0)
        self.assertEqual(result["escalation_rate"], 1.0)
        with self.assertRaises(ValueError):
            evaluate_predictions(corpus, predictions[:1])


if __name__ == "__main__":
    unittest.main()
