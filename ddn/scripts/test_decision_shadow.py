import unittest
import json
import tempfile
from pathlib import Path

from decision_shadow import classify, collect_lines, evaluate, load_labels, main, redact, score


class DecisionShadowTests(unittest.TestCase):
    def test_read_only_rule_alert_survives_model_failure(self):
        event = {"id": "e1", "source": "node", "text": "consensus finality stalled", "observed_at_ms": 100}
        result = classify(event, lambda _: (_ for _ in ()).throw(RuntimeError("offline")))
        self.assertEqual(result["rule"]["health"], "CRITICAL")
        self.assertTrue(result["shadow"]["need_deep_analysis"])
        self.assertEqual(result["shadow"]["health"], "CRITICAL")

    def test_secret_redaction_before_model(self):
        seen = []
        event = {"id": "e2", "source": "ci", "text": "CI failed TYPESAFE_API_KEY=abc123 private key 0x" + "a" * 64, "observed_at_ms": 200}
        classify(event, lambda request: seen.append(request) or None)
        self.assertNotIn("abc123", str(seen))
        self.assertNotIn("a" * 64, str(seen))
        self.assertIn("[REDACTED]", redact(event["text"]))

    def test_model_cannot_clear_critical_rule(self):
        event = {"id": "e3", "source": "node", "text": "finality stalled", "observed_at_ms": 300}
        answer = {"model": "jev-1.13.0", "answers": {
            "q0": {"type": "choice", "choice": "HEALTHY", "probabilities": {"HEALTHY": 0.9, "DEGRADED": 0.05, "CRITICAL": 0.05}, "confidence": 0.9},
            "q1": {"type": "choice", "choice": "CONSENSUS", "probabilities": {"NETWORK": 0.0, "CONSENSUS": 1.0, "EXECUTION": 0.0, "STORAGE": 0.0, "UNKNOWN": 0.0}, "confidence": 0.9},
            "q2": {"type": "noul", "noul": 0.1}}}
        result = classify(event, lambda _: answer)
        self.assertEqual(result["shadow"]["health"], "CRITICAL")

    def test_metrics_expose_severe_misses(self):
        records = [
            {"truth": "CRITICAL", "rule": {"health": "CRITICAL", "domain": "CONSENSUS"}, "shadow": {"health": "CRITICAL", "domain": "CONSENSUS"}, "latency_ms": 2, "model_called": True},
            {"truth": "CRITICAL", "rule": {"health": "HEALTHY", "domain": "UNKNOWN"}, "shadow": {"health": "HEALTHY", "domain": "UNKNOWN"}, "latency_ms": 3, "model_called": False},
        ]
        metrics = score(records, jev_cost_per_million_tokens=0.042, total_input_tokens=100)
        self.assertEqual(metrics["rules"]["severe_recall"], 0.5)
        self.assertEqual(metrics["shadow"]["severe_recall"], 0.5)
        self.assertEqual(metrics["events"], 2)

    def test_rejects_oversized_and_untrusted_events(self):
        event = {"id": "e4", "source": "node", "text": "x" * 8193, "observed_at_ms": 400}
        with self.assertRaises(ValueError):
            classify(event)
        event["text"] = "normal"
        event["source"] = "rpc"
        self.assertEqual(classify(event)["source"], "rpc")
        event["source"] = "wallet"
        with self.assertRaises(ValueError):
            classify(event)

    def test_rejects_incomplete_model_distribution(self):
        response = {"model": "jev-1.13.0", "answers": {
            "q0": {"type": "choice", "choice": "HEALTHY", "probabilities": {"HEALTHY": 1.0}, "confidence": 0.9},
            "q1": {"type": "choice", "choice": "UNKNOWN", "probabilities": {"UNKNOWN": 1.0}, "confidence": 0.9},
            "q2": {"type": "noul", "noul": 0.1}}}
        with self.assertRaises(ValueError):
            evaluate(response)

    def test_cli_writes_new_shadow_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            out = root / "shadow.jsonl"
            metrics = root / "metrics.json"
            events.write_text(json.dumps({"id": "cli1", "source": "qmdb", "text": "storage latency regression", "observed_at_ms": 1, "truth": "DEGRADED"}) + "\n")
            self.assertEqual(main([str(events), "--output", str(out), "--metrics", str(metrics)]), 0)
            self.assertEqual(json.loads(out.read_text())["id"], "cli1")
            self.assertEqual(json.loads(metrics.read_text())["events"], 1)
            self.assertIsNone(json.loads(metrics.read_text())["model_call_reduction_vs_every_event"])

    def test_collects_bounded_redacted_log_lines(self):
        records = list(collect_lines(["normal\n", "TYPESAFE_API_KEY=abc123 finality stalled\n", "x" * 9000], "node", "run1", 10))
        self.assertEqual(len(records), 3)
        self.assertEqual(records[1]["id"], "run1-2")
        self.assertNotIn("abc123", records[1]["text"])
        self.assertEqual(records[1]["observed_at_ms"], 10)
        self.assertTrue(records[2]["truncated"])
        self.assertLessEqual(len(records[2]["text"].encode()), 8192)

    def test_external_labels_reject_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.jsonl"
            path.write_text('{"id":"e1","truth":"CRITICAL","truth_domain":"CONSENSUS"}\n'
                            '{"id":"e1","truth":"HEALTHY","truth_domain":"UNKNOWN"}\n')
            with self.assertRaises(ValueError):
                load_labels(path)


if __name__ == "__main__":
    unittest.main()
