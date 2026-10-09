import json
import tempfile
import unittest
from pathlib import Path

from run_decision_provider import main
from decision_benchmark import main as benchmark_main


class RunnerTests(unittest.TestCase):
    def test_rules_runner_preserves_exact_event_ids_and_resource_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus.jsonl"
            predictions = root / "predictions.jsonl"
            metadata = root / "metadata.json"
            corpus.write_text(json.dumps({"id": "a", "source": "node", "text": "peer timeout", "observed_at_ms": 1,
                                          "truth": "NETWORK", "need_escalation": "YES", "incident_id": "i1"}) + "\n")
            self.assertEqual(main(["rules", str(corpus), "--output", str(predictions), "--metadata", str(metadata)]), 0)
            self.assertEqual(json.loads(predictions.read_text())["id"], "a")
            self.assertEqual(json.loads(metadata.read_text())["events"], 1)
            score = root / "score.json"
            self.assertEqual(benchmark_main(["score", str(corpus), "--predictions", str(predictions),
                                             "--metadata", str(metadata), "--output", str(score)]), 0)
            self.assertEqual(json.loads(score.read_text())["events"], 1)


if __name__ == "__main__":
    unittest.main()
