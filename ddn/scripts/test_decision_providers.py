import unittest

from decision_providers import GliclassProvider, JevProvider, safe_prediction


class ProviderTests(unittest.TestCase):
    def test_gliclass_adapter_uses_cpu_pipeline_and_two_questions(self):
        calls = []
        def pipeline(text, labels, **kwargs):
            calls.append((text, labels, kwargs))
            if "CONSENSUS" in labels:
                return [[{"label": "CONSENSUS", "score": 0.8}, {"label": "UNKNOWN", "score": 0.2}]]
            return [[{"label": "YES", "score": 0.9}, {"label": "NO", "score": 0.1}]]
        provider = GliclassProvider(pipeline=pipeline, model_version="local-test")
        result = provider.predict({"text": "finality stalled", "source": "node"})
        self.assertEqual(result["label"], "CONSENSUS")
        self.assertEqual(result["need_escalation"], "YES")
        self.assertEqual(len(calls), 2)

    def test_model_failure_is_explicit_unknown_and_escalated(self):
        result = safe_prediction(lambda _: (_ for _ in ()).throw(RuntimeError("offline")), {"text": "x"})
        self.assertEqual(result["label"], "UNKNOWN")
        self.assertEqual(result["need_escalation"], "YES")
        self.assertEqual(result["error"], "RuntimeError")

    def test_jev_choice_must_match_highest_probability(self):
        from decision_benchmark import LABELS
        probabilities = {label: 0.0 for label in LABELS}
        probabilities["NETWORK"] = 1.0
        response = {"model": "jev-1.13.0", "answers": {
            "q0": {"type": "choice", "choice": "NORMAL", "confidence": 0.9, "probabilities": probabilities},
            "q1": {"type": "noul", "noul": 0.1}}}
        with self.assertRaises(ValueError):
            JevProvider(call=lambda _: response).predict({"text": "peer timeout"})


if __name__ == "__main__":
    unittest.main()
