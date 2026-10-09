import unittest

from decision_gateway import DecisionGateway


class GatewayTests(unittest.TestCase):
    def test_local_first_skips_cloud_when_local_resolves(self):
        cloud_calls = []
        gateway = DecisionGateway(
            local=lambda _: {"label": "NETWORK", "need_escalation": "NO", "score": 0.7},
            cloud=lambda _: cloud_calls.append(1))
        result = gateway.evaluate({"id": "a", "source": "node", "text": "peer timeout", "observed_at_ms": 1})
        self.assertEqual(result["chosen"]["label"], "NETWORK")
        self.assertEqual(cloud_calls, [])

    def test_unknown_local_uses_cloud_but_rule_urgency_survives(self):
        gateway = DecisionGateway(
            local=lambda _: {"label": "UNKNOWN", "need_escalation": "YES", "score": 0.1},
            cloud=lambda _: {"label": "CONSENSUS", "need_escalation": "NO", "score": 0.9})
        result = gateway.evaluate({"id": "b", "source": "node", "text": "finality stalled", "observed_at_ms": 2})
        self.assertEqual(result["chosen"]["label"], "CONSENSUS")
        self.assertEqual(result["chosen"]["need_escalation"], "YES")

    def test_both_providers_fail_escalates_without_action(self):
        gateway = DecisionGateway(
            local=lambda _: (_ for _ in ()).throw(RuntimeError("local offline")),
            cloud=lambda _: (_ for _ in ()).throw(RuntimeError("cloud offline")))
        result = gateway.evaluate({"id": "c", "source": "ci", "text": "unknown failure", "observed_at_ms": 3})
        self.assertEqual(result["chosen"]["label"], "UNKNOWN")
        self.assertEqual(result["chosen"]["need_escalation"], "YES")

    def test_critical_rule_cannot_be_overridden_to_normal(self):
        gateway = DecisionGateway(local=lambda _: {"label": "NORMAL", "need_escalation": "NO", "score": 0.95})
        result = gateway.evaluate({"id": "d", "source": "node", "text": "state root mismatch", "observed_at_ms": 4})
        self.assertEqual(result["chosen"]["label"], "STORAGE")
        self.assertEqual(result["chosen"]["need_escalation"], "YES")

    def test_malformed_provider_results_fail_closed(self):
        for value in (None, [], "NORMAL", 42, {"label": "NORMAL"},
                      {"label": "NORMAL", "need_escalation": "NO", "score": True},
                      {"label": "NORMAL", "need_escalation": "NO", "escalation_score": float("nan")}):
            with self.subTest(value=value):
                result = DecisionGateway(local=lambda _: value).evaluate(
                    {"id": "bad", "source": "node", "text": "unknown", "observed_at_ms": 1})
                self.assertEqual(result["chosen"]["label"], "UNKNOWN")
                self.assertEqual(result["chosen"]["need_escalation"], "YES")

    def test_providers_receive_redacted_isolated_allowlisted_events(self):
        seen = []
        def local(event):
            seen.append(dict(event))
            event["text"] = "mutated"
            return {"label": "UNKNOWN", "need_escalation": "YES"}
        def cloud(event):
            seen.append(dict(event))
            return {"label": "NETWORK", "need_escalation": "NO"}
        event = {"id": "private", "source": "node", "text": "api_key=secret peer timeout",
                 "observed_at_ms": 1, "metadata": {"private_key": "secret"}}
        result = DecisionGateway(local, cloud).evaluate(event)
        self.assertEqual(seen[0], seen[1])
        self.assertNotIn("secret", repr(seen))
        self.assertNotIn("metadata", seen[0])
        self.assertEqual(event["text"], "api_key=secret peer timeout")
        self.assertTrue(result["read_only"])


if __name__ == "__main__":
    unittest.main()
