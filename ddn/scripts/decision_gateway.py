"""Read-only, local-first N42 System-1 routing prototype."""

import math

from decision_benchmark import LABELS, rule_predict
from decision_providers import safe_prediction
from decision_shadow import redact, validate_event


def _checked(predict, event):
    result = safe_prediction(predict, event)
    if result.get("label") not in LABELS or result.get("need_escalation") not in ("YES", "NO"):
        return {"label": "UNKNOWN", "need_escalation": "YES", "error": "InvalidProviderResult"}
    if "score" in result and (type(result["score"]) not in (int, float) or not math.isfinite(result["score"]) or not 0 <= result["score"] <= 1):
        return {"label": "UNKNOWN", "need_escalation": "YES", "error": "InvalidProviderScore"}
    return result


class DecisionGateway:
    def __init__(self, local, cloud=None):
        self.local = local
        self.cloud = cloud

    def evaluate(self, event):
        validate_event(event)
        sanitized = {key: event[key] for key in ("id", "source", "observed_at_ms")}
        sanitized["text"] = redact(event["text"])
        rule = rule_predict(sanitized)
        local = _checked(self.local, sanitized)
        cloud = None
        chosen = local
        route = "local"
        if local["label"] == "UNKNOWN" and self.cloud is not None:
            cloud = _checked(self.cloud, sanitized)
            if cloud["label"] != "UNKNOWN":
                chosen = cloud
                route = "cloud"
        if chosen["label"] == "UNKNOWN":
            chosen = {**chosen, "need_escalation": "YES"}
            route = "unresolved"
        if rule["need_escalation"] == "YES":
            chosen = {**chosen, "need_escalation": "YES"}
            if chosen["label"] == "NORMAL":
                chosen["label"] = rule["label"]
                route = "rule_override"
        return {"id": event["id"], "rule": rule, "local": local, "cloud": cloud,
                "chosen": chosen, "route": route, "read_only": True}
