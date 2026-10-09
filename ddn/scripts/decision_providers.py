"""Optional, replaceable System-1 benchmark providers; no chain action APIs."""

import math
from pathlib import Path

from decision_benchmark import LABELS
from decision_shadow import MODEL, official_jev, redact


def _top_score(results, labels):
    if isinstance(results, list) and len(results) == 1 and isinstance(results[0], list):
        results = results[0]
    if not isinstance(results, list) or not results:
        raise ValueError("empty provider scores")
    scores = {}
    for item in results:
        if not isinstance(item, dict) or item.get("label") not in labels or item["label"] in scores:
            raise ValueError("invalid provider label")
        value = item.get("score")
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("invalid provider score")
        scores[item["label"]] = float(value)
    return max(scores, key=scores.get), max(scores.values())


class GliclassProvider:
    """GLiClass CPU adapter; pass a fake pipeline for tests or load local files."""

    def __init__(self, pipeline, model_version):
        self.pipeline = pipeline
        self.model_version = model_version

    @classmethod
    def from_local(cls, model_dir):
        directory = Path(model_dir)
        if not directory.is_dir() or not (directory / "config.json").is_file():
            raise ValueError("GLiClass model must already exist in a local directory")
        from gliclass import GLiClassModel, ZeroShotClassificationPipeline
        from transformers import AutoTokenizer
        model = GLiClassModel.from_pretrained(str(directory), local_files_only=True)
        tokenizer = AutoTokenizer.from_pretrained(str(directory), local_files_only=True)
        pipeline = ZeroShotClassificationPipeline(model, tokenizer, classification_type="multi-label", device="cpu")
        return cls(pipeline, str(directory.resolve()))

    def predict(self, event):
        text = redact(event["text"])
        label, score = _top_score(self.pipeline(text, list(LABELS), threshold=0.0), LABELS)
        escalation, escalation_score = _top_score(
            self.pipeline(text, ["YES", "NO"], prompt="Does this N42 event require human or deep-model analysis?", threshold=0.0),
            ("YES", "NO"))
        return {"label": label, "need_escalation": escalation, "score": score,
                "escalation_score": escalation_score, "model": "gliclass", "model_version": self.model_version}


class JevProvider:
    """Pinned external benchmark provider; disabled unless explicitly selected."""

    def __init__(self, call=official_jev):
        self.call = call

    def predict(self, event):
        request = {"model": MODEL, "state": redact(event["text"]), "questions": {
            "q0": {"type": "choice", "instructions": "Classify this N42 operational event into exactly one category.",
                   "criteria": {label: label for label in LABELS}},
            "q1": {"type": "noul", "instructions": "Does this event require human or deep-model analysis?"}}}
        response = self.call(request)
        if not isinstance(response, dict) or response.get("model") != MODEL or set(response.get("answers", {})) != {"q0", "q1"}:
            raise ValueError("invalid Jev model or answer set")
        choice = response["answers"]["q0"]
        if not isinstance(choice, dict) or choice.get("type") != "choice" or choice.get("choice") not in LABELS:
            raise ValueError("invalid Jev label")
        probabilities = choice.get("probabilities")
        confidence = choice.get("confidence")
        if not isinstance(probabilities, dict) or set(probabilities) != set(LABELS) or any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1 for v in probabilities.values()) or abs(sum(probabilities.values()) - 1) > .02:
            raise ValueError("invalid Jev distribution")
        if probabilities[choice["choice"]] + 0.000001 < max(probabilities.values()):
            raise ValueError("Jev choice disagrees with distribution")
        if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("invalid Jev confidence")
        deep = response["answers"]["q1"]
        if not isinstance(deep, dict) or deep.get("type") != "noul" or type(deep.get("noul")) not in (int, float) or not math.isfinite(deep["noul"]) or not 0 <= deep["noul"] <= 1:
            raise ValueError("invalid Jev escalation")
        return {"label": choice["choice"], "need_escalation": "YES" if deep["noul"] >= .5 else "NO",
                "score": float(probabilities[choice["choice"]]), "model": "jev", "model_version": MODEL}


def safe_prediction(predict, event):
    try:
        result = predict(dict(event))
        if not isinstance(result, dict) or result.get("label") not in LABELS or result.get("need_escalation") not in ("YES", "NO"):
            raise ValueError("invalid provider result")
        for key in ("score", "escalation_score"):
            if key in result and (type(result[key]) not in (int, float) or not math.isfinite(result[key]) or not 0 <= result[key] <= 1):
                raise ValueError("invalid provider score")
        return dict(result)
    except Exception as exc:
        return {"label": "UNKNOWN", "need_escalation": "YES", "model": "unavailable", "error": type(exc).__name__}
