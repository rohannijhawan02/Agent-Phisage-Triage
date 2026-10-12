"""Train, calibrate and evaluate a versioned benchmark model."""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections import defaultdict
from pathlib import Path

from src.prompts import CRITERIA
from src.rubric import PROMPT_HASH, RUBRIC_VERSION
from src.scoring import FEATURE_VERSION, decide, finalize_decision, probability
from src.signals import FEATURE_NAMES

ARTIFACT_VERSION = "calibrated-logistic-v3-agentic"


def read_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def write_jsonl(path: str | Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _validate(rows: list[dict]) -> dict[str, list[dict]]:
    partitions = defaultdict(list)
    group_split = {}
    hash_split = {}
    content_split = {}
    indicator_split = {}
    seen_hashes = set()
    for row in rows:
        split = row.get("split")
        if split not in {"train", "calibration", "test"}:
            raise ValueError("every row needs train, calibration, or test split")
        if row.get("label") not in {0, 1}:
            raise ValueError("label must be 0 (non-phishing) or 1 (phishing)")
        if not row.get("source") or not row.get("group"):
            raise ValueError("every row needs source and campaign/domain group")
        if not isinstance(row.get("unknown_signals"), list) or row.get("proposed_verdict") not in {
                "benign", "spam", "suspicious", "malicious", "needs_review"}:
            raise ValueError("every row needs unknown_signals and proposed_verdict from prepare")
        if row.get("sha256") in seen_hashes:
            raise ValueError("duplicate email hash in dataset")
        seen_hashes.add(row["sha256"])
        for mapping, key in ((group_split, row.get("group")), (hash_split, row.get("sha256")),
                             (content_split, row.get("content_fingerprint"))):
            if key and key in mapping and mapping[key] != split:
                raise ValueError(f"related emails cross partitions: {key}")
            if key:
                mapping[key] = split
        iocs = row.get("iocs") or {}
        for category in ("urls", "attachment_hashes"):
            for indicator in iocs.get(category, []):
                key = (category, indicator)
                if key in indicator_split and indicator_split[key] != split:
                    raise ValueError(f"shared indicator crosses partitions: {indicator}")
                indicator_split[key] = split
        partitions[split].append(row)
    for split in ("train", "calibration", "test"):
        if {row["label"] for row in partitions[split]} != {0, 1}:
            raise ValueError(f"{split} needs both phishing and non-phishing examples")
    return partitions


def _raw_score(features: dict, weights: dict, intercept: float) -> float:
    return intercept + sum(float(features.get(name, 0)) * value for name, value in weights.items())


def _choose_thresholds(probs: list[float], labels: list[int]) -> dict:
    # A release with too few calibration examples does not auto-clear or auto-condemn.
    if len(probs) < 100 or min(labels.count(0), labels.count(1)) < 20:
        return {"low": -1.0, "high": 2.0, "status": "review_only_insufficient_calibration"}
    low = -1.0
    high = 2.0
    for threshold in sorted(set(probs)):
        negative = [y for p, y in zip(probs, labels) if p <= threshold]
        if len(negative) >= 20 and 1 - sum(negative) / len(negative) >= 0.98:
            low = threshold
        positive = [y for p, y in zip(probs, labels) if p >= threshold]
        if len(positive) >= 20 and sum(positive) / len(positive) >= 0.95:
            high = min(high, threshold)
    if low >= high:
        low, high = -1.0, 2.0
    return {"low": low, "high": high, "status": "calibration_tuned" if low >= 0 or high <= 1 else "review_only_targets_unmet"}


def fit(rows: list[dict], dataset_name: str, dataset_version: str) -> dict:
    """Fit on train, Platt-calibrate on calibration, never learn from test."""
    from sklearn.linear_model import LogisticRegression

    partitions = _validate(rows)
    if any(row.get("dataset_name") not in (None, dataset_name) or
           row.get("dataset_version") not in (None, dataset_version) for row in rows):
        raise ValueError("feature records and requested dataset identity differ")
    model_ids = {row.get("model_version", "none") for row in rows}
    if len(model_ids) != 1:
        raise ValueError("all partitions must use the same LLM model version")
    if model_ids == {"none"}:
        raise ValueError("agentic calibration requires a configured LLM and valid agent outputs")
    backends = {row.get("backend_identity", "none") for row in rows}
    if len(backends) != 1:
        raise ValueError("all partitions must use the same LLM endpoint and provider")
    configs = {json.dumps(row.get("signal_config"), sort_keys=True) for row in rows}
    if len(configs) != 1:
        raise ValueError("all partitions must use the same signal configuration")
    if any(row.get("feature_version") != FEATURE_VERSION or row.get("rubric_version") != RUBRIC_VERSION or
           row.get("rubric_prompt_hash") != PROMPT_HASH for row in rows):
        raise ValueError("prepared feature or rubric version is incompatible")
    if any(row.get("rubric_invalid_reasons") for row in rows):
        raise ValueError("dataset contains invalid LLM rubric evidence or failed calls")
    names = sorted({name for row in rows for name in row["features"]})
    train = partitions["train"]
    x_train = [[float(row["features"].get(name, 0)) for name in names] for row in train]
    estimator = LogisticRegression(C=1.0, max_iter=2000)
    estimator.fit(x_train, [row["label"] for row in train])
    weights = {name: float(value) for name, value in zip(names, estimator.coef_[0])}
    intercept = float(estimator.intercept_[0])
    calibration = partitions["calibration"]
    logits = [_raw_score(row["features"], weights, intercept) for row in calibration]
    calibrator = LogisticRegression(C=1.0, max_iter=2000)
    calibrator.fit([[value] for value in logits], [row["label"] for row in calibration])
    slope = float(calibrator.coef_[0][0])
    calibration_intercept = float(calibrator.intercept_[0])
    probs = [1 / (1 + math.exp(-max(-700, min(700, slope * value + calibration_intercept)))) for value in logits]
    hashes = sorted(row["sha256"] for row in rows)
    artifact = {"artifact_version": ARTIFACT_VERSION, "feature_version": FEATURE_VERSION,
                "rubric_version": RUBRIC_VERSION, "rubric_prompt_hash": PROMPT_HASH,
                "llm_model": model_ids.pop(), "backend_identity": backends.pop(),
                "signal_config": json.loads(configs.pop()),
                "dataset_name": dataset_name, "dataset_version": dataset_version,
                "dataset_fingerprint": hashlib.sha256("\n".join(hashes).encode()).hexdigest(),
                "split_sizes": {key: len(value) for key, value in partitions.items()},
                "classifier": {"weights": weights, "intercept": intercept},
                "feature_ranges": {name: [min(float(row["features"].get(name, 0)) for row in train),
                                          max(float(row["features"].get(name, 0)) for row in train)]
                                   for name in names},
                "calibrator": {"slope": slope, "intercept": calibration_intercept},
                "thresholds": _choose_thresholds(probs, [row["label"] for row in calibration])}
    return artifact


def _metrics(rows: list[dict], artifact: dict) -> dict:
    if not rows:
        return {}
    probs = [probability(row["features"], artifact) for row in rows]
    labels = [row["label"] for row in rows]
    predictions = [int(p >= 0.5) for p in probs]
    decisions = [_operational_verdict(row, artifact) for row in rows]
    tp = sum(p == 1 and y == 1 for p, y in zip(predictions, labels))
    fp = sum(p == 1 and y == 0 for p, y in zip(predictions, labels))
    fn = sum(p == 0 and y == 1 for p, y in zip(predictions, labels))
    tn = sum(p == 0 and y == 0 for p, y in zip(predictions, labels))
    legitimate = [i for i, row in enumerate(rows)
                  if row["label"] == 0 and set(row.get("slices", [])) & {"benign", "ham", "legitimate", "modern_benign"}]
    legitimate_fp = sum(predictions[i] == 1 for i in legitimate)
    auto_malicious = [decision == "malicious" for decision in decisions]
    review = [decision == "needs_review" for decision in decisions]
    phishing = sum(labels)
    nonphishing = len(labels) - phishing
    legitimate_auto_fp = sum(auto_malicious[i] for i in legitimate)
    bins = []
    for n in range(10):
        indices = [i for i, p in enumerate(probs) if n / 10 <= p < (n + 1) / 10 or (n == 9 and p == 1)]
        if indices:
            bins.append({"range": f"{n/10:.1f}-{(n+1)/10:.1f}", "count": len(indices),
                         "mean_probability": round(sum(probs[i] for i in indices) / len(indices), 4),
                         "observed_rate": round(sum(labels[i] for i in indices) / len(indices), 4)})
    return {"count": len(rows), "phishing_recall": tp / (tp + fn) if tp + fn else None,
            "phishing_precision": tp / (tp + fp) if tp + fp else None,
            "false_positives_per_1000_nonphishing": 1000 * fp / (fp + tn) if fp + tn else None,
            "false_positives_per_1000_legitimate": 1000 * legitimate_fp / len(legitimate) if legitimate else None,
            "brier_score": sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(rows),
            "review_rate": sum(review) / len(rows),
            "operational": {
                "phishing_capture_rate": sum(y == 1 and (flag or held) for y, flag, held in zip(labels, auto_malicious, review)) / phishing if phishing else None,
                "auto_malicious_recall": sum(y == 1 and flag for y, flag in zip(labels, auto_malicious)) / phishing if phishing else None,
                "false_auto_malicious_per_1000_nonphishing": 1000 * sum(y == 0 and flag for y, flag in zip(labels, auto_malicious)) / nonphishing if nonphishing else None,
                "false_auto_malicious_per_1000_legitimate": 1000 * legitimate_auto_fp / len(legitimate) if legitimate else None,
                "auto_decision_rate": 1 - sum(review) / len(rows),
                "verdict_counts": {name: decisions.count(name) for name in ("benign", "spam", "malicious", "needs_review")},
            },
            "mean_cost_usd": sum(float(row.get("cost_usd", 0)) for row in rows) / len(rows),
            "mean_latency_sec": sum(float(row.get("elapsed_seconds", 0)) for row in rows) / len(rows),
            "unsupported_evidence_count": sum(any("unsupported_evidence" in reason for reason in row.get("rubric_invalid_reasons", [])) for row in rows),
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}, "calibration_bins": bins}


def _operational_verdict(row: dict, artifact: dict) -> str:
    """Replay the live scoring and abstention policy on prepared feature rows."""
    features = row["features"]
    signals = {"features": {name: features.get(name, 0) for name in FEATURE_NAMES},
               "unknown_signals": row["unknown_signals"]}
    rubric = {"ratings": {name: {"score": features.get(f"rubric_{name}", 0), "evidence_ids": []}
                          for name in CRITERIA},
              "invalid_reasons": row.get("rubric_invalid_reasons", []),
              "proposed_verdict": row["proposed_verdict"],
              "backend_identity": row["backend_identity"]}
    compatible_config = row["signal_config"] == artifact["signal_config"]
    score = decide(signals, rubric, artifact if compatible_config else None, row["model_version"])
    return finalize_decision(score, rubric, artifact_loaded=True,
                             compatible_config=compatible_config, agent_errors=[])["verdict"]


def _classification_metrics(labels: list[int], predictions: list[int]) -> dict:
    tp = sum(p == 1 and y == 1 for p, y in zip(predictions, labels))
    fp = sum(p == 1 and y == 0 for p, y in zip(predictions, labels))
    fn = sum(p == 0 and y == 1 for p, y in zip(predictions, labels))
    tn = sum(p == 0 and y == 0 for p, y in zip(predictions, labels))
    return {"recall": tp / (tp + fn) if tp + fn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "false_positives_per_1000_legitimate": 1000 * fp / (fp + tn) if fp + tn else None}


def _text_baseline(partitions: dict) -> dict | None:
    """Train a simple subject/body baseline if the original files are available."""
    rows = partitions["train"] + partitions["test"]
    if not all(row.get("path") and Path(row["path"]).is_file() for row in rows):
        return None
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from src.ingest import parse_eml

    def text_of(row):
        mail = parse_eml(row["path"])
        return mail["headers"].get("Subject", "") + "\n" + "\n".join(part["text"] for part in mail["body"])

    train, test = partitions["train"], partitions["test"]
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=20000)
    train_matrix = vectorizer.fit_transform([text_of(row) for row in train])
    test_matrix = vectorizer.transform([text_of(row) for row in test])
    model = LogisticRegression(max_iter=2000)
    model.fit(train_matrix, [row["label"] for row in train])
    return _classification_metrics([row["label"] for row in test], model.predict(test_matrix).tolist())


def evaluate(rows: list[dict], artifact: dict) -> dict:
    partitions = _validate(rows)
    if any(row.get("model_version", "none") != artifact["llm_model"] or
           row.get("backend_identity", "none") != artifact["backend_identity"] or
           row.get("signal_config") != artifact["signal_config"] or
           row.get("feature_version") != artifact["feature_version"] or
           row.get("rubric_version") != artifact["rubric_version"] or
           row.get("rubric_prompt_hash") != artifact["rubric_prompt_hash"] for row in rows):
        raise ValueError("evaluation records and model artifact use different pipeline versions")
    if any(row.get("dataset_name") not in (None, artifact["dataset_name"]) or
           row.get("dataset_version") not in (None, artifact["dataset_version"]) for row in rows):
        raise ValueError("evaluation records and model artifact use different datasets")
    fingerprint = hashlib.sha256("\n".join(sorted(row["sha256"] for row in rows)).encode()).hexdigest()
    if fingerprint != artifact["dataset_fingerprint"]:
        raise ValueError("evaluation emails differ from the artifact dataset")
    test = [row for row in rows if row.get("split") == "test"]
    if not test:
        raise ValueError("no locked test records")
    overall = _metrics(test, artifact)
    slices = sorted({name for row in test for name in row.get("slices", [])})
    deterministic = _classification_metrics([row["label"] for row in test],
        [int(row.get("baseline_verdict") in {"suspicious", "malicious"}) for row in test])
    return {"dataset": artifact["dataset_name"], "version": artifact["dataset_version"],
            "overall": overall,
            "data_audit": {"split_sizes": {name: len(partitions[name]) for name in ("train", "calibration", "test")},
                           "sources": sorted({row.get("source", "") for row in rows}),
                           "date_ranges": {name: [min(dates), max(dates)] if dates else None
                                           for name in ("train", "calibration", "test")
                                           for dates in [[row["date"] for row in partitions[name] if row.get("date")]]}},
            "baselines": {"deterministic": deterministic, "text_tfidf": _text_baseline(partitions)},
            "slices": {name: _metrics([row for row in test if name in row.get("slices", [])], artifact)
                       for name in slices},
            "errors": [{"sha256": row["sha256"], "label": row["label"],
                        "probability": round(probability(row["features"], artifact), 4),
                        "operational_verdict": _operational_verdict(row, artifact),
                        "source": row.get("source", "")}
                       for row in test if (_operational_verdict(row, artifact) == "malicious" and row["label"] == 0) or
                       (_operational_verdict(row, artifact) in {"benign", "spam"} and row["label"] == 1)]}


def compare(incumbent_rows: list[dict], candidate_rows: list[dict], incumbent: dict, candidate: dict) -> dict:
    old = evaluate(incumbent_rows, incumbent)["overall"]
    new = evaluate(candidate_rows, candidate)["overall"]
    old_test = {row["sha256"]: row for row in incumbent_rows if row.get("split") == "test"}
    new_test = {row["sha256"]: row for row in candidate_rows if row.get("split") == "test"}
    if old_test.keys() != new_test.keys():
        raise ValueError("incumbent and candidate need identical locked test emails")
    if any(old_test[key]["label"] != new_test[key]["label"] for key in old_test):
        raise ValueError("paired locked test labels differ")
    keys = sorted(old_test)
    old_scores = [probability(old_test[key]["features"], incumbent) for key in keys]
    new_scores = [probability(new_test[key]["features"], candidate) for key in keys]
    old_decisions = [_operational_verdict(old_test[key], incumbent) for key in keys]
    new_decisions = [_operational_verdict(new_test[key], candidate) for key in keys]
    crossings = sum(a != b for a, b in zip(old_decisions, new_decisions))
    old_ops, new_ops = old["operational"], new["operational"]
    checks = {
        "capture": new_ops["phishing_capture_rate"] >= old_ops["phishing_capture_rate"] - 0.02,
        "auto_malicious_recall": new_ops["auto_malicious_recall"] >= old_ops["auto_malicious_recall"] - 0.02,
        "false_positives": (new_ops["false_auto_malicious_per_1000_nonphishing"] <=
                            old_ops["false_auto_malicious_per_1000_nonphishing"] + 10),
        "review_rate": new["review_rate"] <= old["review_rate"] + 0.05,
        "brier": new["brier_score"] <= old["brier_score"] + 0.02,
        "evidence": new["unsupported_evidence_count"] == 0,
    }
    return {"promote": all(checks.values()), "checks": checks, "incumbent": old,
            "candidate": new, "mean_absolute_score_change": sum(abs(a-b) for a,b in zip(old_scores,new_scores))/len(keys),
            "decision_threshold_crossings": crossings,
            "case_movements": [{"sha256": key, "old_score": round(a, 4), "new_score": round(b, 4),
                                "old_verdict": old_decisions[index], "new_verdict": new_decisions[index]}
                               for index, (key, a, b) in enumerate(zip(keys, old_scores, new_scores))
                               if old_decisions[index] != new_decisions[index]]}


def evaluate_legacy(rows: list[dict]) -> dict:
    """Optional research comparison with the copied upstream LangGraph pipeline."""
    from src.legacy_graph import run

    test = [row for row in rows if row.get("split") == "test"]
    if not test:
        raise ValueError("no locked test records")
    predictions = []
    labels = []
    errors = []
    total_cost = 0.0
    total_latency = 0.0
    for row in test:
        started = time.perf_counter()
        try:
            raw = Path(row["path"]).read_text(encoding="utf-8", errors="replace")
            result = run(raw)
            if result.get("verdict") not in {"benign", "spam", "suspicious", "malicious"}:
                raise ValueError("legacy verdict missing or invalid")
            predictions.append(int(result["verdict"] in {"suspicious", "malicious"}))
            labels.append(row["label"])
            total_cost += float(result.get("total_cost_usd", 0) or 0)
        except Exception as exc:
            errors.append({"sha256": row["sha256"], "error": f"{type(exc).__name__}: {exc}"})
        total_latency += time.perf_counter() - started
    return {"evaluated": len(labels), "errors": errors,
            "metrics": _classification_metrics(labels, predictions) if labels else {},
            "total_cost_usd": round(total_cost, 6), "total_latency_sec": round(total_latency, 3),
            "note": "Research baseline only: inherited logic may trust Authentication-Results inside raw .eml files."}
