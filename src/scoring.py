"""Transparent baseline and benchmark-calibrated logistic phishing model."""

from __future__ import annotations

import math

from src.rubric import PROMPT_HASH, RUBRIC_VERSION, rubric_features

FEATURE_VERSION = "email-features-v4-agentic"
SCHEMA_VERSION = "triage-result-v3-agentic"
OPTIONAL_UNKNOWN_SIGNALS = {"reply-to_missing", "return-path_missing",
                            "trusted_authentication_results_missing"}


def material_unknowns(unknown_signals: list[str]) -> list[str]:
    """Gaps that can hide analyzed content; routine absent headers stay visible."""
    return [name for name in unknown_signals if name not in OPTIONAL_UNKNOWN_SIGNALS]


def vector(signals: dict, rubric: dict) -> dict:
    return {**signals["features"], **rubric_features(rubric)}


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1 / (1 + z)
    z = math.exp(value)
    return z / (1 + z)


def probability(features: dict, artifact: dict) -> float:
    raw = artifact["classifier"]["intercept"] + sum(
        weight * float(features.get(name, 0))
        for name, weight in artifact["classifier"]["weights"].items()
    )
    calibration = artifact["calibrator"]
    return _sigmoid(calibration["slope"] * raw + calibration["intercept"])


def baseline(signals: dict) -> tuple[str, list[str]]:
    f = signals["features"]
    reasons = []
    if f["payment_request"] and f["impersonation"]:
        return "suspicious", ["payment request combined with an authority claim"]
    if f["credential_request"] and f["trusted_dmarc_fail"] and f["reply_domain_mismatch"]:
        return "malicious", ["credential request plus receiver-verified authentication failure and reply mismatch"]
    if f["credential_request"] and f["html_target_mismatch"]:
        return "malicious", ["credential request with deceptive link"]
    if f["risky_attachment"]:
        return "needs_review", ["attachment needs specialist inspection"]
    if f["credential_request"] and f["has_link"]:
        return "suspicious", ["credential request with link"]
    if f["payment_request"] or f["other_scam"]:
        return "suspicious", ["financial or scam language"]
    if f["trusted_dmarc_fail"] and (f["reply_domain_mismatch"] or f["return_domain_mismatch"]):
        return "suspicious", ["trusted receiver reports authentication failure and domain mismatch"]
    if any(f[key] for key in ("html_target_mismatch", "ip_url", "punycode_url", "protected_domain_lookalike")):
        return "suspicious", ["link destination needs investigation"]
    if f["spam"] and not any(f[key] for key in ("credential_request", "payment_request", "other_scam")):
        return "spam", ["bulk or promotional language"]
    if material_unknowns(signals["unknown_signals"]):
        reasons.append("evidence incomplete")
        return "needs_review", reasons
    return "benign", ["no suspicious indicators in assessed content"]


def decide(signals: dict, rubric: dict, artifact: dict | None, expected_model: str) -> dict:
    features = vector(signals, rubric)
    base_verdict, reasons = baseline(signals)
    flags = {
        "spam": bool(features["spam"]),
        "suspected_attachment_threat": bool(features["risky_attachment"]),
        "other_scam": bool(features["other_scam"]),
        "business_email_compromise": bool(features["payment_request"] and
                                           (features["impersonation"] or features["rubric_impersonation"] >= 2)),
    }
    result = {"features": features, "baseline_verdict": base_verdict,
              "baseline_reasons": reasons[:], "verdict": base_verdict,
              "phishing_probability_0_100": None, "probability_scope": None,
              "threat_flags": flags,
              "review_reasons": reasons[:] if base_verdict == "needs_review" else []}
    if not artifact:
        result["review_reasons"].append("calibrated_model_not_loaded")
        failures = [reason for reason in rubric["invalid_reasons"] if reason != "llm_not_configured"]
        if failures:
            result["verdict"] = "needs_review"
            result["review_reasons"].extend(failures)
        return result
    compatible = artifact.get("feature_version") == FEATURE_VERSION and artifact.get("rubric_version") == RUBRIC_VERSION
    compatible &= artifact.get("rubric_prompt_hash") == PROMPT_HASH
    compatible &= artifact.get("llm_model") == expected_model
    compatible &= artifact.get("backend_identity") == rubric.get("backend_identity")
    if not compatible:
        result["verdict"] = "needs_review"
        result["review_reasons"].append("calibration_artifact_incompatible")
        return result
    score = probability(features, artifact)
    result["phishing_probability_0_100"] = round(score * 100, 2)
    result["probability_scope"] = f"benchmark:{artifact['dataset_name']}:{artifact['dataset_version']}"
    ranges = artifact.get("feature_ranges", {})
    outside = [name for name, value in features.items()
               if name in ranges and not (ranges[name][0] <= value <= ranges[name][1])]
    if outside:
        result["review_reasons"].append("feature_outside_training_range:" + ",".join(sorted(outside)))
    low, high = artifact["thresholds"]["low"], artifact["thresholds"]["high"]
    blocking_rubric_errors = [reason for reason in rubric["invalid_reasons"]
                              if reason != "llm_not_configured" or expected_model != "none"]
    if blocking_rubric_errors:
        result["verdict"] = "needs_review"
        result["review_reasons"].extend(blocking_rubric_errors)
    elif score >= high:
        result["verdict"] = "malicious"
    elif score <= low:
        result["verdict"] = "spam" if flags["spam"] else "benign"
    else:
        result["verdict"] = "needs_review"
        result["review_reasons"].append("probability_between_review_thresholds")
    if flags["suspected_attachment_threat"]:
        result["verdict"] = "needs_review"
        result["review_reasons"].append("attachment_content_not_confirmed_safe")
    if material_unknowns(signals["unknown_signals"]) and result["verdict"] == "benign":
        result["verdict"] = "needs_review"
        result["review_reasons"].append("evidence_incomplete")
    if base_verdict == "malicious" and result["verdict"] in {"benign", "spam"}:
        result["verdict"] = "needs_review"
        result["review_reasons"].append("classifier_conflicts_with_strong_observations")
    if outside:
        result["verdict"] = "needs_review"
    result["review_reasons"] = sorted(set(result["review_reasons"]))
    return result


def finalize_decision(score: dict, rubric: dict, *, artifact_loaded: bool,
                      compatible_config: bool, agent_errors: list[str]) -> dict:
    """Apply the same final abstention policy in live runs and evaluation."""
    if not artifact_loaded:
        score["verdict"] = "needs_review"
    if not compatible_config:
        score["verdict"] = "needs_review"
        score["review_reasons"].append("signal_configuration_differs_from_calibration")
    if agent_errors:
        score["verdict"] = "needs_review"
        score["review_reasons"].extend(agent_errors)
    if agent_errors or rubric["invalid_reasons"] or not compatible_config:
        score["phishing_probability_0_100"] = None
        score["probability_scope"] = None
    proposed = rubric["proposed_verdict"]
    if proposed in {"suspicious", "needs_review"}:
        score["verdict"] = "needs_review"
        score["review_reasons"].append("final_judge_requests_review")
    if artifact_loaded and proposed in {"benign", "spam", "malicious"} and \
            score["verdict"] in {"benign", "spam", "malicious"} and proposed != score["verdict"]:
        score["verdict"] = "needs_review"
        score["review_reasons"].append("judge_category_conflicts_with_calibrated_decision")
    score["review_reasons"] = sorted(set(score["review_reasons"]))
    return score
