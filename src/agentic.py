"""Structured LLM specialists, two-round debate, and evidence validation."""

from __future__ import annotations

import json
import os

from src.llm import complete_with_usage
from src.prompts import CRITERIA, DEBATE_SYSTEM, FINAL_SYSTEM, RUBRIC, SPECIALIST_PROMPTS, SPECIALIST_SYSTEM

VERDICTS = {"benign", "spam", "suspicious", "malicious", "needs_review"}
SCOPES = {
    "metadata": {"impersonation", "social_engineering"},
    "content": {"impersonation", "credential_request", "payment_diversion", "social_engineering"},
    "url": {"link_deception", "credential_request"},
    "attachment": {"attachment_concern", "credential_request", "payment_diversion"},
}


def configured_model(model: str | None) -> str | None:
    return model or os.environ.get("TRIAGE_MODEL")


def _json_completion(system: str, payload: dict, model: str | None) -> tuple[dict, dict, list[str]]:
    if not model:
        return {}, {}, ["llm_not_configured"]
    try:
        raw, usage = complete_with_usage(system, json.dumps(payload, ensure_ascii=False), model=model)
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return {}, usage, ["llm_output_not_object"]
        return parsed, usage, []
    except Exception as exc:
        return {}, {}, [f"llm_failure:{type(exc).__name__}"]


def _evidence_for(mail: dict, role: str) -> tuple[list[dict], bool]:
    evidence = mail["evidence"]
    if role == "metadata":
        selected = [item for item in evidence if item["id"].startswith(("header:", "attestation:"))
                    and item["id"] != "header:authentication-results"]
    elif role == "content":
        non_attachment = {part["id"] for part in mail["body"] if not part["attachment"]}
        selected = [item for item in evidence if item["id"] == "header:subject" or
                    item["source"] in non_attachment]
    elif role == "url":
        selected = [item for item in evidence if "-link:" in item["id"] or
                    item["id"].startswith("intel:urls:") or item["id"].startswith("intel:domains:")]
    else:
        selected = [item for item in evidence if item["id"].startswith("attachment:") or
                    item["id"].startswith("intel:hashes:") or
                    item["source"].startswith("body:") and any(
                        part["id"] == item["source"] and part["attachment"] for part in mail["body"])]
    return ([{"id": item["id"], "text": item["text"][:500]} for item in selected[:100]],
            len(selected) > 100)


def _valid_ids(ids: object, allowed: set[str]) -> list[str] | None:
    if not isinstance(ids, list) or len(ids) > 20 or any(
            not isinstance(value, str) or value not in allowed for value in ids):
        return None
    return sorted(set(ids))


def specialist(role: str, mail: dict, signals: dict, intelligence: list[dict],
               memory: list[dict], model: str | None) -> dict:
    evidence, truncated = _evidence_for(mail, role)
    allowed = {item["id"] for item in evidence}
    payload = {"evidence": evidence,
               "deterministic_findings": [item for item in signals["findings"] if item["evidence_id"] in allowed],
               "unknown_signals": signals["unknown_signals"]}
    if role == "url":
        payload["intelligence_hits"] = intelligence
    if role in {"metadata", "url"}:
        payload["related_confirmed_cases"] = memory
    system = SPECIALIST_SYSTEM.format(role=role, scope=SPECIALIST_PROMPTS[role], rubric=RUBRIC)
    raw, usage, errors = _json_completion(system, payload, model)
    if errors and not raw:
        return {"role": role, "provisional_verdict": "needs_review", "findings": [],
                "uncertainties": [], "invalid_reasons": errors, "usage": usage}
    if truncated:
        errors.append("specialist_evidence_truncated")
    findings = []
    raw_findings = raw.get("findings", []) if isinstance(raw.get("findings"), list) else []
    if len(raw_findings) > 20:
        errors.append("specialist_findings_truncated")
    for item in raw_findings[:20]:
        if not isinstance(item, dict):
            errors.append("finding_not_object")
            continue
        criterion, score = item.get("criterion"), item.get("score")
        ids = _valid_ids(item.get("evidence_ids"), allowed)
        if criterion not in SCOPES[role] or type(score) is not int or score not in range(4) or ids is None or score > 0 and not ids:
            errors.append("invalid_or_unsupported_finding")
            continue
        findings.append({"criterion": criterion, "score": score, "evidence_ids": ids,
                         "rationale": str(item.get("rationale", ""))[:500]})
    verdict = raw.get("provisional_verdict")
    if verdict not in VERDICTS:
        errors.append("invalid_provisional_verdict")
        verdict = "needs_review"
    return {"role": role, "provisional_verdict": verdict, "findings": findings,
            "uncertainties": [str(x)[:200] for x in raw.get("uncertainties", [])[:10]]
            if isinstance(raw.get("uncertainties"), list) else [],
            "invalid_reasons": errors, "usage": usage}


def debate_turn(stance: str, round_number: int, mail: dict, specialists: dict,
                previous: list[dict], model: str | None) -> dict:
    visible = [item for item in mail["evidence"] if item["id"] != "header:authentication-results"][:100]
    allowed = {item["id"] for item in visible}
    allowed.update(ref for result in specialists.values() for item in result["findings"]
                   for ref in item["evidence_ids"])
    validated = {name: {key: value for key, value in result.items() if key != "usage"}
                 for name, result in specialists.items()}
    payload = {"round": round_number, "specialist_findings": validated,
               "email_evidence": [{"id": item["id"], "text": item["text"][:400]}
                                  for item in visible],
               "prior_arguments": [{key: value for key, value in item.items() if key != "usage"}
                                   for item in previous], "allowed_evidence_ids": sorted(allowed)}
    raw, usage, errors = _json_completion(DEBATE_SYSTEM.format(stance=stance), payload, model)
    if errors and not raw:
        return {"stance": stance, "round": round_number, "argument": "",
                "evidence_ids": [], "counterpoints": [], "uncertainties": [],
                "invalid_reasons": errors, "usage": usage}
    ids = _valid_ids(raw.get("evidence_ids"), allowed)
    supported = ids is not None
    if not supported:
        errors.append("unsupported_debate_evidence")
        ids = []
    if not raw.get("argument") and not errors:
        errors.append("argument_missing")
    return {"stance": stance, "round": round_number,
            "argument": str(raw.get("argument", ""))[:1200] if supported else "",
            "evidence_ids": ids,
            "counterpoints": [str(x)[:300] for x in raw.get("counterpoints", [])[:5]]
            if isinstance(raw.get("counterpoints"), list) else [],
            "uncertainties": [str(x)[:200] for x in raw.get("uncertainties", [])[:5]]
            if isinstance(raw.get("uncertainties"), list) else [],
            "invalid_reasons": errors, "usage": usage}


def final_judge(mail: dict, specialists: dict, debate: list[dict], model: str | None) -> dict:
    evidence = [item for item in mail["evidence"] if item["id"] != "header:authentication-results"]
    required = {ref for result in specialists.values() for item in result["findings"]
                for ref in item["evidence_ids"]}
    required.update(ref for turn in debate for ref in turn["evidence_ids"])
    selected = evidence[:200]
    selected_ids = {item["id"] for item in selected}
    selected.extend(item for item in evidence if item["id"] in required and item["id"] not in selected_ids)
    allowed = {item["id"] for item in selected}
    payload = {"evidence": [{"id": item["id"], "text": item["text"][:500]} for item in selected],
               "specialists": {name: {key: value for key, value in result.items() if key != "usage"}
                               for name, result in specialists.items()},
               "debate": [{key: value for key, value in turn.items() if key != "usage"} for turn in debate]}
    raw, usage, errors = _json_completion(FINAL_SYSTEM.format(rubric=RUBRIC), payload, model)
    if errors and not raw:
        return {"ratings": {criterion: {"score": 0, "evidence_ids": []} for criterion in CRITERIA},
                "proposed_verdict": "needs_review", "explanation": "",
                "explanation_evidence_ids": [], "uncertainties": [],
                "invalid_reasons": errors, "usage": usage,
                "model": model, "resolved_model": usage.get("resolved_model", model) if usage else model}
    if len(evidence) > 200 or len(selected) > 250:
        errors.append("judge_evidence_truncated")
    ratings = {}
    returned = raw.get("ratings") if isinstance(raw.get("ratings"), dict) else {}
    for criterion in CRITERIA:
        item = returned.get(criterion, {})
        score = item.get("score") if isinstance(item, dict) else None
        ids = _valid_ids(item.get("evidence_ids"), allowed) if isinstance(item, dict) else None
        if type(score) is not int or score not in range(4) or ids is None or score > 0 and not ids:
            errors.append(f"{criterion}:invalid_or_unsupported_rating")
            ratings[criterion] = {"score": 0, "evidence_ids": []}
        else:
            ratings[criterion] = {"score": score, "evidence_ids": ids if score else []}
    explanation_ids = _valid_ids(raw.get("explanation_evidence_ids"), allowed)
    if not raw.get("explanation"):
        errors.append("explanation_missing")
    if explanation_ids is None or raw.get("explanation") and not explanation_ids:
        errors.append("unsupported_explanation")
        explanation_ids = []
    proposed = raw.get("proposed_verdict")
    if proposed not in VERDICTS:
        errors.append("invalid_proposed_verdict")
        proposed = "needs_review"
    return {"ratings": ratings, "proposed_verdict": proposed,
            "explanation": str(raw.get("explanation", ""))[:1000] if explanation_ids else "",
            "explanation_evidence_ids": explanation_ids,
            "uncertainties": [str(x)[:200] for x in raw.get("uncertainties", [])[:10]]
            if isinstance(raw.get("uncertainties"), list) else [],
            "invalid_reasons": errors, "usage": usage,
            "model": model, "resolved_model": usage.get("resolved_model", model) if usage else model}
