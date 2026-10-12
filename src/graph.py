"""Production LangGraph email triage: four specialists, debate, and judge."""

from __future__ import annotations

import operator
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from src.agentic import configured_model, debate_turn, final_judge, specialist
from src.context import confirmed_case_memory, indicators, local_intelligence
from src.ingest import parse_eml
from src.llm import backend_identity
from src.mitre import map_techniques
from src.prompts import PROMPT_HASH
from src.report import render_report
from src.rubric import RUBRIC_VERSION
from src.scoring import FEATURE_VERSION, SCHEMA_VERSION, decide, finalize_decision
from src.signals import extract_signals


def _merge_usage(left: dict, right: dict) -> dict:
    return {**left, **right}


def _snapshot_id(path: str | None) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if path else "none"


class TriageState(TypedDict, total=False):
    path: str
    model: str | None
    artifact: dict | None
    auth_attestations: dict | None
    protected_domains: set[str]
    intel_file: str | None
    memory_file: str | None
    as_of: datetime | None
    started: float
    mail: dict
    signals: dict
    iocs: dict
    intelligence_hits: list[dict]
    related_cases: list[dict]
    metadata_analysis: dict
    content_analysis: dict
    url_analysis: dict
    attachment_analysis: dict
    debate: Annotated[list[dict], operator.add]
    rubric: dict
    usage: Annotated[dict, _merge_usage]
    result: dict


def _ingest(state: TriageState) -> dict:
    return {"mail": parse_eml(state["path"])}


def _facts(state: TriageState) -> dict:
    mail = state["mail"]
    attestation = (state.get("auth_attestations") or {}).get(mail["sha256"])
    if isinstance(attestation, dict) and attestation.get("source") and all(
            attestation.get(key) in {"pass", "fail", "unknown"} for key in ("spf", "dkim", "dmarc")):
        attestation = {**attestation, "sha256": mail["sha256"]}
        mail["evidence"].append({"id": "attestation:authentication", "source": "trusted-mail-system-metadata",
                                 "text": f"{attestation['source']}: SPF={attestation.get('spf')}, "
                                         f"DKIM={attestation.get('dkim')}, DMARC={attestation.get('dmarc')}"})
    else:
        attestation = None
    iocs = indicators(mail)
    intel = local_intelligence(state.get("intel_file"), iocs)
    for index, hit in enumerate(intel):
        hit["evidence_id"] = f"intel:{hit['type']}:{index}"
        mail["evidence"].append({"id": hit["evidence_id"], "source": "local-intelligence",
                                 "text": f"{hit['source']} reports {hit['indicator']} as {hit['verdict']} "
                                         f"(observed {hit['observed_at']})"})
    signals = extract_signals(mail, attestation, state.get("protected_domains"))
    if intel:
        signals["features"]["local_intelligence_hit"] = 1
        signals["findings"].extend({"signal": "local_intelligence_hit", "evidence_id": hit["evidence_id"],
                                     "detail": f"Local intelligence reports {hit['indicator']} as {hit['verdict']}"}
                                    for hit in intel)
    return {"mail": mail, "signals": signals, "iocs": iocs,
            "intelligence_hits": intel,
            "related_cases": confirmed_case_memory(state.get("memory_file"), mail, iocs,
                                                   state.get("as_of"))}


def _specialist_node(role: str):
    def node(state: TriageState) -> dict:
        result = specialist(role, state["mail"], state["signals"],
                            state["intelligence_hits"], state["related_cases"], state.get("model"))
        return {f"{role}_analysis": {key: value for key, value in result.items() if key != "usage"},
                "usage": {f"{role}_agent": result["usage"]}}
    return node


def _specialists(state: TriageState) -> dict:
    return {role: state[f"{role}_analysis"] for role in ("metadata", "content", "url", "attachment")}


def _debate_node(stance: str, round_number: int):
    def node(state: TriageState) -> dict:
        turn = debate_turn(stance, round_number, state["mail"], _specialists(state),
                           state.get("debate", []), state.get("model"))
        return {"debate": [{key: value for key, value in turn.items() if key != "usage"}],
                "usage": {f"debate_{stance}_{round_number}": turn["usage"]}}
    return node


def _judge(state: TriageState) -> dict:
    result = final_judge(state["mail"], _specialists(state), state.get("debate", []), state.get("model"))
    rubric = {**result, "version": RUBRIC_VERSION, "backend_identity": backend_identity()}
    return {"rubric": rubric, "usage": {"final_verdict_agent": result["usage"]}}


def _decide_and_report(state: TriageState) -> dict:
    mail, signals, rubric = state["mail"], state["signals"], state["rubric"]
    artifact = state.get("artifact")
    config = {"auth_attestation_mode": "sidecar" if state.get("auth_attestations") is not None else "none",
              "protected_domains": sorted(state.get("protected_domains") or []),
              "intel_snapshot": _snapshot_id(state.get("intel_file")),
              "memory_snapshot": _snapshot_id(state.get("memory_file"))}
    compatible_config = not artifact or artifact.get("signal_config") == config
    score = decide(signals, rubric, artifact if compatible_config else None, rubric.get("resolved_model") or "none")
    all_agent_errors = [reason for item in _specialists(state).values() for reason in item["invalid_reasons"]]
    all_agent_errors.extend(reason for turn in state.get("debate", []) for reason in turn["invalid_reasons"])
    score = finalize_decision(score, rubric, artifact_loaded=bool(artifact),
                              compatible_config=compatible_config, agent_errors=all_agent_errors)
    evidence_ids = {item["id"] for item in mail["evidence"]}
    if any(item["evidence_id"] not in evidence_ids for item in signals["findings"]):
        raise AssertionError("deterministic finding refers to missing evidence")
    leading = "; ".join(item["detail"] for item in signals["findings"][:3])
    use_judge_explanation = not rubric["invalid_reasons"] and bool(rubric["explanation"])
    explanation = rubric["explanation"] if use_judge_explanation else leading
    explanation_ids = (rubric["explanation_evidence_ids"] if use_judge_explanation else
                       [item["evidence_id"] for item in signals["findings"][:3]])
    if not explanation:
        explanation = "The available evidence does not support a reliable automated conclusion."
    if score["verdict"] == "needs_review":
        explanation += " Analyst review is required."
    usage = state.get("usage", {})
    tokens = sum(int(item.get("total_tokens", 0) or 0) for item in usage.values())
    cost = round(sum(float(item.get("cost_usd", 0) or 0) for item in usage.values()), 6)
    result = {"schema_version": SCHEMA_VERSION, "feature_version": FEATURE_VERSION,
              "rubric_version": RUBRIC_VERSION, "rubric_prompt_hash": PROMPT_HASH,
              "signal_config": config, "file": mail["path"], "sha256": mail["sha256"],
              "content_fingerprint": mail["content_fingerprint"],
              "subject": mail["headers"].get("Subject", ""), "sender": mail["headers"].get("From", ""),
              "risk_score": score["phishing_probability_0_100"],
              "verdict": score["verdict"], "explanation": explanation,
              "phishing_probability_0_100": score["phishing_probability_0_100"],
              "probability_scope": score["probability_scope"],
              "baseline_verdict": score["baseline_verdict"],
              "baseline_reasons": score["baseline_reasons"], "threat_flags": score["threat_flags"],
              "review_reasons": score["review_reasons"], "unknown_signals": signals["unknown_signals"],
              "features": score["features"], "findings": signals["findings"],
              "evidence": mail["evidence"], "links": mail["links"], "attachments": mail["attachments"],
              "iocs": state["iocs"], "intelligence_hits": state["intelligence_hits"],
              "related_cases": state["related_cases"], "agents": _specialists(state),
              "debate": state.get("debate", []),
              "rubric": {key: value for key, value in rubric.items() if key != "usage"},
              "explanation_evidence_ids": explanation_ids,
              "model_version": rubric.get("resolved_model") or "none", "requested_model": state.get("model"),
              "backend_identity": rubric["backend_identity"],
              "calibration_version": artifact.get("artifact_version") if artifact else None,
              "tokens": tokens, "cost_usd": cost, "per_agent_usage": usage,
              "elapsed_seconds": round(time.perf_counter() - state["started"], 3)}
    result["mitre_attack"] = map_techniques(signals, rubric, mail)
    result["report_markdown"] = render_report(result)
    return {"result": result}


def build_graph():
    graph = StateGraph(TriageState)
    graph.add_node("parse_eml", _ingest)
    graph.add_node("extract_evidence", _facts)
    for role in ("metadata", "content", "url", "attachment"):
        graph.add_node(f"{role}_agent", _specialist_node(role))
    graph.add_node("debate_phishing_round_1", _debate_node("phishing", 1))
    graph.add_node("debate_legitimate_round_1", _debate_node("legitimate", 1))
    graph.add_node("debate_phishing_round_2", _debate_node("phishing", 2))
    graph.add_node("debate_legitimate_round_2", _debate_node("legitimate", 2))
    graph.add_node("final_verdict_agent", _judge)
    graph.add_node("score_map_report", _decide_and_report)
    graph.add_edge(START, "parse_eml")
    graph.add_edge("parse_eml", "extract_evidence")
    for role in ("metadata", "content", "url", "attachment"):
        graph.add_edge("extract_evidence", f"{role}_agent")
    graph.add_edge(["metadata_agent", "content_agent", "url_agent", "attachment_agent"],
                   "debate_phishing_round_1")
    graph.add_edge("debate_phishing_round_1", "debate_legitimate_round_1")
    graph.add_edge("debate_legitimate_round_1", "debate_phishing_round_2")
    graph.add_edge("debate_phishing_round_2", "debate_legitimate_round_2")
    graph.add_edge("debate_legitimate_round_2", "final_verdict_agent")
    graph.add_edge("final_verdict_agent", "score_map_report")
    graph.add_edge("score_map_report", END)
    return graph.compile()


def run(path: str | Path, *, artifact: dict | None = None, model: str | None = None,
        auth_attestations: dict | None = None, protected_domains: set[str] | None = None,
        intel_file: str | Path | None = None, memory_file: str | Path | None = None,
        as_of: str | datetime | None = None) -> dict:
    """Invoke the production graph for one .eml and return the analyst record."""
    if isinstance(as_of, str):
        value = as_of.replace("Z", "+00:00")
        if len(value) == 10:
            value += "T00:00:00+00:00"
        as_of = datetime.fromisoformat(value)
    if as_of is not None and as_of.tzinfo is None:
        raise ValueError("analysis cutoff must include a timezone")
    state = build_graph().invoke({"path": str(Path(path)), "model": configured_model(model),
                                  "artifact": artifact, "auth_attestations": auth_attestations,
                                  "protected_domains": protected_domains or set(),
                                  "intel_file": str(intel_file) if intel_file else None,
                                  "memory_file": str(memory_file) if memory_file else None,
                                  "as_of": as_of or datetime.now(timezone.utc),
                                  "started": time.perf_counter(), "debate": [], "usage": {}})
    return state["result"]
