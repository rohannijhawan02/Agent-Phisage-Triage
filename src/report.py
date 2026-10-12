"""Evidence-linked Markdown incident reports for analyst review."""

from __future__ import annotations

import re


def _safe(value: object, limit: int = 500) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value))[:limit]
    return text.replace("<", "&lt;").replace(">", "&gt;").replace("[", "\\[").replace("]", "\\]")


def render_report(result: dict) -> str:
    lines = ["# Email triage incident report", "",
             f"- Source: {_safe(result['file'])}",
             f"- SHA-256: `{result['sha256']}`",
             f"- Subject: {_safe(result['subject'])}",
             f"- Sender: {_safe(result['sender'])}",
             f"- Verdict: **{result['verdict']}**",
             f"- Risk score: {result['risk_score'] if result['risk_score'] is not None else 'unavailable'}",
             f"- Score scope: {_safe(result.get('probability_scope') or 'not calibrated')}",
             "", "## Explanation", "", _safe(result['explanation'], 1200), "",
             "## Specialist findings", ""]
    for role, agent in result["agents"].items():
        lines.append(f"### {role.title()} — {agent['provisional_verdict']}")
        lines.append("")
        if not agent["findings"]:
            lines.append("No validated LLM finding.")
        for item in agent["findings"]:
            refs = ", ".join(f"`{ref}`" for ref in item["evidence_ids"])
            lines.append(f"- {item['criterion']} ({item['score']}/3): {_safe(item['rationale'])} {refs}")
        lines.append("")
    lines.extend(["## Debate", ""])
    for turn in result["debate"]:
        refs = ", ".join(f"`{ref}`" for ref in turn["evidence_ids"])
        lines.append(f"- Round {turn['round']}, {turn['stance']}: {_safe(turn['argument'], 1200)} {refs}")
    lines.extend(["", "## MITRE ATT&CK", ""])
    if not result["mitre_attack"]:
        lines.append("No technique mapped from the available evidence.")
    for mapping in result["mitre_attack"]:
        refs = ", ".join(f"`{ref}`" for ref in mapping["evidence_ids"])
        lines.append(f"- {mapping['id']} {mapping['name']} ({mapping['status']}): {_safe(mapping['reason'])} {refs}")
    lines.extend(["", "## Indicators and intelligence", ""])
    for key, values in result["iocs"].items():
        lines.append(f"- {key}: {', '.join(_safe(value, 200) for value in values) if values else 'none'}")
    for hit in result["intelligence_hits"]:
        lines.append(f"- {_safe(hit['type'])}: {_safe(hit['indicator'])} — {_safe(hit['verdict'])} "
                     f"({_safe(hit['source'])}, {_safe(hit['observed_at'])})")
    if result["related_cases"]:
        lines.extend(["", "## Related confirmed cases", ""])
        for case in result["related_cases"]:
            lines.append(f"- {_safe(case['case_id'])}: {_safe(case['confirmed_verdict'])}; "
                         f"shared indicators: {', '.join(_safe(x) for x in case['shared_indicators'])}")
    lines.extend(["", "## Review notes", ""])
    notes = result["review_reasons"] + result["unknown_signals"]
    lines.extend(f"- {_safe(item)}" for item in sorted(set(notes)))
    if not notes:
        lines.append("- No recorded review gaps.")
    lines.extend(["", "## Evidence excerpts", ""])
    cited = set(result["explanation_evidence_ids"])
    cited.update(ref for agent in result["agents"].values() for finding in agent["findings"] for ref in finding["evidence_ids"])
    for item in result["evidence"]:
        if item["id"] in cited:
            lines.append(f"- `{item['id']}` ({_safe(item['source'])}): {_safe(item['text'])}")
    lines.append("")
    return "\n".join(lines)
