"""Conservative MITRE ATT&CK mappings from observed email evidence."""

from __future__ import annotations

ATTACK_CATALOG = "enterprise-2026-05"


def map_techniques(signals: dict, judge: dict, mail: dict) -> list[dict]:
    features = signals["features"]
    ratings = judge["ratings"]
    mappings = []

    def add(technique_id: str, name: str, status: str, evidence_ids: list[str], reason: str) -> None:
        valid = sorted({item["id"] for item in mail["evidence"]} & set(evidence_ids))
        if valid:
            mappings.append({"id": technique_id, "name": name, "status": status,
                             "evidence_ids": valid, "reason": reason,
                             "attack_catalog": ATTACK_CATALOG})

    evidence_by_signal = {}
    for finding in signals["findings"]:
        evidence_by_signal.setdefault(finding["signal"], []).append(finding["evidence_id"])
    creds = ratings["credential_request"]["score"] >= 2
    malicious_context = any(ratings[key]["score"] >= 2 for key in
                            ("credential_request", "payment_diversion", "link_deception",
                             "attachment_concern", "impersonation"))
    if malicious_context:
        ids = sorted({evidence_id for item in ratings.values() for evidence_id in item["evidence_ids"]})
        add("T1566", "Phishing", "suspected_delivery", ids,
            "Email evidence indicates a phishing or social-engineering attempt.")
    if ratings["attachment_concern"]["score"] >= 2 and features["has_attachment"]:
        add("T1566.001", "Spearphishing Attachment", "suspected_delivery",
            ratings["attachment_concern"]["evidence_ids"],
            "Attachment evidence and message context support attachment-based delivery.")
    if features["has_link"] and ratings["link_deception"]["score"] >= 2:
        add("T1566.002", "Spearphishing Link", "suspected_delivery",
            ratings["link_deception"]["evidence_ids"],
            "The email contains a suspicious link with supporting destination evidence.")
    if creds:
        add("T1598", "Phishing for Information", "suspected_objective",
            ratings["credential_request"]["evidence_ids"],
            "The email requests credentials or other sensitive information.")
    if creds and features["has_link"] and ratings["link_deception"]["score"] >= 2:
        link_ids = [item["id"] for item in mail["links"]]
        add("T1598.003", "Phishing for Information: Spearphishing Link", "suspected_objective",
            ratings["credential_request"]["evidence_ids"] + ratings["link_deception"]["evidence_ids"] + link_ids,
            "A credential request is accompanied by a suspicious link; destination intent needs review.")
    if ratings["impersonation"]["score"] >= 2:
        add("T1684.001", "Social Engineering: Impersonation", "suspected_behavior",
            ratings["impersonation"]["evidence_ids"],
            "The message makes an unsupported trusted-identity claim.")
    if features["trusted_dmarc_fail"] and ratings["impersonation"]["score"] >= 2:
        add("T1684.002", "Social Engineering: Email Spoofing", "suspected_behavior",
            evidence_by_signal.get("trusted_dmarc_fail", []) + ratings["impersonation"]["evidence_ids"],
            "Receiver-verified authentication failure accompanies an identity claim.")
    if features["has_link"] and ratings["link_deception"]["score"] >= 2:
        add("T1204.001", "User Execution: Malicious Link", "possible_follow_on",
            ratings["link_deception"]["evidence_ids"],
            "A user click is possible; no click or execution was observed from this email.")
    return mappings
