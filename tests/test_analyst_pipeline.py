import io
import json
import zipfile
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from src.ingest import parse_eml
from src.context import confirmed_case_memory
from src.context import indicators
from src.pipeline import analyze
from src.rubric import CRITERIA, PROMPT_HASH, RUBRIC_VERSION, judge
from src.scoring import FEATURE_VERSION, baseline, material_unknowns, probability
from src.signals import extract_signals, registered_domain
from src.training import compare, evaluate, fit, write_jsonl


def test_mime_link_attachment_and_auth_boundary(tmp_path):
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("invoice.js", "not executed")
    import base64
    message = ("From: Billing <billing@example.com>\r\n"
               "Reply-To: help@other.example\r\n"
               "Authentication-Results: claimed-receiver; dmarc=pass\r\n"
               "MIME-Version: 1.0\r\n"
               "Content-Type: multipart/mixed; boundary=OUT\r\n\r\n"
               "--OUT\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
               '<a href="http://192.0.2.1/login">https://example.com/login</a>\r\n'
               "--OUT\r\nContent-Type: application/zip\r\n"
               "Content-Disposition: attachment; filename=docs.zip\r\n"
               "Content-Transfer-Encoding: base64\r\n\r\n"
               + base64.b64encode(archive_bytes.getvalue()).decode() + "\r\n--OUT--\r\n")
    path = tmp_path / "mail.eml"
    path.write_bytes(message.encode())
    mail = parse_eml(path)
    assert mail["sha256"]
    assert any(link["url"] == "http://192.0.2.1/login" for link in mail["links"])
    assert mail["attachments"][0]["archive_entries"] == ["invoice.js"]
    untrusted = extract_signals(mail)
    assert untrusted["features"]["auth_unknown"] == 1
    assert untrusted["features"]["trusted_dmarc_pass"] == 0
    assert untrusted["features"]["html_target_mismatch"] == 1
    assert untrusted["features"]["risky_attachment"] == 1
    trusted = extract_signals(mail, {"sha256": mail["sha256"], "source": "trusted-gateway",
                                     "spf": "unknown", "dkim": "unknown", "dmarc": "pass"})
    assert trusted["features"]["trusted_dmarc_pass"] == 1
    assert registered_domain("mail.example.co.uk") == "example.co.uk"


def test_rubric_rejects_invented_evidence(monkeypatch):
    ratings = {name: {"score": 0, "evidence_ids": []} for name in CRITERIA}
    ratings["credential_request"] = {"score": 3, "evidence_ids": ["invented-id"]}
    monkeypatch.setattr("src.rubric.complete_with_usage", lambda *a, **k: (json.dumps({"ratings": ratings}), {}))
    mail = {"headers": {"Subject": "Review"}, "evidence": [{"id": "body:0:0", "text": "Hello"}]}
    result = judge(mail, "test-model")
    assert result["ratings"]["credential_request"]["score"] == 0
    assert "credential_request:unsupported_evidence" in result["invalid_reasons"]


def _records():
    rows = []
    for split, size in (("train", 60), ("calibration", 120), ("test", 40)):
        for index in range(size):
            label = index % 2
            rows.append({"sha256": f"{split}-{index}", "label": label, "split": split,
                         "group": f"campaign-{split}-{index}", "source": "fixture", "slices": ["phishing" if label else "ham"],
                         "features": {"credential_request": label, "auth_unknown": 1-label},
                         "model_version": "fixture-model", "backend_identity": "fixture-backend",
                         "rubric_version": RUBRIC_VERSION,
                         "rubric_prompt_hash": PROMPT_HASH,
                         "feature_version": FEATURE_VERSION,
                         "signal_config": {"auth_attestation_mode": "none", "protected_domains": []},
                         "rubric_invalid_reasons": [], "unknown_signals": [],
                         "proposed_verdict": "malicious" if label else "benign",
                         "cost_usd": 0, "elapsed_seconds": 0.001})
    return rows


def test_calibration_and_paired_comparison():
    rows = _records()
    model = fit(rows, "fixture", "v1")
    report = evaluate(rows, model)
    assert report["overall"]["phishing_recall"] == 1
    assert probability(rows[1]["features"], model) > probability(rows[0]["features"], model)
    comparison = compare(rows, rows, model, model)
    assert comparison["promote"] is True
    assert comparison["decision_threshold_crossings"] == 0
    rows[0]["group"] = rows[-1]["group"]
    with pytest.raises(ValueError, match="cross partitions"):
        fit(rows, "fixture", "v1")


def test_gate_uses_operational_review_decisions():
    rows = _records()
    model = fit(rows, "fixture", "v1")
    candidate = deepcopy(rows)
    next(row for row in candidate if row["split"] == "test" and row["label"] == 1)["proposed_verdict"] = "needs_review"
    report = compare(rows, candidate, model, model)
    assert report["candidate"]["review_rate"] > report["incumbent"]["review_rate"]
    assert report["candidate"]["operational"]["auto_malicious_recall"] < report["incumbent"]["operational"]["auto_malicious_recall"]
    assert report["promote"] is False
    assert report["decision_threshold_crossings"] == 1


def test_fit_rejects_exact_indicator_leakage():
    rows = _records()
    rows[0]["iocs"] = {"urls": ["https://same.example/login"], "attachment_hashes": []}
    calibration = next(row for row in rows if row["split"] == "calibration")
    calibration["iocs"] = {"urls": ["https://same.example/login"], "attachment_hashes": []}
    with pytest.raises(ValueError, match="shared indicator crosses partitions"):
        fit(rows, "fixture", "v1")


def test_case_memory_excludes_undated_and_future_confirmations(tmp_path):
    cases = tmp_path / "confirmed.jsonl"
    cases.write_text("\n".join(json.dumps(case) for case in [
        {"case_id": "old", "confirmed": True, "confirmed_at": "2025-01-01T00:00:00Z",
         "sha256": "old", "verdict": "malicious", "indicators": ["https://bad.example/login"], "campaign_domains": []},
        {"case_id": "future", "confirmed": True, "confirmed_at": "2027-01-01T00:00:00Z",
         "sha256": "future", "verdict": "malicious", "indicators": ["https://bad.example/login"], "campaign_domains": []},
        {"case_id": "undated", "confirmed": True, "sha256": "undated", "verdict": "malicious",
         "indicators": ["https://bad.example/login"], "campaign_domains": []},
    ]) + "\n", encoding="utf-8")
    found = confirmed_case_memory(cases, {"sha256": "current"},
                                  {"urls": ["https://bad.example/login"], "attachment_hashes": [], "domains": []},
                                  datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert [case["case_id"] for case in found] == ["old"]


def test_optional_missing_headers_do_not_force_benign_review(tmp_path):
    path = tmp_path / "ordinary.eml"
    path.write_text("From: Alice <alice@example.org>\nSubject: Hi\n\nLunch tomorrow?\n", encoding="utf-8")
    signals = extract_signals(parse_eml(path))
    assert "trusted_authentication_results_missing" in signals["unknown_signals"]
    assert material_unknowns(signals["unknown_signals"]) == []
    assert baseline(signals)[0] == "benign"


def test_html_display_url_is_not_an_actionable_destination(tmp_path):
    path = tmp_path / "mismatch.eml"
    path.write_text('From: Service <service@example.org>\nContent-Type: text/html\n\n'
                    '<a href="https://bad.example/login">https://example.org/login</a>'
                    ' <a href="mailto:help@example.org">Contact us</a>', encoding="utf-8")
    mail = parse_eml(path)
    iocs = indicators(mail)
    assert "https://bad.example/login" in iocs["urls"]
    assert "https://example.org/login" not in iocs["urls"]
    assert extract_signals(mail)["features"]["html_target_mismatch"] == 1


def test_local_samples_run_without_invented_probability():
    from pathlib import Path
    sample = Path(__file__).parent.parent / "samples" / "phish_giftcard.eml"
    result = analyze(sample)
    assert result["phishing_probability_0_100"] is None
    assert result["verdict"] == "needs_review"
    assert result["baseline_verdict"] in {"suspicious", "malicious"}
    assert result["findings"]


def test_cli_fit_evaluate_and_analyze(tmp_path):
    from pathlib import Path
    from triage import main

    feature_path = tmp_path / "fixture.features.jsonl"
    model_path = tmp_path / "model.json"
    report_path = tmp_path / "report.json"
    output = tmp_path / "results"
    write_jsonl(feature_path, _records())
    assert main(["fit", str(feature_path), "--dataset-name", "fixture", "--dataset-version", "v1",
                 "--output", str(model_path), "--report", str(report_path)]) == 0
    assert json.loads(report_path.read_text())["overall"]["brier_score"] < 0.25
    sample = Path(__file__).parent.parent / "samples" / "phish_giftcard.eml"
    assert main(["analyze", str(sample), "--model-file", str(model_path), "--output", str(output)]) == 0
    row = json.loads((output / "results.jsonl").read_text().strip())
    assert row["risk_score"] is None
    assert row["probability_scope"] is None
    assert row["verdict"] == "needs_review"
    assert Path(row["report_file"]).is_file()
