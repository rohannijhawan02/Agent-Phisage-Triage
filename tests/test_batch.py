"""Tests for the batch triage runner.

The offline tests monkeypatch `complete_with_usage` in all three agent modules
so the real graph (and the real deterministic-floor logic) runs with no
network. A single RUN_LIVE_AI-gated test exercises the real samples/ folder
end to end.
"""

import csv
import os
import statistics

import pytest

import src.agents.content as content_mod
import src.agents.headers as headers_mod
import src.agents.verdict as verdict_mod
from src.batch import (
    REPEAT_CSV_FIELDS,
    aggregate_runs,
    find_eml_files,
    process_email,
    run_batch,
    run_batch_repeated,
    summarize,
    summarize_explanation,
    summarize_repeat,
)

# --- fixtures ----------------------------------------------------------------

SPOOFED_EML = """\
Return-Path: <attacker@evil-lookalike.com>
Reply-To: attacker@evil-lookalike.com
Authentication-Results: mx.corp.com;
\tspf=fail smtp.mailfrom=evil-lookalike.com;
\tdkim=fail header.d=evil-lookalike.com;
\tdmarc=fail (p=reject) header.from=bank.com
From: Bank Security <security@bank.com>
To: victim@corp.com
Subject: Verify your account

Please verify your password immediately.
"""

CLEAN_EML = """\
Return-Path: <priya@corp.com>
Reply-To: priya@corp.com
Authentication-Results: mx.corp.com; spf=pass; dkim=pass; dmarc=pass
From: Priya <priya@corp.com>
To: jane@corp.com
Subject: Lunch?

Are you free for lunch on Thursday?
"""

# content_agent raises when it sees this marker -> exercises the error path.
ERROR_EML = """\
Return-Path: <someone@corp.com>
Authentication-Results: mx.corp.com; spf=pass; dkim=pass; dmarc=pass
From: Someone <someone@corp.com>
To: jane@corp.com
Subject: Boom

RAISE_NOW please.
"""

# Constant benign JSON. The spoofed email's real (high) floor must override it.
BENIGN_JSON = (
    '{"risk_score": 3, "verdict": "benign", '
    '"explanation": "Looks like an ordinary message."}'
)


@pytest.fixture
def patched_llm(monkeypatch):
    """Stub the LLM everywhere the graph calls it; no network."""

    def fake_header(*args, **kwargs):
        return "header analysis (stubbed)", {}

    def fake_content(system_prompt=None, user_content="", *args, **kwargs):
        if "RAISE_NOW" in user_content:
            raise RuntimeError("simulated LLM failure")
        return "content analysis (stubbed)", {}

    def fake_verdict(*args, **kwargs):
        return BENIGN_JSON, {}

    monkeypatch.setattr(headers_mod, "complete_with_usage", fake_header)
    monkeypatch.setattr(content_mod, "complete_with_usage", fake_content)
    monkeypatch.setattr(verdict_mod, "complete_with_usage", fake_verdict)


def _write_folder(tmp_path, files):
    for name, body in files.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return str(tmp_path)


# --- pure helpers ------------------------------------------------------------

def test_summarize_explanation_strips_conflict_and_truncates():
    assert summarize_explanation("[CONFLICT] Overridden.") == "Overridden."
    long = "x" * 500
    out = summarize_explanation(long)
    assert len(out) <= 160
    assert summarize_explanation("") == ""


def test_find_eml_files_sorted(tmp_path):
    folder = _write_folder(
        tmp_path, {"b.eml": CLEAN_EML, "a.eml": CLEAN_EML, "note.txt": "x"}
    )
    files = find_eml_files(folder)
    assert [os.path.basename(f) for f in files] == ["a.eml", "b.eml"]


# --- per-email processing ----------------------------------------------------

def test_process_email_spoofed_floor_overrides_to_conflict(tmp_path, patched_llm):
    (tmp_path / "spoofed.eml").write_text(SPOOFED_EML, encoding="utf-8")
    row = process_email(str(tmp_path / "spoofed.eml"))

    # Model said benign; the real deterministic floor must override it.
    assert row["floor"] >= 85
    assert row["verdict"] in {"suspicious", "malicious"}
    assert row["conflict"] is True
    assert row["risk_score"] >= 85
    assert isinstance(row["latency_sec"], float)


def test_process_email_clean_passes_through(tmp_path, patched_llm):
    (tmp_path / "clean.eml").write_text(CLEAN_EML, encoding="utf-8")
    row = process_email(str(tmp_path / "clean.eml"))

    assert row["floor"] == 0
    assert row["verdict"] == "benign"
    assert row["conflict"] is False
    assert row["risk_score"] == 3


def test_process_email_error_is_captured_not_raised(tmp_path, patched_llm):
    (tmp_path / "boom.eml").write_text(ERROR_EML, encoding="utf-8")
    row = process_email(str(tmp_path / "boom.eml"))

    assert row["verdict"] == "error"
    assert row["risk_score"] == ""
    assert row["summary"].startswith("ERROR:")
    # Even on LLM failure, the deterministic floor is still computed (clean=0).
    assert row["floor"] == 0


# --- full batch --------------------------------------------------------------

def test_run_batch_writes_csv_and_continues_past_error(tmp_path, patched_llm):
    folder = _write_folder(
        tmp_path,
        {"spoofed.eml": SPOOFED_EML, "clean.eml": CLEAN_EML, "boom.eml": ERROR_EML},
    )
    results_dir = str(tmp_path / "results")
    rows, csv_path, elapsed = run_batch(folder, results_dir=results_dir, progress=False)

    # One failing email did not kill the batch.
    assert len(rows) == 3
    assert elapsed >= 0

    # CSV exists, is under results_dir, timestamped, with the right schema.
    assert os.path.isfile(csv_path)
    assert csv_path.startswith(results_dir)
    assert os.path.basename(csv_path).startswith("batch_")
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == [
            "filename", "risk_score", "floor", "verdict",
            "conflict", "latency_sec", "cost_usd", "summary",
        ]
        csv_rows = list(reader)
    assert len(csv_rows) == 3

    agg = summarize(rows)
    assert agg["counts"]["benign"] == 1
    assert agg["counts"]["error"] == 1
    assert agg["counts"]["suspicious"] + agg["counts"]["malicious"] == 1
    assert agg["conflicts"] == 1
    assert agg["errors"] == ["boom.eml"]


# --- repeat / stability mode -------------------------------------------------

def test_aggregate_runs_stable_label():
    rows = [
        {"risk_score": 70, "verdict": "malicious", "cost_usd": 0.01},
        {"risk_score": 80, "verdict": "malicious", "cost_usd": 0.02},
        {"risk_score": 75, "verdict": "malicious", "cost_usd": 0.01},
    ]
    agg = aggregate_runs("x.eml", rows)
    assert agg["runs"] == 3
    assert agg["score_min"] == 70
    assert agg["score_max"] == 80
    assert agg["score_mean"] == 75.0
    assert agg["score_stdev"] == round(statistics.stdev([70, 80, 75]), 2)
    assert agg["label_stable"] is True
    assert agg["labels"] == "malicious"
    assert agg["_cost_usd"] == 0.04


def test_aggregate_runs_unstable_and_excludes_error_from_stats():
    rows = [
        {"risk_score": 60, "verdict": "spam", "cost_usd": 0.01},
        {"risk_score": "", "verdict": "error", "cost_usd": ""},   # error run
        {"risk_score": 65, "verdict": "spam", "cost_usd": 0.01},
    ]
    agg = aggregate_runs("y.eml", rows)
    # Error run's blank score is excluded from stats...
    assert agg["score_min"] == 60
    assert agg["score_max"] == 65
    # ...but still makes the label set unstable.
    assert agg["label_stable"] is False
    assert agg["labels"] == "error|spam"


def test_aggregate_runs_all_error_is_not_stable():
    # A total outage must NOT read as a stable, all-clear run.
    rows = [{"risk_score": "", "verdict": "error", "cost_usd": ""} for _ in range(3)]
    agg = aggregate_runs("dead.eml", rows)
    assert agg["label_stable"] is False
    assert agg["labels"] == "error"
    assert agg["_error_runs"] == 3
    # And the corpus summary counts it as unstable + surfaces the error runs.
    summary = summarize_repeat([agg])
    assert summary["unstable_count"] == 1
    assert summary["error_runs"] == 3


def test_aggregate_runs_single_numeric_score_has_zero_stdev():
    rows = [{"risk_score": 42, "verdict": "benign", "cost_usd": 0.0}]
    agg = aggregate_runs("z.eml", rows)
    assert agg["score_stdev"] == 0.0
    assert agg["label_stable"] is True


def test_run_batch_repeated_flags_unstable_label(monkeypatch, tmp_path):
    monkeypatch.setattr(headers_mod, "complete_with_usage", lambda *a, **k: ("hdr", {}))
    monkeypatch.setattr(content_mod, "complete_with_usage", lambda *a, **k: ("body", {}))
    # Verdict cycles across the three runs -> label flips spam/benign/spam.
    responses = [
        ('{"risk_score": 55, "verdict": "spam", "explanation": "junk"}', {}),
        ('{"risk_score": 30, "verdict": "benign", "explanation": "fine"}', {}),
        ('{"risk_score": 52, "verdict": "spam", "explanation": "junk"}', {}),
    ]
    calls = {"i": 0}

    def cycling(*a, **k):
        r = responses[calls["i"] % len(responses)]
        calls["i"] += 1
        return r

    monkeypatch.setattr(verdict_mod, "complete_with_usage", cycling)

    folder = _write_folder(tmp_path, {"wobbly.eml": CLEAN_EML})
    results_dir = str(tmp_path / "results")
    agg_rows, csv_path, elapsed = run_batch_repeated(
        folder, results_dir=results_dir, repeat=3, progress=False
    )

    assert len(agg_rows) == 1
    row = agg_rows[0]
    assert row["runs"] == 3
    assert row["score_min"] == 30 and row["score_max"] == 55
    assert row["label_stable"] is False
    assert row["labels"] == "benign|spam"
    assert elapsed >= 0

    # CSV uses the repeat schema; the internal _cost_usd key is dropped.
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == REPEAT_CSV_FIELDS
        assert len(list(reader)) == 1

    agg = summarize_repeat(agg_rows)
    assert agg["unstable_count"] == 1
    assert agg["unstable_files"] == ["wobbly.eml"]
    assert agg["total_runs"] == 3


def test_run_batch_repeated_stable_when_model_constant(tmp_path, patched_llm):
    folder = _write_folder(tmp_path, {"steady.eml": CLEAN_EML})
    results_dir = str(tmp_path / "results")
    agg_rows, _csv, _elapsed = run_batch_repeated(
        folder, results_dir=results_dir, repeat=4, progress=False
    )
    row = agg_rows[0]
    assert row["runs"] == 4
    assert row["label_stable"] is True
    assert row["labels"] == "benign"
    assert row["score_stdev"] == 0.0
    assert summarize_repeat(agg_rows)["unstable_count"] == 0


# --- live integration --------------------------------------------------------

@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_AI") != "1",
    reason="set RUN_LIVE_AI=1 to run live AI tests",
)
def test_run_batch_live_over_samples(tmp_path):
    results_dir = str(tmp_path / "results")
    rows, csv_path, elapsed = run_batch("samples", results_dir=results_dir, progress=False)

    assert len(rows) == len(find_eml_files("samples"))
    assert os.path.isfile(csv_path)
    # No row should be an unexpected crash; every verdict is a known label.
    for row in rows:
        assert row["verdict"] in {"benign", "spam", "suspicious", "malicious", "error"}
