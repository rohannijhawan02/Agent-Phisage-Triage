"""Offline tests for cost/latency telemetry.

Token usage is parsed from a mocked OpenRouter response (no network); cost is
computed from env-configured per-1K prices; per-agent usage is accumulated in
the TriageState and surfaced in the batch CSV row.
"""

import pytest

import src.agents.content as content_mod
import src.agents.headers as headers_mod
import src.agents.verdict as verdict_mod
import src.llm as llm
from src.batch import process_email
from src.legacy_graph import run
from src.llm import _cost, complete, complete_with_usage, record_usage

CLEAN_EML = """\
Return-Path: <priya@corp.com>
Authentication-Results: mx.corp.com; spf=pass; dkim=pass; dmarc=pass
From: Priya <priya@corp.com>
To: jane@corp.com
Subject: Lunch?

Are you free for lunch on Thursday?
"""

FAKE_RESPONSE = {
    "choices": [{"message": {"content": "hello"}}],
    "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500},
}


# --- cost computation --------------------------------------------------------

def test_cost_from_env_prices(monkeypatch):
    monkeypatch.setenv("COST_PER_1K_INPUT", "0.003")
    monkeypatch.setenv("COST_PER_1K_OUTPUT", "0.015")
    # 1000 in @ 0.003/1k + 500 out @ 0.015/1k = 0.003 + 0.0075
    assert _cost(1000, 500) == pytest.approx(0.0105)


def test_cost_defaults_to_zero_when_unset(monkeypatch):
    monkeypatch.delenv("COST_PER_1K_INPUT", raising=False)
    monkeypatch.delenv("COST_PER_1K_OUTPUT", raising=False)
    assert _cost(1000, 500) == 0.0


def test_cost_tolerates_bad_env(monkeypatch):
    monkeypatch.setenv("COST_PER_1K_INPUT", "not-a-number")
    monkeypatch.setenv("COST_PER_1K_OUTPUT", "0.01")
    assert _cost(1000, 1000) == 0.01  # bad input price treated as 0


# --- complete_with_usage -----------------------------------------------------

def test_complete_with_usage_parses_tokens_and_cost(monkeypatch):
    monkeypatch.setattr(llm, "_post_chat", lambda *a, **k: FAKE_RESPONSE)
    monkeypatch.setenv("COST_PER_1K_INPUT", "0.003")
    monkeypatch.setenv("COST_PER_1K_OUTPUT", "0.015")

    text, usage = complete_with_usage("sys", "user")

    assert text == "hello"
    assert usage["prompt_tokens"] == 1000
    assert usage["completion_tokens"] == 500
    assert usage["total_tokens"] == 1500
    assert usage["cost_usd"] == 0.0105
    assert usage["latency_sec"] >= 0.0


def test_complete_is_backward_compatible_str(monkeypatch):
    monkeypatch.setattr(llm, "_post_chat", lambda *a, **k: FAKE_RESPONSE)
    reply = complete("sys", "user")
    assert isinstance(reply, str)
    assert reply == "hello"


def test_complete_with_usage_handles_missing_usage_block(monkeypatch):
    monkeypatch.setattr(
        llm, "_post_chat", lambda *a, **k: {"choices": [{"message": {"content": "hi"}}]}
    )
    text, usage = complete_with_usage("sys", "user")
    assert text == "hi"
    assert usage["total_tokens"] == 0
    assert usage["cost_usd"] == 0.0


# --- record_usage accumulation ----------------------------------------------

def test_record_usage_accumulates_per_agent_and_totals():
    state = {}
    record_usage(state, "header_agent", {
        "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
        "latency_sec": 0.10, "cost_usd": 0.001,
    })
    record_usage(state, "verdict_agent", {
        "prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60,
        "latency_sec": 0.05, "cost_usd": 0.0005,
    })

    tel = state["telemetry"]
    assert set(tel["per_agent"]) == {"header_agent", "verdict_agent"}
    assert tel["total_tokens"] == 180
    assert tel["total_prompt_tokens"] == 150
    assert tel["total_completion_tokens"] == 30
    assert tel["total_cost_usd"] == 0.0015
    assert tel["total_llm_latency_sec"] == 0.15
    # Top-level mirrors for easy downstream access.
    assert state["total_tokens"] == 180
    assert state["total_cost_usd"] == 0.0015


def test_record_usage_tolerates_empty_usage():
    state = {}
    record_usage(state, "content_agent", {})
    assert state["telemetry"]["per_agent"]["content_agent"]["total_tokens"] == 0
    assert state["total_tokens"] == 0


def test_record_usage_derives_total_when_absent():
    # No total_tokens supplied -> derive from prompt + completion.
    state = {}
    record_usage(state, "header_agent", {"prompt_tokens": 30, "completion_tokens": 12})
    assert state["telemetry"]["per_agent"]["header_agent"]["total_tokens"] == 42
    assert state["total_tokens"] == 42


# --- full pipeline -----------------------------------------------------------

def _stub_agents(monkeypatch):
    monkeypatch.setattr(headers_mod, "complete_with_usage", lambda *a, **k: (
        "hdr", {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
                "latency_sec": 0.10, "cost_usd": 0.001},
    ))
    monkeypatch.setattr(content_mod, "complete_with_usage", lambda *a, **k: (
        "content", {"prompt_tokens": 250, "completion_tokens": 50, "total_tokens": 300,
                    "latency_sec": 0.20, "cost_usd": 0.003},
    ))
    monkeypatch.setattr(verdict_mod, "complete_with_usage", lambda *a, **k: (
        '{"risk_score": 5, "verdict": "benign", "explanation": "clean"}',
        {"prompt_tokens": 80, "completion_tokens": 10, "total_tokens": 90,
         "latency_sec": 0.05, "cost_usd": 0.0009},
    ))


def test_full_pipeline_accumulates_telemetry(monkeypatch):
    _stub_agents(monkeypatch)
    state = run(CLEAN_EML)

    tel = state["telemetry"]
    assert set(tel["per_agent"]) == {"header_agent", "content_agent", "verdict_agent"}
    assert tel["total_tokens"] == 120 + 300 + 90
    assert tel["total_cost_usd"] == round(0.001 + 0.003 + 0.0009, 6)
    assert tel["total_llm_latency_sec"] == round(0.10 + 0.20 + 0.05, 3)
    # Per-agent latency present.
    for agent in ("header_agent", "content_agent", "verdict_agent"):
        assert "latency_sec" in tel["per_agent"][agent]
    # Top-level mirrors.
    assert state["total_tokens"] == 510
    assert state["total_cost_usd"] == round(0.0049, 6)


def test_batch_row_includes_cost_usd(monkeypatch, tmp_path):
    _stub_agents(monkeypatch)
    path = tmp_path / "clean.eml"
    path.write_text(CLEAN_EML, encoding="utf-8")

    row = process_email(str(path))
    assert isinstance(row["cost_usd"], float)
    assert row["cost_usd"] == round(0.0049, 6)
