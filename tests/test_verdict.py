"""Tests for the verdict node.

The JSON-parsing fallback is pure Python and runs always; the full-graph
test calls the LLM and is gated behind RUN_LIVE_AI=1.
"""

import os

import pytest

from src.agents.verdict import _parse_verdict
from src.graph import run

PHISHING_EMAIL = """\
From: PayPal Service <service@paypal.com>
Return-Path: <bounce@phisher-domain.ru>
Reply-To: support@phisher-domain.ru
Authentication-Results: mx.victim.com;
\tspf=fail smtp.mailfrom=phisher-domain.ru;
\tdkim=fail header.d=phisher-domain.ru;
\tdmarc=fail header.from=paypal.com
Subject: URGENT: Your account has been limited

Dear Customer,

We detected unusual activity. You must verify your password within 24 HOURS
or your account will be permanently suspended.

Confirm your login here: http://paypa1-secure.ru/verify

PayPal Security Team
"""


def test_parse_verdict_happy_path():
    raw = '{"risk_score": 82, "verdict": "Malicious", "explanation": "Bad."}'
    risk_score, verdict, explanation = _parse_verdict(raw)
    assert risk_score == 82
    assert verdict == "malicious"  # normalized to lowercase
    assert explanation == "Bad."


def test_parse_verdict_invalid_json_returns_sentinel():
    risk_score, verdict, explanation = _parse_verdict("not json at all")
    assert risk_score == -1
    assert verdict == "error"
    assert isinstance(explanation, str) and explanation


def test_parse_verdict_missing_fields_returns_sentinel():
    risk_score, verdict, _ = _parse_verdict('{"risk_score": 50}')
    assert risk_score == -1
    assert verdict == "error"


def test_parse_verdict_unknown_label_returns_sentinel():
    # "junk" is not a category; "spam" IS valid, so it can't serve as the
    # unknown-label example any more.
    raw = '{"risk_score": 10, "verdict": "junk", "explanation": "x"}'
    risk_score, verdict, _ = _parse_verdict(raw)
    assert risk_score == -1
    assert verdict == "error"


def test_parse_verdict_accepts_spam_label():
    raw = '{"risk_score": 15, "verdict": "Spam", "explanation": "Bulk junk."}'
    risk_score, verdict, explanation = _parse_verdict(raw)
    assert risk_score == 15
    assert verdict == "spam"  # normalized to lowercase
    assert explanation == "Bulk junk."


@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_AI") != "1",
    reason="set RUN_LIVE_AI=1 to run live AI tests",
)
def test_full_graph_returns_populated_verdict():
    state = run(PHISHING_EMAIL)

    assert isinstance(state["risk_score"], int)
    assert state["risk_score"] != -1
    assert state["verdict"] in {"benign", "spam", "suspicious", "malicious"}
    assert isinstance(state["explanation"], str)
    assert state["explanation"].strip() != ""
