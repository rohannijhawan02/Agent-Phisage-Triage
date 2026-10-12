"""Tests for the content node.

The body-extraction helper is pure Python and runs always; the LLM-backed
content_agent test is gated behind RUN_LIVE_AI=1 (real network call, tokens).
"""

import os

import pytest

from src.agents.content import _extract_body, content_agent

PHISHING_EMAIL = """\
From: IT Help Desk <it-support@acccount-security.com>
Subject: URGENT: Your account will be suspended

Dear User,

Our records show suspicious activity on your account. You must verify your
password within 24 HOURS or your account will be permanently suspended.

Click here to confirm your login: http://acccount-security.com/verify

Failure to act immediately will result in loss of access.

IT Security Team
"""


def test_extract_body_pulls_plaintext():
    body = _extract_body(PHISHING_EMAIL)
    # Normalize wrapped lines before substring checks.
    flat = " ".join(body.split())
    assert "verify your password" in flat
    assert "suspended" in flat
    # Headers must not bleed into the body.
    assert "Subject:" not in body


@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_AI") != "1",
    reason="set RUN_LIVE_AI=1 to run live AI tests",
)
def test_content_agent_flags_social_engineering():
    state = content_agent({"raw_email": PHISHING_EMAIL})
    analysis = state["content_analysis"]

    assert isinstance(analysis, str)
    assert analysis.strip() != ""
    # The model should surface at least one of the obvious tactics.
    lowered = analysis.lower()
    assert any(
        term in lowered
        for term in ("urgency", "credential", "password", "suspend", "lookalike")
    )
