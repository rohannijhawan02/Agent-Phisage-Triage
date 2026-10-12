"""Unit tests for header parsing.

These exercise pure-Python parsing only — no LLM call — so they run
without RUN_LIVE_AI set.
"""

from src.agents.headers import parse_email

# Spoofed sample: the display/From domain (paypal.com) does not match the
# Return-Path or the SPF/DKIM/DMARC verdicts, which all fail.
SPOOFED_EMAIL = """\
From: PayPal Service <service@paypal.com>
Return-Path: <bounce@phisher-domain.ru>
Reply-To: support@phisher-domain.ru
Received: from mail.phisher-domain.ru (mail.phisher-domain.ru [203.0.113.9])
\tby mx.victim.com with ESMTP id abc123
Authentication-Results: mx.victim.com;
\tspf=fail smtp.mailfrom=phisher-domain.ru;
\tdkim=fail header.d=phisher-domain.ru;
\tdmarc=fail header.from=paypal.com
Subject: Your account has been limited

Please verify your account.
"""


def test_parse_email_captures_from_return_path_mismatch():
    state = parse_email({"raw_email": SPOOFED_EMAIL})
    headers = state["parsed_headers"]

    from_addr = headers["From_address"]
    return_path_addr = headers["Return-Path_address"]

    # The spoof: From claims paypal.com but Return-Path is a different domain.
    assert from_addr == "service@paypal.com"
    assert return_path_addr == "bounce@phisher-domain.ru"
    assert from_addr.split("@")[1] != return_path_addr.split("@")[1]


def test_parse_email_captures_auth_failures():
    state = parse_email({"raw_email": SPOOFED_EMAIL})
    auth = "\n".join(state["parsed_headers"]["Authentication-Results"])

    assert "spf=fail" in auth
    assert "dkim=fail" in auth
    assert "dmarc=fail" in auth


def test_parse_email_preserves_received_chain():
    state = parse_email({"raw_email": SPOOFED_EMAIL})
    received = state["parsed_headers"]["Received"]

    assert isinstance(received, list)
    assert any("phisher-domain.ru" in hop for hop in received)
