"""Header parsing and analysis nodes for the triage graph.

`parse_email` is pure stdlib (no LLM); `header_agent` hands the parsed
headers — never the raw email — to the LLM for a plain-language read.
"""

import re

from email import message_from_string
from email.utils import parseaddr

from src.llm import complete_with_usage, record_usage

HEADER_SYSTEM_PROMPT = """You are an email security analyst reviewing the \
headers of a single message for signs of phishing or spoofing.

You will be given ONLY a JSON-like dict of security-relevant headers (the \
raw email body is withheld). Analyze it and call out, in plain language:

- Mismatches between the From address and the Return-Path or Reply-To \
(a classic spoofing tell).
- Failed or missing SPF, DKIM, or DMARC results in Authentication-Results.
- Suspicious Received hops: unexpected relays, mismatched domains, \
private/bogus IPs, or chains that don't trace back to the claimed sender.

Be concise. State what you see and why it is or isn't suspicious. If the \
headers look clean, say so. Do not speculate about content you cannot see."""


def parse_email(state):
    """Parse state['raw_email'] into a dict of security-relevant headers.

    Pure Python — no LLM. Multi-valued headers (Received,
    Authentication-Results) are preserved as lists.
    """
    msg = message_from_string(state["raw_email"])

    from_header = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")

    parsed_headers = {
        "From": from_header,
        "From_address": parseaddr(from_header)[1],
        "Return-Path": return_path,
        "Return-Path_address": parseaddr(return_path)[1],
        "Reply-To": reply_to,
        "Reply-To_address": parseaddr(reply_to)[1],
        "Received": msg.get_all("Received", []),
        "Authentication-Results": msg.get_all("Authentication-Results", []),
    }

    state["parsed_headers"] = parsed_headers
    return state


def header_agent(state):
    """Ask the LLM to assess the parsed headers; store the plain-language read."""
    parsed_headers = state["parsed_headers"]
    text, usage = complete_with_usage(
        system_prompt=HEADER_SYSTEM_PROMPT,
        user_content=repr(parsed_headers),
    )
    record_usage(state, "header_agent", usage)
    state["header_analysis"] = text
    return state


def _domain_of(address: str) -> str:
    """Return the lowercased domain part of an email address, or ''."""
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower()


def _registered_domain(domain: str) -> str:
    """Approximate the registered domain (last two labels) of a hostname.

    This is a deliberately simple eTLD+1 approximation (no public-suffix list
    dependency): it treats `email.brightloop.com` and `brightloop.com` as the
    same organization so legitimate subdomain bounce/return paths are not
    falsely flagged, while still catching cross-organization spoofs like
    `paypal.com` vs `paypal-secure-login.com`. It is intentionally lenient —
    the goal is to avoid false positives on the floor; the LLM header agent
    still reasons about finer-grained mismatches.
    """
    labels = [p for p in domain.split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    # NOTE: naive last-two-label matching. This is wrong for multi-part TLDs
    # (e.g. "example.co.uk" reduces to "co.uk", so two unrelated .co.uk domains
    # would look identical). A future version should use the Public Suffix List
    # (e.g. the `tldextract` or `publicsuffix2` package) for correct eTLD+1.
    return ".".join(labels[-2:])


def deterministic_risk_floor(parsed_headers: dict) -> tuple[int, list[str]]:
    """Compute a minimum risk score from hard header signals — no LLM.

    This is a structural anti-injection control: it is pure Python over
    deterministically-parsed header fields the attacker cannot influence via
    the message body. The verdict node uses it as a floor the model's score
    can never be talked *below*, so a prompt injection that coerces the model
    into "risk_score 0 / benign" still cannot suppress a spoofed, auth-failing
    email.

    Returns (floor, reasons). `floor` is clamped to 0-100.
    """
    reasons: list[str] = []
    floor = 0

    auth = " ".join(parsed_headers.get("Authentication-Results", [])).lower()

    # SPF / DKIM / DMARC failures. DMARC failure is the strongest single tell,
    # especially under an enforcing policy (p=reject / p=quarantine).
    if re.search(r"\bspf\s*=\s*fail\b", auth):
        floor = max(floor, 50)
        reasons.append("SPF failed")
    if re.search(r"\bdkim\s*=\s*fail\b", auth):
        floor = max(floor, 50)
        reasons.append("DKIM failed")
    if re.search(r"\bdmarc\s*=\s*fail\b", auth):
        floor = max(floor, 70)
        reasons.append("DMARC failed")
        if re.search(r"p\s*=\s*(reject|quarantine)", auth):
            floor = max(floor, 85)
            reasons.append("DMARC failed under an enforcing policy")

    # From vs. Return-Path / Reply-To domain mismatch — a spoof tell ONLY when
    # DMARC has not passed.
    #
    # A passing DMARC result already proves the From domain is authenticated and
    # aligned with a passing SPF or DKIM identifier. Legitimate senders using an
    # ESP (SendGrid, Mailchimp, calendar/order-confirmation systems) routinely
    # put Return-Path/Reply-To on the provider's registered domain while the From
    # stays on their own — normal plumbing, not spoofing. Counting the mismatch
    # there false-positived on real legitimate mail (calendar invites,
    # government newsletters, order confirmations), so when DMARC passes this
    # signal contributes 0.
    #
    # If DMARC fails, or there is no DMARC result at all, the mismatch still
    # fires: absence of authentication is not innocence. The SPF/DKIM/DMARC
    # failure contributions above are unaffected either way.
    dmarc_passed = bool(re.search(r"\bdmarc\s*=\s*pass\b", auth))

    if not dmarc_passed:
        from_domain = _registered_domain(
            _domain_of(parsed_headers.get("From_address", ""))
        )
        for label in ("Return-Path_address", "Reply-To_address"):
            other_domain = _registered_domain(_domain_of(parsed_headers.get(label, "")))
            if from_domain and other_domain and from_domain != other_domain:
                floor = max(floor, 70)
                reasons.append(
                    f"From domain ({from_domain}) does not match "
                    f"{label.replace('_address', '')} domain ({other_domain})"
                )

    return min(floor, 100), reasons
