"""Deterministic observations. These are features, never probabilities."""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePath
from urllib.parse import urlsplit

import tldextract

EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta",
                    ".lnk", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".bat", ".cmd", ".ps1"}
PATTERNS = {
    "credential_request": re.compile(r"\b(password|passcode|verify (?:your )?account|confirm (?:your )?login|sign[ -]?in to (?:verify|restore)|one[ -]?time code)\b", re.I),
    "payment_request": re.compile(r"\b(wire transfer|bank details|change (?:the )?bank|gift cards?|send (?:a )?payment|pay (?:this )?invoice|crypto(?:currency)?)\b", re.I),
    "urgency": re.compile(r"\b(urgent|immediately|within 24 hours|account suspended|act now|final notice)\b", re.I),
    "impersonation": re.compile(r"\b(i am (?:your )?(?:ceo|manager|it admin)|on behalf of (?:the )?(?:ceo|finance|it)|this is (?:your )?(?:bank|it department)|chief executive officer|head of finance)\b", re.I),
    "other_scam": re.compile(r"\b(inheritance|lottery winnings|advance fee|claim your prize|investment guaranteed)\b", re.I),
    "spam": re.compile(r"\b(limited time offer|buy now|marketing promotion|unsolicited offer)\b", re.I),
}
FEATURE_NAMES = (
    "reply_domain_mismatch", "return_domain_mismatch", "trusted_dmarc_fail",
    "trusted_spf_fail", "trusted_dkim_fail", "trusted_dmarc_pass", "auth_unknown",
    "html_target_mismatch", "ip_url", "punycode_url", "protected_domain_lookalike",
    "risky_attachment", "credential_request", "payment_request", "urgency",
    "impersonation", "other_scam", "spam", "has_link", "has_attachment",
    "local_intelligence_hit",
)


def registered_domain(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    parsed = EXTRACT(host)
    return f"{parsed.domain}.{parsed.suffix}" if parsed.domain and parsed.suffix else host


def address_domain(address: str) -> str:
    return registered_domain(address.rsplit("@", 1)[-1]) if "@" in address else ""


def _distance_one(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long = sorted((a, b), key=len)
    return any(long[:i] + long[i + 1:] == short for i in range(len(long)))


def _url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def extract_signals(mail: dict, auth_attestation: dict | None = None,
                    protected_domains: set[str] | None = None) -> dict:
    protected_domains = {registered_domain(x) for x in (protected_domains or set())}
    features = {name: 0 for name in FEATURE_NAMES}
    findings = []
    unknown = set(mail["unknown_signals"])
    headers = mail["headers"]

    def add(feature, evidence_id, detail):
        features[feature] = 1
        findings.append({"signal": feature, "evidence_id": evidence_id, "detail": detail})

    from_domain = address_domain(headers.get("From_address", ""))
    if not from_domain:
        unknown.add("sender_domain_missing")
    for name, feature in (("Reply-To", "reply_domain_mismatch"), ("Return-Path", "return_domain_mismatch")):
        value = headers.get(f"{name}_address", "")
        domain = address_domain(value)
        if not value:
            unknown.add(f"{name.lower()}_missing")
        elif from_domain and domain and from_domain != domain:
            add(feature, f"header:{name.lower()}", f"From domain {from_domain} differs from {name} domain {domain}")

    valid_attestation = (isinstance(auth_attestation, dict) and
                         auth_attestation.get("sha256") == mail["sha256"] and
                         bool(auth_attestation.get("source")) and
                         all(auth_attestation.get(key) in {"pass", "fail", "unknown"}
                             for key in ("spf", "dkim", "dmarc")))
    if not valid_attestation:
        features["auth_unknown"] = 1
        unknown.add("trusted_authentication_results_missing")
    else:
        for method, status, feature in (("dmarc", "fail", "trusted_dmarc_fail"),
                                        ("spf", "fail", "trusted_spf_fail"),
                                        ("dkim", "fail", "trusted_dkim_fail"),
                                        ("dmarc", "pass", "trusted_dmarc_pass")):
            if auth_attestation[method] == status:
                add(feature, "attestation:authentication", f"{auth_attestation['source']} reports {method}={status}")

    for link in mail["links"]:
        if link["url"].lower().startswith(("mailto:", "#")):
            continue
        host = _url_host(link["url"])
        if not host:
            unknown.add("link_target_unparseable")
            continue
        features["has_link"] = 1
        label = link.get("label", "")
        if label.startswith(("http://", "https://")):
            label_host = _url_host(label)
            if label_host and registered_domain(label_host) != registered_domain(host):
                add("html_target_mismatch", link["id"], f"Displayed {label_host} links to {host}")
        try:
            ipaddress.ip_address(host)
            add("ip_url", link["id"], f"Link points to IP address {host}")
        except ValueError:
            pass
        if "xn--" in host:
            add("punycode_url", link["id"], f"Link contains Punycode domain {host}")
        current = registered_domain(host)
        for protected in protected_domains:
            if current != protected and _distance_one(current, protected):
                add("protected_domain_lookalike", link["id"], f"{current} resembles protected domain {protected}")
                break

    for item in mail["attachments"]:
        features["has_attachment"] = 1
        names = [item["filename"], *item["archive_entries"]]
        risky = [name for name in names if PurePath(name).suffix.lower() in RISKY_EXTENSIONS]
        if risky:
            add("risky_attachment", item["id"], f"Risky extension: {risky[0][:100]}")

    for part in mail["body"]:
        content = part["text"]
        for feature, pattern in PATTERNS.items():
            match = pattern.search(content)
            if match:
                evidence_id = f"{part['id']}:{(match.start() // 500) * 500}"
                add(feature, evidence_id, f"Matched phrase: {match.group(0)[:80]}")

    return {"features": features, "findings": findings, "unknown_signals": sorted(unknown)}
