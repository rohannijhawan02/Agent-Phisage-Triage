"""Read-only, local intelligence and analyst-confirmed case context."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from src.signals import address_domain, registered_domain


def indicators(mail: dict) -> dict:
    """Extract current-message IOCs without requesting or visiting a URL."""
    urls = sorted({link["url"] for link in mail["links"] if link["url"].startswith(("http://", "https://"))})
    domains = {address_domain(mail["headers"].get("From_address", ""))}
    for url in urls:
        try:
            domains.add(registered_domain(urlsplit(url).hostname or ""))
        except ValueError:
            continue
    return {"urls": urls[:100], "domains": sorted(domains - {""}),
            "attachment_hashes": sorted({item["sha256"] for item in mail["attachments"]})}


def local_intelligence(path: str | Path | None, iocs: dict) -> list[dict]:
    """Lookup IOCs in a supplied reputation snapshot; never transmit mail data."""
    if path is None:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("intelligence file must be a JSON object")
    results = []
    for category, key in (("urls", "urls"), ("domains", "domains"),
                          ("hashes", "attachment_hashes")):
        entries = data.get(category, {})
        if not isinstance(entries, dict):
            raise ValueError(f"intelligence {category} must be an object")
        for value in iocs[key]:
            hit = entries.get(value)
            if not isinstance(hit, dict) or hit.get("verdict") not in {"malicious", "suspicious"}:
                continue
            results.append({"type": category, "indicator": value,
                            "verdict": hit["verdict"],
                            "source": str(hit.get("source", data.get("source", "local_snapshot")))[:200],
                            "observed_at": str(hit.get("observed_at", data.get("observed_at", "unknown")))[:80]})
    return results[:100]


def _utc_instant(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("case timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("case timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def confirmed_case_memory(path: str | Path | None, mail: dict, iocs: dict,
                          as_of: datetime | None = None) -> list[dict]:
    """Retrieve only cases confirmed before the analysis cutoff."""
    if path is None:
        return []
    cutoff = as_of or datetime.now(timezone.utc)
    if cutoff.tzinfo is None:
        raise ValueError("analysis cutoff must include a timezone")
    cutoff = cutoff.astimezone(timezone.utc)
    current_exact = set(iocs["urls"] + iocs["attachment_hashes"])
    current_domains = set(iocs["domains"])
    matches = []
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            case = json.loads(line)
            if not isinstance(case, dict) or case.get("confirmed") is not True:
                continue
            # Undated confirmations cannot establish that a benchmark label was
            # available before the message being evaluated.
            try:
                confirmed_at = _utc_instant(case["confirmed_at"])
            except (KeyError, TypeError, ValueError):
                continue
            if confirmed_at >= cutoff:
                continue
            if case.get("sha256") == mail["sha256"]:
                continue
            indicators = case.get("indicators", [])
            campaign_domains = case.get("campaign_domains", [])
            if not isinstance(indicators, list) or not isinstance(campaign_domains, list):
                continue
            shared = sorted((current_exact & set(str(item) for item in indicators if isinstance(item, str))) |
                            (current_domains & set(str(item) for item in campaign_domains if isinstance(item, str))))
            if shared:
                matches.append({"case_id": str(case.get("case_id", "unknown"))[:100],
                                "shared_indicators": shared[:10],
                                "confirmed_at": confirmed_at.isoformat(),
                                "confirmed_verdict": str(case.get("verdict", "unknown"))[:40]})
    return matches[:10]
