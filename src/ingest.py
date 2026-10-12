"""Bounded, offline MIME extraction for analyst triage."""

from __future__ import annotations

import hashlib
import html
import io
import re
import time
import zipfile
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_PARTS = 100
MAX_TEXT_CHARS = 200_000
MAX_PART_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100
MAX_EXTRACTION_SECONDS = 10
TEXT_ATTACHMENT_TYPES = {"text/plain", "text/csv", "text/html"}
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)


class _HTMLReader(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.standalone_text = []
        self.links = []
        self._href = None
        self._label = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._label = []

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append({"url": html.unescape(self._href), "label": " ".join(self._label).strip()})
            self._href = None
            self._label = []

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._label.append(data)
        else:
            self.standalone_text.append(data)


def _decode(part, payload):
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _chunks(text, prefix, evidence):
    for start in range(0, min(len(text), MAX_TEXT_CHARS), 500):
        excerpt = text[start : start + 500].strip()
        if excerpt:
            evidence.append({"id": f"{prefix}:{start}", "source": prefix, "text": excerpt})


def parse_eml(path: str | Path) -> dict:
    started = time.monotonic()
    path = Path(path)
    if path.stat().st_size > MAX_EMAIL_BYTES:
        raise ValueError(f"email exceeds {MAX_EMAIL_BYTES} byte limit")
    raw = path.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = {key: str(msg.get(key, "")) for key in ("From", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID", "List-Unsubscribe")}
    headers["From_address"] = parseaddr(headers["From"])[1]
    headers["Reply-To_address"] = parseaddr(headers["Reply-To"])[1]
    headers["Return-Path_address"] = parseaddr(headers["Return-Path"])[1]
    headers["Authentication-Results"] = [str(value) for value in msg.get_all("Authentication-Results", [])]
    evidence = [{"id": f"header:{key.lower()}", "source": f"header:{key}", "text": value[:1000]}
                for key, value in headers.items() if value and isinstance(value, str)]
    if headers["Authentication-Results"]:
        evidence.append({"id": "header:authentication-results", "source": "header:Authentication-Results",
                         "text": " | ".join(headers["Authentication-Results"])[:2000]})
    body = []
    links = []
    attachments = []
    unknown = []
    parts = [part for part in msg.walk() if not part.is_multipart()]
    if len(parts) > MAX_PARTS:
        unknown.append("mime_parts_truncated")
    for index, part in enumerate(parts[:MAX_PARTS]):
        if time.monotonic() - started > MAX_EXTRACTION_SECONDS:
            raise TimeoutError("MIME extraction exceeded time budget")
        ctype = part.get_content_type()
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        payload = part.get_payload(decode=True) or b""
        if len(payload) > MAX_PART_BYTES:
            unknown.append(f"part_{index}_too_large")
            continue
        is_attachment = disposition == "attachment" or bool(filename)
        if is_attachment:
            item = {"id": f"attachment:{index}", "filename": filename or "(unnamed)",
                    "content_type": ctype, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                    "archive_entries": []}
            if zipfile.is_zipfile(io.BytesIO(payload)):
                try:
                    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                        item["archive_entries"] = [entry.filename[:300] for entry in archive.infolist()[:MAX_ARCHIVE_ENTRIES]]
                        if len(archive.infolist()) > MAX_ARCHIVE_ENTRIES:
                            unknown.append(f"attachment_{index}_archive_truncated")
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    unknown.append(f"attachment_{index}_archive_unreadable")
            if time.monotonic() - started > MAX_EXTRACTION_SECONDS:
                raise TimeoutError("attachment inspection exceeded time budget")
            attachments.append(item)
            evidence.append({"id": item["id"], "source": item["id"],
                             "text": f"{item['filename']} ({ctype}, {len(payload)} bytes)"})
            if ctype not in TEXT_ATTACHMENT_TYPES:
                unknown.append(f"attachment_{index}_content_unassessed")
                continue
        if ctype not in {"text/plain", "text/html", "text/csv"}:
            continue
        decoded = _decode(part, payload)
        if ctype == "text/html":
            parser = _HTMLReader()
            parser.feed(decoded[:MAX_TEXT_CHARS])
            visible = " ".join(parser.text)
            text_with_standalone_urls = " ".join(parser.standalone_text)
            for link_index, link in enumerate(parser.links):
                link_id = f"html-link:{index}:{link_index}"
                links.append({"id": link_id, **link})
                evidence.append({"id": link_id, "source": f"html:{index}",
                                 "text": f"label={link['label'][:250]} target={link['url'][:500]}"})
        else:
            visible = decoded
            text_with_standalone_urls = visible
        if len(decoded) > MAX_TEXT_CHARS:
            unknown.append(f"part_{index}_text_truncated")
        visible = visible[:MAX_TEXT_CHARS]
        body.append({"id": f"body:{index}", "content_type": ctype,
                     "attachment": is_attachment, "text": visible})
        _chunks(visible, f"body:{index}", evidence)
        # An anchor's displayed URL is a claim, not another destination.
        # Its href was already recorded above; only standalone text URLs are
        # added as text-link destinations.
        for link_index, match in enumerate(URL_RE.finditer(text_with_standalone_urls)):
            url = match.group(0).rstrip(".,;)")
            link_id = f"text-link:{index}:{link_index}"
            links.append({"id": link_id, "url": url, "label": url})
            evidence.append({"id": link_id, "source": f"body:{index}", "text": url[:500]})
    if not body:
        unknown.append("body_missing_or_unreadable")
    normalized_content = re.sub(r"\s+", " ", headers.get("Subject", "").lower() + " " +
                                " ".join(part["text"].lower() for part in body)).strip()
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest(),
            "content_fingerprint": hashlib.sha256(normalized_content.encode("utf-8")).hexdigest(),
            "headers": headers, "body": body, "links": links, "attachments": attachments,
            "evidence": evidence, "unknown_signals": sorted(set(unknown))}
