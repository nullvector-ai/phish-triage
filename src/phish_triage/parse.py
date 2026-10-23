"""Parse a raw RFC 5322 email (.eml) into the fields the analysers need."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser


@dataclass
class Link:
    href: str
    text: str = ""


@dataclass
class ParsedEmail:
    subject: str
    from_name: str
    from_addr: str
    reply_to: str
    return_path: str
    auth_results: str
    text: str
    links: list[Link] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[Link] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(Link(self._href.strip(), "".join(self._buf).strip()))
            self._href = None

    def handle_data(self, data):
        self.text_parts.append(data)
        if self._href is not None:
            self._buf.append(data)


_URL_RX = re.compile(r"https?://[^\s<>\"')]+", re.I)


def parse_email(raw: bytes | str) -> ParsedEmail:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))

    texts, links, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        if fname or part.get_content_disposition() == "attachment":
            attachments.append(fname or "unnamed")
            continue
        ctype = part.get_content_type()
        try:
            payload = part.get_content()
        except Exception:  # undecodable part
            continue
        if ctype == "text/html":
            ex = _LinkExtractor()
            ex.feed(payload)
            links.extend(ex.links)
            texts.append(" ".join(ex.text_parts))
        elif ctype == "text/plain":
            texts.append(payload)
            links.extend(Link(u) for u in _URL_RX.findall(payload))

    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_name=from_name,
        from_addr=from_addr.lower(),
        reply_to=reply_to.lower(),
        return_path=return_path.lower(),
        auth_results=str(msg.get("Authentication-Results", "")),
        text=re.sub(r"\s+", " ", " ".join(texts)).strip(),
        links=links,
        attachments=attachments,
    )
