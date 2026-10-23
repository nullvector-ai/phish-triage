"""Deterministic phishing indicators. Each one is explainable and weighted."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .parse import ParsedEmail

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "t.ly"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "work", "support", "rest"}
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img", ".lnk",
             ".docm", ".xlsm", ".pptm", ".html", ".htm", ".zip", ".rar", ".7z")
BRANDS = ["paypal", "microsoft", "office365", "apple", "amazon", "netflix", "dhl", "fedex", "google",
          "bank", "facebook", "instagram", "whatsapp", "binance", "coinbase"]
URGENCY = re.compile(
    r"\b(urgent|immediately|within 24 hours|account (will be )?(suspended|locked|closed)|verify your (account|identity)|"
    r"unusual (sign-in|activity)|final notice|action required|confirm your (password|details)|payment failed|"
    r"you have won|claim your|gift card)\b", re.I)
# French and Thai lures. Thai has no spaces between words, so these are plain substrings, no \b.
URGENCY_FR = re.compile(
    r"\b(action requise|sous 24 ?heures|imm[ée]diatement|compte (sera )?(suspendu|bloqu[ée]|ferm[ée])|"
    r"v[ée]rifie[rz]? votre (compte|identit[ée])|dernier avis|frais de (r[ée]exp[ée]dition|livraison)|colis (en attente|bloqu[ée]))", re.I)
URGENCY_TH = re.compile(r"ถูกระงับ|ภายใน 24 ชั่วโมง|ยืนยันตัวตน|ด่วน|การเข้าสู่ระบบที่ผิดปกติ|บัญชีของคุณถูกล็อก")
CREDENTIAL_FR = re.compile(r"\b(mot de passe|coordonn[ée]es bancaires|num[ée]ro de carte|code de s[ée]curit[ée]|identifiants)\b", re.I)
CREDENTIAL_TH = re.compile(r"รหัสผ่าน|รหัส OTP|เลขบัตร|ข้อมูลบัตรเครดิต")
CREDENTIAL_ASK = re.compile(r"\b(password|passcode|one-time code|otp|ssn|credit card|card number|cvv|seed phrase|login details)\b", re.I)


@dataclass
class Indicator:
    name: str
    weight: float
    detail: str


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _registered(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyse(mail: ParsedEmail) -> list[Indicator]:
    out: list[Indicator] = []
    fd = mail.from_domain

    # --- sender / header checks ---
    if mail.reply_to and _registered(mail.reply_to.split("@")[-1]) != _registered(fd):
        out.append(Indicator("reply_to_mismatch", 2.0, f"Reply-To {mail.reply_to} differs from From domain {fd}"))
    if mail.return_path and fd and _registered(mail.return_path.split("@")[-1]) != _registered(fd):
        out.append(Indicator("return_path_mismatch", 1.0, f"Return-Path {mail.return_path} differs from {fd}"))
    name_l = mail.from_name.lower()
    for b in BRANDS:
        if b in name_l and b not in fd:
            out.append(Indicator("display_name_spoof", 2.5, f"display name mentions '{b}' but sender domain is {fd}"))
            break
    if fd and fd.rsplit(".", 1)[-1] in RISKY_TLDS:
        out.append(Indicator("risky_tld", 1.0, f"sender domain uses .{fd.rsplit('.', 1)[-1]} TLD ({fd})"))
    ar = mail.auth_results.lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mech}=(fail|softfail|none|permerror)", ar):
            out.append(Indicator(f"{mech}_fail", 1.5 if mech == "dmarc" else 1.0, f"{mech.upper()} did not pass"))

    # --- content checks ---
    blob = f"{mail.subject} {mail.text}"
    urg = sorted({m.group(0).lower() for rx in (URGENCY, URGENCY_FR, URGENCY_TH) for m in rx.finditer(blob)})
    if urg:
        out.append(Indicator("urgency_language", min(2.0, 0.75 * len(urg)), "phrases: " + ", ".join(urg[:5])))
    cred = sorted({m.group(0).lower() for rx in (CREDENTIAL_ASK, CREDENTIAL_FR, CREDENTIAL_TH) for m in rx.finditer(blob)})
    if cred:
        out.append(Indicator("credential_request", 1.5, "mentions: " + ", ".join(cred[:5])))

    # --- link checks ---
    seen = set()
    for link in mail.links:
        h = _host(link.href)
        if not h or (h, link.text) in seen:
            continue
        seen.add((h, link.text))
        if _is_ip(h):
            out.append(Indicator("ip_url", 2.0, f"link to raw IP {h}"))
        if _registered(h) in SHORTENERS:
            out.append(Indicator("url_shortener", 1.0, f"shortened link {h}"))
        if h.rsplit(".", 1)[-1] in RISKY_TLDS:
            out.append(Indicator("risky_tld", 1.0, f"link uses .{h.rsplit('.', 1)[-1]} TLD ({h})"))
        if h.startswith("xn--") or ".xn--" in h:
            out.append(Indicator("punycode_domain", 2.0, f"internationalised (lookalike?) domain {h}"))
        shown = _host(link.text) if link.text.lower().startswith(("http", "www.")) else ""
        if link.text.lower().startswith("www."):
            shown = link.text.lower().split("/")[0]
        if shown and _registered(shown) != _registered(h):
            out.append(Indicator("link_text_mismatch", 2.5, f"text shows {shown} but goes to {h}"))
        for b in BRANDS:
            if b in h and _registered(h) not in (f"{b}.com", f"{b}.net", f"{b}.org") and b not in fd:
                out.append(Indicator("brand_in_foreign_domain", 1.5, f"'{b}' inside unrelated domain {h}"))
                break

    # --- attachments ---
    for a in mail.attachments:
        al = a.lower()
        if al.endswith(RISKY_EXT) or re.search(r"\.(pdf|docx?|xlsx?)\.(exe|js|scr|html?)$", al):
            out.append(Indicator("risky_attachment", 2.5, f"attachment {a}"))
    return out


def score(indicators: list[Indicator]) -> tuple[float, str]:
    total = sum(i.weight for i in indicators)
    if total >= 5:
        return total, "phishing"
    if total >= 2.5:
        return total, "suspicious"
    return total, "likely_benign"
