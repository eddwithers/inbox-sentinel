"""IS-LinkGuard — deterministic suspicious-URL signals (pre_gate).

Checks links the way phishing guidance recommends: IP-literal destinations
(including hex/octal obfuscation), embedded credentials (the
http://good.com@evil.com trick), punycode/IDN homograph hosts, URL
shorteners, high-risk TLDs (.zip/.mov file-extension confusion and heavily
abused free TLDs), deep subdomain chains, and plaintext-HTTP URLs carrying
login/verify/billing language.

Pure, bounded, offline: at most 50 URLs, each capped at 2048 characters,
stdlib parsing only, no network, no reputation feeds. Links come from the
host's bounded HTML extraction plus URLs visible in the body text. False
positives are expected (a legitimate shortener or IDN host will warn);
over-warn rather than under-warn — the summary stays in the alert.
"""

import ipaddress
import re
from urllib.parse import urlsplit

NAME = "linkguard"
BRAND = "IS-LinkGuard"
VERSION = "1.0.0"
STAGES = ("pre_gate",)
DEFAULT_ENABLED = True

MAX_URLS = 50
MAX_URL_LEN = 2048

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorte.st", "bl.ink",
    "soo.gd", "s.id", "clck.ru", "lnkd.in",
}
_HIGH_RISK_TLD = {
    ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
    ".click", ".link", ".rest", ".fit", ".gdn", ".work", ".date", ".racing",
    ".win", ".bid", ".stream", ".loan", ".download",
}
# Linear character-class pattern; no nested quantifiers (ReDoS-safe).
_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
_HEX_IP_RE = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*$", re.I)
_SENSITIVE_PATH = re.compile(
    r"(?:login|signin|sign-in|verify|account|update|billing|secure|password|confirm)",
    re.I,
)


def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Hex/octal-style obfuscation, e.g. 0x7f.0x0.0x0.0x1 or 2130706433.
    return bool(_HEX_IP_RE.match(host)) and any(c in host for c in ".x")


def link_signals(links, body=""):
    """Ordered, de-duplicated signal names across hrefs and visible URLs."""
    urls = []
    seen = set()
    for raw in list(links or []) + _URL_RE.findall(str(body or "")):
        url = str(raw)[:MAX_URL_LEN].strip().rstrip(".,;")
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
        if len(urls) >= MAX_URLS:
            break
    hits = []

    def add(name):
        if name not in hits:
            hits.append(name)

    for url in urls:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            continue  # malformed (e.g. bad IPv6 literal) — not a signal
        if not host:
            continue
        if parts.username is not None or parts.password is not None:
            add("credentials-in-URL")
        if _is_ip_literal(host):
            add("IP-address link")
        if host.startswith("xn--") or ".xn--" in host:
            add("punycode/IDN link")
        if host in _SHORTENERS:
            add("shortened link")
        tld = "." + host.rsplit(".", 1)[-1]
        if tld in _HIGH_RISK_TLD:
            add("high-risk TLD")
        if host.count(".") >= 4:
            add("deep-subdomain link")
        if parts.scheme == "http" and _SENSITIVE_PATH.search(url):
            add("insecure login link")
    return hits


def pre_gate(message, api):
    hits = link_signals(message.get("links"), message.get("body", ""))
    if not hits:
        return None
    return {"force_alert": True, "signals": hits, "brand": BRAND}
