from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .schemas import Signal

URL_RE = re.compile(r"https?://[^\s<>\"']{1,2048}", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URGENCY_RE = re.compile(
    r"\b(urgent|immediately|verify your account|password expires|act now|"
    r"account suspended|confirm your password|payment failed)\b",
    re.IGNORECASE,
)
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly"}


def _public_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return parsed.is_global


def _safe_url_excerpt(scheme: str, hostname: str, path: str) -> str:
    # Never echo URL user-info, query parameters, or fragments into a report.
    safe_host = hostname[:253]
    base = f"{scheme.lower()}://{safe_host}"
    suffix = "/…" if path and path != "/" else ""
    return (base + suffix)[:300]


def analyze_text(text: str) -> list[Signal]:
    """Return explainable signals only; absence of signals does not imply safety."""
    signals: list[Signal] = []
    seen_urls: set[str] = set()

    for match in URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,);!?]")
        if raw in seen_urls:
            continue
        seen_urls.add(raw)
        try:
            parsed = urlsplit(raw)
            hostname = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not hostname:
            continue

        if parsed.scheme.lower() != "https":
            signals.append(Signal(
                id=f"url-insecure-{len(signals) + 1}",
                category="url",
                severity="medium",
                description="URL uses HTTP rather than HTTPS; this alone does not establish maliciousness.",
                evidence_excerpt=_safe_url_excerpt(parsed.scheme, hostname, parsed.path),
            ))
        if hostname in URL_SHORTENERS:
            signals.append(Signal(
                id=f"url-shortener-{len(signals) + 1}",
                category="url",
                severity="low",
                description="URL uses a known link-shortening domain; inspect the resolved destination safely.",
                evidence_excerpt=_safe_url_excerpt(parsed.scheme, hostname, parsed.path),
            ))
        if hostname.startswith("xn--") or ".xn--" in hostname:
            signals.append(Signal(
                id=f"url-idn-{len(signals) + 1}",
                category="url",
                severity="low",
                description="URL hostname contains an internationalized-domain label; verify the intended domain.",
                evidence_excerpt=_safe_url_excerpt(parsed.scheme, hostname, parsed.path),
            ))

    for match in IP_RE.finditer(text):
        value = match.group(0)
        if _public_ip(value):
            signals.append(Signal(
                id=f"public-ip-{len(signals) + 1}",
                category="ip",
                severity="info",
                description="A public IPv4 address is present; reputation or context is needed to assess it.",
                evidence_excerpt=value,
            ))

    for match in URGENCY_RE.finditer(text):
        excerpt = match.group(0)
        signals.append(Signal(
            id=f"urgency-{len(signals) + 1}",
            category="language",
            severity="low",
            description="Urgency or account-pressure language is present; interpret it in context.",
            evidence_excerpt=excerpt[:300],
        ))

    return signals[:50]
