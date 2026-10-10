"""Deterministic, UI-neutral finding model for SATARK results."""

import re

_SEVERITY = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "clear": 0,
    "unknown": 0,
}
_NEGATORS = re.compile(
    r"(?:\bnot\s+considered|\bnot\s+classified\s+as|"
    r"\bnever\s+considered|\bnot|\bno|\bnever|\bisn['’]?t|\bis\s+not)"
    r"\s+(?:(?:a|an|the)\s+)?$"
)
_LABELS = (
    ("critical", re.compile(r"\b(?:critical|severe)\b")),
    ("high", re.compile(r"\bhigh\b")),
    ("medium", re.compile(r"\b(?:medium|moderate)\b")),
    ("low", re.compile(r"\blow\b")),
)


def _has_unnegated_label(text, pattern):
    """Match a severity label only when it is not directly negated."""
    for match in pattern.finditer(text):
        prefix = text[max(0, match.start() - 32):match.start()]
        if not _NEGATORS.search(prefix):
            return True
    return False


def finding_severity(value):
    """Map a displayed check value to a conservative severity.

    Explicit negative states take precedence, followed by unnegated severity
    labels. Generic words such as "detected" are only a fallback; a value like
    "Low risk — detected" therefore remains Low instead of becoming High.
    """
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"

    # Negation must be evaluated before positive keywords. Avoid treating
    # "not clear" as a clear result.
    if re.search(r"\b(?:not detected|no sign(?:s)?(?: of)?|no indicators?|none detected|absent|false)\b", text):
        return "clear"
    if re.fullmatch(r"(?:status\s*:\s*)?clear[.! ]*", text):
        return "clear"

    saw_severity_label = False
    for severity, pattern in _LABELS:
        if pattern.search(text):
            saw_severity_label = True
            if _has_unnegated_label(text, pattern):
                return severity

    # Do not let a generic "detected" word override a negated severity label,
    # as in "no high risk detected".
    if not saw_severity_label and _has_unnegated_label(
        text, re.compile(r"\b(?:detected|present|confirmed)\b")
    ):
        return "high"

    return "unknown"


def build_findings(result):
    """Normalize threat checks into stable finding objects for every UI/export."""
    checks = result.get("threat_analysis", {}) if isinstance(result, dict) else {}
    if not isinstance(checks, dict):
        checks = {}
    findings = []
    for name, value in checks.items():
        title = str(name)
        severity = finding_severity(value)
        findings.append({
            "id": re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "finding",
            "title": title,
            "status": str(value or "Needs review"),
            "severity": severity,
            "action": (
                "Verify independently before acting."
                if severity in {"critical", "high", "medium", "unknown"}
                else (
                    "This check did not report an indicator; that does not prove the item is safe."
                    if severity == "clear"
                    else "Review this low-severity signal in context."
                )
            ),
        })
    findings.sort(key=lambda item: _SEVERITY.get(item["severity"], 0), reverse=True)
    return findings
