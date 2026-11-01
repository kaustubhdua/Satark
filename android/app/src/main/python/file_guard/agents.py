"""Deterministic specialist agents and evidence fusion for offline File Guard.

The agents borrow the independent-specialist, typed-evidence and deterministic
arbitration pattern used by CyberSentinel, adapted to static file inspection.
They do not call LLMs, hosted APIs or network services.
"""
from pathlib import Path
import re

_DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png)\.(exe|scr|com|bat|cmd|ps1)$", re.I
)
_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".sh", ".elf", ".so"}

def route_file(filename, detected_type, yara_configured=False):
    """Return deterministic specialist routing for a file."""
    extension = Path(filename or "unnamed").suffix.lower()
    route = ["magic_signature", "sha256_intelligence", "filename_metadata", "evidence_fusion"]
    if yara_configured:
        route.insert(3, "local_yara")
    if detected_type == "Unknown / unrecognized":
        route.append("unknown_format_review")
    return {
        "agent": "file_router",
        "status": "complete",
        "detected_type": detected_type,
        "extension": extension,
        "specialists": route,
    }

def inspect_filename(filename):
    name = Path(filename or "unnamed").name[:255]
    extension = Path(name).suffix.lower()
    signals = []
    if _DOUBLE_EXTENSION.search(name):
        signals.append({
            "code": "DOUBLE_EXTENSION",
            "severity": "high",
            "detail": "Document/image extension is followed by an executable extension.",
        })
    if extension in _EXECUTABLE_EXTENSIONS:
        signals.append({
            "code": "EXECUTABLE_FILE",
            "severity": "info",
            "detail": "The extension identifies an executable/script format; this alone is not evidence of malware.",
        })
    return {
        "agent": "filename_metadata",
        "status": "complete",
        "signals": signals,
    }

def inspect_hash(digest, intelligence):
    match = intelligence.lookup(digest) if intelligence else None
    signals = []
    if match and match["label"] == "malicious":
        signals.append({
            "code": "KNOWN_MALICIOUS_HASH",
            "severity": "critical",
            "detail": "Exact SHA-256 match in imported dataset " + str(match["source"]) + ".",
        })
    elif match and match["label"] == "benign":
        signals.append({
            "code": "KNOWN_BENIGN_HASH",
            "severity": "info",
            "detail": "Exact benign hash match in imported dataset " + str(match["source"]) + ".",
        })
    return {
        "agent": "sha256_intelligence",
        "status": "match" if match else "no_match",
        "match": match,
        "signals": signals,
    }

def inspect_yara(data, rules_path):
    if not rules_path:
        return {"agent": "local_yara", "status": "not_configured", "available": False,
                "matches": [], "error": None, "signals": []}
    path = Path(rules_path)
    if not path.is_file():
        return {"agent": "local_yara", "status": "rules_missing", "available": False,
                "matches": [], "error": "rules_file_missing", "signals": []}
    try:
        import yara
    except ImportError:
        return {"agent": "local_yara", "status": "dependency_missing", "available": False,
                "matches": [], "error": "yara_python_not_installed", "signals": []}
    try:
        compiled = yara.compile(filepath=str(path))
        matches = [str(match.rule) for match in compiled.match(data=data, timeout=3)]
        signals = []
        if matches:
            signals.append({
                "code": "YARA_MATCH",
                "severity": "high",
                "detail": "Local YARA rule match: " + ", ".join(matches[:8]),
            })
        return {"agent": "local_yara", "status": "match" if matches else "no_match",
                "available": True, "matches": matches, "error": None, "signals": signals}
    except Exception as exc:
        return {"agent": "local_yara", "status": "rules_error", "available": True,
                "matches": [], "error": type(exc).__name__, "signals": []}

def fuse_evidence(signals, hash_match=None, yara_matches=None):
    """Combine independent evidence with explicit precedence; benign is not a whitelist."""
    codes = {item.get("code") for item in signals}
    score = 0
    if "EXTENSION_SIGNATURE_MISMATCH" in codes:
        score += 45
    if "DOUBLE_EXTENSION" in codes:
        score += 45
    score = min(score, 100)
    if hash_match and hash_match.get("label") == "malicious":
        return {"agent": "evidence_fusion", "score": 100, "verdict": "Known threat",
                "risk_level": "critical", "precedence": "exact_malicious_sha256"}
    if yara_matches:
        return {"agent": "evidence_fusion", "score": max(score, 80), "verdict": "Signature match",
                "risk_level": "high", "precedence": "local_yara"}
    if score >= 40:
        return {"agent": "evidence_fusion", "score": score, "verdict": "Suspicious",
                "risk_level": "high", "precedence": "metadata_mismatch"}
    if score >= 20:
        return {"agent": "evidence_fusion", "score": score, "verdict": "Needs review",
                "risk_level": "medium", "precedence": "heuristic"}
    return {"agent": "evidence_fusion", "score": score, "verdict": "No known threat detected",
            "risk_level": "low", "precedence": "no_enabled_indicator_matched"}
