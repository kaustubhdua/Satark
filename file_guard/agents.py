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
    route = ["magic_signature", "builtin_byte_signatures", "sha256_intelligence", "filename_metadata", "evidence_fusion"]
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
            "detail": "Exact SHA-256 match in " + str(match["source"]) +
                ((" · type " + str(match.get("file_type"))) if match.get("file_type") else "") +
                ((" · family " + str(match.get("family"))) if match.get("family") else "") +
                ((" · dataset date " + str(match.get("dataset_date"))) if match.get("dataset_date") else "") + ".",
        })
    elif match and match["label"] == "benign":
        signals.append({
            "code": "KNOWN_BENIGN_HASH",
            "severity": "info",
            "detail": "Exact benign hash match in " + str(match["source"]) +
                ((" · type " + str(match.get("file_type"))) if match.get("file_type") else "") + ".",
        })
    return {
        "agent": "sha256_intelligence",
        "status": "match" if match else "no_match",
        "match": match,
        "signals": signals,
    }

class BuiltinSignatureMatcher:
    """Incremental, bounded-memory matcher for selected static byte indicators."""

    _RAW_TAIL_BYTES = 64
    _COMPACT_TAIL_BYTES = 32

    def __init__(self, filename, detected_type):
        self.name = Path(filename or "unnamed").name.lower()
        self.detected_type = detected_type
        self._raw_tail = b""
        self._compact_tail = b""
        self._seen = set()

    def update(self, chunk):
        raw = bytes(chunk).lower()
        if not raw:
            return
        combined = self._raw_tail + raw
        compact = self._compact_tail + raw.replace(bytes([0]), b"")

        if self.detected_type == "PDF":
            if b"/openaction" in combined:
                self._seen.add("pdf_openaction")
            if b"/javascript" in combined or b"/js" in combined:
                self._seen.add("pdf_javascript")
            if b"/launch" in combined:
                self._seen.add("pdf_launch")

        if self.detected_type == "OLE document":
            # Record each token independently: Office macro markers can be
            # separated by hundreds of bytes or span different read chunks.
            if b"autoopen" in compact:
                self._seen.add("ole_autoopen")
            if b"shell" in compact:
                self._seen.add("ole_shell")

        if self.name.endswith((".ps1", ".psm1", ".bat", ".cmd")):
            if any(token in combined for token in (b"downloadstring", b"downloadfile", b"invoke-webrequest")):
                self._seen.add("script_download")
            if any(token in combined for token in (b"invoke-expression", b"iex(", b"start-process")):
                self._seen.add("script_execute")

        if self.name.endswith((".js", ".mjs", ".cjs")):
            for token in (b"eval(", b"fromcharcode", b"unescape("):
                if token in combined:
                    self._seen.add("js:" + token.decode("ascii"))

        if self.detected_type == "Android DEX":
            if b"dexclassloader" in combined or b"loaddex" in combined:
                self._seen.add("dex_dynamic_loading")

        self._raw_tail = combined[-self._RAW_TAIL_BYTES:]
        self._compact_tail = compact[-self._COMPACT_TAIL_BYTES:]

    def result(self):
        descriptions = {
            "PDF_OPENACTION_JAVASCRIPT": "PDF contains both an automatic open action and a JavaScript marker.",
            "PDF_OPENACTION_LAUNCH": "PDF contains an automatic open action and a launch action marker.",
            "OLE_AUTOOPEN_SHELL": "OLE document contains both AutoOpen and Shell automation markers.",
            "SCRIPT_DOWNLOAD_EXECUTE": "Script contains both a network-download marker and an execution marker.",
            "JAVASCRIPT_OBFUSCATION_CLUSTER": "JavaScript contains a cluster of three obfuscation-related markers.",
            "DEX_DYNAMIC_LOADING": "DEX bytecode contains a dynamic class-loading marker.",
        }
        matched = []
        if {"pdf_openaction", "pdf_javascript"} <= self._seen:
            matched.append("PDF_OPENACTION_JAVASCRIPT")
        if {"pdf_openaction", "pdf_launch"} <= self._seen:
            matched.append("PDF_OPENACTION_LAUNCH")
        if {"ole_autoopen", "ole_shell"} <= self._seen:
            matched.append("OLE_AUTOOPEN_SHELL")
        if {"script_download", "script_execute"} <= self._seen:
            matched.append("SCRIPT_DOWNLOAD_EXECUTE")
        if len(self._seen.intersection({"js:eval(", "js:fromcharcode", "js:unescape("})) >= 3:
            matched.append("JAVASCRIPT_OBFUSCATION_CLUSTER")
        if "dex_dynamic_loading" in self._seen:
            matched.append("DEX_DYNAMIC_LOADING")
        findings = [{"rule_id": rule_id, "description": descriptions[rule_id]} for rule_id in matched]
        signals = [{
            "code": "BUILTIN_PATTERN_MATCH",
            "severity": "high",
            "detail": item["description"],
            "rule_id": item["rule_id"],
        } for item in findings]
        return {
            "agent": "builtin_byte_signatures",
            "status": "match" if findings else "no_match",
            "matches": findings,
            "signals": signals,
        }

def inspect_builtin_signatures(data, filename, detected_type):
    """Inspect raw bytes with bounded static patterns; never decode or extract content."""
    matcher = BuiltinSignatureMatcher(filename, detected_type)
    matcher.update(data)
    return matcher.result()

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
    if "BUILTIN_PATTERN_MATCH" in codes:
        score += 45
    score = min(score, 100)
    if hash_match and hash_match.get("label") == "malicious":
        return {"agent": "evidence_fusion", "score": 100, "verdict": "Known threat",
                "risk_level": "critical", "precedence": "exact_malicious_sha256"}
    if yara_matches:
        return {"agent": "evidence_fusion", "score": max(score, 80), "verdict": "Signature match",
                "risk_level": "high", "precedence": "local_yara"}
    if score >= 40:
        precedence = "metadata_mismatch" if codes & {"EXTENSION_SIGNATURE_MISMATCH", "DOUBLE_EXTENSION"} else "builtin_byte_pattern"
        return {"agent": "evidence_fusion", "score": score, "verdict": "Suspicious",
                "risk_level": "high", "precedence": precedence}
    if score >= 20:
        return {"agent": "evidence_fusion", "score": score, "verdict": "Needs review",
                "risk_level": "medium", "precedence": "heuristic"}
    return {"agent": "evidence_fusion", "score": score, "verdict": "No known threat detected",
            "risk_level": "low", "precedence": "no_enabled_indicator_matched"}
