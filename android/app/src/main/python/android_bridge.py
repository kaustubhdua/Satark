"""Small JSON bridge called from Kotlin through Chaquopy."""
import json
from pathlib import Path
from file_guard.engine import scan_bytes
from file_guard.history import ScanHistory
from file_guard.intelligence import ThreatIntelligenceStore

def scan_shared_file(data, filename, app_data_dir):
    root = Path(app_data_dir)
    root.mkdir(parents=True, exist_ok=True)
    intel = ThreatIntelligenceStore(root / "file_guard_intelligence.sqlite3")
    result = scan_bytes(bytes(data), str(filename or "shared-file"), intelligence=intel)
    ScanHistory(root / "file_guard_history.sqlite3").add(result)
    return json.dumps(result.to_dict(), ensure_ascii=True)

def scan_stats(app_data_dir):
    root = Path(app_data_dir)
    return json.dumps(ThreatIntelligenceStore(root / "file_guard_intelligence.sqlite3").stats())
