"""Small JSON bridge called from Kotlin through Chaquopy."""
import json
from io import StringIO
from pathlib import Path
from file_guard.engine import scan_bytes
from file_guard.history import ScanHistory
from file_guard.intelligence import ThreatIntelligenceStore

def _paths(app_data_dir):
    root = Path(app_data_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root

def scan_shared_file(data, filename, app_data_dir):
    root = _paths(app_data_dir)
    intel = ThreatIntelligenceStore(root / "file_guard_intelligence.sqlite3")
    result = scan_bytes(bytes(data), str(filename or "shared-file"), intelligence=intel)
    ScanHistory(root / "file_guard_history.sqlite3").add(result)
    return json.dumps(result.to_dict(), ensure_ascii=True)

def import_csv_snapshot(data, source_name, app_data_dir):
    root = _paths(app_data_dir)
    store = ThreatIntelligenceStore(root / "file_guard_intelligence.sqlite3")
    text = bytes(data).decode("utf-8-sig")
    outcome = store.import_csv(StringIO(text), str(source_name), max_rows=2_000_000)
    return json.dumps({"import": outcome, "stats": store.stats()}, ensure_ascii=True)

def scan_history(app_data_dir):
    root = _paths(app_data_dir)
    return json.dumps(ScanHistory(root / "file_guard_history.sqlite3").list_recent(100), ensure_ascii=True)

def clear_scan_history(app_data_dir):
    root = _paths(app_data_dir)
    ScanHistory(root / "file_guard_history.sqlite3").clear()
    return json.dumps({"cleared": True})

def clear_intelligence(app_data_dir):
    root = _paths(app_data_dir)
    ThreatIntelligenceStore(root / "file_guard_intelligence.sqlite3").clear()
    return json.dumps({"cleared": True})

def scan_stats(app_data_dir):
    root = _paths(app_data_dir)
    return json.dumps(ThreatIntelligenceStore(root / "file_guard_intelligence.sqlite3").stats())
