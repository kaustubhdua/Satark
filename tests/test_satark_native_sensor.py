import json
import tempfile
import unittest
from pathlib import Path

from satark_native_sensor import (
    append_hash_chain,
    classify_auth_line,
    integrity_events,
    parse_auth_log,
    scan_files,
    verify_hash_chain,
)


class NativeSensorTests(unittest.TestCase):
    def test_auth_classification_is_bounded_to_security_relevant_patterns(self):
        self.assertEqual(classify_auth_line("Failed password for invalid user guest"), "auth_failed")
        self.assertEqual(classify_auth_line("Accepted publickey for ops"), "auth_success")
        self.assertIsNone(classify_auth_line("system boot completed"))

    def test_auth_log_collects_observed_lines_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            log = root / "auth.log"
            log.write_text("normal startup\nFailed password for invalid user admin\nAccepted publickey for ops\n")
            events = parse_auth_log(log, max_bytes=1024)
            self.assertEqual([e["event_type"] for e in events], ["auth_failed", "auth_success"])
            self.assertTrue(all(e["evidence_class"] == "observed_local_source" for e in events))
            link = root / "link"
            link.symlink_to(log)
            with self.assertRaises(ValueError):
                parse_auth_log(link)

    def test_file_integrity_detects_add_modify_and_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a.conf"
            b = root / "b.conf"
            a.write_text("one")
            before = scan_files([a, b])
            a.write_text("two")
            b.write_text("new")
            after = scan_files([a, b])
            events = integrity_events(before, after, observed_at=100)
            self.assertEqual({e["event_type"] for e in events}, {"file_modified", "file_added"})
            events = integrity_events(after, scan_files([]), observed_at=101)
            self.assertTrue(events)
            self.assertTrue(all(e["event_type"] == "file_missing" for e in events))

    def test_hash_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Path(td) / "events.jsonl"
            append_hash_chain(journal, [{"event_type": "auth_failed", "raw_sha256": "a"}])
            self.assertEqual(verify_hash_chain(journal), (True, 1))
            item = json.loads(journal.read_text().strip())
            item["event_type"] = "auth_success"
            journal.write_text(json.dumps(item) + "\n")
            self.assertEqual(verify_hash_chain(journal), (False, 0))

    def test_append_refuses_symlinked_journal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.jsonl"
            target.write_text("keep me")
            link = root / "events.jsonl"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                append_hash_chain(link, [{"event_type": "auth_failed"}])
            self.assertEqual(target.read_text(), "keep me")

    def test_duplicate_event_appends_are_chain_linked(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Path(td) / "events.jsonl"
            event = {"event_id": "same", "event_type": "auth_failed"}
            self.assertEqual(append_hash_chain(journal, [event, event]), 2)
            self.assertEqual(verify_hash_chain(journal), (True, 2))


if __name__ == "__main__":
    unittest.main()
