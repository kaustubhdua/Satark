import json
import tempfile
import unittest
from pathlib import Path

from satark_native_sensor import (
    append_hash_chain,
    classify_auth_line,
    integrity_events,
    load_json,
    MAX_STATE_BYTES,
    parse_auth_log,
    scan_files,
    verify_hash_chain,
    write_json_atomic,
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

    def test_verify_refuses_symlinked_journal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.jsonl"
            append_hash_chain(target, [{"event_type": "auth_failed"}])
            link = root / "events.jsonl"
            link.symlink_to(target)
            self.assertEqual(verify_hash_chain(link), (False, 0))

    def test_verify_refuses_broken_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            link = Path(td) / "events.jsonl"
            link.symlink_to(Path(td) / "missing.jsonl")
            self.assertEqual(verify_hash_chain(link), (False, 0))

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

    def test_state_loader_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.json"
            target.write_text('{"safe": true}')
            link = root / "state.json"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                load_json(link)

    def test_state_writer_atomically_replaces_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.json"
            target.write_text('{"owner": "other"}')
            state = root / "state.json"
            state.symlink_to(target)
            write_json_atomic(state, {"owner": "satark"})
            self.assertFalse(state.is_symlink())
            self.assertEqual(json.loads(state.read_text()), {"owner": "satark"})
            self.assertEqual(json.loads(target.read_text()), {"owner": "other"})

    def test_scan_files_skips_symlinked_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "real.conf"
            target.write_text("real")
            link = root / "link.conf"
            link.symlink_to(target)
            manifest = scan_files([root])
            self.assertIn(str(target), manifest)
            self.assertNotIn(str(link), manifest)

    def test_append_refuses_to_extend_tampered_journal(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Path(td) / "events.jsonl"
            append_hash_chain(journal, [{"event_type": "auth_failed"}])
            item = json.loads(journal.read_text().strip())
            item["event_type"] = "auth_success"
            journal.write_text(json.dumps(item) + "\\n")
            with self.assertRaises(ValueError):
                append_hash_chain(journal, [{"event_type": "new_event"}])

    def test_auth_log_rejects_nonpositive_read_limit(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "auth.log"
            path.write_text("Accepted password for alice")
            with self.assertRaises(ValueError):
                parse_auth_log(path, max_bytes=0)

    def test_state_loader_rejects_oversized_state(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.json"
            path.write_bytes(b" " * (MAX_STATE_BYTES + 1))
            with self.assertRaises(ValueError):
                load_json(path)


if __name__ == "__main__":
    unittest.main()
