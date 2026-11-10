"""YARA rule-pack tests and a small synthetic false-positive regression corpus.

The corpus is deliberately synthetic. Its metrics are regression diagnostics only,
not estimates of real-world malware detection quality.
"""
from pathlib import Path
import unittest

try:
    import yara
except ImportError:  # pragma: no cover - optional local dependency
    yara = None

from file_guard.engine import scan_bytes

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "local_file_signatures.yar"

SAMPLES = [
    ("suspicious", "download.ps1", b"System.Net.WebClient DownloadString Invoke-Expression"),
    ("suspicious", "action.pdf", b"%PDF-1.7\n/OpenAction /JavaScript /JS"),
    ("suspicious", "macro.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 AutoOpen Shell CreateObject"),
    ("suspicious", "packed.js", b"eval( String.fromCharCode unescape("),
    ("benign", "report.pdf", b"%PDF-1.7\n/Pages /Page /Contents"),
    ("benign", "admin.ps1", b"Get-Process; Get-Service; Write-Output 'status'"),
    ("benign", "macro.doc", b"Sub AutoOpen()\nMsgBox \"Hello\"\nEnd Sub"),
    ("benign", "app.js", b"console.log('hello world');"),
    ("benign", "random.bin", bytes(range(64))),
]


@unittest.skipIf(yara is None, "install yara-python to run local YARA tests")
class YaraRulePackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = yara.compile(filepath=str(RULES), error_on_warning=True)

    def test_rule_pack_compiles(self):
        self.assertTrue(RULES.is_file())
        self.assertGreaterEqual(len(self.compiled.rules), 5)

    def test_synthetic_corpus_precision_recall_and_false_positive_rate(self):
        tp = fp = tn = fn = 0
        for expected, filename, payload in SAMPLES:
            with self.subTest(filename=filename):
                detected = bool(self.compiled.match(data=payload, timeout=3))
                if expected == "suspicious" and detected:
                    tp += 1
                elif expected == "suspicious":
                    fn += 1
                elif detected:
                    fp += 1
                else:
                    tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
        self.assertEqual((tp, fp, tn, fn), (4, 0, 5, 0))
        self.assertEqual(precision, 1.0)
        self.assertEqual(recall, 1.0)
        self.assertEqual(false_positive_rate, 0.0)

    def test_engine_surfaces_rule_matches_as_evidence(self):
        result = scan_bytes(
            b"%PDF-1.7\n/OpenAction /JavaScript /JS",
            "action.pdf",
            yara_rules_path=RULES,
        )
        self.assertEqual(result.verdict, "Signature match")
        self.assertIn("SATARK_PDF_AutoOpen_JavaScript", result.yara_matches)
        self.assertTrue(result.yara_available)


if __name__ == "__main__":
    unittest.main()
