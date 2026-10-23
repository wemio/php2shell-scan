import importlib.util
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("php2shell_scan", ROOT / "php2shell_scan.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VersionTests(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(MODULE.parse_version("PHP 8.3.36 (fpm-fcgi)"), (8, 3, 36))
        self.assertEqual(MODULE.parse_version("8.5.12"), (8, 5, 12))
        self.assertIsNone(MODULE.parse_version("not a version"))

    def test_fixed_boundaries(self):
        for version in [(8, 5, 12), (8, 4, 27), (8, 3, 36), (8, 2, 35)]:
            state, _ = MODULE.evaluate_version(version)
            self.assertEqual(state, "fixed", version)

    def test_vulnerable_boundaries(self):
        for version in [(8, 5, 11), (8, 4, 26), (8, 3, 35), (8, 2, 34)]:
            state, _ = MODULE.evaluate_version(version)
            self.assertEqual(state, "vulnerable", version)

    def test_eol_branch(self):
        state, _ = MODULE.evaluate_version((7, 4, 3))
        self.assertEqual(state, "vulnerable")

    def test_newer_unknown_branch(self):
        state, _ = MODULE.evaluate_version((8, 6, 0))
        self.assertEqual(state, "unknown")

    def test_normalize(self):
        for value in ("1", "On", "true", "yes"):
            self.assertTrue(MODULE.normalize(value))
        for value in ("0", "Off", "false", "no", None):
            self.assertFalse(MODULE.normalize(value))


class LogScanTests(unittest.TestCase):
    def test_detects_trigger_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(
                '2026-10-21T16:21:09Z 94.154.43.7 "POST / HTTP/1.1" 500 1234 '
                'field="PHP_SESSION_UPLOAD_PROGRESS"\n',
                encoding="utf-8",
            )
            report = MODULE.Report()
            MODULE.scan_logs(report, [str(path)], date(2026, 10, 17))
            self.assertGreaterEqual(report.count("critical"), 1)

    def test_respects_since(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(
                "2026-10-01 00:00:00 p2shell\n",
                encoding="utf-8",
            )
            report = MODULE.Report()
            MODULE.scan_logs(report, [str(path)], date(2026, 10, 17))
            self.assertEqual(report.count("critical"), 0)


if __name__ == "__main__":
    unittest.main()
