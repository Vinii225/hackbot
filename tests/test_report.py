"""Report rendering: severity + CWE/OWASP classification per finding (issue #1)."""
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.catalog import CLASS_META, meta_for
from orchestrator.report import write_report

CLASSES = ["IDOR", "CMDI", "PATH-TRAVERSAL", "XSS", "ACCESS-CONTROL", "SQLI"]


class _FakeStore:
    def __init__(self, tmp, findings):
        self.dir = Path(tmp)
        self.state = {"mode": "auto", "objective": "test"}
        self._findings = findings

    def read_findings(self):
        return self._findings


class CatalogTests(unittest.TestCase):
    def test_every_live_class_has_cwe_and_owasp(self):
        for cls in CLASSES:
            m = meta_for(cls)
            self.assertIsNotNone(m, cls)
            self.assertTrue(m["cwe"].startswith("CWE-"), cls)
            self.assertTrue(m["owasp"].startswith("A0"), cls)
            self.assertIn(m["severity"], ("critical", "high", "medium", "low"))

    def test_aliases_resolve(self):
        self.assertEqual(meta_for("SQL-INJECTION"), CLASS_META["SQLI"])
        self.assertEqual(meta_for("ACCESS_CONTROL"), CLASS_META["ACCESS-CONTROL"])


class ReportClassificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _report(self, finding):
        write_report(_FakeStore(self.tmp, [finding]))
        return (Path(self.tmp) / "reports" / "REPORT.md").read_text()

    def test_renders_severity_and_classification(self):
        report = self._report({
            "status": "confirmed", "class": "SQLI", "endpoint": "/filter",
            "method": "GET", "parameter": "category", "severity": "high",
            "payload": "x", "proof": "p", "evidence": {"dir": "d/", "files": ["a"]}})
        self.assertIn("[HIGH] SQLI", report)
        self.assertIn("CWE-89", report)
        self.assertIn("A03:2021", report)

    def test_severity_falls_back_to_catalog(self):
        report = self._report({
            "status": "confirmed", "class": "XSS", "endpoint": "/search",
            "method": "GET", "parameter": "q", "severity": None,
            "payload": "x", "proof": "p", "evidence": {}})
        self.assertIn("[MEDIUM] XSS", report)  # from the catalog default


if __name__ == "__main__":
    unittest.main()
