"""Every live class carries remediation guidance, surfaced in the Markdown, JSON and HTML."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.catalog import CLASS_META, meta_for
from orchestrator.export import write_html, write_json
from orchestrator.report import write_report


class _FakeStore:
    def __init__(self, tmp, findings):
        self.dir = Path(tmp)
        self.state = {"mode": "auto", "objective": "test"}
        self._findings = findings

    def read_findings(self):
        return self._findings


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_every_class_has_remediation(self):
        for cls, m in CLASS_META.items():
            self.assertIn("remediation", m, cls)
            self.assertGreater(len(m["remediation"]), 20, cls)

    def _finding(self, cls):
        return {"status": "confirmed", "class": cls, "endpoint": "/x", "method": "GET",
                "parameter": "p", "severity": "high", "payload": "x", "proof": "p",
                "evidence": {"dir": "d/", "files": ["a"]}}

    def test_remediation_rendered_in_all_formats(self):
        store = _FakeStore(self.tmp, [self._finding("SQLI")])
        write_report(store)
        write_json(store)
        write_html(store)
        reports = Path(self.tmp) / "reports"
        snippet = meta_for("SQLI")["remediation"][:24]
        self.assertIn("Remediation:", (reports / "REPORT.md").read_text())
        self.assertIn(snippet, (reports / "REPORT.md").read_text())
        self.assertEqual(json.loads((reports / "report.json").read_text())
                         ["findings"][0]["remediation"], meta_for("SQLI")["remediation"])
        self.assertIn("Remediation:", (reports / "report.html").read_text())


if __name__ == "__main__":
    unittest.main()
