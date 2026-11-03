"""Export to JSON, HTML and DOCX (issue #14). Validates each format from the same findings."""
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from orchestrator.export import write_docx, write_exports, write_html, write_json

FINDINGS = [
    {"status": "confirmed", "class": "SQLI", "endpoint": "/filter", "method": "GET",
     "parameter": "category", "severity": "high", "payload": "1'", "proof": "error-based",
     "evidence": {"dir": "findings/evidence/F-001/", "files": ["control.request.http"]}},
    {"status": "confirmed", "class": "XSS", "endpoint": "/search", "method": "GET",
     "parameter": "q", "severity": "medium", "payload": "<x>", "proof": "reflected",
     "evidence": {}},
    {"status": "unconfirmed", "class": "IDOR", "endpoint": "/a", "evidence": {}},
    {"status": "false-positive", "class": "CMDI", "endpoint": "/p", "evidence": {}},
]


class _FakeStore:
    def __init__(self, tmp):
        self.dir = Path(tmp)
        self.state = {"mode": "auto", "objective": "test"}

    def read_findings(self):
        return FINDINGS


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.store = _FakeStore(self.tmp)

    def test_json_has_summary_and_findings(self):
        data = json.loads(Path(write_json(self.store)).read_text())
        self.assertEqual(data["summary"]["confirmed"], 2)
        self.assertEqual(data["summary"]["false_positive"], 1)
        self.assertEqual(data["summary"]["by_severity"], {"high": 1, "medium": 1})
        classes = {f["class"] for f in data["findings"]}
        self.assertEqual(classes, {"SQLI", "XSS"})
        self.assertEqual(data["findings"][0]["cwe"], "CWE-89")  # high sorted first

    def test_html_is_standalone_and_lists_findings(self):
        html = Path(write_html(self.store)).read_text()
        self.assertIn("<!doctype html>", html.lower())
        self.assertIn("Executive Summary", html)
        self.assertIn("SQLI", html)
        self.assertIn("/filter", html)
        self.assertIn("CWE-89", html)

    def test_docx_is_valid_ooxml_zip(self):
        path = Path(write_docx(self.store))
        self.assertTrue(zipfile.is_zipfile(path))
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            self.assertIn("[Content_Types].xml", names)
            self.assertIn("word/document.xml", names)
            doc = z.read("word/document.xml").decode()
        self.assertIn("Security Assessment Report", doc)
        self.assertIn("SQLI", doc)
        self.assertIn("CWE-89", doc)

    def test_write_exports_produces_all_three(self):
        out = write_exports(self.store)
        self.assertEqual(set(out), {"json", "html", "docx"})
        for p in out.values():
            self.assertTrue(Path(p).exists())


if __name__ == "__main__":
    unittest.main()
