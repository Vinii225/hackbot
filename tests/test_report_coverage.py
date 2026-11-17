"""The report's Coverage appendix summarizes every class exercised, plus those not reached."""
import json, shutil, tempfile, unittest, zipfile
from pathlib import Path
from orchestrator.core import StateStore
from orchestrator.report import write_report
from orchestrator.export import write_exports


class ReportCoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "state").mkdir(parents=True)
        (self.tmp / "findings").mkdir()
        (self.tmp / "state" / "state.json").write_text(
            json.dumps({"mode": "auto", "objective": "demo", "status": "complete"}))
        findings = [
            {"class": "SQLI", "status": "confirmed", "endpoint": "/a", "method": "GET"},
            {"class": "XSS", "status": "false-positive", "endpoint": "/b", "method": "GET"},
            {"class": "XSS", "status": "confirmed", "endpoint": "/c", "method": "GET"},
            {"class": "IDOR", "status": "unconfirmed", "endpoint": "/d", "method": "GET"},
        ]
        for i, f in enumerate(findings):
            (self.tmp / "findings" / f"F-{i:03d}.json").write_text(json.dumps(f))
        self.store = StateStore(self.tmp).load()

    def test_markdown_coverage_section(self):
        write_report(self.store)
        md = (self.tmp / "reports" / "REPORT.md").read_text()
        self.assertIn("## Coverage", md)
        self.assertIn("XSS: 2 checked (confirmed 1, false-positive 1, unconfirmed 0)", md)
        self.assertIn("SQLI: 1 checked (confirmed 1", md)
        # A class with no findings must be listed as not reached.
        self.assertIn("Not reached", md)
        self.assertIn("CRLF", md.split("Not reached")[1])

    def test_scope_is_echoed(self):
        (self.tmp / "scope.md").write_text(
            "# Scope\n## In scope\n```\nhttps://lab-abc.example-target.net\n```\n")
        write_report(self.store)
        md = (self.tmp / "reports" / "REPORT.md").read_text()
        self.assertIn("Authorized scope: https://lab-abc.example-target.net", md)

    def test_scope_na_without_scope_file(self):
        write_report(self.store)
        self.assertIn("Authorized scope: n/a", (self.tmp / "reports" / "REPORT.md").read_text())

    def test_json_and_html_coverage(self):
        write_report(self.store)
        write_exports(self.store)
        model = json.loads((self.tmp / "reports" / "report.json").read_text())
        classes = {c["class"]: c for c in model["coverage"]}
        self.assertEqual(classes["XSS"]["checked"], 2)
        self.assertEqual(classes["XSS"]["confirmed"], 1)
        self.assertIn("CRLF", model["not_reached"])
        html = (self.tmp / "reports" / "report.html").read_text()
        self.assertIn("Coverage", html)
        # DOCX is a valid zip with the coverage text in the document part.
        with zipfile.ZipFile(self.tmp / "reports" / "report.docx") as z:
            doc = z.read("word/document.xml").decode()
        self.assertIn("Coverage", doc)


if __name__ == "__main__":
    unittest.main()
