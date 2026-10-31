"""Command-injection checker against the local fixture over real HTTP."""
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.checks import CheckContext, check_cmdi
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session


class CmdiCheckerTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _check(self, endpoint, param, method, name):
        return check_cmdi(Session(self.base),
                          {"endpoint": endpoint, "parameter": param, "method": method},
                          Path(self.tmp) / name, CheckContext())

    def test_reflected_confirmed(self):
        res = self._check("/ping", "host", "GET", "ref")
        self.assertEqual(res.status, "confirmed")
        self.assertIn("echo", res.payload)

    def test_blind_timebased_confirmed(self):
        res = self._check("/ping-blind", "host", "GET", "blind")
        self.assertEqual(res.status, "confirmed")
        self.assertIn("sleep", res.payload)

    def test_echo_only_is_false_positive(self):
        res = self._check("/feedback", "message", "POST", "safe")
        self.assertEqual(res.status, "false-positive")
        self.assertIn("echoed", res.false_positive_reason)


if __name__ == "__main__":
    unittest.main()
