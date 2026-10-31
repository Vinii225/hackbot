"""IDOR checker against the local fixture over real HTTP."""
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.checks import CheckContext, check_idor
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session


class IdorCheckerTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _session(self):
        s = Session(self.base)
        s.post("/login", data={"username": "wiener", "password": "peter"})
        return s

    def test_confirms_cross_user_access(self):
        ev = Path(self.tmp) / "ev"
        res = check_idor(self._session(), {"endpoint": "/api/user/{id}"}, ev,
                         CheckContext(actor="wiener"))
        self.assertEqual(res.status, "confirmed")
        self.assertIn("carlos", res.proof)
        cross = (ev / "cross-victim.response.http").read_text()
        self.assertIn("carlos@victim.net", cross)
        self.assertIn("APIKEY-CARLOS-0002", cross)
        self.assertIn("wiener@normal-user.net", (ev / "baseline-own.response.http").read_text())

    def test_access_controlled_is_false_positive(self):
        ev = Path(self.tmp) / "ev-safe"
        res = check_idor(self._session(), {"endpoint": "/api/safe-user/{id}"}, ev,
                         CheckContext(actor="wiener"))
        self.assertEqual(res.status, "false-positive")
        self.assertIn("403", res.false_positive_reason)


if __name__ == "__main__":
    unittest.main()
