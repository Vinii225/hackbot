"""`python -m orchestrator --list-classes` prints every catalog class and needs no target."""
import io, unittest
from contextlib import redirect_stdout
from orchestrator.__main__ import main
from orchestrator.catalog import CLASS_META


class ListClassesTests(unittest.TestCase):
    def test_lists_all_classes_without_target(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--list-classes"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(f"Supported vulnerability classes: {len(CLASS_META)}", out)
        for cls in CLASS_META:
            self.assertIn(cls, out)

    def test_target_required_without_list(self):
        with self.assertRaises(SystemExit):
            main([])


if __name__ == "__main__":
    unittest.main()
