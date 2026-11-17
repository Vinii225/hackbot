"""Integrity guard: every vulnerability class must be wired end-to-end.

This locks the project's core invariant — a class is only "supported" when its checker,
catalog metadata, skill playbook and example config all exist and agree — so a half-added
skill fails CI instead of silently shipping.
"""
import json
import unittest
from pathlib import Path

import orchestrator.checks as checks
from orchestrator.catalog import CLASS_META, meta_for

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "agents" / "vuln-hunter" / "skills"
CONFIG = json.loads((ROOT / "targets" / "target-example" / "state" / "config.json").read_text())


class ConsistencyTests(unittest.TestCase):
    def test_every_class_has_a_checker(self):
        for cls in CLASS_META:
            self.assertIn(cls, checks.REGISTRY, f"{cls} has catalog meta but no checker")

    def test_every_class_has_full_metadata(self):
        for cls in CLASS_META:
            m = meta_for(cls) or {}
            for field in ("title", "cwe", "owasp", "severity", "remediation"):
                self.assertTrue(m.get(field), f"{cls} missing {field}")

    def test_every_class_has_a_skill_playbook(self):
        for cls in CLASS_META:
            d = cls.lower()
            self.assertTrue((SKILLS / d / f"{d}.md").is_file(),
                            f"{cls}: missing skill file {d}/{d}.md")

    def test_every_class_is_enabled_in_example_config(self):
        allowed = set(CONFIG["allowed_skills"])
        for cls in CLASS_META:
            self.assertIn(cls.lower(), allowed,
                          f"{cls} not enabled in example target allowed_skills")

    def test_no_orphan_skill_dirs(self):
        canon = {c.lower() for c in CLASS_META} | {"recon"}
        for p in SKILLS.iterdir():
            if p.is_dir():
                self.assertIn(p.name, canon, f"orphan skill dir with no catalog class: {p.name}")


if __name__ == "__main__":
    unittest.main()
