import unittest
import subprocess
import re
from pathlib import Path

class TestB01Foundation(unittest.TestCase):
    def test_tuple_imported_in_utils(self):
        """AUD-01: Tuple is imported from typing in core.utils and annotations are valid."""
        import core.utils
        self.assertTrue(hasattr(core.utils, "Tuple"))
        import typing
        self.assertIs(core.utils.Tuple, typing.Tuple)

    def test_ci_matrix_python_versions(self):
        """AUD-01: CI workflow has a python-version matrix containing '3.10' and '3.12'."""
        ci_path = Path(".github/workflows/ci.yml")
        self.assertTrue(ci_path.exists())
        content = ci_path.read_text(encoding="utf-8")
        self.assertIn("matrix", content)
        self.assertTrue(
            ("3.10" in content and "3.12" in content),
            "CI matrix must contain '3.10' and '3.12'"
        )

    def test_requirements_dependencies(self):
        """AUD-02: requirements.txt lists reportlab and urllib3."""
        req_path = Path("requirements.txt")
        self.assertTrue(req_path.exists())
        content = req_path.read_text(encoding="utf-8")
        lines = [line.strip().lower() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
        has_reportlab = any(re.match(r"^reportlab\b", line) for line in lines)
        has_urllib3 = any(re.match(r"^urllib3\b", line) for line in lines)
        self.assertTrue(has_reportlab, "requirements.txt must list reportlab")
        self.assertTrue(has_urllib3, "requirements.txt must list urllib3")

    def test_gitignore_audit_json_not_ignored(self):
        """AUD-03: audit/fixture.json is not ignored, but data/reports/x.json is ignored."""
        res_fixture = subprocess.run(
            ["git", "check-ignore", "audit/fixture.json"],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(
            res_fixture.returncode, 0,
            f"audit/fixture.json should not be ignored, but got: {res_fixture.stdout}"
        )

        res_data = subprocess.run(
            ["git", "check-ignore", "data/reports/x.json"],
            capture_output=True,
            text=True
        )
        self.assertEqual(
            res_data.returncode, 0,
            f"data/reports/x.json should be ignored, but got returncode {res_data.returncode}"
        )

if __name__ == "__main__":
    unittest.main()
