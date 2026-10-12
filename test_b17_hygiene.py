"""
Unit tests for Batch 17: Test & Runtime Hygiene
- AUD-46: Tests write into the real data/ directory (AUTOSEC_DATA_DIR override, lazy DB init, data/reports count unchanged).
- AUD-47: Library modules configure logging (no logging.basicConfig in core/, plugins/, intelligence/, reports/, ui/).
"""

import os
import sys
import tempfile
import unittest
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).parent


class TestAUD46DataDirHygiene(unittest.TestCase):
    """AUD-46: AUTOSEC_DATA_DIR overridable and core.auth DB initialized lazily."""

    def test_autosec_data_dir_environment_override(self):
        """Setting AUTOSEC_DATA_DIR redirects config.DATA_DIR and config.REPORTS_DIR."""
        import config

        with tempfile.TemporaryDirectory() as tmp_dir:
            orig_env = os.environ.get("AUTOSEC_DATA_DIR")
            try:
                os.environ["AUTOSEC_DATA_DIR"] = tmp_dir
                self.assertEqual(config.DATA_DIR, tmp_dir)
                expected_reports = str(Path(tmp_dir) / "reports")
                self.assertEqual(config.REPORTS_DIR, expected_reports)
            finally:
                if orig_env is not None:
                    os.environ["AUTOSEC_DATA_DIR"] = orig_env
                else:
                    os.environ.pop("AUTOSEC_DATA_DIR", None)

    def test_core_auth_no_db_created_on_import(self):
        """Importing core.auth does NOT create a database file on disk."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_script = f"""
import os
import sys
from pathlib import Path

os.environ["AUTOSEC_DATA_DIR"] = r"{tmp_dir}"
import core.auth

# Check if users.db was created in tmp_dir
db_file = Path(r"{tmp_dir}") / "users.db"
if db_file.exists():
    sys.exit(1)
sys.exit(0)
"""
            res = subprocess.run([sys.executable, "-c", test_script], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"users.db was created on import: {res.stderr}")

    def test_core_auth_lazy_initialization_on_first_use(self):
        """Database is initialized lazily upon first use (e.g. create_user or init_user_db)."""
        import config
        import core.auth as auth

        with tempfile.TemporaryDirectory() as tmp_dir:
            orig_env = os.environ.get("AUTOSEC_DATA_DIR")
            orig_db = auth.DB_PATH
            try:
                os.environ["AUTOSEC_DATA_DIR"] = tmp_dir
                temp_db = Path(tmp_dir) / "users.db"
                auth.DB_PATH = temp_db

                self.assertFalse(temp_db.exists())

                # First use: create_user triggers lazy initialization
                ok, msg, user = auth.create_user("testuser", "test@example.com", "SecretPass123!", role="developer")
                self.assertTrue(ok)
                self.assertTrue(temp_db.exists())

                # Default admin account and newly created user both exist
                user_record = auth.get_user_by_username("testuser")
                self.assertIsNotNone(user_record)
                admin_record = auth.get_user_by_username("admin")
                self.assertIsNotNone(admin_record)
            finally:
                auth.DB_PATH = orig_db
                if orig_env is not None:
                    os.environ["AUTOSEC_DATA_DIR"] = orig_env
                else:
                    os.environ.pop("AUTOSEC_DATA_DIR", None)


class TestAUD47LoggingHygiene(unittest.TestCase):
    """AUD-47: Library modules do NOT configure logging; only main.py and mcp_server.py do."""

    def test_no_logging_basicconfig_in_library_modules(self):
        """No logging.basicConfig calls exist in core/, plugins/, intelligence/, reports/, or ui/."""
        forbidden_dirs = ["core", "plugins", "intelligence", "reports", "ui"]
        violations = []

        for d in forbidden_dirs:
            dir_path = BASE_DIR / d
            if not dir_path.is_dir():
                continue
            for py_file in dir_path.rglob("*.py"):
                content = py_file.read_text(encoding="utf-8", errors="replace")
                for line_no, line in enumerate(content.splitlines(), start=1):
                    # Strip comments
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if "logging.basicConfig" in line:
                        rel_path = py_file.relative_to(BASE_DIR).as_posix()
                        violations.append(f"{rel_path}:{line_no} -> {stripped}")

        self.assertEqual(violations, [], f"Found logging.basicConfig in library modules:\n" + "\n".join(violations))

    def test_mcp_server_stdout_contains_only_json_rpc(self):
        """MCP server mode emits only JSON-RPC protocol messages to stdout, nothing else."""
        mcp_script = """
import sys
import json
import subprocess

p = subprocess.Popen(
    [sys.executable, "mcp_server.py"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

init_request = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2024-11-05"}
}) + "\\n"

stdout, stderr = p.communicate(input=init_request, timeout=10)

lines = [l.strip() for l in stdout.splitlines() if l.strip()]
for line in lines:
    try:
        data = json.loads(line)
        if "jsonrpc" not in data:
            sys.exit(2)
    except Exception:
        sys.exit(1)
sys.exit(0)
"""
        res = subprocess.run([sys.executable, "-c", mcp_script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"MCP server emitted non-JSON-RPC stdout: {res.stderr}")


if __name__ == "__main__":
    unittest.main()
