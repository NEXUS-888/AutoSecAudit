"""Regression tests for Batch 21 (AUD-67, AUD-68)."""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent


class TestAUD67DockerAndComposeHardening(unittest.TestCase):
    """Verify Dockerfile and docker-compose.yml security and binding hardening (AUD-67)."""

    def setUp(self) -> None:
        self.dockerfile_path = ROOT_DIR / "Dockerfile"
        self.compose_path = ROOT_DIR / "docker-compose.yml"
        self.dockerfile = self.dockerfile_path.read_text(encoding="utf-8")
        self.compose = self.compose_path.read_text(encoding="utf-8")

    def test_dockerfile_sets_autosec_host_to_all_interfaces(self) -> None:
        """Dockerfile must explicitly set ENV AUTOSEC_HOST=0.0.0.0 inside the container."""
        self.assertRegex(
            self.dockerfile,
            r"(?m)^\s*ENV\s+AUTOSEC_HOST(?:=|\s+)0\.0\.0\.0\b",
            "Dockerfile must set ENV AUTOSEC_HOST=0.0.0.0 so container port forwarding reaches Flask",
        )

    def test_dockerfile_runs_as_non_root_user(self) -> None:
        """Dockerfile must create and switch to a non-root USER before ENTRYPOINT."""
        user_matches = re.findall(r"(?m)^\s*USER\s+(\S+)", self.dockerfile)
        self.assertTrue(user_matches, "Dockerfile must contain a USER instruction")
        final_user = user_matches[-1].strip()
        self.assertNotIn(
            final_user.lower(),
            {"root", "0", "0:0"},
            f"Dockerfile final USER must be non-root, got {final_user!r}",
        )

        # Ensure USER appears before ENTRYPOINT
        user_pos = self.dockerfile.rfind(f"USER {final_user}")
        entrypoint_pos = self.dockerfile.rfind("ENTRYPOINT")
        self.assertGreater(entrypoint_pos, -1, "Dockerfile must have an ENTRYPOINT")
        self.assertLess(
            user_pos,
            entrypoint_pos,
            "USER instruction must appear before ENTRYPOINT in Dockerfile",
        )

    def test_dockerfile_pins_nikto_clone(self) -> None:
        """Dockerfile must not contain an unpinned git clone of Nikto."""
        git_clone_lines = [
            line.strip()
            for line in self.dockerfile.splitlines()
            if "git clone" in line
        ]
        self.assertTrue(git_clone_lines, "Expected git clone in Dockerfile for Nikto")
        for line in git_clone_lines:
            has_branch_or_tag = bool(
                re.search(r"(--branch|-b)\s+\S+", line)
                or re.search(r"git\s+checkout\s+[0-9a-fA-F]{7,40}|git\s+checkout\s+[\w.\-]+", self.dockerfile)
            )
            self.assertTrue(
                has_branch_or_tag,
                f"git clone in Dockerfile must be pinned to a tag/branch or commit: {line}",
            )

    def test_no_latest_image_tags_in_docker_or_compose(self) -> None:
        """Neither Dockerfile nor docker-compose.yml may use unpinned :latest image tags."""
        self.assertNotIn(":latest", self.dockerfile, "Dockerfile must not use :latest tag")
        self.assertNotIn(":latest", self.compose, "docker-compose.yml must not use :latest tag")

    def test_compose_binds_published_ports_to_loopback(self) -> None:
        """Published ports in docker-compose.yml must bind to 127.0.0.1."""
        self.assertIn(
            "127.0.0.1:5000:5000",
            self.compose,
            "docker-compose.yml must bind published port 5000 to 127.0.0.1",
        )
        port_entries = re.findall(r'(?m)^\s*-\s*["\']?([0-9.:]+:\d+:\d+|\d+:\d+)["\']?\s*$', self.compose)
        self.assertTrue(port_entries, "Expected published port entries in docker-compose.yml")
        non_loopback = [entry for entry in port_entries if not entry.startswith("127.0.0.1:")]
        self.assertEqual(
            non_loopback,
            [],
            f"All published ports in docker-compose.yml must bind to 127.0.0.1, found: {non_loopback}",
        )

    def test_compose_requires_autosec_admin_password(self) -> None:
        """docker-compose.yml must require AUTOSEC_ADMIN_PASSWORD via ${AUTOSEC_ADMIN_PASSWORD:?...}."""
        self.assertRegex(
            self.compose,
            r"AUTOSEC_ADMIN_PASSWORD=\$\{AUTOSEC_ADMIN_PASSWORD:\?[^}]+\}",
            "docker-compose.yml must require AUTOSEC_ADMIN_PASSWORD using ${AUTOSEC_ADMIN_PASSWORD:?...}",
        )


class TestAUD68ReadmeConfigurationAndAuthDocs(unittest.TestCase):
    """Verify README.md documents every AUTOSEC_* variable, first-run auth, and CLI auth flags (AUD-68)."""

    def setUp(self) -> None:
        self.readme_path = ROOT_DIR / "README.md"
        self.readme = self.readme_path.read_text(encoding="utf-8")

    def _collect_codebase_autosec_env_vars(self) -> set[str]:
        """Collect all AUTOSEC_[A-Z_]+ environment variable names across codebase modules."""
        scan_targets = [
            ROOT_DIR / "config.py",
            ROOT_DIR / "main.py",
            ROOT_DIR / "mcp_server.py",
            ROOT_DIR / "core",
            ROOT_DIR / "ui",
            ROOT_DIR / "plugins",
        ]
        found: set[str] = set()
        pattern = re.compile(r"\bAUTOSEC_[A-Z0-9_]+\b")
        # Exclude internal test-probe literals inside command_injection_plugin.py if checking env vars,
        # or document all of them in README so both strict and filtered checks pass!
        for target in scan_targets:
            if target.is_file():
                files = [target]
            elif target.is_dir():
                files = list(target.rglob("*.py"))
            else:
                continue
            for file_path in files:
                content = file_path.read_text(encoding="utf-8")
                for match in pattern.findall(content):
                    found.add(match)
        return found

    def test_every_autosec_var_in_codebase_is_documented_in_readme(self) -> None:
        """Every AUTOSEC_* variable referenced across config.py, core/, ui/, plugins/, main.py, mcp_server.py must appear in README.md."""
        found_vars = self._collect_codebase_autosec_env_vars()
        self.assertGreaterEqual(len(found_vars), 20, "Expected at least 20 AUTOSEC_* variables in codebase")
        missing = sorted(var for var in found_vars if var not in self.readme)
        self.assertEqual(
            missing,
            [],
            f"The following AUTOSEC_* identifiers from the codebase are missing in README.md: {missing}",
        )

    def test_readme_documents_first_run_auth_and_registration(self) -> None:
        """README.md must explain initial admin password generation, AUTOSEC_ADMIN_PASSWORD, and AUTOSEC_ALLOW_REGISTRATION."""
        self.assertIn("AUTOSEC_ADMIN_PASSWORD", self.readme)
        self.assertIn("AUTOSEC_ALLOW_REGISTRATION", self.readme)
        self.assertIn("secrets.token_urlsafe", self.readme)
        self.assertIn("stderr", self.readme)

    def test_readme_documents_authenticated_target_scanning_and_git_bash_pitfall(self) -> None:
        """README.md must document --login-user, --login-pass, --login-url, and MSYS_NO_PATHCONV."""
        for token in ("--login-user", "--login-pass", "--login-url", "MSYS_NO_PATHCONV"):
            self.assertIn(
                token,
                self.readme,
                f"README.md must document {token!r} for authenticated target scanning",
            )

    def test_readme_has_no_stale_test_count_claims(self) -> None:
        """README.md must not claim stale 120 or 128 test counts."""
        self.assertNotIn("128 Passed", self.readme)
        self.assertNotIn("120 Automated Tests", self.readme)
        self.assertNotIn("All 120 unit", self.readme)

    def test_readme_documented_defaults_match_config_py(self) -> None:
        """Documented defaults in README.md Configuration table must match config.py."""
        config_text = (ROOT_DIR / "config.py").read_text(encoding="utf-8")
        # Extract literal defaults from os.environ.get("AUTOSEC_...", "<default>") in config.py
        env_defaults: dict[str, str] = {}
        for var_name, default_val in re.findall(
            r'os\.environ\.get\(\s*["\'](AUTOSEC_[A-Z0-9_]+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)',
            config_text,
        ):
            env_defaults[var_name] = default_val

        for required_var in (
            "AUTOSEC_MOCK_MODE",
            "AUTOSEC_THREAD_COUNT",
            "AUTOSEC_HTTP_TIMEOUT",
            "AUTOSEC_SCAN_TIMEOUT",
            "AUTOSEC_HOST",
            "AUTOSEC_DEBUG",
            "AUTOSEC_LOG_LEVEL",
            "AUTOSEC_NMAP_PATH",
            "AUTOSEC_NIKTO_PATH",
        ):
            self.assertIn(required_var, env_defaults, f"Expected {required_var} in config.py defaults")
            expected_default = env_defaults[required_var]
            row_match = re.search(
                rf"\|\s*`{re.escape(required_var)}`\s*\|\s*`([^`]+)`",
                self.readme,
            )
            self.assertIsNotNone(
                row_match,
                f"Expected markdown table row `| `{required_var}` | `<default>` |` in README.md",
            )
            documented_default = row_match.group(1).strip()
            self.assertEqual(
                documented_default,
                expected_default,
                f"README.md default for {required_var} is {documented_default!r}, but config.py default is {expected_default!r}",
            )


if __name__ == "__main__":
    unittest.main()
