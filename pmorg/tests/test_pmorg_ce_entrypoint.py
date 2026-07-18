from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from pmorg_ce import entrypoint  # noqa: E402


class ProcessReplaced(BaseException):
    """Test sentinel representing a successful os.execvp call."""


class PmorgCeEntrypointTests(unittest.TestCase):
    def test_rejects_each_enabled_enterprise_flag(self) -> None:
        for flag_name in entrypoint.EE_FLAG_NAMES:
            with self.subTest(flag_name=flag_name):
                environment = {
                    "ENABLE_PAID_ENTERPRISE_EDITION_FEATURES": "false",
                    "LICENSE_ENFORCEMENT_ENABLED": "false",
                    flag_name: " TrUe ",
                }
                stderr = io.StringIO()
                with (
                    patch.object(entrypoint.os, "execvp") as execvp,
                    contextlib.redirect_stderr(stderr),
                ):
                    exit_code = entrypoint.main(["example", "argument"], environment)

                self.assertEqual(exit_code, entrypoint.EXIT_CONFIGURATION)
                self.assertIn(flag_name, stderr.getvalue())
                execvp.assert_not_called()

    def test_rejects_unknown_boolean_spelling(self) -> None:
        stderr = io.StringIO()
        environment = {
            "ENABLE_PAID_ENTERPRISE_EDITION_FEATURES": "sometimes",
            "LICENSE_ENFORCEMENT_ENABLED": "false",
        }
        with (
            patch.object(entrypoint.os, "execvp") as execvp,
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = entrypoint.main(["example"], environment)

        self.assertEqual(exit_code, entrypoint.EXIT_CONFIGURATION)
        self.assertIn("unsupported boolean value", stderr.getvalue())
        execvp.assert_not_called()

    def test_rejects_each_fixed_environment_override(self) -> None:
        for variable_name, required_value in entrypoint.FIXED_ENVIRONMENT_VALUES:
            with self.subTest(variable_name=variable_name):
                environment = {
                    "ENABLE_PAID_ENTERPRISE_EDITION_FEATURES": "false",
                    "LICENSE_ENFORCEMENT_ENABLED": "false",
                    "DISABLE_TELEMETRY": "true",
                    "AUTO_LLM_CONFIG_URL": "",
                    variable_name: f"{required_value}changed",
                }
                stderr = io.StringIO()
                with (
                    patch.object(entrypoint.os, "execvp") as execvp,
                    contextlib.redirect_stderr(stderr),
                ):
                    exit_code = entrypoint.main(["example"], environment)

                self.assertEqual(exit_code, entrypoint.EXIT_CONFIGURATION)
                self.assertIn(variable_name, stderr.getvalue())
                execvp.assert_not_called()

    def test_accepts_exact_fixed_environment_values(self) -> None:
        command = ["example-command"]
        environment = {
            "ENABLE_PAID_ENTERPRISE_EDITION_FEATURES": "false",
            "LICENSE_ENFORCEMENT_ENABLED": "false",
            "DISABLE_TELEMETRY": "true",
            "AUTO_LLM_CONFIG_URL": "",
        }
        with patch.object(
            entrypoint.os,
            "execvp",
            side_effect=ProcessReplaced,
        ) as execvp:
            with self.assertRaises(ProcessReplaced):
                entrypoint.main(command, environment)

        execvp.assert_called_once_with(command[0], command)

    def test_execs_command_with_original_argument_boundaries(self) -> None:
        command = ["example-command", "argument with spaces", "--flag=value"]
        environment = {
            "ENABLE_PAID_ENTERPRISE_EDITION_FEATURES": "0",
            "LICENSE_ENFORCEMENT_ENABLED": "off",
        }
        with patch.object(
            entrypoint.os,
            "execvp",
            side_effect=ProcessReplaced,
        ) as execvp:
            with self.assertRaises(ProcessReplaced):
                entrypoint.main(command, environment)

        execvp.assert_called_once_with(command[0], command)

    def test_missing_flags_default_to_disabled(self) -> None:
        command = ["example-command"]
        with patch.object(
            entrypoint.os,
            "execvp",
            side_effect=ProcessReplaced,
        ) as execvp:
            with self.assertRaises(ProcessReplaced):
                entrypoint.main(command, {})

        execvp.assert_called_once_with(command[0], command)

    def test_requires_a_command(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(entrypoint.os, "execvp") as execvp,
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = entrypoint.main([], {})

        self.assertEqual(exit_code, entrypoint.EXIT_USAGE)
        self.assertIn("requires a command", stderr.getvalue())
        execvp.assert_not_called()

    def test_child_process_exit_status_is_preserved(self) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "ENABLE_PAID_ENTERPRISE_EDITION_FEATURES": "false",
                "LICENSE_ENFORCEMENT_ENABLED": "false",
                "DISABLE_TELEMETRY": "true",
                "AUTO_LLM_CONFIG_URL": "",
                "PYTHONPATH": str(BACKEND_ROOT),
            }
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pmorg_ce.entrypoint",
                sys.executable,
                "-c",
                "raise SystemExit(23)",
            ],
            cwd=BACKEND_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

        self.assertEqual(completed.returncode, 23, completed.stderr)


if __name__ == "__main__":
    unittest.main()
