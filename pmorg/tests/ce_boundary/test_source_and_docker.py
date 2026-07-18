from __future__ import annotations

import tempfile
from pathlib import Path

from _support import CEBoundaryTestCase
from verify_ce_boundary import MAX_ARCHIVE_SOURCE_BYTES
from verify_ce_boundary import _scan_archive_source_bytes
from verify_ce_boundary import _scan_python_imports
from verify_ce_boundary import _scan_typescript_imports
from verify_ce_boundary import run_gate


class SourceAndDockerTest(CEBoundaryTestCase):
    def test_source_mode_passes_without_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)

            report = run_gate(self._config(root))

            self.assertTrue(
                report.passed, [item.render() for item in report.violations]
            )
            self.assertEqual(report.mode, "source")
            self.assertEqual(report.scanned_source_files, 3)
            self.assertEqual(report.inspected_artifact_entries, 0)
            self.assertEqual(report.qualified_images, ())

    def test_multiline_and_escaped_typescript_imports_are_detected(self) -> None:
        source = """\
import {
  secret
} from "@/\\x65e/secret";
export {
  hidden
} from "@/app/ee/admin";
"""

        _, violations = _scan_typescript_imports(
            source,
            "web/src/app/page.tsx",
            None,
            None,
            (),
        )

        self.assertEqual(
            [violation.rule for violation in violations],
            ["TYPESCRIPT_EE_IMPORT", "TYPESCRIPT_EE_IMPORT"],
        )

    def test_javascript_comments_and_strings_are_not_import_edges(self) -> None:
        source = """\
// import hidden from "@/ee/hidden";
const text = 'require("@/ee/hidden")';
/* export { hidden } from "@/ee/hidden"; */
import safe from "@/lib/safe";
"""

        _, violations = _scan_typescript_imports(source, "safe.ts", None, None, ())

        self.assertEqual(violations, [])

    def test_constant_python_dynamic_import_is_detected(self) -> None:
        _, violations = _scan_python_imports(
            'import importlib\nimportlib.import_module("ee." + "onyx.main")\n',
            "backend/onyx/main.py",
        )

        self.assertIn("PYTHON_EE_IMPORT", {item.rule for item in violations})

    def test_oversize_and_non_utf8_artifact_sources_fail_closed(self) -> None:
        oversize = _scan_archive_source_bytes(
            b" " * (MAX_ARCHIVE_SOURCE_BYTES + 1), "app/main.py", ()
        )
        undecodable = _scan_archive_source_bytes(
            b"\xff\xfe", "app/main.ts", ()
        )

        self.assertEqual(oversize[0].rule, "ARTIFACT_SOURCE_TOO_LARGE")
        self.assertEqual(undecodable[0].rule, "ARTIFACT_SOURCE_DECODE_ERROR")

    def test_docker_build_contamination_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            self._write(
                root,
                "backend/Dockerfile.pmorg-ce",
                """\
FROM python:3.13-slim
COPY requirements/ee.txt /tmp/ee-requirements.txt
RUN uv sync --group ee
COPY . /app
""",
            )
            self._write(
                root,
                "backend/Dockerfile.pmorg-ce.dockerignore",
                "__pycache__/\n",
            )

            report = run_gate(self._config(root))

            rules = self._rules(report)
            self.assertIn("DOCKERFILE_EE_DEPENDENCY", rules)
            self.assertIn("DOCKERFILE_UV_DEFAULT_GROUPS", rules)
            self.assertIn("DOCKERIGNORE_MISSING_DENY", rules)
            self.assertIn("DELIVERABLE_EE_PATH", rules)
