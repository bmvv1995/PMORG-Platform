from __future__ import annotations

import tempfile
from pathlib import Path

from _support import CEBoundaryTestCase
from verify_ce_boundary import run_gate


class DependencyEvidenceTest(CEBoundaryTestCase):
    def test_qualification_refuses_missing_dependency_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            evidence.pop("dependency_export")
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("DEPENDENCY_EVIDENCE_MISSING", self._rules(report))
            self.assertFalse(report.dependency_evidence_verified)

    def test_verified_status_cannot_mask_dependency_export_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            evidence["dependency_export"]["status"] = "verified"
            self._uv_export_overrides[root.resolve()] = b"different==9.9\n"
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("DEPENDENCY_EXPORT_DRIFT", self._rules(report))
            self.assertFalse(report.dependency_evidence_verified)

    def test_dependency_evidence_rejects_noncanonical_declared_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            evidence["dependency_export"]["command"].append("--all-groups")
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("DEPENDENCY_EVIDENCE_COMMAND", self._rules(report))
            self.assertFalse(report.dependency_evidence_verified)

    def test_dependency_export_requires_exact_uv_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            self._uv_version = "uv 0.11.24\n"
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("DEPENDENCY_UV_VERSION", self._rules(report))
            self.assertFalse(report.dependency_evidence_verified)
