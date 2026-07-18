from __future__ import annotations

import tempfile
from pathlib import Path

from _support import CEBoundaryTestCase
from verify_ce_boundary import run_gate


class ArtifactBindingTest(CEBoundaryTestCase):
    def test_image_archive_is_bound_to_expected_config_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            backend = self._image(evidence, "backend")
            fake_id = "sha256:" + "0" * 64
            backend["image_id"] = fake_id
            backend["filesystem_image_id"] = fake_id
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("IMAGE_CONFIG_DIGEST_MISMATCH", self._rules(report))

    def test_layer_bytes_are_verified_against_rootfs_diff_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            backend = self._image(evidence, "backend")
            archive = root / backend["archive"]
            image_id = self._write_docker_save(
                archive,
                backend["tag"],
                [{"app/onyx/main.py": b"import os\n"}],
                component="backend",
                diff_ids=["sha256:" + "f" * 64],
            )
            backend["image_id"] = image_id
            backend["filesystem_image_id"] = image_id
            backend["archive_sha256"] = self._digest_file(archive)
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("LAYER_DIFF_ID_MISMATCH", self._rules(report))

    def test_archive_and_filesystem_digests_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            backend = self._image(evidence, "backend")
            backend["archive_sha256"] = "sha256:" + "1" * 64
            backend["filesystem_sha256"] = "sha256:" + "2" * 64
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertEqual(
                [item.rule for item in report.violations].count(
                    "EVIDENCE_FILE_DIGEST_MISMATCH"
                ),
                2,
            )

    def test_filesystem_export_is_bound_to_same_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            self._image(evidence, "web")["filesystem_image_id"] = (
                "sha256:" + "3" * 64
            )
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("FILESYSTEM_IMAGE_BINDING_MISMATCH", self._rules(report))

    def test_ee_paths_in_layers_and_final_filesystem_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            backend = self._image(evidence, "backend")
            archive = root / backend["archive"]
            image_id = self._write_docker_save(
                archive,
                backend["tag"],
                [{"app/ee/onyx/main.py": b"from ee.onyx import main\n"}],
                component="backend",
            )
            filesystem = root / backend["filesystem"]
            self._write_tar(
                filesystem,
                {"app/ee/onyx/main.py": b"from ee.onyx import main\n"},
            )
            backend["image_id"] = image_id
            backend["filesystem_image_id"] = image_id
            backend["archive_sha256"] = self._digest_file(archive)
            backend["filesystem_sha256"] = self._digest_file(filesystem)
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            rules = self._rules(report)
            self.assertIn("ARTIFACT_EE_PATH", rules)
            self.assertIn("PYTHON_EE_IMPORT", rules)

    def test_empty_filesystem_export_cannot_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            web = self._image(evidence, "web")
            filesystem = root / web["filesystem"]
            self._write_tar(filesystem, {})
            web["filesystem_sha256"] = self._digest_file(filesystem)
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("FILESYSTEM_EXPORT_EMPTY", self._rules(report))

    def test_wrong_tag_cannot_select_an_unrelated_clean_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            self._image(evidence, "backend")["tag"] = "pmorg/other:gate-a"
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("LAYER_ARCHIVE_INVALID", self._rules(report))
