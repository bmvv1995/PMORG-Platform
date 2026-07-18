from __future__ import annotations

import tempfile
from pathlib import Path

from _support import CEBoundaryTestCase
from verify_ce_boundary import run_gate


class QualificationIdentityTest(CEBoundaryTestCase):
    def test_qualify_requires_evidence_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)

            report = run_gate(self._config(root, mode="qualify"))

            self.assertIn("EVIDENCE_MANIFEST_REQUIRED", self._rules(report))

    def test_clean_backend_and_web_artifacts_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertTrue(
                report.passed, [item.render() for item in report.violations]
            )
            self.assertTrue(report.dependency_evidence_verified)
            self.assertEqual(report.source_revision, self.SOURCE_REVISION)
            self.assertEqual(report.target_platform, "linux/amd64")
            self.assertRegex(
                report.baseline_manifest_sha256 or "", r"^sha256:[0-9a-f]{64}$"
            )
            self.assertEqual(
                [image.name for image in report.qualified_images], ["backend", "web"]
            )
            self.assertGreater(report.inspected_artifact_entries, 0)
            self.assertTrue(
                all(image.layer_count == 1 for image in report.qualified_images)
            )
            export_command = next(
                command
                for command in self._subprocess_commands
                if command[:2] == ("uv", "export")
            )
            self.assertEqual(
                export_command[:-1],
                (
                    "uv",
                    "export",
                    "--locked",
                    "--no-emit-project",
                    "--no-default-groups",
                    "--group",
                    "backend",
                    "--no-header",
                    "--output-file",
                ),
            )
            self.assertEqual(Path(export_command[-1]).name, "default.txt")

    def test_gzip_oci_layers_are_hashed_after_decompression(self) -> None:
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
                compress_layers=True,
            )
            backend["image_id"] = image_id
            backend["filesystem_image_id"] = image_id
            backend["archive_sha256"] = self._digest_file(archive)
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertTrue(
                report.passed, [item.render() for item in report.violations]
            )

    def test_qualification_rejects_dirty_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            self._dirty_roots.add(root.resolve())
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("QUALIFICATION_WORKTREE_DIRTY", self._rules(report))

    def test_qualification_rejects_baseline_bytes_stale_from_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            baseline = root / "pmorg/baseline-manifest.json"
            baseline.write_bytes(baseline.read_bytes() + b" ")
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("BASELINE_MANIFEST_STALE", self._rules(report))

    def test_qualification_rejects_image_platform_or_variant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            self._rewrite_image_archive(
                root,
                evidence,
                "backend",
                config_overrides={"architecture": "arm64", "variant": "v8"},
            )
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("IMAGE_PLATFORM_MISMATCH", self._rules(report))

    def test_qualification_rejects_each_missing_identity_label(self) -> None:
        required_labels = (
            "org.opencontainers.image.source",
            "org.opencontainers.image.revision",
            "io.pmorg.edition",
            "io.pmorg.component",
            "io.pmorg.onyx.version",
            "io.pmorg.onyx.upstream.revision",
            "io.pmorg.specification.revision",
            "io.pmorg.build.target-platform",
        )
        for label in required_labels:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    self._write_clean_source_fixture(root)
                    evidence = self._clean_evidence(root)
                    self._rewrite_image_archive(
                        root,
                        evidence,
                        "web",
                        label_overrides={label: None},
                    )
                    manifest = self._write_evidence(root, evidence)

                    report = run_gate(
                        self._config(
                            root,
                            mode="qualify",
                            evidence_manifest=manifest,
                        )
                    )

                    self.assertIn("IMAGE_LABEL_MISMATCH", self._rules(report))

    def test_qualification_rejects_backend_entrypoint_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            self._rewrite_image_archive(
                root,
                evidence,
                "backend",
                runtime_overrides={"Entrypoint": ["python", "-m", "onyx.main"]},
            )
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("IMAGE_ENTRYPOINT_MISMATCH", self._rules(report))

    def test_qualification_rejects_web_command_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            self._rewrite_image_archive(
                root,
                evidence,
                "web",
                runtime_overrides={"Cmd": ["node", "other.js"]},
            )
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("IMAGE_CMD_MISMATCH", self._rules(report))

    def test_qualification_requires_exact_backend_and_web_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            evidence["images"] = [self._image(evidence, "backend")]
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("EVIDENCE_IMAGE_SET", self._rules(report))

    def test_each_qualified_artifact_must_be_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_clean_source_fixture(root)
            evidence = self._clean_evidence(root)
            backend = self._image(evidence, "backend")
            web = self._image(evidence, "web")
            web["filesystem"] = backend["filesystem"]
            web["filesystem_sha256"] = backend["filesystem_sha256"]
            manifest = self._write_evidence(root, evidence)

            report = run_gate(
                self._config(root, mode="qualify", evidence_manifest=manifest)
            )

            self.assertIn("EVIDENCE_ARTIFACT_REUSED", self._rules(report))
