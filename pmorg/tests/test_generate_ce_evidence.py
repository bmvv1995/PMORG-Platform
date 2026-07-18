from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from unittest.mock import patch


SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import generate_ce_evidence as generator  # noqa: E402
from verify_ce_boundary import GateReport  # noqa: E402
from verify_ce_boundary import QualificationIdentity  # noqa: E402
from verify_ce_boundary import QualifiedImage  # noqa: E402
from verify_ce_boundary import Violation  # noqa: E402


class GenerateCEEvidenceTest(unittest.TestCase):
    BACKEND_IMAGE = "pmorg/backend-ce:test"
    WEB_IMAGE = "pmorg/web-ce:test"
    BACKEND_CONFIG = b'{"component":"backend"}'
    WEB_CONFIG = b'{"component":"web"}'
    BACKEND_IMAGE_ID = f"sha256:{hashlib.sha256(BACKEND_CONFIG).hexdigest()}"
    WEB_IMAGE_ID = f"sha256:{hashlib.sha256(WEB_CONFIG).hexdigest()}"
    BACKEND_CONTAINER_ID = "c" * 64
    WEB_CONTAINER_ID = "d" * 64

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.base = Path(self._temporary_directory.name).resolve()
        self.repository_root = self.base / "repository"
        self.repository_root.mkdir()
        (self.repository_root / "backend" / "requirements").mkdir(parents=True)
        (self.repository_root / "backend" / "requirements" / "default.txt").write_text(
            "safe==1.0\n", encoding="utf-8"
        )
        (self.repository_root / "uv.lock").write_text(
            "version = 1\n", encoding="utf-8"
        )

        self.identity = QualificationIdentity(
            source_repository="https://github.com/example/PMORG-Platform",
            source_revision="1" * 40,
            baseline_manifest_sha256=f"sha256:{'2' * 64}",
            onyx_version="v4.3.9",
            onyx_upstream_revision="3" * 40,
            specification_revision="4" * 40,
            target_platform="linux/amd64",
        )
        self.commands: list[tuple[str, ...]] = []
        self.staged_manifests: list[dict[str, Any]] = []
        self.backend_inspect_image_id = self.BACKEND_IMAGE_ID
        self.web_inspect_image_id = self.WEB_IMAGE_ID
        self.backend_container_image_id = self.BACKEND_IMAGE_ID
        self.web_container_image_id = self.WEB_IMAGE_ID
        self.backend_manifest_config_id = self.BACKEND_IMAGE_ID
        self.web_manifest_config_id = self.WEB_IMAGE_ID
        self.backend_manifest_descriptor: str | None = None
        self.web_manifest_descriptor: str | None = None
        self.failure_action: str | None = None
        self.failure_raised = False

        self.preflight_mock = Mock(return_value=(self.identity, []))
        self.dependency_mock = Mock(return_value=(True, []))
        self.gate_mock = Mock(side_effect=self._successful_gate)
        self.subprocess_mock = Mock(side_effect=self._docker_run)
        patchers = (
            patch.object(
                generator,
                "verify_qualification_preflight",
                self.preflight_mock,
            ),
            patch.object(
                generator,
                "verify_dependency_evidence",
                self.dependency_mock,
            ),
            patch.object(generator, "run_gate", self.gate_mock),
            patch.object(generator.subprocess, "run", self.subprocess_mock),
        )
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _qualified_image(self, name: str, image_id: str) -> QualifiedImage:
        return QualifiedImage(
            name=name,
            tag=(self.BACKEND_IMAGE if name == "backend" else self.WEB_IMAGE),
            image_id=image_id,
            archive_sha256=f"sha256:{'5' * 64}",
            filesystem_sha256=f"sha256:{'6' * 64}",
            layer_count=1,
            layer_entries=1,
            filesystem_entries=1,
        )

    def _report(self, violations: tuple[Violation, ...] = ()) -> GateReport:
        return GateReport(
            mode="qualify",
            scanned_source_files=2,
            inspected_artifact_entries=4,
            dependency_evidence_verified=not violations,
            qualified_images=(
                self._qualified_image("backend", self.BACKEND_IMAGE_ID),
                self._qualified_image("web", self.WEB_IMAGE_ID),
            ),
            source_revision=self.identity.source_revision,
            baseline_manifest_sha256=self.identity.baseline_manifest_sha256,
            target_platform=self.identity.target_platform,
            violations=violations,
        )

    def _successful_gate(self, config: Any) -> GateReport:
        manifest_path = Path(config.evidence_manifest)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.staged_manifests.append(manifest)
        for image in manifest["images"]:
            self.assertEqual(Path(image["archive"]).parent, manifest_path.parent)
            self.assertEqual(Path(image["filesystem"]).parent, manifest_path.parent)
        return self._report()

    def _action(self, command: tuple[str, ...]) -> str:
        if command[:3] == ("docker", "image", "inspect"):
            return "image-inspect"
        if command[:3] == ("docker", "image", "save"):
            return "image-save"
        if command[:3] == ("docker", "container", "create"):
            return "container-create"
        if command[:3] == ("docker", "container", "inspect"):
            return "container-inspect"
        if command[:3] == ("docker", "container", "export"):
            return "container-export"
        if command[:3] == ("docker", "container", "rm"):
            return "container-rm"
        raise AssertionError(f"unexpected command: {command!r}")

    def _oci_manifest_bytes(self, config_digest: str) -> bytes:
        return json.dumps(
            {
                "config": {
                    "digest": config_digest,
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": 1,
                },
                "layers": [],
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "schemaVersion": 2,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    def _write_archive(
        self,
        path: Path,
        image: str,
        config_bytes: bytes,
        manifest_config_id: str,
        manifest_descriptor: str | None,
    ) -> None:
        config_digest = f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"
        config_name = f"{config_digest.removeprefix('sha256:')}.json"
        docker_manifest = json.dumps(
            [{"Config": config_name, "Layers": [], "RepoTags": [image]}],
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        entries = {
            "manifest.json": docker_manifest,
            config_name: config_bytes,
        }
        if manifest_descriptor is not None:
            manifest_bytes = self._oci_manifest_bytes(manifest_config_id)
            self.assertEqual(
                manifest_descriptor,
                f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}",
            )
            entries[
                "blobs/sha256/"
                + manifest_descriptor.removeprefix("sha256:")
            ] = manifest_bytes
        with tarfile.open(path, mode="w") as archive:
            for name, data in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mtime = 0
                archive.addfile(member, io.BytesIO(data))

    def _docker_run(
        self,
        command: list[str],
        *,
        cwd: Path,
        check: bool,
        stdout: int,
        stderr: int,
    ) -> subprocess.CompletedProcess[bytes]:
        self.assertEqual(Path(cwd), self.repository_root)
        self.assertTrue(check)
        self.assertEqual(stdout, subprocess.PIPE)
        self.assertEqual(stderr, subprocess.PIPE)
        normalized = tuple(command)
        self.commands.append(normalized)
        action = self._action(normalized)
        if self.failure_action == action and not self.failure_raised:
            self.failure_raised = True
            raise subprocess.CalledProcessError(
                17, command, output=b"", stderr=b"synthetic Docker failure"
            )

        if action == "image-inspect":
            image_id = (
                self.backend_inspect_image_id
                if normalized[-1] == self.BACKEND_IMAGE
                else self.web_inspect_image_id
            )
            output = f"{image_id}\n".encode()
        elif action == "image-save":
            archive = Path(normalized[normalized.index("--output") + 1])
            is_backend = normalized[-1] == self.BACKEND_IMAGE
            self._write_archive(
                archive,
                normalized[-1],
                self.BACKEND_CONFIG if is_backend else self.WEB_CONFIG,
                (
                    self.backend_manifest_config_id
                    if is_backend
                    else self.web_manifest_config_id
                ),
                (
                    self.backend_manifest_descriptor
                    if is_backend
                    else self.web_manifest_descriptor
                ),
            )
            output = b""
        elif action == "container-create":
            container_id = (
                self.BACKEND_CONTAINER_ID
                if normalized[-1] == self.BACKEND_IMAGE
                else self.WEB_CONTAINER_ID
            )
            output = f"{container_id}\n".encode()
        elif action == "container-inspect":
            is_backend = normalized[-1] == self.BACKEND_CONTAINER_ID
            image_id = (
                self.backend_container_image_id
                if is_backend
                else self.web_container_image_id
            )
            descriptor = (
                self.backend_manifest_descriptor
                if normalized[-1] == self.BACKEND_CONTAINER_ID
                else self.web_manifest_descriptor
            )
            inspect_object: dict[str, object] = {"Image": image_id}
            if descriptor is not None:
                inspect_object["ImageManifestDescriptor"] = {"digest": descriptor}
            output = json.dumps([inspect_object]).encode()
        elif action == "container-export":
            filesystem = Path(normalized[normalized.index("--output") + 1])
            filesystem.write_bytes(f"filesystem:{normalized[-1]}".encode())
            output = b""
        elif action == "container-rm":
            output = f"{normalized[-1]}\n".encode()
        else:  # pragma: no cover - _action rejects unknown commands
            raise AssertionError(action)
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")

    def _generate(self, output_directory: Path) -> Path:
        return generator.generate_evidence(
            repository_root=self.repository_root,
            backend_image=self.BACKEND_IMAGE,
            web_image=self.WEB_IMAGE,
            output_directory=output_directory,
        )

    def _assert_no_staging(self, output_directory: Path) -> None:
        self.assertEqual(
            list(
                output_directory.parent.glob(
                    f".{output_directory.name}.staging-*"
                )
            ),
            [],
        )

    def test_success_is_deterministic_and_publishes_final_paths(self) -> None:
        output_directory = self.base / "evidence"

        manifest_path = self._generate(output_directory)
        first_manifest_bytes = manifest_path.read_bytes()
        first_manifest = json.loads(first_manifest_bytes)

        self.assertEqual(manifest_path, output_directory / "evidence-manifest.json")
        self.assertEqual(first_manifest["schema_version"], "pmorg.ce-evidence/v1")
        self.assertEqual(
            [image["name"] for image in first_manifest["images"]],
            ["backend", "web"],
        )
        for image in first_manifest["images"]:
            self.assertEqual(Path(image["archive"]).parent, output_directory)
            self.assertEqual(Path(image["filesystem"]).parent, output_directory)
        self.assertEqual(len(self.staged_manifests), 1)
        self._assert_no_staging(output_directory)

        shutil.rmtree(output_directory)
        self.commands.clear()
        self.staged_manifests.clear()
        second_manifest_path = self._generate(output_directory)

        self.assertEqual(second_manifest_path.read_bytes(), first_manifest_bytes)
        self._assert_no_staging(output_directory)

    def test_container_config_digest_wins_over_image_index_digest(self) -> None:
        output_directory = self.base / "evidence-index-digest"
        index_digest = f"sha256:{'e' * 64}"
        manifest_bytes = self._oci_manifest_bytes(self.BACKEND_IMAGE_ID)
        manifest_digest = f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
        self.backend_inspect_image_id = index_digest
        self.backend_container_image_id = index_digest
        self.backend_manifest_descriptor = manifest_digest

        manifest_path = self._generate(output_directory)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        images = {image["name"]: image for image in manifest["images"]}
        self.assertEqual(images["backend"]["image_id"], self.BACKEND_IMAGE_ID)
        self.assertEqual(
            images["backend"]["filesystem_image_id"], self.BACKEND_IMAGE_ID
        )
        self.assertEqual(images["web"]["image_id"], self.WEB_IMAGE_ID)
        self.assertEqual(images["web"]["filesystem_image_id"], self.WEB_IMAGE_ID)
        self.assertNotIn(index_digest, manifest_path.read_text())
        self.assertNotIn(manifest_digest, manifest_path.read_text())

    def test_container_manifest_config_mismatch_is_rejected(self) -> None:
        output_directory = self.base / "evidence-config-mismatch"
        index_digest = f"sha256:{'e' * 64}"
        wrong_config_digest = f"sha256:{'f' * 64}"
        manifest_bytes = self._oci_manifest_bytes(wrong_config_digest)
        self.backend_inspect_image_id = index_digest
        self.backend_container_image_id = index_digest
        self.backend_manifest_config_id = wrong_config_digest
        self.backend_manifest_descriptor = (
            f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
        )

        with self.assertRaisesRegex(
            generator.EvidenceGenerationError,
            "config digest does not match docker-save Config",
        ):
            self._generate(output_directory)

        self.assertFalse(output_directory.exists())
        self._assert_no_staging(output_directory)
        self.assertIn(
            (
                "docker",
                "container",
                "rm",
                "--force",
                self.BACKEND_CONTAINER_ID,
            ),
            self.commands,
        )

    def test_each_docker_command_failure_leaves_no_output(self) -> None:
        for action in (
            "image-inspect",
            "image-save",
            "container-create",
            "container-inspect",
            "container-export",
            "container-rm",
        ):
            with self.subTest(action=action):
                output_directory = self.base / f"evidence-{action}"
                self.failure_action = action
                self.failure_raised = False
                self.commands.clear()

                with self.assertRaises(generator.EvidenceGenerationError):
                    self._generate(output_directory)

                self.assertTrue(self.failure_raised)
                self.assertFalse(output_directory.exists())
                self._assert_no_staging(output_directory)

    def test_container_is_removed_after_export_failure(self) -> None:
        output_directory = self.base / "evidence-export-failure"
        self.failure_action = "container-export"

        with self.assertRaises(generator.EvidenceGenerationError):
            self._generate(output_directory)

        self.assertIn(
            (
                "docker",
                "container",
                "rm",
                "--force",
                self.BACKEND_CONTAINER_ID,
            ),
            self.commands,
        )
        self.assertFalse(output_directory.exists())
        self._assert_no_staging(output_directory)

    def test_refuses_output_inside_repository_or_at_existing_path(self) -> None:
        inside_repository = self.repository_root / "evidence"
        existing_output = self.base / "existing-evidence"
        existing_output.mkdir()

        for output_directory in (inside_repository, existing_output):
            with self.subTest(output_directory=output_directory):
                with self.assertRaises(generator.EvidenceGenerationError):
                    self._generate(output_directory)

        self.preflight_mock.assert_not_called()
        self.subprocess_mock.assert_not_called()

    def test_preflight_failure_leaves_no_output(self) -> None:
        output_directory = self.base / "evidence-preflight-failure"
        self.preflight_mock.return_value = (
            None,
            [
                Violation(
                    "QUALIFICATION_WORKTREE_DIRTY",
                    str(self.repository_root),
                    0,
                    "synthetic dirty worktree",
                )
            ],
        )

        with self.assertRaisesRegex(
            generator.EvidenceGenerationError, "qualification preflight failed"
        ):
            self._generate(output_directory)

        self.dependency_mock.assert_not_called()
        self.subprocess_mock.assert_not_called()
        self.assertFalse(output_directory.exists())
        self._assert_no_staging(output_directory)

    def test_dependency_verification_failure_leaves_no_output(self) -> None:
        output_directory = self.base / "evidence-dependency-failure"
        self.dependency_mock.return_value = (
            False,
            [
                Violation(
                    "DEPENDENCY_EXPORT_DRIFT",
                    "backend/requirements/default.txt",
                    0,
                    "synthetic drift",
                )
            ],
        )

        with self.assertRaisesRegex(
            generator.EvidenceGenerationError, "dependency evidence failed"
        ):
            self._generate(output_directory)

        self.subprocess_mock.assert_not_called()
        self.assertFalse(output_directory.exists())
        self._assert_no_staging(output_directory)

    def test_qualification_failure_leaves_no_output(self) -> None:
        output_directory = self.base / "evidence-qualification-failure"
        self.gate_mock.side_effect = None
        self.gate_mock.return_value = self._report(
            (
                Violation(
                    "ARTIFACT_EE_PATH",
                    "backend-image.tar!app/ee/secret.py",
                    0,
                    "synthetic CE boundary violation",
                ),
            )
        )

        with self.assertRaisesRegex(
            generator.EvidenceGenerationError, "staged evidence was rejected"
        ):
            self._generate(output_directory)

        self.assertFalse(output_directory.exists())
        self._assert_no_staging(output_directory)
        removed_containers = [
            command[-1]
            for command in self.commands
            if command[:3] == ("docker", "container", "rm")
        ]
        self.assertEqual(
            removed_containers,
            [self.BACKEND_CONTAINER_ID, self.WEB_CONTAINER_ID],
        )


if __name__ == "__main__":
    unittest.main()
