#!/usr/bin/env python3
"""Generate fail-closed PMORG CE qualification evidence.

The generator only publishes an evidence directory after the existing CE gate
has qualified the staged Docker archives and container filesystem exports.
It deliberately does not claim signed provenance or update Gate A status.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from verify_ce_boundary import DEFAULT_DOCKERFILES
from verify_ce_boundary import DEPENDENCY_EVIDENCE_COMMAND
from verify_ce_boundary import EVIDENCE_SCHEMA_VERSION
from verify_ce_boundary import MAX_ARCHIVE_SOURCE_BYTES
from verify_ce_boundary import SHA256_PATTERN
from verify_ce_boundary import DependencyEvidence
from verify_ce_boundary import DockerBuild
from verify_ce_boundary import GateConfig
from verify_ce_boundary import GateReport
from verify_ce_boundary import QualificationIdentity
from verify_ce_boundary import Violation
from verify_ce_boundary import run_gate
from verify_ce_boundary import verify_dependency_evidence
from verify_ce_boundary import verify_qualification_preflight


EVIDENCE_MANIFEST_NAME = "evidence-manifest.json"
CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class EvidenceGenerationError(RuntimeError):
    """Raised when evidence cannot be generated and qualified safely."""


@dataclass(frozen=True)
class GeneratedImageArtifacts:
    name: str
    tag: str
    image_id: str
    archive_name: str
    archive_sha256: str
    filesystem_name: str
    filesystem_sha256: str
    filesystem_image_id: str


@dataclass(frozen=True)
class SavedImageBinding:
    config_digest: str
    archive: Path


@dataclass(frozen=True)
class ContainerImageBinding:
    image_digest: str
    manifest_digest: str | None


def _sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceGenerationError(f"expected evidence file is missing: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _render_violations(violations: Sequence[Violation]) -> str:
    return "; ".join(violation.render() for violation in violations)


def _run(command: Sequence[str], repository_root: Path) -> bytes:
    argv = list(command)
    try:
        result = subprocess.run(
            argv,
            cwd=repository_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as error:
        stderr = error.stderr
        if isinstance(stderr, bytes):
            detail = stderr.decode("utf-8", errors="replace").strip()
        elif isinstance(stderr, str):
            detail = stderr.strip()
        else:
            detail = ""
        suffix = f": {detail}" if detail else ""
        raise EvidenceGenerationError(
            f"command failed with status {error.returncode}: {argv!r}{suffix}"
        ) from error
    except OSError as error:
        raise EvidenceGenerationError(
            f"cannot execute command {argv!r}: {error}"
        ) from error
    return result.stdout


def _single_line(output: bytes, description: str) -> str:
    try:
        value = output.decode("utf-8").strip()
    except UnicodeError as error:
        raise EvidenceGenerationError(
            f"{description} is not valid UTF-8"
        ) from error
    if not value or "\n" in value or "\r" in value:
        raise EvidenceGenerationError(
            f"{description} must contain exactly one non-empty line"
        )
    return value


def _observe_image_id(image: str, repository_root: Path) -> None:
    observed_id = _single_line(
        _run(
            ["docker", "image", "inspect", "--format={{.Id}}", image],
            repository_root,
        ),
        f"Docker image ID for {image!r}",
    )
    if SHA256_PATTERN.fullmatch(observed_id) is None:
        raise EvidenceGenerationError(
            f"Docker image {image!r} returned a non-canonical image ID"
        )


def _read_tar_member(archive: tarfile.TarFile, name: str) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError as error:
        raise EvidenceGenerationError(
            f"Docker archive is missing required member {name!r}"
        ) from error
    if not member.isfile() or member.size > MAX_ARCHIVE_SOURCE_BYTES:
        raise EvidenceGenerationError(
            f"Docker archive member {name!r} is not a bounded regular file"
        )
    source = archive.extractfile(member)
    if source is None:
        raise EvidenceGenerationError(
            f"Docker archive member {name!r} cannot be read"
        )
    data = source.read(MAX_ARCHIVE_SOURCE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_SOURCE_BYTES:
        raise EvidenceGenerationError(
            f"Docker archive member {name!r} exceeds the safe size limit"
        )
    return data


def _json_object(data: bytes, description: str) -> dict[str, object]:
    try:
        value = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceGenerationError(f"{description} is not valid JSON") from error
    if not isinstance(value, dict):
        raise EvidenceGenerationError(f"{description} must be a JSON object")
    return value


def _saved_image_binding(archive_path: Path, tag: str) -> SavedImageBinding:
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            try:
                manifest = json.loads(_read_tar_member(archive, "manifest.json"))
            except (UnicodeError, json.JSONDecodeError) as error:
                raise EvidenceGenerationError(
                    "Docker archive manifest.json is invalid"
                ) from error
            if not isinstance(manifest, list):
                raise EvidenceGenerationError(
                    "Docker archive manifest.json must be an array"
                )
            matching = [
                item
                for item in manifest
                if isinstance(item, dict)
                and isinstance(item.get("RepoTags"), list)
                and tag in item["RepoTags"]
            ]
            if len(matching) != 1:
                raise EvidenceGenerationError(
                    f"Docker archive must contain exactly one entry for tag {tag!r}"
                )
            config_name = matching[0].get("Config")
            if not isinstance(config_name, str) or not config_name:
                raise EvidenceGenerationError(
                    "Docker archive manifest Config must be a non-empty string"
                )
            config_bytes = _read_tar_member(archive, config_name)
    except (tarfile.TarError, OSError) as error:
        raise EvidenceGenerationError(
            f"cannot inspect Docker archive {archive_path}: {error}"
        ) from error
    return SavedImageBinding(
        config_digest=f"sha256:{hashlib.sha256(config_bytes).hexdigest()}",
        archive=archive_path,
    )


def _container_image_binding(output: bytes, container_id: str) -> ContainerImageBinding:
    try:
        raw = json.loads(output)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceGenerationError(
            f"Docker inspect output for container {container_id} is invalid"
        ) from error
    if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
        raise EvidenceGenerationError(
            f"Docker inspect output for container {container_id} must contain one object"
        )
    image_digest = raw[0].get("Image")
    if not isinstance(image_digest, str) or SHA256_PATTERN.fullmatch(image_digest) is None:
        raise EvidenceGenerationError(
            f"Docker container {container_id} has a non-canonical .Image digest"
        )
    raw_descriptor = raw[0].get("ImageManifestDescriptor")
    manifest_digest: str | None = None
    if raw_descriptor is not None:
        if not isinstance(raw_descriptor, dict):
            raise EvidenceGenerationError(
                f"Docker container {container_id} has an invalid image descriptor"
            )
        descriptor_digest = raw_descriptor.get("digest")
        if not isinstance(descriptor_digest, str) or SHA256_PATTERN.fullmatch(
            descriptor_digest
        ) is None:
            raise EvidenceGenerationError(
                f"Docker container {container_id} has a non-canonical manifest digest"
            )
        manifest_digest = descriptor_digest
    return ContainerImageBinding(image_digest, manifest_digest)


def _verify_container_archive_binding(
    container: ContainerImageBinding,
    saved: SavedImageBinding,
) -> None:
    if container.image_digest == saved.config_digest:
        return
    if container.manifest_digest is None:
        raise EvidenceGenerationError(
            "container .Image differs from the saved config digest and has no "
            "ImageManifestDescriptor"
        )
    manifest_name = (
        "blobs/sha256/" + container.manifest_digest.removeprefix("sha256:")
    )
    try:
        with tarfile.open(saved.archive, mode="r:*") as archive:
            manifest_bytes = _read_tar_member(archive, manifest_name)
    except (tarfile.TarError, OSError) as error:
        raise EvidenceGenerationError(
            f"cannot inspect Docker archive {saved.archive}: {error}"
        ) from error
    actual_manifest_digest = (
        f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
    )
    if actual_manifest_digest != container.manifest_digest:
        raise EvidenceGenerationError(
            "container image manifest descriptor does not match its archive blob"
        )
    manifest = _json_object(manifest_bytes, "Docker OCI image manifest")
    config = manifest.get("config")
    if not isinstance(config, dict):
        raise EvidenceGenerationError(
            "Docker OCI image manifest has no config descriptor"
        )
    config_digest = config.get("digest")
    if config_digest != saved.config_digest:
        raise EvidenceGenerationError(
            "Docker OCI image manifest config digest does not match docker-save Config"
        )


def _remove_container(container_id: str, repository_root: Path) -> None:
    _run(
        ["docker", "container", "rm", "--force", container_id],
        repository_root,
    )


def _generate_image_artifacts(
    name: str,
    image: str,
    staging_directory: Path,
    repository_root: Path,
) -> GeneratedImageArtifacts:
    # Docker Desktop may expose image-index digests; docker-save Config is the
    # canonical digest after the container-to-archive chain is verified below.
    _observe_image_id(image, repository_root)
    archive_name = f"{name}-image.tar"
    archive_path = staging_directory / archive_name
    _run(
        ["docker", "image", "save", "--output", str(archive_path), image],
        repository_root,
    )
    saved_binding = _saved_image_binding(archive_path, image)

    container_id: str | None = None
    filesystem_name = f"{name}-filesystem.tar"
    filesystem_path = staging_directory / filesystem_name
    try:
        container_id = _single_line(
            _run(
                ["docker", "container", "create", "--network", "none", image],
                repository_root,
            ),
            f"Docker container ID for {image!r}",
        )
        if CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
            raise EvidenceGenerationError(
                f"Docker returned a non-canonical container ID for {image!r}"
            )
        container_binding = _container_image_binding(
            _run(
                ["docker", "container", "inspect", container_id],
                repository_root,
            ),
            container_id,
        )
        _verify_container_archive_binding(container_binding, saved_binding)
        _run(
            [
                "docker",
                "container",
                "export",
                "--output",
                str(filesystem_path),
                container_id,
            ],
            repository_root,
        )
    finally:
        if container_id is not None and CONTAINER_ID_PATTERN.fullmatch(container_id):
            _remove_container(container_id, repository_root)

    return GeneratedImageArtifacts(
        name=name,
        tag=image,
        image_id=saved_binding.config_digest,
        archive_name=archive_name,
        archive_sha256=_sha256_file(archive_path),
        filesystem_name=filesystem_name,
        filesystem_sha256=_sha256_file(filesystem_path),
        filesystem_image_id=saved_binding.config_digest,
    )


def _dependency_evidence(repository_root: Path) -> DependencyEvidence:
    lockfile = (repository_root / "uv.lock").resolve()
    requirements = (
        repository_root / "backend" / "requirements" / "default.txt"
    ).resolve()
    evidence = DependencyEvidence(
        status="regenerated-and-verified",
        command=DEPENDENCY_EVIDENCE_COMMAND,
        lockfile=lockfile,
        lockfile_sha256=_sha256_file(lockfile),
        requirements=requirements,
        requirements_sha256=_sha256_file(requirements),
    )
    verified, violations = verify_dependency_evidence(evidence, repository_root)
    if not verified or violations:
        detail = _render_violations(violations) or "dependency export was not verified"
        raise EvidenceGenerationError(f"dependency evidence failed: {detail}")
    return evidence


def _manifest(
    dependency: DependencyEvidence,
    images: Sequence[GeneratedImageArtifacts],
    artifact_directory: Path,
    repository_root: Path,
) -> dict[str, object]:
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "dependency_export": {
            "status": dependency.status,
            "command": list(dependency.command),
            "lockfile": dependency.lockfile.relative_to(repository_root).as_posix(),
            "lockfile_sha256": dependency.lockfile_sha256,
            "requirements": dependency.requirements.relative_to(
                repository_root
            ).as_posix(),
            "requirements_sha256": dependency.requirements_sha256,
        },
        "images": [
            {
                "name": image.name,
                "tag": image.tag,
                "image_id": image.image_id,
                "archive": str((artifact_directory / image.archive_name).resolve()),
                "archive_sha256": image.archive_sha256,
                "filesystem": str(
                    (artifact_directory / image.filesystem_name).resolve()
                ),
                "filesystem_sha256": image.filesystem_sha256,
                "filesystem_image_id": image.filesystem_image_id,
            }
            for image in images
        ],
    }


def _write_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _gate_builds(repository_root: Path) -> tuple[DockerBuild, ...]:
    builds: list[DockerBuild] = []
    for relative_path in DEFAULT_DOCKERFILES:
        dockerfile = repository_root / relative_path
        builds.append(
            DockerBuild(
                dockerfile=dockerfile,
                context=dockerfile.parent,
                dockerignore=Path(str(dockerfile) + ".dockerignore"),
            )
        )
    return tuple(builds)


def _validate_gate_report(
    report: GateReport, identity: QualificationIdentity
) -> None:
    if not report.passed:
        detail = _render_violations(report.violations) or "qualification failed"
        raise EvidenceGenerationError(f"staged evidence was rejected: {detail}")
    if not report.dependency_evidence_verified:
        raise EvidenceGenerationError(
            "staged evidence passed without verified dependency evidence"
        )
    if (
        report.source_revision != identity.source_revision
        or report.baseline_manifest_sha256 != identity.baseline_manifest_sha256
        or report.target_platform != identity.target_platform
    ):
        raise EvidenceGenerationError(
            "qualification identity changed while evidence was generated"
        )
    if {image.name for image in report.qualified_images} != {"backend", "web"}:
        raise EvidenceGenerationError(
            "qualification did not bind exactly the backend and web images"
        )


def _validate_paths(repository_root: Path, output_directory: Path) -> tuple[Path, Path]:
    if os.path.lexists(output_directory):
        raise EvidenceGenerationError(
            f"output directory must not already exist: {output_directory}"
        )
    repository_root = repository_root.resolve()
    output_directory = output_directory.resolve()
    if not repository_root.is_dir():
        raise EvidenceGenerationError(
            f"repository root is not a directory: {repository_root}"
        )
    if output_directory == repository_root or output_directory.is_relative_to(
        repository_root
    ):
        raise EvidenceGenerationError(
            "output directory must be outside the repository worktree"
        )
    if os.path.lexists(output_directory):
        raise EvidenceGenerationError(
            f"output directory must not already exist: {output_directory}"
        )
    if not output_directory.parent.is_dir():
        raise EvidenceGenerationError(
            f"output parent directory does not exist: {output_directory.parent}"
        )
    return repository_root, output_directory


def generate_evidence(
    repository_root: Path,
    backend_image: str,
    web_image: str,
    output_directory: Path,
) -> Path:
    """Generate and atomically publish qualified CE evidence."""

    repository_root, output_directory = _validate_paths(
        repository_root, output_directory
    )
    identity, preflight_violations = verify_qualification_preflight(repository_root)
    if identity is None or preflight_violations:
        detail = _render_violations(preflight_violations) or "identity is unavailable"
        raise EvidenceGenerationError(f"qualification preflight failed: {detail}")
    dependency = _dependency_evidence(repository_root)

    staging_directory = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}.staging-",
            dir=output_directory.parent,
        )
    )
    try:
        images = (
            _generate_image_artifacts(
                "backend", backend_image, staging_directory, repository_root
            ),
            _generate_image_artifacts(
                "web", web_image, staging_directory, repository_root
            ),
        )
        staged_manifest_path = staging_directory / EVIDENCE_MANIFEST_NAME
        _write_manifest(
            staged_manifest_path,
            _manifest(dependency, images, staging_directory, repository_root),
        )
        report = run_gate(
            GateConfig(
                repository_root=repository_root,
                builds=_gate_builds(repository_root),
                mode="qualify",
                evidence_manifest=staged_manifest_path,
            )
        )
        _validate_gate_report(report, identity)

        _write_manifest(
            staged_manifest_path,
            _manifest(dependency, images, output_directory, repository_root),
        )
        if os.path.lexists(output_directory):
            raise EvidenceGenerationError(
                f"output directory appeared during generation: {output_directory}"
            )
        os.rename(staging_directory, output_directory)
    finally:
        if staging_directory.exists():
            shutil.rmtree(staging_directory)
    return output_directory / EVIDENCE_MANIFEST_NAME


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate qualified PMORG CE Docker evidence atomically."
    )
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--backend-image", required=True)
    parser.add_argument("--web-image", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        manifest = generate_evidence(
            repository_root=Path(arguments.repository_root),
            backend_image=arguments.backend_image,
            web_image=arguments.web_image,
            output_directory=Path(arguments.output_dir),
        )
    except (EvidenceGenerationError, OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: qualified CE evidence published at {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
