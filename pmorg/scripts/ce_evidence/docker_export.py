"""Create Docker image and filesystem artifacts with guaranteed cleanup."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Sequence

from verify_ce_boundary import SHA256_PATTERN

from ce_evidence.models import EvidenceGenerationError
from ce_evidence.models import GeneratedImageArtifacts
from ce_evidence.runtime_binding import container_image_binding
from ce_evidence.runtime_binding import saved_image_binding
from ce_evidence.runtime_binding import sha256_file
from ce_evidence.runtime_binding import verify_container_archive_binding


CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


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


def _remove_container(container_id: str, repository_root: Path) -> None:
    _run(
        ["docker", "container", "rm", "--force", container_id],
        repository_root,
    )


def generate_image_artifacts(
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
    saved_binding = saved_image_binding(archive_path, image)

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
        container_binding = container_image_binding(
            _run(
                ["docker", "container", "inspect", container_id],
                repository_root,
            ),
            container_id,
        )
        verify_container_archive_binding(container_binding, saved_binding)
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
        archive_sha256=sha256_file(archive_path),
        filesystem_name=filesystem_name,
        filesystem_sha256=sha256_file(filesystem_path),
        filesystem_image_id=saved_binding.config_digest,
    )
