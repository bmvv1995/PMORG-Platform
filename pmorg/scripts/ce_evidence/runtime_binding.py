"""Bind Docker runtime identity to the config stored by ``docker save``."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

from verify_ce_boundary import MAX_ARCHIVE_SOURCE_BYTES
from verify_ce_boundary import SHA256_PATTERN

from ce_evidence.models import ContainerImageBinding
from ce_evidence.models import EvidenceGenerationError
from ce_evidence.models import SavedImageBinding


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceGenerationError(f"expected evidence file is missing: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


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


def saved_image_binding(archive_path: Path, tag: str) -> SavedImageBinding:
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


def container_image_binding(
    output: bytes, container_id: str
) -> ContainerImageBinding:
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


def verify_container_archive_binding(
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
    actual_manifest_digest = f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
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
    if config.get("digest") != saved.config_digest:
        raise EvidenceGenerationError(
            "Docker OCI image manifest config digest does not match docker-save Config"
        )
