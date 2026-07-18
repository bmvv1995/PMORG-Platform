"""Cryptographic image binding and historical-layer qualification."""

from __future__ import annotations

import gzip
import hashlib
import json
import tarfile
import tempfile
from typing import Sequence

from .artifacts import _scan_tar_members
from .artifacts import scan_filesystem_path
from .evidence import _required_string
from .evidence import _sha256_bytes
from .evidence import _verify_file_digest
from .evidence import load_qualification_evidence
from .evidence import verify_dependency_evidence
from .evidence import verify_qualification_preflight
from .models import MAX_ARCHIVE_SOURCE_BYTES
from .models import QUALIFIED_IMAGE_NAMES
from .models import SHA256_PATTERN
from .models import GateConfig
from .models import ImageEvidence
from .models import QualificationIdentity
from .models import QualifiedImage
from .models import Violation
from .models import _MutableStats

def _expected_image_labels(
    identity: QualificationIdentity, component: str
) -> dict[str, str]:
    return {
        "org.opencontainers.image.source": identity.source_repository,
        "org.opencontainers.image.revision": identity.source_revision,
        "io.pmorg.edition": "community",
        "io.pmorg.component": component,
        "io.pmorg.onyx.version": identity.onyx_version,
        "io.pmorg.onyx.upstream.revision": identity.onyx_upstream_revision,
        "io.pmorg.specification.revision": identity.specification_revision,
        "io.pmorg.build.target-platform": identity.target_platform,
    }


def _validate_image_config(
    config: dict[str, object],
    evidence: ImageEvidence,
    identity: QualificationIdentity,
) -> list[Violation]:
    display_path = f"{evidence.archive}!config"
    violations: list[Violation] = []
    if (
        config.get("os") != "linux"
        or config.get("architecture") != "amd64"
        or "variant" in config
    ):
        violations.append(
            Violation(
                "IMAGE_PLATFORM_MISMATCH",
                display_path,
                0,
                "image config must be linux/amd64 and omit variant",
            )
        )

    runtime_config = config.get("config")
    if not isinstance(runtime_config, dict):
        return [
            *violations,
            Violation(
                "IMAGE_RUNTIME_CONFIG_INVALID",
                display_path,
                0,
                "image config.config must be an object",
            ),
        ]

    labels = runtime_config.get("Labels")
    if not isinstance(labels, dict):
        violations.append(
            Violation(
                "IMAGE_LABEL_MISMATCH",
                display_path,
                0,
                "image config must contain the complete PMORG label set",
            )
        )
    else:
        for key, expected in _expected_image_labels(
            identity, evidence.name
        ).items():
            actual = labels.get(key)
            if actual != expected:
                violations.append(
                    Violation(
                        "IMAGE_LABEL_MISMATCH",
                        f"{display_path}:{key}",
                        0,
                        f"expected {expected!r}, got {actual!r}",
                    )
                )

    expected_entrypoints: dict[str, list[str]] = {
        "backend": ["python", "-m", "pmorg_ce.entrypoint"],
        "web": ["docker-entrypoint.sh"],
    }
    expected_commands: dict[str, list[str]] = {
        "backend": ["tail", "-f", "/dev/null"],
        "web": ["node", "server.js"],
    }
    expected_entrypoint = expected_entrypoints.get(evidence.name)
    if runtime_config.get("Entrypoint") != expected_entrypoint:
        violations.append(
            Violation(
                "IMAGE_ENTRYPOINT_MISMATCH",
                display_path,
                0,
                f"{evidence.name} Entrypoint must be {expected_entrypoint!r}",
            )
        )
    expected_command = expected_commands.get(evidence.name)
    if runtime_config.get("Cmd") != expected_command:
        violations.append(
            Violation(
                "IMAGE_CMD_MISMATCH",
                display_path,
                0,
                f"{evidence.name} Cmd must be {expected_command!r}",
            )
        )
    return violations


def scan_bound_image_archive(
    evidence: ImageEvidence,
    identity: QualificationIdentity,
    denied_prefixes: Sequence[str],
    stats: _MutableStats,
) -> tuple[int, list[Violation]]:
    """Verify and scan one classic ``docker image save`` archive.

    Each layer is copied into a spooled temporary file while hashing. This
    bounds memory use and validates the uncompressed layer bytes against the
    config's ``rootfs.diff_ids`` before scanning its tar members.
    """

    if not evidence.archive.is_file():
        return 0, [
            Violation(
                "LAYER_ARCHIVE_MISSING",
                str(evidence.archive),
                0,
                "bound Docker-save archive does not exist",
            )
        ]
    violations: list[Violation] = []
    try:
        with tarfile.open(evidence.archive, mode="r:*") as outer_archive:
            manifest_member = outer_archive.getmember("manifest.json")
            manifest_file = outer_archive.extractfile(manifest_member)
            if manifest_file is None:
                raise ValueError("manifest.json is not readable")
            manifest = json.load(manifest_file)
            if not isinstance(manifest, list):
                raise ValueError("manifest.json must contain an array")
            matching_images = [
                image
                for image in manifest
                if isinstance(image, dict)
                and isinstance(image.get("RepoTags"), list)
                and evidence.tag in image["RepoTags"]
            ]
            if len(matching_images) != 1:
                raise ValueError(
                    f"expected exactly one manifest entry for tag {evidence.tag!r}"
                )
            image = matching_images[0]
            config_name = _required_string(image.get("Config"), "manifest.Config")
            layers = image.get("Layers")
            if not isinstance(layers, list) or not all(
                isinstance(layer, str) for layer in layers
            ):
                raise ValueError("manifest.Layers must be a string array")
            if not layers:
                raise ValueError("qualified image has no filesystem layers")

            config_member = outer_archive.getmember(config_name)
            config_file = outer_archive.extractfile(config_member)
            if config_file is None:
                raise ValueError(f"config {config_name!r} is not readable")
            config_bytes = config_file.read(MAX_ARCHIVE_SOURCE_BYTES + 1)
            if len(config_bytes) > MAX_ARCHIVE_SOURCE_BYTES:
                raise ValueError("image config exceeds the safe manifest size")
            actual_image_id = _sha256_bytes(config_bytes)
            if actual_image_id != evidence.image_id:
                violations.append(
                    Violation(
                        "IMAGE_CONFIG_DIGEST_MISMATCH",
                        str(evidence.archive),
                        0,
                        f"tag {evidence.tag!r} expected {evidence.image_id}, "
                        f"calculated {actual_image_id}",
                    )
                )
            config = json.loads(config_bytes)
            if not isinstance(config, dict) or not isinstance(
                config.get("rootfs"), dict
            ):
                raise ValueError("image config has no rootfs object")
            violations.extend(_validate_image_config(config, evidence, identity))
            diff_ids = config["rootfs"].get("diff_ids")
            if not isinstance(diff_ids, list) or not all(
                isinstance(digest, str) and SHA256_PATTERN.fullmatch(digest)
                for digest in diff_ids
            ):
                raise ValueError("image config rootfs.diff_ids is invalid")
            if len(diff_ids) != len(layers):
                raise ValueError("manifest layer count differs from rootfs.diff_ids")

            for layer_name, expected_diff_id in zip(layers, diff_ids, strict=True):
                layer_member = outer_archive.getmember(layer_name)
                layer_file = outer_archive.extractfile(layer_member)
                if layer_file is None:
                    raise ValueError(f"layer {layer_name!r} is not readable")
                digest = hashlib.sha256()
                with (
                    tempfile.SpooledTemporaryFile(
                        max_size=8 * 1024 * 1024, mode="w+b"
                    ) as stored_layer_spool,
                    tempfile.SpooledTemporaryFile(
                        max_size=8 * 1024 * 1024, mode="w+b"
                    ) as layer_spool,
                ):
                    while chunk := layer_file.read(1024 * 1024):
                        stored_layer_spool.write(chunk)
                    stored_layer_spool.seek(0)
                    magic = stored_layer_spool.read(4)
                    stored_layer_spool.seek(0)
                    if magic.startswith(b"\x1f\x8b"):
                        with gzip.GzipFile(
                            fileobj=stored_layer_spool, mode="rb"
                        ) as expanded_layer:
                            while chunk := expanded_layer.read(1024 * 1024):
                                digest.update(chunk)
                                layer_spool.write(chunk)
                    elif magic == b"\x28\xb5\x2f\xfd":
                        raise ValueError(
                            f"layer {layer_name!r} uses unsupported zstd compression"
                        )
                    else:
                        while chunk := stored_layer_spool.read(1024 * 1024):
                            digest.update(chunk)
                            layer_spool.write(chunk)
                    actual_diff_id = f"sha256:{digest.hexdigest()}"
                    if actual_diff_id != expected_diff_id:
                        violations.append(
                            Violation(
                                "LAYER_DIFF_ID_MISMATCH",
                                f"{evidence.archive}!{layer_name}",
                                0,
                                f"expected {expected_diff_id}, "
                                f"calculated {actual_diff_id}",
                            )
                        )
                    layer_spool.seek(0)
                    with tarfile.open(fileobj=layer_spool, mode="r:*") as layer:
                        violations.extend(
                            _scan_tar_members(
                                layer,
                                f"{evidence.archive}!{layer_name}",
                                denied_prefixes,
                                stats,
                            )
                        )
            return len(layers), violations
    except (
        tarfile.TarError,
        OSError,
        KeyError,
        ValueError,
        EOFError,
        json.JSONDecodeError,
    ) as error:
        violations.append(
            Violation(
                "LAYER_ARCHIVE_INVALID",
                str(evidence.archive),
                0,
                str(error),
            )
        )
        return 0, violations


def _qualify_artifacts(
    config: GateConfig,
) -> tuple[
    bool,
    tuple[QualifiedImage, ...],
    int,
    QualificationIdentity | None,
    list[Violation],
]:
    identity, preflight_violations = verify_qualification_preflight(
        config.repository_root
    )
    if config.evidence_manifest is None:
        return False, (), 0, identity, [
            *preflight_violations,
            Violation(
                "EVIDENCE_MANIFEST_REQUIRED",
                "qualification",
                0,
                "qualify mode requires --evidence-manifest",
            ),
        ]
    evidence, violations = load_qualification_evidence(
        config.evidence_manifest, config.repository_root.resolve()
    )
    violations = [*preflight_violations, *violations]
    if evidence is None:
        return False, (), 0, identity, violations
    if identity is None:
        return False, (), 0, None, violations

    image_names = [image.name for image in evidence.images]
    if len(image_names) != len(QUALIFIED_IMAGE_NAMES) or set(
        image_names
    ) != QUALIFIED_IMAGE_NAMES:
        violations.append(
            Violation(
                "EVIDENCE_IMAGE_SET",
                str(config.evidence_manifest),
                0,
                "qualification requires exactly one backend and one web image",
            )
        )
    artifact_paths = [
        path.resolve()
        for image in evidence.images
        for path in (image.archive, image.filesystem)
    ]
    if len(artifact_paths) != len(set(artifact_paths)):
        violations.append(
            Violation(
                "EVIDENCE_ARTIFACT_REUSED",
                str(config.evidence_manifest),
                0,
                "backend and web image/filesystem evidence must use four "
                "distinct artifacts",
            )
        )

    dependency_verified, dependency_violations = verify_dependency_evidence(
        evidence.dependency_export, config.repository_root.resolve()
    )
    violations.extend(dependency_violations)
    qualified_images: list[QualifiedImage] = []
    total_entries = 0
    for image in evidence.images:
        violations.extend(_verify_file_digest(image.archive, image.archive_sha256))
        violations.extend(
            _verify_file_digest(image.filesystem, image.filesystem_sha256)
        )
        if image.filesystem_image_id != image.image_id:
            violations.append(
                Violation(
                    "FILESYSTEM_IMAGE_BINDING_MISMATCH",
                    str(image.filesystem),
                    0,
                    f"filesystem is bound to {image.filesystem_image_id}, "
                    f"expected {image.image_id}",
                )
            )

        layer_stats = _MutableStats()
        layer_count, layer_violations = scan_bound_image_archive(
            image, identity, config.denied_source_prefixes, layer_stats
        )
        violations.extend(layer_violations)
        filesystem_stats = _MutableStats()
        violations.extend(
            scan_filesystem_path(
                image.filesystem, config.denied_source_prefixes, filesystem_stats
            )
        )
        if layer_stats.artifact_entries == 0:
            violations.append(
                Violation(
                    "IMAGE_LAYERS_EMPTY",
                    str(image.archive),
                    0,
                    "qualified image yielded no layer entries",
                )
            )
        if filesystem_stats.artifact_entries == 0:
            violations.append(
                Violation(
                    "FILESYSTEM_EXPORT_EMPTY",
                    str(image.filesystem),
                    0,
                    "qualified filesystem export contains no entries",
                )
            )
        total_entries += (
            layer_stats.artifact_entries + filesystem_stats.artifact_entries
        )
        qualified_images.append(
            QualifiedImage(
                name=image.name,
                tag=image.tag,
                image_id=image.image_id,
                archive_sha256=image.archive_sha256,
                filesystem_sha256=image.filesystem_sha256,
                layer_count=layer_count,
                layer_entries=layer_stats.artifact_entries,
                filesystem_entries=filesystem_stats.artifact_entries,
            )
        )
    return (
        dependency_verified,
        tuple(sorted(qualified_images, key=lambda image: image.name)),
        total_entries,
        identity,
        violations,
    )
