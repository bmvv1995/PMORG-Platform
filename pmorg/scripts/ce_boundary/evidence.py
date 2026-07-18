"""Qualification identity, evidence loading, and dependency-export proof."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from .models import BASELINE_MANIFEST_PATH
from .models import BASELINE_SCHEMA_VERSION
from .models import DEPENDENCY_EVIDENCE_COMMAND
from .models import EVIDENCE_SCHEMA_VERSION
from .models import GIT_SHA_PATTERN
from .models import QUALIFICATION_TARGET_PLATFORM
from .models import QUALIFICATION_UV_IMAGE
from .models import QUALIFICATION_UV_VERSION
from .models import SHA256_PATTERN
from .models import DependencyEvidence
from .models import ImageEvidence
from .models import QualificationEvidence
from .models import QualificationIdentity
from .models import Violation

def _sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _evidence_path(repository_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else repository_root / path


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _required_digest(value: object, field: str) -> str:
    digest = _required_string(value, field)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return digest


def _required_git_sha(value: object, field: str) -> str:
    revision = _required_string(value, field)
    if GIT_SHA_PATTERN.fullmatch(revision) is None:
        raise ValueError(f"{field} must be a lowercase full 40-hex Git SHA")
    return revision


def _required_object(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _command_failure_message(error: subprocess.CalledProcessError) -> str:
    stderr = error.stderr
    if isinstance(stderr, bytes):
        detail = stderr.decode("utf-8", errors="replace").strip()
    elif isinstance(stderr, str):
        detail = stderr.strip()
    else:
        detail = ""
    return detail or f"command exited with status {error.returncode}"


def verify_qualification_preflight(
    repository_root: Path,
) -> tuple[QualificationIdentity | None, list[Violation]]:
    """Bind qualification to an immutable, clean repository identity."""

    repository_root = repository_root.resolve()
    violations: list[Violation] = []
    try:
        revision_result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=repository_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        source_revision = revision_result.stdout.decode("ascii").strip()
        if GIT_SHA_PATTERN.fullmatch(source_revision) is None:
            raise ValueError("git rev-parse returned a non-canonical revision")

        status_result = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=repository_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if status_result.stdout:
            violations.append(
                Violation(
                    "QUALIFICATION_WORKTREE_DIRTY",
                    str(repository_root),
                    0,
                    "qualification requires a clean tracked and untracked worktree",
                )
            )

        baseline_result = subprocess.run(
            ["git", "show", f"HEAD:{BASELINE_MANIFEST_PATH.as_posix()}"],
            cwd=repository_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        head_baseline_bytes = baseline_result.stdout
    except subprocess.CalledProcessError as error:
        return None, [
            Violation(
                "QUALIFICATION_GIT_PREFLIGHT",
                str(repository_root),
                0,
                _command_failure_message(error),
            )
        ]
    except (OSError, UnicodeError, ValueError) as error:
        return None, [
            Violation(
                "QUALIFICATION_GIT_PREFLIGHT",
                str(repository_root),
                0,
                str(error),
            )
        ]

    baseline_path = repository_root / BASELINE_MANIFEST_PATH
    try:
        working_baseline_bytes = baseline_path.read_bytes()
    except OSError as error:
        violations.append(
            Violation(
                "BASELINE_MANIFEST_READ_ERROR",
                str(baseline_path),
                0,
                str(error),
            )
        )
    else:
        if working_baseline_bytes != head_baseline_bytes:
            violations.append(
                Violation(
                    "BASELINE_MANIFEST_STALE",
                    str(baseline_path),
                    0,
                    "working baseline manifest bytes differ from HEAD",
                )
            )

    try:
        raw = json.loads(head_baseline_bytes)
        baseline = _required_object(raw, "baseline manifest")
        if baseline.get("schema_version") != BASELINE_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {BASELINE_SCHEMA_VERSION!r}"
            )
        source_repository = _required_string(
            baseline.get("repository"), "repository"
        ).removesuffix(".git")
        upstream = _required_object(baseline.get("upstream"), "upstream")
        specification = _required_object(
            baseline.get("specification"), "specification"
        )
        build = _required_object(baseline.get("build"), "build")
        target_platform = _required_string(
            build.get("target_platform"), "build.target_platform"
        )
        if target_platform != QUALIFICATION_TARGET_PLATFORM:
            raise ValueError(
                "build.target_platform must be "
                f"{QUALIFICATION_TARGET_PLATFORM!r}"
            )
        toolchain = _required_object(build.get("toolchain"), "build.toolchain")
        uv_toolchain = _required_object(toolchain.get("uv"), "build.toolchain.uv")
        uv_version = _required_string(
            uv_toolchain.get("version"), "build.toolchain.uv.version"
        )
        if uv_version != QUALIFICATION_UV_VERSION:
            raise ValueError(
                f"build.toolchain.uv.version must be {QUALIFICATION_UV_VERSION!r}"
            )
        uv_image = _required_string(
            uv_toolchain.get("image"), "build.toolchain.uv.image"
        )
        if uv_image != QUALIFICATION_UV_IMAGE:
            raise ValueError(
                f"build.toolchain.uv.image must be {QUALIFICATION_UV_IMAGE!r}"
            )
        identity = QualificationIdentity(
            source_repository=source_repository,
            source_revision=source_revision,
            baseline_manifest_sha256=_sha256_bytes(head_baseline_bytes),
            onyx_version=_required_string(
                upstream.get("release_tag"), "upstream.release_tag"
            ),
            onyx_upstream_revision=_required_git_sha(
                upstream.get("commit"), "upstream.commit"
            ),
            specification_revision=_required_git_sha(
                specification.get("commit"), "specification.commit"
            ),
            target_platform=target_platform,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        violations.append(
            Violation(
                "BASELINE_MANIFEST_INVALID",
                str(baseline_path),
                0,
                str(error),
            )
        )
        return None, violations

    return identity, violations


def load_qualification_evidence(
    evidence_manifest: Path, repository_root: Path
) -> tuple[QualificationEvidence | None, list[Violation]]:
    if not evidence_manifest.is_file():
        return None, [
            Violation(
                "EVIDENCE_MANIFEST_MISSING",
                str(evidence_manifest),
                0,
                "qualification evidence manifest does not exist",
            )
        ]
    try:
        with evidence_manifest.open(encoding="utf-8") as source:
            raw = json.load(source)
        if not isinstance(raw, dict):
            raise ValueError("manifest root must be an object")
        if raw.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {EVIDENCE_SCHEMA_VERSION!r}"
            )

        raw_dependency = raw.get("dependency_export")
        dependency: DependencyEvidence | None = None
        if raw_dependency is not None:
            if not isinstance(raw_dependency, dict):
                raise ValueError("dependency_export must be an object")
            raw_command = raw_dependency.get("command")
            if not isinstance(raw_command, list) or not all(
                isinstance(item, str) for item in raw_command
            ):
                raise ValueError("dependency_export.command must be a string array")
            dependency = DependencyEvidence(
                status=_required_string(
                    raw_dependency.get("status"), "dependency_export.status"
                ),
                command=tuple(raw_command),
                lockfile=_evidence_path(
                    repository_root,
                    _required_string(
                        raw_dependency.get("lockfile"),
                        "dependency_export.lockfile",
                    ),
                ),
                lockfile_sha256=_required_digest(
                    raw_dependency.get("lockfile_sha256"),
                    "dependency_export.lockfile_sha256",
                ),
                requirements=_evidence_path(
                    repository_root,
                    _required_string(
                        raw_dependency.get("requirements"),
                        "dependency_export.requirements",
                    ),
                ),
                requirements_sha256=_required_digest(
                    raw_dependency.get("requirements_sha256"),
                    "dependency_export.requirements_sha256",
                ),
            )

        raw_images = raw.get("images")
        if not isinstance(raw_images, list):
            raise ValueError("images must be an array")
        images: list[ImageEvidence] = []
        for index, raw_image in enumerate(raw_images):
            if not isinstance(raw_image, dict):
                raise ValueError(f"images[{index}] must be an object")
            field = f"images[{index}]"
            images.append(
                ImageEvidence(
                    name=_required_string(raw_image.get("name"), f"{field}.name"),
                    tag=_required_string(raw_image.get("tag"), f"{field}.tag"),
                    image_id=_required_digest(
                        raw_image.get("image_id"), f"{field}.image_id"
                    ),
                    archive=_evidence_path(
                        repository_root,
                        _required_string(
                            raw_image.get("archive"), f"{field}.archive"
                        ),
                    ),
                    archive_sha256=_required_digest(
                        raw_image.get("archive_sha256"),
                        f"{field}.archive_sha256",
                    ),
                    filesystem=_evidence_path(
                        repository_root,
                        _required_string(
                            raw_image.get("filesystem"), f"{field}.filesystem"
                        ),
                    ),
                    filesystem_sha256=_required_digest(
                        raw_image.get("filesystem_sha256"),
                        f"{field}.filesystem_sha256",
                    ),
                    filesystem_image_id=_required_digest(
                        raw_image.get("filesystem_image_id"),
                        f"{field}.filesystem_image_id",
                    ),
                )
            )
        return QualificationEvidence(dependency, tuple(images)), []
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        return None, [
            Violation(
                "EVIDENCE_MANIFEST_INVALID",
                str(evidence_manifest),
                0,
                str(error),
            )
        ]


def _verify_file_digest(path: Path, expected: str) -> list[Violation]:
    if not path.is_file():
        return [
            Violation(
                "EVIDENCE_FILE_MISSING",
                str(path),
                0,
                "evidence file does not exist",
            )
        ]
    try:
        actual = _sha256_file(path)
    except OSError as error:
        return [Violation("EVIDENCE_FILE_READ_ERROR", str(path), 0, str(error))]
    if actual != expected:
        return [
            Violation(
                "EVIDENCE_FILE_DIGEST_MISMATCH",
                str(path),
                0,
                f"expected {expected}, calculated {actual}",
            )
        ]
    return []


def verify_dependency_evidence(
    evidence: DependencyEvidence | None, repository_root: Path
) -> tuple[bool, list[Violation]]:
    if evidence is None:
        return False, [
            Violation(
                "DEPENDENCY_EVIDENCE_MISSING",
                "dependency_export",
                0,
                "qualification requires a verified backend-only uv export",
            )
        ]
    violations: list[Violation] = []
    if evidence.command != DEPENDENCY_EVIDENCE_COMMAND:
        violations.append(
            Violation(
                "DEPENDENCY_EVIDENCE_COMMAND",
                "dependency_export.command",
                0,
                "declared command must exactly match the canonical backend-only "
                "uv export argv",
            )
        )
    expected_lockfile = (repository_root / "uv.lock").resolve()
    expected_requirements = (
        repository_root / "backend" / "requirements" / "default.txt"
    ).resolve()
    if evidence.lockfile.resolve() != expected_lockfile:
        violations.append(
            Violation(
                "DEPENDENCY_EVIDENCE_PATH",
                str(evidence.lockfile),
                0,
                "dependency evidence must bind the repository uv.lock",
            )
        )
    if evidence.requirements.resolve() != expected_requirements:
        violations.append(
            Violation(
                "DEPENDENCY_EVIDENCE_PATH",
                str(evidence.requirements),
                0,
                "dependency evidence must bind backend/requirements/default.txt",
            )
        )
    violations.extend(
        _verify_file_digest(evidence.lockfile, evidence.lockfile_sha256)
    )
    violations.extend(
        _verify_file_digest(evidence.requirements, evidence.requirements_sha256)
    )
    if violations:
        return False, violations

    try:
        version_result = subprocess.run(
            ["uv", "--version"],
            cwd=repository_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        version_output = version_result.stdout.decode("utf-8").strip()
    except subprocess.CalledProcessError as error:
        return False, [
            Violation(
                "DEPENDENCY_UV_EXECUTION",
                "uv --version",
                0,
                _command_failure_message(error),
            )
        ]
    except (OSError, UnicodeError) as error:
        return False, [
            Violation("DEPENDENCY_UV_EXECUTION", "uv --version", 0, str(error))
        ]
    if re.fullmatch(
        rf"uv {re.escape(QUALIFICATION_UV_VERSION)}(?:\s+.*)?", version_output
    ) is None:
        return False, [
            Violation(
                "DEPENDENCY_UV_VERSION",
                "uv --version",
                0,
                f"expected uv {QUALIFICATION_UV_VERSION}, got {version_output!r}",
            )
        ]

    try:
        with tempfile.TemporaryDirectory(prefix="pmorg-uv-export-") as temporary:
            generated_path = Path(temporary) / "default.txt"
            command = [*DEPENDENCY_EVIDENCE_COMMAND[:-1], str(generated_path)]
            subprocess.run(
                command,
                cwd=repository_root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            generated = generated_path.read_bytes()
            tracked = expected_requirements.read_bytes()
    except subprocess.CalledProcessError as error:
        return False, [
            Violation(
                "DEPENDENCY_EXPORT_EXECUTION",
                "uv export",
                0,
                _command_failure_message(error),
            )
        ]
    except (OSError, ValueError) as error:
        return False, [
            Violation("DEPENDENCY_EXPORT_EXECUTION", "uv export", 0, str(error))
        ]

    if generated != tracked:
        return False, [
            Violation(
                "DEPENDENCY_EXPORT_DRIFT",
                str(expected_requirements),
                0,
                "pinned uv export differs byte-for-byte from tracked requirements",
            )
        ]
    return True, []
