"""Shared constants, path policy helpers, and data models for the CE gate."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

DEFAULT_DENIED_SOURCE_PREFIXES = (
    "backend/ee",
    "web/src/app/ee",
    "web/src/ee",
)
DEFAULT_FORBIDDEN_DEPENDENCY_INPUTS = (
    "backend/requirements/ee.txt",
    "backend/requirements/combined.txt",
)
DEFAULT_DOCKERFILES = (
    "backend/Dockerfile.pmorg-ce",
    "web/Dockerfile.pmorg-ce",
)
SOURCE_SUFFIXES = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
PYTHON_SUFFIXES = {".py", ".pyi"}
TYPESCRIPT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
MAX_ARCHIVE_SOURCE_BYTES = 8 * 1024 * 1024
EVIDENCE_SCHEMA_VERSION = "pmorg.ce-evidence/v1"
REPORT_SCHEMA_VERSION = "pmorg.ce-boundary-report/v3"
QUALIFIED_IMAGE_NAMES = frozenset({"backend", "web"})
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
BASELINE_MANIFEST_PATH = Path("pmorg/baseline-manifest.json")
BASELINE_SCHEMA_VERSION = "pmorg.platform.baseline/v1"
QUALIFICATION_TARGET_PLATFORM = "linux/amd64"
QUALIFICATION_UV_VERSION = "0.11.25"
QUALIFICATION_UV_IMAGE = (
    "ghcr.io/astral-sh/uv:0.11.25@sha256:"
    "1e3808aa9023d0980e7c15b1fa7c1ac16ff35925780cf5c459858b2d693f01a9"
)
DEPENDENCY_EVIDENCE_COMMAND = (
    "uv",
    "export",
    "--locked",
    "--no-emit-project",
    "--no-default-groups",
    "--group",
    "backend",
    "--no-header",
    "--output-file",
    "backend/requirements/default.txt",
)


@dataclass(frozen=True, order=True)
class Violation:
    rule: str
    path: str
    line: int
    message: str

    def render(self) -> str:
        location = self.path if self.line <= 0 else f"{self.path}:{self.line}"
        return f"{self.rule} {location}: {self.message}"


@dataclass(frozen=True)
class ImportEdge:
    source_path: str
    line: int
    specifier: str
    language: str
    resolved_path: str | None = None


@dataclass(frozen=True)
class DockerBuild:
    dockerfile: Path
    context: Path
    dockerignore: Path


@dataclass(frozen=True)
class DependencyEvidence:
    """Version-one evidence fields retained for backwards compatibility.

    ``status`` and ``command`` are claims, not proof. Qualify mode independently
    regenerates the export with its own pinned command before it sets
    ``dependency_evidence_verified``.
    """

    status: str
    command: tuple[str, ...]
    lockfile: Path
    lockfile_sha256: str
    requirements: Path
    requirements_sha256: str


@dataclass(frozen=True)
class ImageEvidence:
    name: str
    tag: str
    image_id: str
    archive: Path
    archive_sha256: str
    filesystem: Path
    filesystem_sha256: str
    filesystem_image_id: str


@dataclass(frozen=True)
class QualificationEvidence:
    dependency_export: DependencyEvidence | None
    images: tuple[ImageEvidence, ...]


@dataclass(frozen=True)
class QualificationIdentity:
    source_repository: str
    source_revision: str
    baseline_manifest_sha256: str
    onyx_version: str
    onyx_upstream_revision: str
    specification_revision: str
    target_platform: str


@dataclass(frozen=True)
class QualifiedImage:
    name: str
    tag: str
    image_id: str
    archive_sha256: str
    filesystem_sha256: str
    layer_count: int
    layer_entries: int
    filesystem_entries: int


@dataclass(frozen=True)
class GateConfig:
    repository_root: Path
    builds: tuple[DockerBuild, ...]
    mode: str = "source"
    source_paths: tuple[Path, ...] = ()
    evidence_manifest: Path | None = None
    denied_source_prefixes: tuple[str, ...] = DEFAULT_DENIED_SOURCE_PREFIXES
    forbidden_dependency_inputs: tuple[str, ...] = (
        DEFAULT_FORBIDDEN_DEPENDENCY_INPUTS
    )


@dataclass(frozen=True)
class GateReport:
    mode: str
    scanned_source_files: int
    inspected_artifact_entries: int
    dependency_evidence_verified: bool
    qualified_images: tuple[QualifiedImage, ...]
    source_revision: str | None
    baseline_manifest_sha256: str | None
    target_platform: str | None
    violations: tuple[Violation, ...]

    @property
    def passed(self) -> bool:
        return not self.violations


@dataclass(frozen=True)
class DockerInstruction:
    name: str
    arguments: str
    line: int


@dataclass(frozen=True)
class DockerIgnoreRule:
    pattern: str
    negated: bool
    line: int
    directory_only: bool


@dataclass
class _MutableStats:
    artifact_entries: int = 0


@dataclass(frozen=True)
class _JavaScriptToken:
    kind: str
    value: str
    line: int


def _normalize_path(value: str) -> str:
    normalized = posixpath.normpath(value.replace("\\", "/"))
    if normalized == ".":
        return ""
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lstrip("/").rstrip("/")


def _is_under(path: str, prefix: str) -> bool:
    normalized_path = _normalize_path(path)
    normalized_prefix = _normalize_path(prefix)
    return normalized_path == normalized_prefix or normalized_path.startswith(
        normalized_prefix + "/"
    )


def _relative_to_root(path: Path, repository_root: Path) -> str | None:
    try:
        return path.resolve().relative_to(repository_root.resolve()).as_posix()
    except ValueError:
        return None


def _is_denied_repository_path(path: str, denied_prefixes: Sequence[str]) -> bool:
    return any(_is_under(path, prefix) for prefix in denied_prefixes)
