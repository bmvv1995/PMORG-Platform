"""Data models shared by CE evidence generation stages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


EVIDENCE_MANIFEST_NAME = "evidence-manifest.json"


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
