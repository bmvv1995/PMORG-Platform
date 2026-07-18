"""Inspection of exported filesystems and source bytes inside artifacts."""

from __future__ import annotations

import tarfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Sequence

from .models import MAX_ARCHIVE_SOURCE_BYTES
from .models import PYTHON_SUFFIXES
from .models import SOURCE_SUFFIXES
from .models import Violation
from .models import _MutableStats
from .models import _normalize_path
from .source import _scan_python_imports
from .source import _scan_typescript_imports

def _artifact_path_targets_ee(path: str) -> bool:
    components = [
        component for component in _normalize_path(path).split("/") if component
    ]
    return "ee" in components


def _artifact_source_size_violation(member_path: str) -> Violation:
    return Violation(
        "ARTIFACT_SOURCE_TOO_LARGE",
        member_path,
        0,
        "source exceeds the qualification scan limit of "
        f"{MAX_ARCHIVE_SOURCE_BYTES} bytes",
    )


def _scan_archive_source_bytes(
    data: bytes,
    member_path: str,
    denied_prefixes: Sequence[str],
) -> list[Violation]:
    suffix = PurePosixPath(member_path).suffix.lower()
    if suffix not in SOURCE_SUFFIXES:
        return []
    if len(data) > MAX_ARCHIVE_SOURCE_BYTES:
        return [_artifact_source_size_violation(member_path)]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [
            Violation(
                "ARTIFACT_SOURCE_DECODE_ERROR",
                member_path,
                0,
                f"source is not valid UTF-8: {error}",
            )
        ]
    if suffix in PYTHON_SUFFIXES:
        return _scan_python_imports(text, member_path)[1]
    return _scan_typescript_imports(
        text,
        member_path,
        None,
        None,
        denied_prefixes,
    )[1]


def _scan_tar_members(
    archive: tarfile.TarFile,
    display_prefix: str,
    denied_prefixes: Sequence[str],
    stats: _MutableStats,
) -> list[Violation]:
    violations: list[Violation] = []
    for member in archive:
        stats.artifact_entries += 1
        member_path = _normalize_path(member.name)
        display_path = f"{display_prefix}!{member_path}"
        if _artifact_path_targets_ee(member_path):
            violations.append(
                Violation(
                    "ARTIFACT_EE_PATH",
                    display_path,
                    0,
                    "artifact entry contains a forbidden EE path component",
                )
            )
        if (
            not member.isfile()
            or PurePosixPath(member_path).suffix.lower() not in SOURCE_SUFFIXES
        ):
            continue
        if member.size > MAX_ARCHIVE_SOURCE_BYTES:
            violations.append(_artifact_source_size_violation(display_path))
            continue
        extracted = archive.extractfile(member)
        if extracted is None:
            violations.append(
                Violation(
                    "ARTIFACT_READ_ERROR",
                    display_path,
                    0,
                    "source member cannot be read",
                )
            )
            continue
        data = extracted.read(MAX_ARCHIVE_SOURCE_BYTES + 1)
        violations.extend(
            _scan_archive_source_bytes(data, display_path, denied_prefixes)
        )
    return violations
def scan_filesystem_path(
    filesystem_path: Path,
    denied_prefixes: Sequence[str],
    stats: _MutableStats,
) -> list[Violation]:
    if not filesystem_path.exists():
        return [
            Violation(
                "ARTIFACT_INPUT_MISSING",
                str(filesystem_path),
                0,
                "filesystem path or tar archive does not exist",
            )
        ]
    if filesystem_path.is_file():
        try:
            with tarfile.open(filesystem_path, mode="r:*") as archive:
                return _scan_tar_members(
                    archive, str(filesystem_path), denied_prefixes, stats
                )
        except (tarfile.TarError, OSError) as error:
            return [
                Violation(
                    "ARTIFACT_ARCHIVE_INVALID",
                    str(filesystem_path),
                    0,
                    str(error),
                )
            ]

    violations: list[Violation] = []
    for candidate in filesystem_path.rglob("*"):
        stats.artifact_entries += 1
        relative_path = candidate.relative_to(filesystem_path).as_posix()
        display_path = f"{filesystem_path}!{relative_path}"
        if _artifact_path_targets_ee(relative_path):
            violations.append(
                Violation(
                    "ARTIFACT_EE_PATH",
                    display_path,
                    0,
                    "artifact entry contains a forbidden EE path component",
                )
            )
        if not candidate.is_file() or candidate.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            if candidate.stat().st_size > MAX_ARCHIVE_SOURCE_BYTES:
                violations.append(_artifact_source_size_violation(display_path))
                continue
        except OSError as error:
            violations.append(
                Violation("ARTIFACT_READ_ERROR", display_path, 0, str(error))
            )
            continue
        try:
            data = candidate.read_bytes()
        except OSError as error:
            violations.append(
                Violation(
                    "ARTIFACT_READ_ERROR", display_path, 0, str(error)
                )
            )
            continue
        violations.extend(
            _scan_archive_source_bytes(data, display_path, denied_prefixes)
        )
    return violations
