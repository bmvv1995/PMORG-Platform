"""Derive deterministic backend and web contexts from a PMORG CE source tar."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import cast
from typing import Sequence

from pmorg.build.artifact import _canonical_json
from pmorg.build.artifact import _parse_json_object
from pmorg.build.artifact import _read_json_object
from pmorg.build.artifact import _tar_info
from pmorg.build.artifact import _unsafe_symlink
from pmorg.build.artifact import MANIFEST_NAME

CONTEXT_SPEC_PATH = Path(__file__).with_name("ce-image-contexts.json")
CONTEXT_MANIFEST_NAME = "PMORG-CONTEXT.json"


@dataclass(frozen=True)
class SourceFile:
    mode: int
    path: str
    data: bytes
    is_symlink: bool = False


@dataclass(frozen=True)
class ContextResult:
    name: str
    path: Path
    sha256: str
    size: int
    file_count: int


def validate_context_spec(spec: dict[str, object]) -> None:
    expected = {
        "schema_version": "pmorg.ce-image-contexts/v1",
        "source_artifact_schema": "pmorg.ce-source-artifact/v1",
        "source_date_epoch": 0,
    }
    for key, value in expected.items():
        if spec.get(key) != value:
            raise ValueError(f"{key} must equal {value!r}")
    raw_contexts = spec.get("contexts")
    if not isinstance(raw_contexts, list) or len(raw_contexts) != 2:
        raise ValueError("contexts must contain exactly backend and web")
    names: list[str] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            raise ValueError("every context must be an object")
        context = cast(dict[str, object], raw_context)
        name = context.get("name")
        prefix = context.get("source_prefix")
        required = context.get("required_paths")
        if name not in {"backend", "web"} or prefix != f"{name}/":
            raise ValueError("context name and source prefix drifted")
        if (
            not isinstance(required, list)
            or not required
            or not all(isinstance(path, str) for path in required)
            or required != sorted(required)
            or len(required) != len(set(required))
        ):
            raise ValueError(f"required_paths must be unique and sorted for {name}")
        names.append(cast(str, name))
    if names != ["backend", "web"]:
        raise ValueError("contexts must be ordered backend then web")


def _safe_path(path: str) -> bool:
    value = PurePosixPath(path)
    return bool(path) and not value.is_absolute() and ".." not in value.parts


def read_source_artifact(
    path: Path,
) -> tuple[dict[str, object], tuple[SourceFile, ...]]:
    with tarfile.open(path, mode="r:") as archive:
        members = archive.getmembers()
        if not members or members[0].name != MANIFEST_NAME:
            raise ValueError("source artifact manifest must be first")
        manifest_file = archive.extractfile(members[0])
        if manifest_file is None:
            raise ValueError("source artifact manifest is not a regular file")
        manifest_value = json.load(manifest_file)
        if not isinstance(manifest_value, dict):
            raise ValueError("source artifact manifest must be an object")
        manifest = cast(dict[str, object], manifest_value)
        raw_files = manifest.get("files")
        if not isinstance(raw_files, list):
            raise ValueError("source artifact file manifest must be an array")
        expected: dict[str, dict[str, object]] = {}
        for raw_file in raw_files:
            if not isinstance(raw_file, dict):
                raise ValueError("source artifact file record must be an object")
            record = cast(dict[str, object], raw_file)
            record_path = record.get("path")
            if not isinstance(record_path, str) or not _safe_path(record_path):
                raise ValueError("source artifact contains an unsafe path")
            if record_path in expected:
                raise ValueError("source artifact contains a duplicate path")
            expected[record_path] = record
        files: list[SourceFile] = []
        seen: set[str] = set()
        for member in members[1:]:
            if not _safe_path(member.name) or member.name not in expected:
                raise ValueError("source artifact tar and manifest paths differ")
            if member.issym():
                if _unsafe_symlink(member.name, member.linkname):
                    raise ValueError(
                        f"source artifact has unsafe symlink {member.name}"
                    )
                data = member.linkname.encode("utf-8")
            elif member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError("source artifact member could not be read")
                data = extracted.read()
            else:
                raise ValueError(
                    "image contexts admit regular files and safe symlinks only"
                )
            record = expected[member.name]
            if record.get("sha256") != hashlib.sha256(data).hexdigest():
                raise ValueError(f"source artifact digest drifted for {member.name}")
            if record.get("size") != len(data):
                raise ValueError(f"source artifact size drifted for {member.name}")
            files.append(SourceFile(member.mode, member.name, data, member.issym()))
            seen.add(member.name)
        if seen != set(expected):
            raise ValueError("source artifact manifest has missing tar members")
    return manifest, tuple(files)


def _context_manifest(
    name: str,
    source_sha256: str,
    source_manifest: dict[str, object],
    files: Sequence[SourceFile],
) -> bytes:
    return _canonical_json(
        {
            "schema_version": "pmorg.ce-image-context/v1",
            "name": name,
            "source_artifact_sha256": source_sha256,
            "source_commit": source_manifest.get("source_commit"),
            "files": [
                {
                    "mode": file.mode,
                    "path": file.path,
                    "sha256": hashlib.sha256(file.data).hexdigest(),
                    "size": len(file.data),
                    "type": "symlink" if file.is_symlink else "file",
                }
                for file in files
            ],
        }
    )


def build_contexts(
    source_artifact: Path,
    output_directory: Path,
    *,
    spec_path: Path | None = None,
) -> tuple[ContextResult, ...]:
    source_manifest, source_files = read_source_artifact(source_artifact)
    if spec_path is None:
        committed_spec = next(
            (
                file.data
                for file in source_files
                if file.path == "pmorg/build/ce-image-contexts.json"
            ),
            None,
        )
        if committed_spec is None:
            raise ValueError("source artifact is missing the image-context spec")
        spec = _parse_json_object(committed_spec, "committed image-context spec")
    else:
        spec = _read_json_object(spec_path)
    validate_context_spec(spec)
    if source_manifest.get("schema_version") != spec["source_artifact_schema"]:
        raise ValueError("source artifact schema drifted")
    source_sha256 = hashlib.sha256(source_artifact.read_bytes()).hexdigest()
    source_date_epoch = cast(int, spec["source_date_epoch"])
    output_directory.mkdir(parents=True, exist_ok=True)
    results: list[ContextResult] = []
    for raw_context in cast(list[dict[str, object]], spec["contexts"]):
        name = cast(str, raw_context["name"])
        prefix = cast(str, raw_context["source_prefix"])
        files = tuple(
            sorted(
                (
                    SourceFile(
                        file.mode,
                        file.path.removeprefix(prefix),
                        file.data,
                        file.is_symlink,
                    )
                    for file in source_files
                    if file.path.startswith(prefix)
                ),
                key=lambda file: file.path.encode("utf-8"),
            )
        )
        paths = {file.path for file in files}
        missing = set(cast(list[str], raw_context["required_paths"])) - paths
        if missing:
            raise ValueError(
                f"{name} context is missing required paths: {sorted(missing)}"
            )
        if not files:
            raise ValueError(f"{name} context is empty")
        manifest = _context_manifest(name, source_sha256, source_manifest, files)
        output_path = output_directory / f"{name}-context.tar"
        with output_path.open("wb") as output_file:
            with tarfile.open(
                fileobj=output_file, mode="w", format=tarfile.GNU_FORMAT
            ) as archive:
                archive.addfile(
                    _tar_info(
                        CONTEXT_MANIFEST_NAME,
                        len(manifest),
                        0o644,
                        source_date_epoch,
                    ),
                    io.BytesIO(manifest),
                )
                for file in files:
                    if file.is_symlink:
                        target = file.data.decode("utf-8")
                        if _unsafe_symlink(file.path, target):
                            raise ValueError(
                                f"context {name} has unsafe symlink {file.path}"
                            )
                        info = _tar_info(file.path, 0, 0o777, source_date_epoch)
                        info.type = tarfile.SYMTYPE
                        info.linkname = target
                        archive.addfile(info)
                    else:
                        archive.addfile(
                            _tar_info(
                                file.path,
                                len(file.data),
                                file.mode,
                                source_date_epoch,
                            ),
                            io.BytesIO(file.data),
                        )
        output = output_path.read_bytes()
        results.append(
            ContextResult(
                name=name,
                path=output_path,
                sha256=hashlib.sha256(output).hexdigest(),
                size=len(output),
                file_count=len(files),
            )
        )
    return tuple(results)
