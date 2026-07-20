"""Build and verify the deterministic PMORG CE source artifact."""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import cast
from typing import Iterable
from typing import Sequence

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = Path(__file__).with_name("ce-artifact-spec.json")
EGRESS_PATH = Path(__file__).with_name("ce-build-egress.json")
MANIFEST_NAME = "PMORG-MANIFEST.json"
SOURCE_SUFFIXES = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
NETWORK_MODULES = {
    "aiohttp",
    "ftplib",
    "http",
    "requests",
    "socket",
    "urllib",
    "websockets",
}
ALLOWED_GIT_SUBCOMMANDS = {"cat-file", "ls-tree", "rev-parse"}


@dataclass(frozen=True, order=True)
class Violation:
    rule: str
    path: str
    message: str

    def render(self) -> str:
        return f"{self.rule} {self.path}: {self.message}"


@dataclass(frozen=True)
class GitEntry:
    mode: str
    object_id: str
    path: str
    data: bytes


@dataclass(frozen=True)
class BuildResult:
    commit: str
    artifact_path: Path
    artifact_sha256: str
    artifact_size: int
    file_count: int
    manifest_sha256: str


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _read_json_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _run_git(repository_root: Path, *arguments: str, text: bool = False) -> bytes | str:
    if not arguments or arguments[0] not in ALLOWED_GIT_SUBCOMMANDS:
        raise ValueError("builder attempted a non-allowlisted git operation")
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=text,
    )
    return completed.stdout.strip() if text else completed.stdout


def _read_git_blobs(
    repository_root: Path, object_ids: Sequence[str]
) -> dict[str, bytes]:
    unique_ids = tuple(dict.fromkeys(object_ids))
    completed = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=repository_root,
        check=True,
        input="".join(f"{object_id}\n" for object_id in unique_ids).encode("ascii"),
        capture_output=True,
    )
    stream = io.BytesIO(completed.stdout)
    blobs: dict[str, bytes] = {}
    for expected_id in unique_ids:
        header = stream.readline().decode("ascii").strip().split(" ")
        if len(header) != 3 or header[0] != expected_id or header[1] != "blob":
            raise ValueError(f"unexpected git cat-file response for {expected_id}")
        size = int(header[2])
        blobs[expected_id] = stream.read(size)
        if stream.read(1) != b"\n":
            raise ValueError("git cat-file batch response is malformed")
    if stream.read():
        raise ValueError("git cat-file batch response has trailing bytes")
    return blobs


def resolve_commit(repository_root: Path, revision: str) -> str:
    result = _run_git(
        repository_root, "rev-parse", "--verify", f"{revision}^{{commit}}", text=True
    )
    assert isinstance(result, str)
    if not re.fullmatch(r"[0-9a-f]{40}", result):
        raise ValueError("revision did not resolve to a full commit SHA")
    return result


def _matches(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) for item in value)
    ):
        raise ValueError(f"{label} must be a non-empty string array")
    return tuple(cast(str, item) for item in value)


def _all_tree_entries(
    repository_root: Path, commit: str
) -> tuple[tuple[str, str, str], ...]:
    raw = _run_git(repository_root, "ls-tree", "-r", "-z", "--full-tree", commit)
    assert isinstance(raw, bytes)
    entries: list[tuple[str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        if object_type != "blob":
            raise ValueError(f"unsupported Git object type {object_type!r}")
        path = raw_path.decode("utf-8")
        entries.append((mode, object_id, path))
    return tuple(entries)


def selected_entries(
    repository_root: Path,
    commit: str,
    spec: dict[str, object],
) -> tuple[GitEntry, ...]:
    includes = _string_list(spec.get("include_patterns"), "include_patterns")
    excludes = _string_list(spec.get("exclude_patterns"), "exclude_patterns")
    selected_metadata: list[tuple[str, str, str]] = []
    for mode, object_id, path in _all_tree_entries(repository_root, commit):
        if not _matches(path, includes) or _matches(path, excludes):
            continue
        selected_metadata.append((mode, object_id, path))
    if not selected_metadata:
        raise ValueError("CE artifact selection is empty")
    blobs = _read_git_blobs(repository_root, [item[1] for item in selected_metadata])
    selected = [
        GitEntry(mode=mode, object_id=object_id, path=path, data=blobs[object_id])
        for mode, object_id, path in selected_metadata
    ]
    return tuple(sorted(selected, key=lambda entry: entry.path.encode("utf-8")))


def _manifest(
    commit: str, entries: Sequence[GitEntry], spec: dict[str, object]
) -> bytes:
    files = [
        {
            "mode": entry.mode,
            "path": entry.path,
            "sha256": hashlib.sha256(entry.data).hexdigest(),
            "size": len(entry.data),
        }
        for entry in entries
    ]
    value = {
        "schema_version": spec["schema_version"],
        "artifact_name": spec["artifact_name"],
        "media_type": spec["media_type"],
        "onyx_surface": spec["onyx_surface"],
        "usage_mode": spec["usage_mode"],
        "source_commit": commit,
        "files": files,
    }
    return _canonical_json(value)


def _tar_info(
    path: str, size: int, mode: int, source_date_epoch: int
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.size = size
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = source_date_epoch
    return info


def build_artifact(
    repository_root: Path,
    output_path: Path,
    *,
    revision: str = "HEAD",
    spec_path: Path = SPEC_PATH,
) -> BuildResult:
    spec = _read_json_object(spec_path)
    validate_spec(spec, repository_root)
    commit = resolve_commit(repository_root, revision)
    entries = selected_entries(repository_root, commit, spec)
    violations = scan_entries_for_ee(entries, repository_root, commit, spec)
    if violations:
        raise ValueError(
            "CE source selection rejected:\n"
            + "\n".join(item.render() for item in violations)
        )

    source_date_epoch = spec.get("source_date_epoch")
    if not isinstance(source_date_epoch, int) or source_date_epoch < 0:
        raise ValueError("source_date_epoch must be a non-negative integer")
    manifest = _manifest(commit, entries, spec)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as output_file:
        with tarfile.open(
            fileobj=output_file, mode="w", format=tarfile.GNU_FORMAT
        ) as archive:
            manifest_info = _tar_info(
                MANIFEST_NAME, len(manifest), 0o644, source_date_epoch
            )
            archive.addfile(manifest_info, io.BytesIO(manifest))
            for entry in entries:
                if entry.mode == "120000":
                    info = _tar_info(entry.path, 0, 0o777, source_date_epoch)
                    info.type = tarfile.SYMTYPE
                    info.linkname = entry.data.decode("utf-8")
                    archive.addfile(info)
                    continue
                file_mode = 0o755 if entry.mode == "100755" else 0o644
                info = _tar_info(
                    entry.path, len(entry.data), file_mode, source_date_epoch
                )
                archive.addfile(info, io.BytesIO(entry.data))

    artifact_bytes = output_path.read_bytes()
    return BuildResult(
        commit=commit,
        artifact_path=output_path,
        artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
        artifact_size=len(artifact_bytes),
        file_count=len(entries),
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
    )


def validate_spec(spec: dict[str, object], repository_root: Path) -> None:
    expected_scalars = {
        "schema_version": "pmorg.ce-source-artifact/v1",
        "onyx_surface": "ce",
        "usage_mode": "development_test",
        "source_date_epoch": 0,
    }
    for key, expected in expected_scalars.items():
        if spec.get(key) != expected:
            raise ValueError(f"{key} must equal {expected!r}")
    for key in (
        "include_patterns",
        "exclude_patterns",
        "forbidden_source_prefixes",
        "upstream_ee_reference_prefixes",
    ):
        _string_list(spec.get(key), key)
    for required_prefix in ("backend/ee", "web/src/app/ee", "web/src/ee"):
        if required_prefix not in _string_list(
            spec["forbidden_source_prefixes"], "forbidden_source_prefixes"
        ):
            raise ValueError(f"missing forbidden source prefix {required_prefix}")
    egress_ref = spec.get("egress_inventory")
    if egress_ref != "pmorg/build/ce-build-egress.json":
        raise ValueError("egress inventory reference drifted")
    if not (repository_root / str(egress_ref)).is_file():
        raise ValueError("egress inventory is missing")


def _path_is_under(path: str, prefix: str) -> bool:
    normalized = PurePosixPath(path)
    parent = PurePosixPath(prefix)
    return normalized == parent or parent in normalized.parents


def _unsafe_symlink(path: str, target: str) -> bool:
    if target.startswith("/"):
        return True
    resolved = PurePosixPath(path).parent.joinpath(target)
    depth = 0
    for part in resolved.parts:
        if part == "..":
            depth -= 1
        elif part not in ("", "."):
            depth += 1
        if depth < 0:
            return True
    return False


def _ee_imports(path: str, data: bytes) -> tuple[str, ...]:
    if PurePosixPath(path).suffix not in SOURCE_SUFFIXES:
        return ()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ("source is not UTF-8",)
    findings: set[str] = set()
    if path.endswith((".py", ".pyi")):
        try:
            tree = ast.parse(text, filename=path)
        except SyntaxError as error:
            return (f"Python parse failure: {error.msg}",)
        for node in ast.walk(tree):
            modules: Iterable[str] = ()
            if isinstance(node, ast.Import):
                modules = (alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules = (node.module or "",)
            for module in modules:
                if "ee" in PurePosixPath(module.replace(".", "/")).parts:
                    findings.add(f"Enterprise import {module!r}")
    else:
        pattern = re.compile(
            r"(?:from\s+|import\s*\(|require\s*\()\s*['\"]([^'\"]+)['\"]"
        )
        for module in pattern.findall(text):
            if "ee" in PurePosixPath(module.replace("@/", "")).parts:
                findings.add(f"Enterprise import {module!r}")
    return tuple(sorted(findings))


def _ee_reference_hashes(
    repository_root: Path,
    commit: str,
    prefixes: Sequence[str],
) -> set[str]:
    object_ids = [
        object_id
        for _mode, object_id, path in _all_tree_entries(repository_root, commit)
        if any(_path_is_under(path, prefix) for prefix in prefixes)
    ]
    blobs = _read_git_blobs(repository_root, object_ids)
    hashes: set[str] = set()
    for data in blobs.values():
        if data.strip():
            hashes.add(hashlib.sha256(data).hexdigest())
    return hashes


def scan_entries_for_ee(
    entries: Sequence[GitEntry],
    repository_root: Path,
    commit: str,
    spec: dict[str, object],
) -> tuple[Violation, ...]:
    forbidden = _string_list(
        spec["forbidden_source_prefixes"], "forbidden_source_prefixes"
    )
    ee_hashes = _ee_reference_hashes(
        repository_root,
        commit,
        _string_list(
            spec["upstream_ee_reference_prefixes"], "upstream_ee_reference_prefixes"
        ),
    )
    ownership_patterns = _ownership_patterns(repository_root, spec)
    violations: list[Violation] = []
    for entry in entries:
        if any(_path_is_under(entry.path, prefix) for prefix in forbidden):
            violations.append(
                Violation("EE_PATH", entry.path, "forbidden Enterprise path selected")
            )
        if entry.mode == "120000":
            target = entry.data.decode("utf-8", errors="replace")
            if _unsafe_symlink(entry.path, target):
                violations.append(
                    Violation("UNSAFE_SYMLINK", entry.path, f"unsafe target {target!r}")
                )
            continue
        if (
            _matches(entry.path, ownership_patterns)
            and entry.data.strip()
            and hashlib.sha256(entry.data).hexdigest() in ee_hashes
        ):
            violations.append(
                Violation(
                    "EE_COPY",
                    entry.path,
                    "bytes exactly match pinned upstream EE source",
                )
            )
        for finding in _ee_imports(entry.path, entry.data):
            violations.append(Violation("EE_IMPORT", entry.path, finding))
    return tuple(sorted(set(violations)))


def _ownership_patterns(
    repository_root: Path, spec: dict[str, object]
) -> tuple[str, ...]:
    policy_ref = spec.get("pmorg_ownership_policy")
    if not isinstance(policy_ref, str):
        raise ValueError("pmorg_ownership_policy must be a string")
    policy = _read_json_object(repository_root / policy_ref)
    roots = policy.get("roots")
    if not isinstance(roots, list):
        raise ValueError("ownership roots must be an array")
    patterns: list[str] = []
    for root_value in roots:
        if not isinstance(root_value, dict):
            raise ValueError("every ownership root must be an object")
        root = cast(dict[str, object], root_value)
        if root.get("ownership") != "pmorg_owned":
            raise ValueError("every declared ownership root must be PMORG-owned")
        pattern = root.get("path_pattern")
        if not isinstance(pattern, str):
            raise ValueError("ownership root path_pattern must be a string")
        patterns.append(pattern)
    return tuple(patterns)


def scan_pmorg_worktree(
    repository_root: Path, spec: dict[str, object]
) -> tuple[Violation, ...]:
    commit = resolve_commit(repository_root, "HEAD")
    ee_hashes = _ee_reference_hashes(
        repository_root,
        commit,
        _string_list(
            spec["upstream_ee_reference_prefixes"], "upstream_ee_reference_prefixes"
        ),
    )
    patterns = _ownership_patterns(repository_root, spec)
    violations: list[Violation] = []
    for path in sorted(repository_root.rglob("*")):
        if (
            ".git" in path.parts
            or "__pycache__" in path.parts
            or not (path.is_file() or path.is_symlink())
        ):
            continue
        relative = path.relative_to(repository_root).as_posix()
        if not _matches(relative, patterns):
            continue
        if "ee" in PurePosixPath(relative).parts:
            violations.append(
                Violation(
                    "PMORG_EE_PATH",
                    relative,
                    "PMORG-owned Enterprise path is forbidden",
                )
            )
        if path.is_symlink():
            target = os.readlink(path)
            if _unsafe_symlink(relative, target):
                violations.append(
                    Violation("UNSAFE_SYMLINK", relative, f"unsafe target {target!r}")
                )
            continue
        data = path.read_bytes()
        if data.strip() and hashlib.sha256(data).hexdigest() in ee_hashes:
            violations.append(
                Violation(
                    "PMORG_EE_COPY",
                    relative,
                    "bytes exactly match pinned upstream EE source",
                )
            )
        for finding in _ee_imports(relative, data):
            violations.append(Violation("PMORG_EE_IMPORT", relative, finding))
    return tuple(sorted(set(violations)))


def verify_egress(
    repository_root: Path, egress_path: Path = EGRESS_PATH
) -> tuple[Violation, ...]:
    inventory = _read_json_object(egress_path)
    violations: list[Violation] = []
    if inventory.get("schema_version") != "pmorg.build-egress-inventory/v1":
        violations.append(
            Violation("EGRESS_SCHEMA", str(egress_path), "unexpected schema version")
        )
    if (
        inventory.get("network_access") is not False
        or inventory.get("destinations") != []
    ):
        violations.append(
            Violation(
                "EGRESS_NETWORK",
                str(egress_path),
                "offline stage must declare zero destinations",
            )
        )
    processes = inventory.get("local_processes")
    expected_processes = [
        {
            "executable": "git",
            "allowed_subcommands": sorted(ALLOWED_GIT_SUBCOMMANDS),
            "network_capable_invocations": False,
        }
    ]
    normalized_processes = processes
    if isinstance(processes, list):
        normalized_processes = []
        for process in processes:
            if isinstance(process, dict):
                normalized = dict(process)
                commands = normalized.get("allowed_subcommands")
                if isinstance(commands, list):
                    normalized["allowed_subcommands"] = sorted(commands)
                normalized_processes.append(normalized)
    if normalized_processes != expected_processes:
        violations.append(
            Violation(
                "EGRESS_PROCESS", str(egress_path), "local process allowlist drifted"
            )
        )

    source_path = repository_root / "pmorg/build/artifact.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    for node in ast.walk(tree):
        modules: Iterable[str] = ()
        if isinstance(node, ast.Import):
            modules = (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules = (node.module or "",)
        for module in modules:
            if module.split(".", 1)[0] in NETWORK_MODULES:
                violations.append(
                    Violation(
                        "UNDECLARED_EGRESS",
                        str(source_path),
                        f"network module import {module!r}",
                    )
                )
    return tuple(sorted(set(violations)))
