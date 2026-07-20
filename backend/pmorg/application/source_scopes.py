"""Derive byte-closed Onyx CE and EE source-scope denominators."""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import SourceScopeManifest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_SCOPE_ROOT = REPOSITORY_ROOT / "pmorg" / "capabilities" / "source-scopes"
POLICY_PATH = REPOSITORY_ROOT / "pmorg" / "capabilities" / "source-scope-policy.json"
GENERATOR_PATH = Path(__file__)
SCHEMA_VERSION = "pmorg.source-scope-manifest/v1"

_POLICY_KEYS = {
    "schema_version",
    "repository",
    "onyx_commit",
    "enterprise_license_paths",
    "inventory_fields",
    "scopes",
}
_SCOPE_KEYS = {"selection", "roots"}
_SCOPE_KINDS = ("onyx_ce", "onyx_ee")
_INVENTORY_FIELDS = ("path", "mode", "git_object_id", "sha256", "size_bytes")
_OUTPUT_PATHS = {
    "onyx_ce": "pmorg/capabilities/source-scopes/onyx-ce-path-inventory-v1.json",
    "onyx_ee": "pmorg/capabilities/source-scopes/onyx-ee-path-inventory-v1.json",
}
_MANIFEST_PATHS = {
    "onyx_ce": "pmorg/capabilities/source-scopes/onyx-ce-source-scope-v1.json",
    "onyx_ee": "pmorg/capabilities/source-scopes/onyx-ee-source-scope-v1.json",
}
_EVIDENCE_PATH = "pmorg/capabilities/source-scopes/onyx-source-scope-derivation-v1.json"


class SourceScopeError(ValueError):
    """Raised when source-scope derivation is incomplete or has drifted."""


@dataclass(frozen=True)
class GitBlob:
    mode: str
    object_id: str
    path: str
    data: bytes


@dataclass(frozen=True)
class SourceScopeOutputs:
    inventories: Mapping[str, bytes]
    evidence: bytes
    manifests: Mapping[str, bytes]


def canonical_document_bytes(value: Any) -> bytes:
    """Encode a stable JSON evidence document."""

    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_digest(payload: bytes) -> str:
    """Return the canonical PMORG SHA-256 spelling."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _inventory_document_bytes(value: Mapping[str, Any]) -> bytes:
    """Encode large inventories with one canonical entry per reviewable line."""

    entries = value.get("entries")
    if not isinstance(entries, list):
        raise SourceScopeError("source inventory entries must be an array")
    lines = ["{"]
    ordered_keys = sorted(value)
    for key_index, key in enumerate(ordered_keys):
        suffix = "," if key_index < len(ordered_keys) - 1 else ""
        if key != "entries":
            encoded = json.dumps(value[key], ensure_ascii=False, sort_keys=True)
            lines.append(f"  {json.dumps(key)}: {encoded}{suffix}")
            continue
        lines.append('  "entries": [')
        for entry_index, entry in enumerate(entries):
            entry_suffix = "," if entry_index < len(entries) - 1 else ""
            encoded = json.dumps(
                entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            lines.append(f"    {encoded}{entry_suffix}")
        lines.append(f"  ]{suffix}")
    lines.append("}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SourceScopeError(f"JSON repeats key: {key}")
        value[key] = item
    return value


def _read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceScopeError(f"{label} is not readable canonical JSON") from error
    if not isinstance(value, dict):
        raise SourceScopeError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], *, label: str
) -> None:
    if set(value) != expected:
        raise SourceScopeError(
            f"{label} keys are not exact; "
            f"missing={sorted(expected - set(value))}, "
            f"unknown={sorted(set(value) - expected)}"
        )


def _string_list(value: Any, *, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise SourceScopeError(f"{label} must be a non-empty string array")
    strings = cast(list[str], value)
    if strings != sorted(set(strings)):
        raise SourceScopeError(f"{label} must be unique and ordered")
    return strings


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise SourceScopeError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _run_git(repository_root: Path, *arguments: str) -> bytes:
    if not arguments or arguments[0] not in {"cat-file", "ls-tree", "rev-parse"}:
        raise SourceScopeError("source-scope derivation attempted unsafe Git operation")
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SourceScopeError(
            f"Git object read failed: {' '.join(arguments)}"
        ) from error
    return completed.stdout


def _resolve_object(repository_root: Path, revision: str, object_type: str) -> str:
    resolved = (
        _run_git(
            repository_root, "rev-parse", "--verify", f"{revision}^{{{object_type}}}"
        )
        .decode("ascii")
        .strip()
    )
    if len(resolved) != 40 or any(
        character not in "0123456789abcdef" for character in resolved
    ):
        raise SourceScopeError(
            f"{revision} did not resolve to a full Git {object_type}"
        )
    return resolved


def _tree_metadata(
    repository_root: Path, commit: str
) -> tuple[tuple[str, str, str], ...]:
    raw = _run_git(repository_root, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise SourceScopeError(
                "Git tree contains an unreadable path record"
            ) from error
        if object_type != "blob":
            raise SourceScopeError(f"unsupported Git object type {object_type!r}")
        if path in seen:
            raise SourceScopeError(f"Git tree repeats path: {path}")
        seen.add(path)
        entries.append((mode, object_id, path))
    if not entries:
        raise SourceScopeError("pinned Onyx tree contains no blobs")
    ordered = sorted(entries, key=lambda item: item[2].encode("utf-8"))
    if entries != ordered:
        raise SourceScopeError("Git tree enumeration is not byte-ordered")
    return tuple(entries)


def _read_blob_batch(repository_root: Path, object_ids: list[str]) -> dict[str, bytes]:
    completed = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=repository_root,
        check=True,
        input="".join(f"{object_id}\n" for object_id in object_ids).encode("ascii"),
        capture_output=True,
    )
    stream = io.BytesIO(completed.stdout)
    blobs: dict[str, bytes] = {}
    for expected_id in object_ids:
        header = stream.readline().decode("ascii").strip().split(" ")
        if len(header) != 3 or header[0] != expected_id or header[1] != "blob":
            raise SourceScopeError(f"unreadable Git blob: {expected_id}")
        size = int(header[2])
        blobs[expected_id] = stream.read(size)
        if stream.read(1) != b"\n":
            raise SourceScopeError("Git cat-file batch response is malformed")
    if stream.read():
        raise SourceScopeError("Git cat-file batch response has trailing bytes")
    return blobs


def _read_blobs(
    repository_root: Path, metadata: tuple[tuple[str, str, str], ...]
) -> tuple[GitBlob, ...]:
    unique_ids = list(dict.fromkeys(object_id for _, object_id, _ in metadata))
    data_by_id: dict[str, bytes] = {}
    try:
        for start in range(0, len(unique_ids), 256):
            batch = unique_ids[start : start + 256]
            data_by_id.update(_read_blob_batch(repository_root, batch))
    except (
        OSError,
        subprocess.CalledProcessError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        raise SourceScopeError("one or more pinned Git blobs are unreadable") from error
    if set(data_by_id) != set(unique_ids):
        raise SourceScopeError("Git blob read did not cover the complete tree")
    return tuple(
        GitBlob(mode=mode, object_id=object_id, path=path, data=data_by_id[object_id])
        for mode, object_id, path in metadata
    )


def _evidence_ref(
    repository_root: Path,
    relative_path: str,
    payload: bytes,
    *,
    logical_name: str,
) -> EvidenceArtifactRef:
    _safe_path(repository_root, relative_path)
    return EvidenceArtifactRef(
        logical_name=logical_name,
        media_type="application/json"
        if relative_path.endswith(".json")
        else "text/x-python",
        digest=sha256_digest(payload),
        size_bytes=len(payload),
        relative_path=relative_path,
    )


def _load_policy(repository_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    policy = _read_object(
        repository_root / "pmorg/capabilities/source-scope-policy.json",
        label="source-scope policy",
    )
    baseline = _read_object(
        repository_root / "pmorg/baseline-manifest.json", label="PMORG baseline"
    )
    _require_exact_keys(policy, _POLICY_KEYS, label="source-scope policy")
    if policy["schema_version"] != "pmorg.source-scope-derivation-policy/v1":
        raise SourceScopeError("source-scope policy schema identity drifted")
    try:
        baseline_repository = baseline["upstream"]["repository"]
        baseline_commit = baseline["upstream"]["commit"]
        enterprise_paths = baseline["licensing"]["enterprise_license_paths"]
    except (KeyError, TypeError) as error:
        raise SourceScopeError("baseline source-scope pins are incomplete") from error
    if policy["repository"] != baseline_repository:
        raise SourceScopeError("source-scope repository pin drifted from baseline")
    if policy["onyx_commit"] != baseline_commit:
        raise SourceScopeError("source-scope commit pin drifted from baseline")
    patterns = _string_list(
        policy["enterprise_license_paths"], label="enterprise license paths"
    )
    if patterns != enterprise_paths:
        raise SourceScopeError("enterprise license paths drifted from baseline")
    fields = policy["inventory_fields"]
    if not isinstance(fields, list) or tuple(fields) != _INVENTORY_FIELDS:
        raise SourceScopeError("source inventory field set drifted")
    scopes = policy["scopes"]
    if not isinstance(scopes, dict) or set(scopes) != set(_SCOPE_KINDS):
        raise SourceScopeError("source-scope policy must define exact CE and EE scopes")
    expected_selection = {
        "onyx_ce": "all_git_blobs_except_enterprise_license_paths",
        "onyx_ee": "enterprise_license_paths_only",
    }
    for scope_kind in _SCOPE_KINDS:
        raw_scope = scopes[scope_kind]
        if not isinstance(raw_scope, dict):
            raise SourceScopeError(f"{scope_kind} policy must be an object")
        _require_exact_keys(raw_scope, _SCOPE_KEYS, label=f"{scope_kind} policy")
        if raw_scope["selection"] != expected_selection[scope_kind]:
            raise SourceScopeError(f"{scope_kind} selection rule drifted")
        _string_list(raw_scope["roots"], label=f"{scope_kind} roots")
    return policy, baseline


def _is_enterprise(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _inventory(
    *,
    repository: str,
    commit: str,
    git_tree_id: str,
    scope_kind: str,
    roots: list[str],
    blobs: tuple[GitBlob, ...],
) -> bytes:
    entries = [
        {
            "git_object_id": blob.object_id,
            "mode": blob.mode,
            "path": blob.path,
            "sha256": sha256_digest(blob.data),
            "size_bytes": len(blob.data),
        }
        for blob in blobs
    ]
    return _inventory_document_bytes(
        {
            "schema_version": "pmorg.source-path-inventory/v1",
            "repository": repository,
            "commit": commit,
            "git_tree_id": git_tree_id,
            "scope_kind": scope_kind,
            "roots": roots,
            "path_count": len(entries),
            "entries": entries,
        }
    )


def derive_source_scope_outputs(
    repository_root: Path = REPOSITORY_ROOT,
) -> SourceScopeOutputs:
    """Derive CE and EE inventories, evidence, and strict contract manifests."""

    repository_root = repository_root.resolve()
    policy, _ = _load_policy(repository_root)
    commit = cast(str, policy["onyx_commit"])
    repository = cast(str, policy["repository"])
    if _resolve_object(repository_root, commit, "commit") != commit:
        raise SourceScopeError("pinned Onyx commit resolved to another identity")
    git_tree_id = _resolve_object(repository_root, commit, "tree")
    metadata = _tree_metadata(repository_root, commit)
    blobs = _read_blobs(repository_root, metadata)
    patterns = cast(list[str], policy["enterprise_license_paths"])
    ee_blobs = tuple(blob for blob in blobs if _is_enterprise(blob.path, patterns))
    ce_blobs = tuple(blob for blob in blobs if not _is_enterprise(blob.path, patterns))
    if not ce_blobs or not ee_blobs:
        raise SourceScopeError("CE and EE source denominators must both be non-empty")
    all_paths = {blob.path for blob in blobs}
    ce_paths = {blob.path for blob in ce_blobs}
    ee_paths = {blob.path for blob in ee_blobs}
    if ce_paths & ee_paths:
        raise SourceScopeError("CE and EE source denominators overlap")
    if ce_paths | ee_paths != all_paths:
        raise SourceScopeError("source denominator contains unclassified paths")

    scopes = cast(dict[str, dict[str, Any]], policy["scopes"])
    scope_blobs = {"onyx_ce": ce_blobs, "onyx_ee": ee_blobs}
    inventories = {
        scope_kind: _inventory(
            repository=repository,
            commit=commit,
            git_tree_id=git_tree_id,
            scope_kind=scope_kind,
            roots=cast(list[str], scopes[scope_kind]["roots"]),
            blobs=scope_blobs[scope_kind],
        )
        for scope_kind in _SCOPE_KINDS
    }

    policy_relative = "pmorg/capabilities/source-scope-policy.json"
    generator_relative = "backend/pmorg/application/source_scopes.py"
    policy_payload = _safe_path(repository_root, policy_relative).read_bytes()
    generator_payload = _safe_path(repository_root, generator_relative).read_bytes()
    inventory_refs = {
        scope_kind: _evidence_ref(
            repository_root,
            _OUTPUT_PATHS[scope_kind],
            inventories[scope_kind],
            logical_name=f"{scope_kind}-path-inventory",
        )
        for scope_kind in _SCOPE_KINDS
    }
    policy_ref = _evidence_ref(
        repository_root,
        policy_relative,
        policy_payload,
        logical_name="source-scope-derivation-policy",
    )
    generator_ref = _evidence_ref(
        repository_root,
        generator_relative,
        generator_payload,
        logical_name="source-scope-generator",
    )
    evidence = canonical_document_bytes(
        {
            "schema_version": "pmorg.source-scope-derivation-evidence/v1",
            "repository": repository,
            "commit": commit,
            "git_tree_id": git_tree_id,
            "expected_path_count": len(blobs),
            "scanned_path_count": len(blobs),
            "classified_path_count": len(ce_blobs) + len(ee_blobs),
            "ce_path_count": len(ce_blobs),
            "ee_path_count": len(ee_blobs),
            "duplicate_path_count": 0,
            "unreadable_path_count": 0,
            "unclassified_path_count": 0,
            "overlap_path_count": 0,
            "policy": policy_ref.model_dump(mode="json"),
            "generator": generator_ref.model_dump(mode="json"),
            "inventories": [
                inventory_refs[scope_kind].model_dump(mode="json")
                for scope_kind in _SCOPE_KINDS
            ],
        }
    )
    evidence_ref = _evidence_ref(
        repository_root,
        _EVIDENCE_PATH,
        evidence,
        logical_name="onyx-source-scope-derivation-evidence",
    )
    manifests: dict[str, bytes] = {}
    try:
        for scope_kind in _SCOPE_KINDS:
            inventory = inventories[scope_kind]
            manifest = SourceScopeManifest(
                schema_version=SCHEMA_VERSION,
                repository=repository,
                commit=commit,
                scope_kind=scope_kind,
                roots=cast(list[str], scopes[scope_kind]["roots"]),
                tree_hash=sha256_digest(inventory),
                path_inventory=inventory_refs[scope_kind],
                derivation_policy_hash=sha256_digest(policy_payload),
                generator_identity="pmorg.source-scope-generator/v1",
                generator_artifact_digest=sha256_digest(generator_payload),
                derivation_evidence_bundle=evidence_ref,
                expected_path_count=len(scope_blobs[scope_kind]),
                duplicate_path_count=0,
                unreadable_path_count=0,
            )
            manifests[scope_kind] = canonical_document_bytes(
                manifest.model_dump(mode="json")
            )
    except ValidationError as error:
        raise SourceScopeError("derived source-scope manifest is invalid") from error
    return SourceScopeOutputs(
        inventories=inventories, evidence=evidence, manifests=manifests
    )


def _validate_schema(repository_root: Path, manifest_bytes: bytes) -> None:
    contract_root = repository_root / "backend" / "pmorg" / "contracts"
    contract_manifest = _read_object(
        contract_root / "manifest.json", label="contract manifest"
    )
    try:
        entry = next(
            item
            for item in contract_manifest["contracts"]
            if item["schema_version"] == SCHEMA_VERSION
        )
        schema_bytes = (contract_root / entry["schema_path"]).read_bytes()
        schema = json.loads(schema_bytes, object_pairs_hook=_reject_duplicate_keys)
        value = json.loads(manifest_bytes, object_pairs_hook=_reject_duplicate_keys)
    except (KeyError, StopIteration, TypeError, OSError, json.JSONDecodeError) as error:
        raise SourceScopeError("committed source-scope schema is incomplete") from error
    if sha256_digest(schema_bytes) != entry.get("schema_sha256"):
        raise SourceScopeError("committed source-scope schema digest drifted")
    try:
        Draft202012Validator(schema).validate(value)
    except Exception as error:
        raise SourceScopeError(
            "source-scope manifest does not validate against committed schema"
        ) from error


def write_source_scopes(repository_root: Path = REPOSITORY_ROOT) -> None:
    """Write deterministic source-scope evidence artifacts."""

    outputs = derive_source_scope_outputs(repository_root)
    for scope_kind in _SCOPE_KINDS:
        inventory_path = _safe_path(repository_root, _OUTPUT_PATHS[scope_kind])
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        inventory_path.write_bytes(outputs.inventories[scope_kind])
        _safe_path(repository_root, _MANIFEST_PATHS[scope_kind]).write_bytes(
            outputs.manifests[scope_kind]
        )
    _safe_path(repository_root, _EVIDENCE_PATH).write_bytes(outputs.evidence)


def check_source_scopes(repository_root: Path = REPOSITORY_ROOT) -> None:
    """Fail closed when any committed source-scope artifact has drifted."""

    outputs = derive_source_scope_outputs(repository_root)
    expected_by_path = {
        _OUTPUT_PATHS[scope_kind]: outputs.inventories[scope_kind]
        for scope_kind in _SCOPE_KINDS
    }
    expected_by_path.update(
        {
            _MANIFEST_PATHS[scope_kind]: outputs.manifests[scope_kind]
            for scope_kind in _SCOPE_KINDS
        }
    )
    expected_by_path[_EVIDENCE_PATH] = outputs.evidence
    for relative_path, expected in expected_by_path.items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise SourceScopeError(
                f"committed source-scope artifact is missing: {relative_path}"
            ) from error
        if actual != expected:
            raise SourceScopeError(
                f"committed source-scope artifact drifted: {relative_path}"
            )
    for scope_kind in _SCOPE_KINDS:
        _validate_schema(repository_root, outputs.manifests[scope_kind])
