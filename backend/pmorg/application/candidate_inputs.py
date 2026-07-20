"""Derive byte-closed, candidate-specific qualification input manifests."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator

from pmorg.application.candidate_search import _candidate_group

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SEARCH_ROOT = "pmorg/capabilities/candidate-search"
OUTPUT_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
SCHEMA_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.schema.json"
DERIVATION_ARTIFACTS = (
    "backend/pmorg/application/candidate_inputs.py",
    "backend/pmorg/application/candidate_search.py",
    "pmorg/scripts/build_candidate_inputs.py",
)

BUNDLE_SCHEMA_VERSION = "pmorg.candidate-input-bundle/v1"
MANIFEST_SCHEMA_VERSION = "pmorg.candidate-input-manifest/v1"
BLOB_SET_SCHEMA_VERSION = "pmorg.candidate-blob-set/v1"
PINNED_SOURCE_COMMIT = "1da679cefc96165c6b9b64c3bc769584b88f88c2"
PINNED_SOURCE_TREE = "7696e9ff17a5ddc9acc0e7e21a1d213925056a58"
PINNED_SOURCE_REPOSITORY = "https://github.com/onyx-dot-app/onyx.git"


class CandidateInputError(ValueError):
    """Raised when a candidate input cannot be derived exactly."""


def canonical_document_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise CandidateInputError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateInputError(f"{label} is not readable JSON") from error
    if not isinstance(value, dict):
        raise CandidateInputError(f"{label} must be an object")
    return value


def _read_path(repository_root: Path, relative_path: str, *, label: str) -> bytes:
    try:
        return _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise CandidateInputError(f"{label} is missing") from error


def _verified_artifact(
    repository_root: Path, ref: dict[str, Any], *, label: str
) -> tuple[dict[str, Any], bytes]:
    relative_path = ref.get("relative_path")
    if not isinstance(relative_path, str) or not relative_path:
        raise CandidateInputError(f"{label} has no relative path")
    payload = _read_path(repository_root, relative_path, label=label)
    if ref.get("digest") != sha256_digest(payload):
        raise CandidateInputError(f"{label} digest drifted")
    if ref.get("size_bytes") != len(payload):
        raise CandidateInputError(f"{label} size drifted")
    return _read_object(payload, label=label), payload


def _artifact_ref(
    relative_path: str,
    payload: bytes,
    *,
    logical_name: str,
    media_type: str = "application/json",
) -> dict[str, Any]:
    return {
        "digest": sha256_digest(payload),
        "logical_name": logical_name,
        "media_type": media_type,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _git(repository_root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository_root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CandidateInputError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def _pinned_tree_entries(repository_root: Path) -> dict[str, tuple[str, str, str]]:
    tree = _git(repository_root, "rev-parse", f"{PINNED_SOURCE_COMMIT}^{{tree}}")
    if tree.decode("ascii").strip() != PINNED_SOURCE_TREE:
        raise CandidateInputError("pinned Onyx source tree identity drifted")
    output = _git(
        repository_root,
        "ls-tree",
        "-rz",
        "--full-tree",
        PINNED_SOURCE_COMMIT,
    )
    entries: dict[str, tuple[str, str, str]] = {}
    for raw_record in output.split(b"\0"):
        if not raw_record:
            continue
        metadata, raw_path = raw_record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        path = raw_path.decode("utf-8")
        if path in entries:
            raise CandidateInputError(f"pinned tree repeats path: {path}")
        entries[path] = (mode, object_type, object_id)
    return entries


def _read_blobs(repository_root: Path, object_ids: list[str]) -> dict[str, bytes]:
    process = subprocess.Popen(
        ["git", "-C", str(repository_root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    blobs: dict[str, bytes] = {}
    for expected_id in object_ids:
        process.stdin.write(expected_id.encode("ascii") + b"\n")
        process.stdin.flush()
        header = process.stdout.readline().decode("ascii").strip().split(" ")
        if len(header) != 3 or header[0] != expected_id or header[1] != "blob":
            raise CandidateInputError(
                f"pinned object is not the expected blob: {expected_id}"
            )
        size = int(header[2])
        payload = process.stdout.read(size)
        if len(payload) != size or process.stdout.read(1) != b"\n":
            raise CandidateInputError(f"pinned blob is truncated: {expected_id}")
        blobs[expected_id] = payload
    process.stdin.close()
    return_code = process.wait()
    assert process.stderr is not None
    detail = process.stderr.read().decode("utf-8", errors="replace").strip()
    process.stdout.close()
    process.stderr.close()
    if return_code:
        raise CandidateInputError(f"git cat-file failed: {detail}")
    return blobs


def candidate_input_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    git_sha = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
    nonempty = {"type": "string", "minLength": 1}
    nonnegative = {"type": "integer", "minimum": 0}
    artifact_ref = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "digest",
            "logical_name",
            "media_type",
            "relative_path",
            "size_bytes",
        ],
        "properties": {
            "digest": digest,
            "logical_name": nonempty,
            "media_type": nonempty,
            "relative_path": nonempty,
            "size_bytes": nonnegative,
        },
    }
    blob = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "git_object_id",
            "mode",
            "path",
            "sha256",
            "size_bytes",
        ],
        "properties": {
            "git_object_id": git_sha,
            "mode": {"type": "string", "pattern": "^[0-9]{6}$"},
            "path": nonempty,
            "sha256": digest,
            "size_bytes": nonnegative,
        },
    }
    manifest = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "manifest_digest",
            "capability_id",
            "candidate_id",
            "candidate_group",
            "source_surface",
            "source_repository",
            "source_commit",
            "source_tree_id",
            "blob_count",
            "blob_set_digest",
            "matched_hit_ids",
            "source_inventory",
            "raw_results",
            "hit_classification",
            "candidate_search_evidence",
        ],
        "properties": {
            "schema_version": {"const": MANIFEST_SCHEMA_VERSION},
            "manifest_digest": digest,
            "capability_id": nonempty,
            "candidate_id": {"type": "string", "pattern": "^candidate-[0-9a-f]{64}$"},
            "candidate_group": nonempty,
            "source_surface": {"enum": ["ce", "ee"]},
            "source_repository": {"const": PINNED_SOURCE_REPOSITORY},
            "source_commit": {"const": PINNED_SOURCE_COMMIT},
            "source_tree_id": {"const": PINNED_SOURCE_TREE},
            "blob_count": {"type": "integer", "minimum": 1},
            "blob_set_digest": digest,
            "matched_hit_ids": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "pattern": "^hit-[0-9a-f]{64}$"},
            },
            "source_inventory": artifact_ref,
            "raw_results": artifact_ref,
            "hit_classification": artifact_ref,
            "candidate_search_evidence": artifact_ref,
        },
    }
    blob_set = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "blob_set_digest",
            "candidate_group",
            "source_surface",
            "source_repository",
            "source_commit",
            "source_tree_id",
            "blob_count",
            "blobs",
        ],
        "properties": {
            "schema_version": {"const": BLOB_SET_SCHEMA_VERSION},
            "blob_set_digest": digest,
            "candidate_group": nonempty,
            "source_surface": {"enum": ["ce", "ee"]},
            "source_repository": {"const": PINNED_SOURCE_REPOSITORY},
            "source_commit": {"const": PINNED_SOURCE_COMMIT},
            "source_tree_id": {"const": PINNED_SOURCE_TREE},
            "blob_count": {"type": "integer", "minimum": 1},
            "blobs": {"type": "array", "minItems": 1, "items": blob},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:candidate-input-bundle:v1",
        "title": "PMORG candidate-specific qualification inputs",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "source_repository",
            "source_commit",
            "source_tree_id",
            "candidate_count",
            "candidate_blob_membership_count",
            "blob_set_count",
            "blob_set_membership_count",
            "unique_blob_count",
            "derivation_artifacts",
            "manifest_schema",
            "blob_sets",
            "candidates",
        ],
        "properties": {
            "schema_version": {"const": BUNDLE_SCHEMA_VERSION},
            "source_repository": {"const": PINNED_SOURCE_REPOSITORY},
            "source_commit": {"const": PINNED_SOURCE_COMMIT},
            "source_tree_id": {"const": PINNED_SOURCE_TREE},
            "candidate_count": {"type": "integer", "minimum": 1},
            "candidate_blob_membership_count": {
                "type": "integer",
                "minimum": 1,
            },
            "blob_set_count": {"type": "integer", "minimum": 1},
            "blob_set_membership_count": {"type": "integer", "minimum": 1},
            "unique_blob_count": {"type": "integer", "minimum": 1},
            "derivation_artifacts": {
                "type": "array",
                "minItems": 3,
                "items": artifact_ref,
            },
            "manifest_schema": artifact_ref,
            "blob_sets": {"type": "array", "minItems": 1, "items": blob_set},
            "candidates": {"type": "array", "minItems": 1, "items": manifest},
        },
    }


def _manifest_digest(manifest: dict[str, Any]) -> str:
    payload = {
        key: value for key, value in manifest.items() if key != "manifest_digest"
    }
    return sha256_digest(canonical_document_bytes(payload))


def _blob_set_digest(blob_set: dict[str, Any]) -> str:
    payload = {
        key: value for key, value in blob_set.items() if key != "blob_set_digest"
    }
    return sha256_digest(canonical_document_bytes(payload))


def _candidate_id(
    capability_id: str,
    surface: str,
    candidate_group: str,
    raw_hits: list[dict[str, Any]],
) -> str:
    binding = canonical_document_bytes(
        {
            "capability_id": capability_id,
            "surface": surface,
            "candidate_group": candidate_group,
            "hit_bindings": [
                {"path": hit["path"], "git_object_id": hit["git_object_id"]}
                for hit in raw_hits
            ],
        }
    )
    return "candidate-" + hashlib.sha256(binding).hexdigest()


def _derive_manifests(
    repository_root: Path,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    evidence_paths = sorted(
        _safe_path(repository_root, SEARCH_ROOT).glob("*-search-evidence-v1.json")
    )
    if not evidence_paths:
        raise CandidateInputError("candidate-search evidence is absent")
    inventory_cache: dict[str, dict[str, Any]] = {}
    manifests: list[dict[str, Any]] = []
    blob_sets_by_group: dict[tuple[str, str], dict[str, Any]] = {}
    selected_entries: dict[str, dict[str, Any]] = {}

    for evidence_path in evidence_paths:
        evidence_relative = evidence_path.relative_to(repository_root).as_posix()
        evidence_payload = evidence_path.read_bytes()
        evidence = _read_object(evidence_payload, label=evidence_relative)
        capability_id = evidence.get("capability_id")
        candidate_ids = evidence.get("candidate_ids")
        if not isinstance(capability_id, str) or not isinstance(candidate_ids, list):
            raise CandidateInputError("candidate-search evidence identity is invalid")
        raw_ref = cast(dict[str, Any], evidence.get("raw_results"))
        classification_ref = cast(dict[str, Any], evidence.get("hit_classification"))
        raw_results, _ = _verified_artifact(
            repository_root, raw_ref, label=f"{capability_id} raw results"
        )
        classifications, _ = _verified_artifact(
            repository_root,
            classification_ref,
            label=f"{capability_id} hit classification",
        )
        raw_hits = cast(list[dict[str, Any]], raw_results.get("hits"))
        records = cast(list[dict[str, Any]], classifications.get("records"))
        if not isinstance(raw_hits, list) or not isinstance(records, list):
            raise CandidateInputError("candidate-search records are invalid")
        raw_by_id = {cast(str, item.get("hit_id")): item for item in raw_hits}
        if len(raw_by_id) != len(raw_hits):
            raise CandidateInputError("candidate raw hits are not unique")

        scopes: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        for scope_ref in cast(list[dict[str, Any]], evidence.get("source_scopes")):
            scope_kind = cast(str, scope_ref.get("scope_kind"))
            surface = {"onyx_ce": "ce", "onyx_ee": "ee"}.get(scope_kind)
            if surface is None:
                raise CandidateInputError(f"unknown source scope: {scope_kind}")
            inventory_ref = cast(dict[str, Any], scope_ref.get("path_inventory"))
            relative_path = cast(str, inventory_ref.get("relative_path"))
            inventory = inventory_cache.get(relative_path)
            if inventory is None:
                inventory, _ = _verified_artifact(
                    repository_root,
                    inventory_ref,
                    label=f"{surface} source inventory",
                )
                inventory_cache[relative_path] = inventory
            if (
                inventory.get("repository") != PINNED_SOURCE_REPOSITORY
                or inventory.get("commit") != PINNED_SOURCE_COMMIT
                or inventory.get("git_tree_id") != PINNED_SOURCE_TREE
                or inventory.get("scope_kind") != scope_kind
            ):
                raise CandidateInputError(
                    f"{surface} source inventory identity drifted"
                )
            scopes[surface] = (inventory_ref, inventory)
        if set(scopes) != {"ce", "ee"}:
            raise CandidateInputError(
                "candidate evidence does not bind both source scopes"
            )

        for candidate_id in candidate_ids:
            if not isinstance(candidate_id, str):
                raise CandidateInputError("candidate ID is not a string")
            candidate_records = [
                item for item in records if item.get("candidate_id") == candidate_id
            ]
            if not candidate_records or any(
                item.get("classification") != "candidate" for item in candidate_records
            ):
                raise CandidateInputError(
                    f"candidate classification is absent: {candidate_id}"
                )
            hit_ids = [cast(str, item.get("hit_id")) for item in candidate_records]
            if len(hit_ids) != len(set(hit_ids)):
                raise CandidateInputError(f"candidate repeats a hit: {candidate_id}")
            try:
                candidate_hits = [raw_by_id[hit_id] for hit_id in hit_ids]
            except KeyError as error:
                raise CandidateInputError(
                    f"candidate references an unknown hit: {candidate_id}"
                ) from error
            groups = {cast(str, item.get("candidate_group")) for item in candidate_hits}
            surfaces = {cast(str, item.get("surface")) for item in candidate_hits}
            if len(groups) != 1 or len(surfaces) != 1:
                raise CandidateInputError(
                    f"candidate does not map to one module group: {candidate_id}"
                )
            candidate_group = next(iter(groups))
            surface = next(iter(surfaces))
            ordered_group_hits = [
                item
                for item in raw_hits
                if item.get("surface") == surface
                and item.get("candidate_group") == candidate_group
            ]
            if (
                _candidate_id(
                    capability_id, surface, candidate_group, ordered_group_hits
                )
                != candidate_id
            ):
                raise CandidateInputError(f"candidate identity drifted: {candidate_id}")
            inventory_ref, inventory = scopes[surface]
            inventory_entries = cast(list[dict[str, Any]], inventory.get("entries"))
            group_entries = sorted(
                (
                    entry
                    for entry in inventory_entries
                    if _candidate_group(cast(str, entry.get("path"))) == candidate_group
                ),
                key=lambda entry: cast(str, entry["path"]),
            )
            if not group_entries:
                raise CandidateInputError(
                    f"candidate module group is empty: {candidate_id}"
                )
            group_by_path = {cast(str, item["path"]): item for item in group_entries}
            for hit in candidate_hits:
                path = cast(str, hit.get("path"))
                inventory_entry = group_by_path.get(path)
                if inventory_entry is None or any(
                    inventory_entry.get(key) != hit.get(hit_key)
                    for key, hit_key in (
                        ("git_object_id", "git_object_id"),
                        ("mode", "mode"),
                        ("sha256", "content_sha256"),
                        ("size_bytes", "size_bytes"),
                    )
                ):
                    raise CandidateInputError(
                        f"candidate hit is not bound to the source inventory: {path}"
                    )
            blobs = [
                {
                    "git_object_id": entry["git_object_id"],
                    "mode": entry["mode"],
                    "path": entry["path"],
                    "sha256": entry["sha256"],
                    "size_bytes": entry["size_bytes"],
                }
                for entry in group_entries
            ]
            for entry in blobs:
                selected_entries[cast(str, entry["path"])] = entry
            blob_set = {
                "schema_version": BLOB_SET_SCHEMA_VERSION,
                "candidate_group": candidate_group,
                "source_surface": surface,
                "source_repository": PINNED_SOURCE_REPOSITORY,
                "source_commit": PINNED_SOURCE_COMMIT,
                "source_tree_id": PINNED_SOURCE_TREE,
                "blob_count": len(blobs),
                "blobs": blobs,
            }
            blob_set["blob_set_digest"] = _blob_set_digest(blob_set)
            group_key = (surface, candidate_group)
            existing_blob_set = blob_sets_by_group.get(group_key)
            if existing_blob_set is not None and existing_blob_set != blob_set:
                raise CandidateInputError(
                    f"candidate module group membership drifted: {surface}:{candidate_group}"
                )
            blob_sets_by_group[group_key] = blob_set
            manifest = {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "capability_id": capability_id,
                "candidate_id": candidate_id,
                "candidate_group": candidate_group,
                "source_surface": surface,
                "source_repository": PINNED_SOURCE_REPOSITORY,
                "source_commit": PINNED_SOURCE_COMMIT,
                "source_tree_id": PINNED_SOURCE_TREE,
                "blob_count": len(blobs),
                "blob_set_digest": blob_set["blob_set_digest"],
                "matched_hit_ids": sorted(hit_ids),
                "source_inventory": inventory_ref,
                "raw_results": raw_ref,
                "hit_classification": classification_ref,
                "candidate_search_evidence": _artifact_ref(
                    evidence_relative,
                    evidence_payload,
                    logical_name=f"{capability_id}-candidate-search-evidence",
                ),
            }
            manifest["manifest_digest"] = _manifest_digest(manifest)
            manifests.append(manifest)

    manifests.sort(key=lambda item: (item["capability_id"], item["candidate_id"]))
    blob_sets = sorted(
        blob_sets_by_group.values(),
        key=lambda item: (item["source_surface"], item["candidate_group"]),
    )
    return manifests, blob_sets, selected_entries


def _verify_pinned_blobs(
    repository_root: Path, selected_entries: dict[str, dict[str, Any]]
) -> None:
    tree_entries = _pinned_tree_entries(repository_root)
    object_ids: set[str] = set()
    for path, entry in selected_entries.items():
        expected = tree_entries.get(path)
        actual = (
            entry.get("mode"),
            "blob",
            entry.get("git_object_id"),
        )
        if expected != actual:
            raise CandidateInputError(
                f"candidate blob is not in the pinned tree: {path}"
            )
        object_ids.add(cast(str, entry["git_object_id"]))
    ordered_ids = sorted(object_ids)
    blobs = _read_blobs(repository_root, ordered_ids)
    for path, entry in selected_entries.items():
        payload = blobs[cast(str, entry["git_object_id"])]
        if len(payload) != entry.get("size_bytes"):
            raise CandidateInputError(f"candidate blob size drifted: {path}")
        if sha256_digest(payload) != entry.get("sha256"):
            raise CandidateInputError(f"candidate blob digest drifted: {path}")


def validate_candidate_input_bundle(bundle: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(candidate_input_schema()).iter_errors(bundle), key=str
    )
    if errors:
        first_error = cast(Any, errors[0])
        raise CandidateInputError(
            f"candidate input schema violation: {first_error.message}"
        )
    candidates = cast(list[dict[str, Any]], bundle["candidates"])
    blob_sets = cast(list[dict[str, Any]], bundle["blob_sets"])
    identities = [
        (cast(str, item["capability_id"]), cast(str, item["candidate_id"]))
        for item in candidates
    ]
    if identities != sorted(set(identities)):
        raise CandidateInputError(
            "candidate input identities are not unique and ordered"
        )
    if bundle["candidate_count"] != len(candidates) or len(candidates) != 402:
        raise CandidateInputError("candidate input coverage is not exactly 402")
    blob_set_identities = [
        (cast(str, item["source_surface"]), cast(str, item["candidate_group"]))
        for item in blob_sets
    ]
    if blob_set_identities != sorted(set(blob_set_identities)):
        raise CandidateInputError("candidate blob sets are not unique and ordered")
    if bundle["blob_set_count"] != len(blob_sets) or len(blob_sets) != 119:
        raise CandidateInputError("candidate blob-set coverage is not exactly 119")
    blob_sets_by_digest: dict[str, dict[str, Any]] = {}
    blob_set_membership_count = 0
    unique_blobs: set[tuple[str, str]] = set()
    for blob_set in blob_sets:
        if blob_set["blob_set_digest"] != _blob_set_digest(blob_set):
            raise CandidateInputError("candidate blob-set digest drifted")
        blobs = cast(list[dict[str, Any]], blob_set["blobs"])
        paths = [cast(str, item["path"]) for item in blobs]
        if paths != sorted(set(paths)) or blob_set["blob_count"] != len(blobs):
            raise CandidateInputError("candidate blob-set membership is not exact")
        blob_sets_by_digest[cast(str, blob_set["blob_set_digest"])] = blob_set
        blob_set_membership_count += len(blobs)
        unique_blobs.update(
            (cast(str, item["git_object_id"]), cast(str, item["sha256"]))
            for item in blobs
        )
    candidate_blob_membership_count = 0
    for manifest in candidates:
        if manifest["manifest_digest"] != _manifest_digest(manifest):
            raise CandidateInputError("candidate manifest digest drifted")
        blob_set = blob_sets_by_digest.get(cast(str, manifest["blob_set_digest"]))
        if blob_set is None or any(
            manifest[key] != blob_set[key]
            for key in (
                "candidate_group",
                "source_surface",
                "source_repository",
                "source_commit",
                "source_tree_id",
                "blob_count",
            )
        ):
            raise CandidateInputError("candidate does not bind its exact blob set")
        hit_ids = cast(list[str], manifest["matched_hit_ids"])
        if hit_ids != sorted(set(hit_ids)):
            raise CandidateInputError(
                "candidate matched hits are not unique and ordered"
            )
        candidate_blob_membership_count += cast(int, manifest["blob_count"])
    if bundle["candidate_blob_membership_count"] != candidate_blob_membership_count:
        raise CandidateInputError("expanded candidate blob membership count drifted")
    if bundle["blob_set_membership_count"] != blob_set_membership_count:
        raise CandidateInputError("candidate blob-set membership count drifted")
    if bundle["unique_blob_count"] != len(unique_blobs):
        raise CandidateInputError("candidate unique blob count drifted")
    derivation_paths = [
        cast(str, item["relative_path"])
        for item in cast(list[dict[str, Any]], bundle["derivation_artifacts"])
    ]
    if derivation_paths != list(DERIVATION_ARTIFACTS):
        raise CandidateInputError("candidate input derivation artifacts drifted")


def build_candidate_input_bundle(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    repository_root = repository_root.resolve()
    manifests, blob_sets, selected_entries = _derive_manifests(repository_root)
    _verify_pinned_blobs(repository_root, selected_entries)
    schema_bytes = canonical_document_bytes(candidate_input_schema())
    bundle = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "source_repository": PINNED_SOURCE_REPOSITORY,
        "source_commit": PINNED_SOURCE_COMMIT,
        "source_tree_id": PINNED_SOURCE_TREE,
        "candidate_count": len(manifests),
        "candidate_blob_membership_count": sum(
            item["blob_count"] for item in manifests
        ),
        "blob_set_count": len(blob_sets),
        "blob_set_membership_count": sum(item["blob_count"] for item in blob_sets),
        "unique_blob_count": len(
            {
                (blob["git_object_id"], blob["sha256"])
                for blob_set in blob_sets
                for blob in blob_set["blobs"]
            }
        ),
        "derivation_artifacts": [
            _artifact_ref(
                relative_path,
                _read_path(
                    repository_root,
                    relative_path,
                    label=f"candidate input derivation artifact {relative_path}",
                ),
                logical_name=Path(relative_path).name,
                media_type="text/x-python",
            )
            for relative_path in DERIVATION_ARTIFACTS
        ],
        "manifest_schema": _artifact_ref(
            SCHEMA_RELATIVE,
            schema_bytes,
            logical_name="candidate-input-bundle-schema",
            media_type="application/schema+json",
        ),
        "blob_sets": blob_sets,
        "candidates": manifests,
    }
    validate_candidate_input_bundle(bundle)
    return bundle


def write_candidate_inputs(repository_root: Path = REPOSITORY_ROOT) -> None:
    repository_root = repository_root.resolve()
    outputs = {
        OUTPUT_RELATIVE: canonical_document_bytes(
            build_candidate_input_bundle(repository_root)
        ),
        SCHEMA_RELATIVE: canonical_document_bytes(candidate_input_schema()),
    }
    for relative_path, payload in outputs.items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_candidate_inputs(repository_root: Path = REPOSITORY_ROOT) -> None:
    repository_root = repository_root.resolve()
    expected = {
        OUTPUT_RELATIVE: canonical_document_bytes(
            build_candidate_input_bundle(repository_root)
        ),
        SCHEMA_RELATIVE: canonical_document_bytes(candidate_input_schema()),
    }
    for relative_path, payload in expected.items():
        actual = _read_path(repository_root, relative_path, label=relative_path)
        if actual != payload:
            raise CandidateInputError(
                f"committed candidate input drifted: {relative_path}"
            )


__all__ = [
    "CandidateInputError",
    "build_candidate_input_bundle",
    "candidate_input_schema",
    "check_candidate_inputs",
    "validate_candidate_input_bundle",
    "write_candidate_inputs",
]
