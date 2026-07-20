"""Build complete, byte-closed candidate-search evidence over pinned Onyx."""

from __future__ import annotations

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

from pmorg.contracts.types import CandidateSearchEvidence
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import SourceScopeManifest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CAPABILITY_ROOT = REPOSITORY_ROOT / "pmorg" / "capabilities"
SEARCH_ROOT = CAPABILITY_ROOT / "candidate-search"
POLICY_RELATIVE = "pmorg/capabilities/candidate-search-policy.json"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
GENERATOR_RELATIVE = "backend/pmorg/application/candidate_search.py"
SOURCE_SCOPE_EVIDENCE_RELATIVE = (
    "pmorg/capabilities/source-scopes/onyx-source-scope-derivation-v1.json"
)
SEARCH_SCHEMA_VERSION = "pmorg.candidate-search-evidence/v1"

_POLICY_KEYS = {
    "schema_version",
    "catalog_version",
    "search_spec_version",
    "search_tool_name",
    "search_tool_version",
    "path_matching",
    "content_matching",
    "raw_hit_rule",
    "capabilities",
}
_CAPABILITY_POLICY_KEYS = {
    "capability_id",
    "minimum_candidate_group_count",
    "term_groups",
}
_CATALOG_KEYS = {
    "schema_version",
    "catalog_version",
    "pmorg_spec_commit",
    "disposition_scope_rule",
    "applicable_requirement_set",
    "required_search_surfaces",
    "expected_requirement_count",
    "mapped_requirement_count",
    "unmapped_requirement_count",
    "unknown_requirement_count",
    "duplicate_capability_id_count",
    "items",
    "item_count",
}
_SOURCE_SCOPE_PATHS = {
    "ce": "pmorg/capabilities/source-scopes/onyx-ce-source-scope-v1.json",
    "ee": "pmorg/capabilities/source-scopes/onyx-ee-source-scope-v1.json",
}
_INVENTORY_PATHS = {
    "ce": "pmorg/capabilities/source-scopes/onyx-ce-path-inventory-v1.json",
    "ee": "pmorg/capabilities/source-scopes/onyx-ee-path-inventory-v1.json",
}


class CandidateSearchError(ValueError):
    """Raised when candidate search is incomplete, ambiguous, or drifted."""


@dataclass(frozen=True)
class SearchBlob:
    surface: str
    path: str
    mode: str
    object_id: str
    sha256: str
    size_bytes: int
    data: bytes


@dataclass(frozen=True)
class CandidateSearchOutputs:
    query_plans: Mapping[str, bytes]
    raw_results: Mapping[str, bytes]
    classifications: Mapping[str, bytes]
    evidence: Mapping[str, bytes]


def canonical_document_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _record_document_bytes(value: Mapping[str, Any], record_key: str) -> bytes:
    records = value.get(record_key)
    if not isinstance(records, list):
        raise CandidateSearchError(f"{record_key} must be an array")
    lines = ["{"]
    keys = sorted(value)
    for key_index, key in enumerate(keys):
        suffix = "," if key_index < len(keys) - 1 else ""
        if key != record_key:
            encoded = json.dumps(value[key], ensure_ascii=False, sort_keys=True)
            lines.append(f"  {json.dumps(key)}: {encoded}{suffix}")
            continue
        lines.append(f"  {json.dumps(key)}: [")
        for record_index, record in enumerate(records):
            record_suffix = "," if record_index < len(records) - 1 else ""
            encoded = json.dumps(
                record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            lines.append(f"    {encoded}{record_suffix}")
        lines.append(f"  ]{suffix}")
    lines.append("}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def sha256_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CandidateSearchError(f"JSON repeats key: {key}")
        value[key] = item
    return value


def _read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateSearchError(f"{label} is not readable JSON") from error
    if not isinstance(value, dict):
        raise CandidateSearchError(f"{label} must be a JSON object")
    return value


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise CandidateSearchError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], *, label: str
) -> None:
    if set(value) != expected:
        raise CandidateSearchError(
            f"{label} keys are not exact; "
            f"missing={sorted(expected - set(value))}, "
            f"unknown={sorted(set(value) - expected)}"
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


def _load_inputs(
    repository_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, SourceScopeManifest]]:
    policy = _read_object(
        _safe_path(repository_root, POLICY_RELATIVE), label="candidate-search policy"
    )
    catalog = _read_object(
        _safe_path(repository_root, CATALOG_RELATIVE), label="capability catalog"
    )
    _require_exact_keys(policy, _POLICY_KEYS, label="candidate-search policy")
    _require_exact_keys(catalog, _CATALOG_KEYS, label="capability catalog")
    if policy["schema_version"] != "pmorg.candidate-search-policy/v1":
        raise CandidateSearchError("candidate-search policy schema drifted")
    if policy["catalog_version"] != catalog["catalog_version"]:
        raise CandidateSearchError("candidate-search policy catalog version drifted")
    if policy["path_matching"] != "utf8_casefolded_literal_text":
        raise CandidateSearchError("path matching rule drifted")
    if policy["content_matching"] != "ascii_casefolded_literal_bytes":
        raise CandidateSearchError("content matching rule drifted")
    if policy["raw_hit_rule"] != "one_or_more_terms_match_path_or_blob":
        raise CandidateSearchError("raw-hit rule drifted")
    if catalog["required_search_surfaces"] != ["ce", "ee"]:
        raise CandidateSearchError("catalog does not require exact CE and EE search")
    source_scopes: dict[str, SourceScopeManifest] = {}
    try:
        for surface, relative_path in _SOURCE_SCOPE_PATHS.items():
            source_scopes[surface] = SourceScopeManifest.model_validate(
                _read_object(
                    _safe_path(repository_root, relative_path),
                    label=f"{surface} source-scope manifest",
                ),
                strict=True,
            )
    except ValidationError as error:
        raise CandidateSearchError("source-scope manifest is invalid") from error
    if source_scopes["ce"].scope_kind != "onyx_ce":
        raise CandidateSearchError("CE source-scope identity drifted")
    if source_scopes["ee"].scope_kind != "onyx_ee":
        raise CandidateSearchError("EE source-scope identity drifted")
    if source_scopes["ce"].commit != source_scopes["ee"].commit:
        raise CandidateSearchError("CE and EE source scopes bind different commits")
    return policy, catalog, source_scopes


def _read_blob_batch(repository_root: Path, object_ids: list[str]) -> dict[str, bytes]:
    try:
        completed = subprocess.run(
            ["git", "cat-file", "--batch"],
            cwd=repository_root,
            check=True,
            input="".join(f"{object_id}\n" for object_id in object_ids).encode("ascii"),
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise CandidateSearchError(
            "candidate search could not read pinned Git blobs"
        ) from error
    stream = io.BytesIO(completed.stdout)
    blobs: dict[str, bytes] = {}
    for expected_id in object_ids:
        try:
            header = stream.readline().decode("ascii").strip().split(" ")
            if len(header) != 3 or header[0] != expected_id or header[1] != "blob":
                raise CandidateSearchError(f"unreadable Git blob: {expected_id}")
            size = int(header[2])
        except (UnicodeDecodeError, ValueError) as error:
            raise CandidateSearchError("malformed Git blob response") from error
        blobs[expected_id] = stream.read(size)
        if stream.read(1) != b"\n":
            raise CandidateSearchError("Git blob response is truncated")
    if stream.read():
        raise CandidateSearchError("Git blob response has trailing bytes")
    return blobs


def _verified_search_blobs(
    repository_root: Path, source_scopes: Mapping[str, SourceScopeManifest]
) -> tuple[SearchBlob, ...]:
    records: list[tuple[str, dict[str, Any]]] = []
    seen_paths: set[str] = set()
    object_ids: list[str] = []
    for surface in ("ce", "ee"):
        inventory_path = _safe_path(repository_root, _INVENTORY_PATHS[surface])
        inventory_payload = inventory_path.read_bytes()
        manifest = source_scopes[surface]
        if manifest.path_inventory.digest != sha256_digest(inventory_payload):
            raise CandidateSearchError(f"{surface} inventory digest drifted")
        inventory = _read_object(inventory_path, label=f"{surface} path inventory")
        raw_entries = inventory.get("entries")
        if not isinstance(raw_entries, list):
            raise CandidateSearchError(f"{surface} inventory entries are absent")
        if inventory.get("path_count") != len(raw_entries):
            raise CandidateSearchError(f"{surface} inventory count drifted")
        if manifest.expected_path_count != len(raw_entries):
            raise CandidateSearchError(f"{surface} manifest count drifted")
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict):
                raise CandidateSearchError("source inventory entry must be an object")
            entry = cast(dict[str, Any], raw_entry)
            expected_keys = {"path", "mode", "git_object_id", "sha256", "size_bytes"}
            _require_exact_keys(entry, expected_keys, label="source inventory entry")
            path = entry["path"]
            object_id = entry["git_object_id"]
            if not isinstance(path, str) or not isinstance(object_id, str):
                raise CandidateSearchError("source inventory identity is malformed")
            if path in seen_paths:
                raise CandidateSearchError(f"source inventories repeat path: {path}")
            seen_paths.add(path)
            object_ids.append(object_id)
            records.append((surface, entry))
    unique_ids = list(dict.fromkeys(object_ids))
    blob_data: dict[str, bytes] = {}
    for start in range(0, len(unique_ids), 256):
        blob_data.update(
            _read_blob_batch(repository_root, unique_ids[start : start + 256])
        )
    if set(blob_data) != set(unique_ids):
        raise CandidateSearchError("candidate search did not read every inventory blob")
    blobs: list[SearchBlob] = []
    for surface, entry in records:
        object_id = cast(str, entry["git_object_id"])
        data = blob_data[object_id]
        if sha256_digest(data) != entry["sha256"] or len(data) != entry["size_bytes"]:
            raise CandidateSearchError(
                f"source blob drifted from inventory: {entry['path']}"
            )
        blobs.append(
            SearchBlob(
                surface=surface,
                path=cast(str, entry["path"]),
                mode=cast(str, entry["mode"]),
                object_id=object_id,
                sha256=cast(str, entry["sha256"]),
                size_bytes=cast(int, entry["size_bytes"]),
                data=data,
            )
        )
    return tuple(blobs)


def _policy_capabilities(
    policy: Mapping[str, Any], catalog: Mapping[str, Any]
) -> list[dict[str, Any]]:
    raw_capabilities = policy["capabilities"]
    catalog_items = catalog["items"]
    if not isinstance(raw_capabilities, list) or not isinstance(catalog_items, list):
        raise CandidateSearchError("candidate-search capabilities are absent")
    catalog_by_id = {
        item["capability_id"]: item
        for item in catalog_items
        if isinstance(item, dict) and isinstance(item.get("capability_id"), str)
    }
    capabilities: list[dict[str, Any]] = []
    ids: list[str] = []
    for raw in raw_capabilities:
        if not isinstance(raw, dict):
            raise CandidateSearchError("candidate-search capability must be an object")
        capability = cast(dict[str, Any], raw)
        _require_exact_keys(
            capability, _CAPABILITY_POLICY_KEYS, label="candidate-search capability"
        )
        capability_id = capability["capability_id"]
        minimum = capability["minimum_candidate_group_count"]
        term_groups = capability["term_groups"]
        if not isinstance(capability_id, str) or capability_id not in catalog_by_id:
            raise CandidateSearchError(
                f"unknown candidate-search capability: {capability_id}"
            )
        if not isinstance(term_groups, list) or len(term_groups) < 2:
            raise CandidateSearchError(
                f"{capability_id} requires at least two term groups"
            )
        normalized_groups: list[list[str]] = []
        for group in term_groups:
            if (
                not isinstance(group, list)
                or not group
                or not all(
                    isinstance(term, str)
                    and len(term) >= 3
                    and term == term.casefold()
                    and term.isascii()
                    for term in group
                )
            ):
                raise CandidateSearchError(f"{capability_id} has an invalid term group")
            terms = cast(list[str], group)
            if terms != sorted(set(terms)):
                raise CandidateSearchError(
                    f"{capability_id} terms must be unique and ordered"
                )
            normalized_groups.append(terms)
        if (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or minimum < 2
            or minimum > len(normalized_groups)
        ):
            raise CandidateSearchError(
                f"{capability_id} candidate threshold is invalid"
            )
        ids.append(capability_id)
        capabilities.append(capability)
    if ids != sorted(set(ids)) or set(ids) != set(catalog_by_id):
        raise CandidateSearchError(
            "candidate-search policy must cover exact catalog IDs"
        )
    return capabilities


def _contract_test_binding(
    repository_root: Path, catalog_item: Mapping[str, Any]
) -> tuple[EvidenceArtifactRef, list[str]]:
    refs = catalog_item.get("contract_tests")
    if not isinstance(refs, list) or len(refs) != 1 or not isinstance(refs[0], dict):
        raise CandidateSearchError(
            "capability must bind exactly one contract-test manifest"
        )
    ref = EvidenceArtifactRef.model_validate(refs[0], strict=True)
    payload = _safe_path(repository_root, ref.relative_path).read_bytes()
    if ref.digest != sha256_digest(payload) or ref.size_bytes != len(payload):
        raise CandidateSearchError("catalog contract-test binding drifted")
    manifest = _read_object(
        _safe_path(repository_root, ref.relative_path), label="contract-test manifest"
    )
    test_ids = manifest.get("test_ids")
    if (
        not isinstance(test_ids, list)
        or not test_ids
        or not all(isinstance(item, str) for item in test_ids)
    ):
        raise CandidateSearchError("contract-test manifest has no exact test IDs")
    return ref, cast(list[str], test_ids)


def _matched_terms(
    blob: SearchBlob, term_groups: list[list[str]]
) -> tuple[list[str], list[int]]:
    path_text = blob.path.casefold()
    content = blob.data.lower()
    matched: list[str] = []
    matched_groups: list[int] = []
    for group_index, group in enumerate(term_groups):
        group_matched = False
        for term in group:
            if term in path_text or term.encode("ascii") in content:
                matched.append(term)
                group_matched = True
        if group_matched:
            matched_groups.append(group_index)
    return sorted(set(matched)), matched_groups


def _candidate_group(path: str) -> str:
    parts = path.split("/")
    if parts[:3] == ["backend", "ee", "onyx"]:
        depth = 4
    elif parts[:2] == ["backend", "onyx"]:
        depth = 3
    elif parts[:3] == ["web", "src", "app"]:
        depth = 4
    elif parts[:2] == ["web", "src"]:
        depth = 3
    else:
        depth = 2
    if len(parts) == 1:
        return parts[0]
    return "/".join(parts[: min(depth, len(parts) - 1)])


def _artifact_paths(capability_id: str) -> dict[str, str]:
    prefix = f"pmorg/capabilities/candidate-search/{capability_id}"
    return {
        "query_plan": f"{prefix}-query-plan-v1.json",
        "raw_results": f"{prefix}-raw-results-v1.json",
        "classifications": f"{prefix}-hit-classification-v1.json",
        "evidence": f"{prefix}-search-evidence-v1.json",
    }


def derive_candidate_search_outputs(
    repository_root: Path = REPOSITORY_ROOT,
) -> CandidateSearchOutputs:
    repository_root = repository_root.resolve()
    policy, catalog, source_scopes = _load_inputs(repository_root)
    capabilities = _policy_capabilities(policy, catalog)
    catalog_items = cast(list[dict[str, Any]], catalog["items"])
    catalog_by_id = {item["capability_id"]: item for item in catalog_items}
    blobs = _verified_search_blobs(repository_root, source_scopes)
    expected_path_count = sum(
        scope.expected_path_count for scope in source_scopes.values()
    )
    if len(blobs) != expected_path_count:
        raise CandidateSearchError("candidate search denominator is incomplete")
    if len({blob.path for blob in blobs}) != len(blobs):
        raise CandidateSearchError("candidate search denominator repeats paths")
    catalog_payload = _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    catalog_hash = sha256_digest(catalog_payload)
    generator_payload = _safe_path(repository_root, GENERATOR_RELATIVE).read_bytes()
    generator_digest = sha256_digest(generator_payload)
    source_scope_values = [source_scopes[surface] for surface in ("ce", "ee")]

    query_plans: dict[str, bytes] = {}
    raw_results: dict[str, bytes] = {}
    classifications: dict[str, bytes] = {}
    evidence: dict[str, bytes] = {}
    for capability in capabilities:
        capability_id = cast(str, capability["capability_id"])
        term_groups = cast(list[list[str]], capability["term_groups"])
        minimum = cast(int, capability["minimum_candidate_group_count"])
        contract_ref, test_ids = _contract_test_binding(
            repository_root, catalog_by_id[capability_id]
        )
        paths = _artifact_paths(capability_id)
        search_id = (
            f"candidate-search:{policy['catalog_version']}:{capability_id}:"
            f"{source_scopes['ce'].commit}"
        )
        query_plan_value = {
            "schema_version": "pmorg.candidate-query-plan/v1",
            "search_id": search_id,
            "catalog_hash": catalog_hash,
            "capability_id": capability_id,
            "searched_surfaces": ["ce", "ee"],
            "search_spec_version": policy["search_spec_version"],
            "path_matching": policy["path_matching"],
            "content_matching": policy["content_matching"],
            "raw_hit_rule": policy["raw_hit_rule"],
            "minimum_candidate_group_count": minimum,
            "term_groups": term_groups,
            "required_contract_tests": contract_ref.model_dump(mode="json"),
            "required_test_ids": test_ids,
        }
        query_plan = canonical_document_bytes(query_plan_value)
        query_plans[capability_id] = query_plan
        query_plan_ref = _evidence_ref(
            repository_root,
            paths["query_plan"],
            query_plan,
            logical_name=f"{capability_id}-candidate-query-plan",
        )

        raw_hits: list[dict[str, Any]] = []
        for blob in blobs:
            matched_terms, matched_groups = _matched_terms(blob, term_groups)
            if not matched_terms:
                continue
            hit_binding = canonical_document_bytes(
                {
                    "capability_id": capability_id,
                    "surface": blob.surface,
                    "path": blob.path,
                    "git_object_id": blob.object_id,
                    "content_sha256": blob.sha256,
                    "matched_terms": matched_terms,
                }
            )
            hit_id = "hit-" + hashlib.sha256(hit_binding).hexdigest()
            raw_hits.append(
                {
                    "hit_id": hit_id,
                    "surface": blob.surface,
                    "path": blob.path,
                    "mode": blob.mode,
                    "git_object_id": blob.object_id,
                    "content_sha256": blob.sha256,
                    "size_bytes": blob.size_bytes,
                    "candidate_group": _candidate_group(blob.path),
                    "matched_terms": matched_terms,
                    "matched_group_indexes": matched_groups,
                }
            )
        grouped_hits: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for hit in raw_hits:
            group_key = (cast(str, hit["surface"]), cast(str, hit["candidate_group"]))
            grouped_hits.setdefault(group_key, []).append(hit)
        candidate_by_group: dict[tuple[str, str], str] = {}
        for group_key, group_hits in sorted(grouped_hits.items()):
            covered_groups = {
                group_index
                for hit in group_hits
                for group_index in cast(list[int], hit["matched_group_indexes"])
            }
            if len(covered_groups) < minimum:
                continue
            candidate_binding = canonical_document_bytes(
                {
                    "capability_id": capability_id,
                    "surface": group_key[0],
                    "candidate_group": group_key[1],
                    "hit_bindings": [
                        {
                            "path": hit["path"],
                            "git_object_id": hit["git_object_id"],
                        }
                        for hit in group_hits
                    ],
                }
            )
            candidate_by_group[group_key] = (
                "candidate-" + hashlib.sha256(candidate_binding).hexdigest()
            )
        candidate_ids = [
            candidate_by_group[group_key] for group_key in sorted(candidate_by_group)
        ]
        classification_records: list[dict[str, Any]] = []
        for hit in raw_hits:
            group_key = (cast(str, hit["surface"]), cast(str, hit["candidate_group"]))
            candidate_id = candidate_by_group.get(group_key)
            group_hits = grouped_hits[group_key]
            covered_groups = sorted(
                {
                    group_index
                    for group_hit in group_hits
                    for group_index in cast(
                        list[int], group_hit["matched_group_indexes"]
                    )
                }
            )
            is_candidate = candidate_id is not None
            classification_records.append(
                {
                    "hit_id": hit["hit_id"],
                    "classification": "candidate" if is_candidate else "rejected",
                    "candidate_id": candidate_id,
                    "candidate_group": hit["candidate_group"],
                    "matched_group_count": len(covered_groups),
                    "matched_group_indexes": covered_groups,
                    "minimum_candidate_group_count": minimum,
                    "reason": "meets_declared_group_threshold"
                    if is_candidate
                    else "below_declared_group_threshold",
                }
            )
        if len({item["hit_id"] for item in raw_hits}) != len(raw_hits):
            raise CandidateSearchError(f"{capability_id} produced duplicate hit IDs")
        if len(set(candidate_ids)) != len(candidate_ids):
            raise CandidateSearchError(
                f"{capability_id} produced duplicate candidate IDs"
            )
        if [item["hit_id"] for item in raw_hits] != [
            item["hit_id"] for item in classification_records
        ]:
            raise CandidateSearchError(
                f"{capability_id} classification is not bijective"
            )
        raw_value = {
            "schema_version": "pmorg.candidate-raw-results/v1",
            "search_id": search_id,
            "catalog_hash": catalog_hash,
            "capability_id": capability_id,
            "query_plan_digest": query_plan_ref.digest,
            "expected_path_count": expected_path_count,
            "scanned_path_count": len(blobs),
            "unscanned_path_count": 0,
            "duplicate_path_count": 0,
            "unreadable_path_count": 0,
            "raw_hit_count": len(raw_hits),
            "hits": raw_hits,
        }
        raw_payload = _record_document_bytes(raw_value, "hits")
        raw_results[capability_id] = raw_payload
        raw_ref = _evidence_ref(
            repository_root,
            paths["raw_results"],
            raw_payload,
            logical_name=f"{capability_id}-candidate-raw-results",
        )
        rejected_hit_count = sum(
            record["classification"] == "rejected" for record in classification_records
        )
        classification_value = {
            "schema_version": "pmorg.candidate-hit-classification/v1",
            "search_id": search_id,
            "catalog_hash": catalog_hash,
            "capability_id": capability_id,
            "raw_results_digest": raw_ref.digest,
            "raw_hit_count": len(raw_hits),
            "classification_record_count": len(classification_records),
            "candidate_count": len(candidate_ids),
            "rejected_hit_count": rejected_hit_count,
            "unclassified_hit_count": 0,
            "duplicate_hit_id_count": 0,
            "records": classification_records,
        }
        classification_payload = _record_document_bytes(classification_value, "records")
        classifications[capability_id] = classification_payload
        classification_ref = _evidence_ref(
            repository_root,
            paths["classifications"],
            classification_payload,
            logical_name=f"{capability_id}-candidate-hit-classification",
        )
        try:
            search_evidence = CandidateSearchEvidence(
                schema_version=SEARCH_SCHEMA_VERSION,
                search_id=search_id,
                catalog_hash=catalog_hash,
                capability_id=capability_id,
                searched_surfaces=["ce", "ee"],
                source_scopes=source_scope_values,
                search_spec_version=cast(str, policy["search_spec_version"]),
                search_tool_name=cast(str, policy["search_tool_name"]),
                search_tool_version=cast(str, policy["search_tool_version"]),
                search_tool_artifact_digest=generator_digest,
                expected_path_count=expected_path_count,
                scanned_path_count=len(blobs),
                unscanned_path_count=0,
                duplicate_path_count=0,
                unreadable_path_count=0,
                raw_hit_count=len(raw_hits),
                candidate_ids=candidate_ids,
                rejected_hit_count=rejected_hit_count,
                classification_record_count=len(classification_records),
                unclassified_hit_count=0,
                duplicate_hit_id_count=0,
                query_plan=query_plan_ref,
                raw_results=raw_ref,
                hit_classification=classification_ref,
            )
        except ValidationError as error:
            raise CandidateSearchError(
                f"{capability_id} candidate-search evidence is invalid"
            ) from error
        evidence[capability_id] = canonical_document_bytes(
            search_evidence.model_dump(mode="json")
        )
    return CandidateSearchOutputs(
        query_plans=query_plans,
        raw_results=raw_results,
        classifications=classifications,
        evidence=evidence,
    )


def _validate_search_schema(repository_root: Path, payload: bytes) -> None:
    contract_root = repository_root / "backend" / "pmorg" / "contracts"
    manifest = _read_object(contract_root / "manifest.json", label="contract manifest")
    try:
        entry = next(
            item
            for item in manifest["contracts"]
            if item["schema_version"] == SEARCH_SCHEMA_VERSION
        )
        schema_bytes = (contract_root / entry["schema_path"]).read_bytes()
        schema = json.loads(schema_bytes, object_pairs_hook=_reject_duplicate_keys)
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (KeyError, StopIteration, TypeError, OSError, json.JSONDecodeError) as error:
        raise CandidateSearchError(
            "candidate-search contract schema is incomplete"
        ) from error
    if sha256_digest(schema_bytes) != entry.get("schema_sha256"):
        raise CandidateSearchError("candidate-search contract schema digest drifted")
    try:
        Draft202012Validator(schema).validate(value)
    except Exception as error:
        raise CandidateSearchError(
            "candidate-search evidence does not validate against committed schema"
        ) from error


def write_candidate_search(repository_root: Path = REPOSITORY_ROOT) -> None:
    outputs = derive_candidate_search_outputs(repository_root)
    SEARCH_ROOT.mkdir(parents=True, exist_ok=True)
    for capability_id in sorted(outputs.evidence):
        paths = _artifact_paths(capability_id)
        for key, payloads in (
            ("query_plan", outputs.query_plans),
            ("raw_results", outputs.raw_results),
            ("classifications", outputs.classifications),
            ("evidence", outputs.evidence),
        ):
            _safe_path(repository_root, paths[key]).write_bytes(payloads[capability_id])


def check_candidate_search(repository_root: Path = REPOSITORY_ROOT) -> None:
    outputs = derive_candidate_search_outputs(repository_root)
    for capability_id in sorted(outputs.evidence):
        paths = _artifact_paths(capability_id)
        for key, payloads in (
            ("query_plan", outputs.query_plans),
            ("raw_results", outputs.raw_results),
            ("classifications", outputs.classifications),
            ("evidence", outputs.evidence),
        ):
            relative_path = paths[key]
            try:
                actual = _safe_path(repository_root, relative_path).read_bytes()
            except OSError as error:
                raise CandidateSearchError(
                    f"committed candidate-search artifact is missing: {relative_path}"
                ) from error
            if actual != payloads[capability_id]:
                raise CandidateSearchError(
                    f"committed candidate-search artifact drifted: {relative_path}"
                )
        _validate_search_schema(repository_root, outputs.evidence[capability_id])
