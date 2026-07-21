"""Build exhaustive, byte-closed admission interface-fit screening evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator

from pmorg.application.candidate_inputs import _read_blobs
from pmorg.application.candidate_inputs import PINNED_SOURCE_COMMIT
from pmorg.application.candidate_inputs import PINNED_SOURCE_REPOSITORY
from pmorg.application.candidate_inputs import PINNED_SOURCE_TREE
from pmorg.application.candidate_inputs import validate_candidate_input_bundle
from pmorg.application.candidate_interface_fit import _PROBES

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
INTERFACE_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-interfaces-v1.json"
VECTOR_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-test-vectors-v1.json"
OUTPUT_RELATIVE = (
    "pmorg/capabilities/candidate-interface-fit-denominator-evidence-v1.json"
)
SCHEMA_RELATIVE = (
    "pmorg/capabilities/candidate-interface-fit-denominator-evidence-v1.schema.json"
)
DERIVATION_RELATIVES = (
    "backend/pmorg/application/candidate_interface_fit.py",
    "backend/pmorg/application/candidate_interface_fit_denominator.py",
    "pmorg/scripts/build_candidate_interface_fit_denominator.py",
)

SCHEMA_VERSION = "pmorg.candidate-interface-fit-denominator-evidence/v1"
EVIDENCE_VERSION = "1.0.0"
CAPABILITIES = ("deployment-admission", "distribution-admission")
_ALL_TERMS = tuple(
    sorted(
        {
            term.decode("ascii")
            for probes in _PROBES.values()
            for _, terms in probes
            for term in terms
        }
    )
)
_TOKEN_PATTERNS = {
    term: re.compile(
        rb"(?<![a-z0-9_])" + re.escape(term.encode("ascii")) + rb"(?![a-z0-9_])"
    )
    for term in _ALL_TERMS
}


class CandidateInterfaceFitDenominatorError(ValueError):
    """Raised when exhaustive fit evidence cannot be reproduced exactly."""


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
        raise CandidateInterfaceFitDenominatorError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateInterfaceFitDenominatorError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise CandidateInterfaceFitDenominatorError(
            f"artifact is not an object: {relative_path}"
        )
    return value


def _artifact_ref(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise CandidateInterfaceFitDenominatorError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return {
        "digest": sha256_digest(payload),
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def evidence_schema() -> dict[str, Any]:
    nonempty = {"type": "string", "minLength": 1}
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    artifact = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "relative_path", "size_bytes"],
        "properties": {
            "digest": digest,
            "relative_path": nonempty,
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }
    term_match = {
        "type": "object",
        "additionalProperties": False,
        "required": ["occurrences", "path", "term"],
        "properties": {
            "occurrences": {"type": "integer", "minimum": 1},
            "path": nonempty,
            "term": {"enum": list(_ALL_TERMS)},
        },
    }
    coverage = {
        "type": "object",
        "additionalProperties": False,
        "required": ["expected", "scanned", "unreadable", "unverified"],
        "properties": {
            "expected": {"type": "integer", "minimum": 1},
            "scanned": {"type": "integer", "minimum": 1},
            "unreadable": {"const": 0},
            "unverified": {"const": 0},
        },
    }
    scan = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "blob_count",
            "blob_index_digest",
            "blob_set_digest",
            "candidate_group",
            "coverage",
            "scan_digest",
            "source_surface",
            "term_matches",
        ],
        "properties": {
            "blob_count": {"type": "integer", "minimum": 1},
            "blob_index_digest": digest,
            "blob_set_digest": digest,
            "candidate_group": nonempty,
            "coverage": coverage,
            "scan_digest": digest,
            "source_surface": {"enum": ["ce", "ee"]},
            "term_matches": {"type": "array", "items": term_match},
        },
    }
    candidate = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "blob_count",
            "blob_set_digest",
            "candidate_group",
            "candidate_id",
            "candidate_manifest_digest",
            "capability_id",
            "missing_probe_ids",
            "plausibility_state",
            "scan_digest",
        ],
        "properties": {
            "blob_count": {"type": "integer", "minimum": 1},
            "blob_set_digest": digest,
            "candidate_group": nonempty,
            "candidate_id": nonempty,
            "candidate_manifest_digest": digest,
            "capability_id": {"enum": list(CAPABILITIES)},
            "missing_probe_ids": {
                "type": "array",
                "minItems": 1,
                "items": nonempty,
                "uniqueItems": True,
            },
            "plausibility_state": {
                "const": "no_direct_candidate_level_admission_surface_observed"
            },
            "scan_digest": digest,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:candidate-interface-fit-denominator-evidence:v1",
        "title": "PMORG exhaustive candidate interface-fit denominator evidence",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "evidence_version",
            "source_repository",
            "source_commit",
            "source_tree_id",
            "candidate_inputs",
            "qualification_interfaces",
            "qualification_test_vectors",
            "derivation_artifacts",
            "selection_policy",
            "capability_candidate_counts",
            "candidate_count",
            "candidate_blob_membership_count",
            "blob_set_scan_count",
            "blob_set_membership_count",
            "coverage",
            "blob_set_scans",
            "candidates",
            "claim_boundary",
            "oracle_activation",
        ],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "evidence_version": {"const": EVIDENCE_VERSION},
            "source_repository": {"const": PINNED_SOURCE_REPOSITORY},
            "source_commit": {"const": PINNED_SOURCE_COMMIT},
            "source_tree_id": {"const": PINNED_SOURCE_TREE},
            "candidate_inputs": artifact,
            "qualification_interfaces": artifact,
            "qualification_test_vectors": artifact,
            "derivation_artifacts": {
                "type": "array",
                "minItems": 3,
                "maxItems": 3,
                "items": artifact,
            },
            "selection_policy": {
                "const": "all_discovered_candidate_manifests_for_admission_capabilities"
            },
            "capability_candidate_counts": {
                "type": "object",
                "additionalProperties": False,
                "required": list(CAPABILITIES),
                "properties": {
                    "deployment-admission": {"const": 82},
                    "distribution-admission": {"const": 104},
                },
            },
            "candidate_count": {"const": 186},
            "candidate_blob_membership_count": {"const": 10351},
            "blob_set_scan_count": {"const": 115},
            "blob_set_membership_count": {"const": 5802},
            "coverage": coverage,
            "blob_set_scans": {
                "type": "array",
                "minItems": 115,
                "maxItems": 115,
                "items": scan,
            },
            "candidates": {
                "type": "array",
                "minItems": 186,
                "maxItems": 186,
                "items": candidate,
            },
            "claim_boundary": {
                "const": "exhaustive_plausibility_screen_only_no_qualification_or_disposition"
            },
            "oracle_activation": {"const": False},
        },
    }


def _blob_index(blob_set: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "git_object_id": blob["git_object_id"],
            "path": blob["path"],
            "sha256": blob["sha256"],
            "size_bytes": blob["size_bytes"],
        }
        for blob in cast(list[dict[str, Any]], blob_set["blobs"])
    ]


def _scan_blob_set(repository_root: Path, blob_set: dict[str, Any]) -> dict[str, Any]:
    blobs = cast(list[dict[str, Any]], blob_set["blobs"])
    object_ids = [cast(str, blob["git_object_id"]) for blob in blobs]
    payloads = _read_blobs(repository_root, object_ids)
    matches: list[dict[str, Any]] = []
    for blob in blobs:
        object_id = cast(str, blob["git_object_id"])
        payload = payloads[object_id]
        if sha256_digest(payload) != blob["sha256"]:
            raise CandidateInterfaceFitDenominatorError(
                f"candidate blob digest drifted: {blob['path']}"
            )
        if len(payload) != blob["size_bytes"]:
            raise CandidateInterfaceFitDenominatorError(
                f"candidate blob size drifted: {blob['path']}"
            )
        lowered = payload.lower()
        for term in _ALL_TERMS:
            occurrences = len(_TOKEN_PATTERNS[term].findall(lowered))
            if occurrences:
                matches.append(
                    {
                        "occurrences": occurrences,
                        "path": blob["path"],
                        "term": term,
                    }
                )
    index_digest = sha256_digest(canonical_document_bytes(_blob_index(blob_set)))
    scan_core = {
        "blob_count": len(blobs),
        "blob_index_digest": index_digest,
        "blob_set_digest": blob_set["blob_set_digest"],
        "candidate_group": blob_set["candidate_group"],
        "coverage": {
            "expected": len(blobs),
            "scanned": len(blobs),
            "unreadable": 0,
            "unverified": 0,
        },
        "source_surface": blob_set["source_surface"],
        "term_matches": matches,
    }
    return {
        **scan_core,
        "scan_digest": sha256_digest(canonical_document_bytes(scan_core)),
    }


def _missing_probes(capability_id: str, scan: dict[str, Any]) -> list[str]:
    matched_terms = {
        cast(str, item["term"])
        for item in cast(list[dict[str, Any]], scan["term_matches"])
    }
    missing = [
        probe_id
        for probe_id, terms in _PROBES[capability_id]
        if not any(term.decode("ascii") in matched_terms for term in terms)
    ]
    if not missing:
        raise CandidateInterfaceFitDenominatorError(
            "candidate requires semantic adapter review instead of negative evidence: "
            f"{capability_id}:{scan['candidate_group']}"
        )
    return missing


def build_candidate_interface_fit_denominator_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    all_candidates = cast(list[dict[str, Any]], bundle["candidates"])
    selected = [
        candidate
        for candidate in all_candidates
        if candidate["capability_id"] in CAPABILITIES
    ]
    selected.sort(key=lambda item: (item["capability_id"], item["candidate_group"]))
    counts = {
        capability_id: sum(
            candidate["capability_id"] == capability_id for candidate in selected
        )
        for capability_id in CAPABILITIES
    }
    referenced_digests = {
        cast(str, candidate["blob_set_digest"]) for candidate in selected
    }
    all_blob_sets = cast(list[dict[str, Any]], bundle["blob_sets"])
    selected_blob_sets = [
        blob_set
        for blob_set in all_blob_sets
        if blob_set["blob_set_digest"] in referenced_digests
    ]
    selected_blob_sets.sort(
        key=lambda item: (item["source_surface"], item["candidate_group"])
    )
    scans = [
        _scan_blob_set(repository_root, blob_set) for blob_set in selected_blob_sets
    ]
    scans_by_digest = {cast(str, scan["blob_set_digest"]): scan for scan in scans}
    candidate_records: list[dict[str, Any]] = []
    for candidate in selected:
        scan = scans_by_digest.get(cast(str, candidate["blob_set_digest"]))
        if scan is None:
            raise CandidateInterfaceFitDenominatorError(
                "candidate references an unscanned blob set"
            )
        capability_id = cast(str, candidate["capability_id"])
        candidate_records.append(
            {
                "blob_count": candidate["blob_count"],
                "blob_set_digest": candidate["blob_set_digest"],
                "candidate_group": candidate["candidate_group"],
                "candidate_id": candidate["candidate_id"],
                "candidate_manifest_digest": candidate["manifest_digest"],
                "capability_id": capability_id,
                "missing_probe_ids": _missing_probes(capability_id, scan),
                "plausibility_state": (
                    "no_direct_candidate_level_admission_surface_observed"
                ),
                "scan_digest": scan["scan_digest"],
            }
        )
    candidate_memberships = sum(
        cast(int, candidate["blob_count"]) for candidate in selected
    )
    blob_set_memberships = sum(cast(int, scan["blob_count"]) for scan in scans)
    document = {
        "schema_version": SCHEMA_VERSION,
        "evidence_version": EVIDENCE_VERSION,
        "source_repository": PINNED_SOURCE_REPOSITORY,
        "source_commit": PINNED_SOURCE_COMMIT,
        "source_tree_id": PINNED_SOURCE_TREE,
        "candidate_inputs": _artifact_ref(repository_root, CANDIDATE_INPUTS_RELATIVE),
        "qualification_interfaces": _artifact_ref(
            repository_root, INTERFACE_MANIFEST_RELATIVE
        ),
        "qualification_test_vectors": _artifact_ref(
            repository_root, VECTOR_MANIFEST_RELATIVE
        ),
        "derivation_artifacts": [
            _artifact_ref(repository_root, relative_path)
            for relative_path in DERIVATION_RELATIVES
        ],
        "selection_policy": (
            "all_discovered_candidate_manifests_for_admission_capabilities"
        ),
        "capability_candidate_counts": counts,
        "candidate_count": len(candidate_records),
        "candidate_blob_membership_count": candidate_memberships,
        "blob_set_scan_count": len(scans),
        "blob_set_membership_count": blob_set_memberships,
        "coverage": {
            "expected": blob_set_memberships,
            "scanned": blob_set_memberships,
            "unreadable": 0,
            "unverified": 0,
        },
        "blob_set_scans": scans,
        "candidates": candidate_records,
        "claim_boundary": (
            "exhaustive_plausibility_screen_only_no_qualification_or_disposition"
        ),
        "oracle_activation": False,
    }
    errors = sorted(
        Draft202012Validator(evidence_schema()).iter_errors(document), key=str
    )
    if errors:
        raise CandidateInterfaceFitDenominatorError(
            f"interface-fit denominator schema violation: {errors[0]}"
        )
    return {
        SCHEMA_RELATIVE: canonical_document_bytes(evidence_schema()),
        OUTPUT_RELATIVE: canonical_document_bytes(document),
    }


def write_candidate_interface_fit_denominator_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_candidate_interface_fit_denominator_evidence(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_candidate_interface_fit_denominator_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_candidate_interface_fit_denominator_evidence(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise CandidateInterfaceFitDenominatorError(
                f"committed denominator evidence is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise CandidateInterfaceFitDenominatorError(
                f"committed denominator evidence drifted: {relative_path}"
            )


__all__ = [
    "CandidateInterfaceFitDenominatorError",
    "build_candidate_interface_fit_denominator_evidence",
    "check_candidate_interface_fit_denominator_evidence",
    "write_candidate_interface_fit_denominator_evidence",
]
