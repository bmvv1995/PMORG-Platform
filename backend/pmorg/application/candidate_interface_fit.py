"""Build byte-closed, non-verdict candidate interface-fit evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator

from pmorg.application.candidate_inputs import _read_blobs
from pmorg.application.candidate_inputs import PINNED_SOURCE_COMMIT
from pmorg.application.candidate_inputs import PINNED_SOURCE_REPOSITORY
from pmorg.application.candidate_inputs import PINNED_SOURCE_TREE
from pmorg.application.candidate_inputs import validate_candidate_input_bundle

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
INTERFACE_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-interfaces-v1.json"
VECTOR_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-test-vectors-v1.json"
OUTPUT_RELATIVE = "pmorg/capabilities/candidate-interface-fit-evidence-v1.json"
SCHEMA_RELATIVE = "pmorg/capabilities/candidate-interface-fit-evidence-v1.schema.json"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/candidate_interface_fit.py",
    "pmorg/scripts/build_candidate_interface_fit.py",
)

SCHEMA_VERSION = "pmorg.candidate-interface-fit-evidence/v1"
EVIDENCE_VERSION = "1.0.0"

_SELECTION: dict[str, tuple[str, ...]] = {
    "deployment-admission": (
        "deployment/aws_ecs_fargate",
        "deployment/data",
        "deployment/docker_compose",
        "deployment/helm",
        "deployment/terraform",
        "loadtest/k8s",
    ),
    "distribution-admission": (
        ".github/workflows",
        "backend/onyx/connectors",
        "backend/onyx/federated_connectors",
        "backend/onyx/file_store",
        "cli/cmd",
        "cli/internal",
    ),
}

_PROBES: dict[str, tuple[tuple[str, tuple[bytes, ...]], ...]] = {
    "deployment-admission": (
        ("pmorg-authority", (b"pmorg", b"pmorg-contracts/1.0")),
        ("qualified-build-measurement", (b"bqm",)),
        ("qualified-build-attestation", (b"bqa",)),
        (
            "signed-deployment-admission",
            (b"signed deployment admission", b"deploymentadmissionrecord"),
        ),
        ("dsse-envelope", (b"dsse",)),
        ("pre-deadline-quiesce", (b"quiesce",)),
    ),
    "distribution-admission": (
        ("pmorg-authority", (b"pmorg", b"pmorg-contracts/1.0")),
        ("qualified-build-measurement", (b"bqm",)),
        ("qualified-build-attestation", (b"bqa",)),
        (
            "signed-distribution-admission",
            (b"signed distribution admission", b"distributionadmissionrecord"),
        ),
        ("dsse-envelope", (b"dsse",)),
        ("active-transfer-abort", (b"active-transfer abort", b"abort transfer")),
    ),
}


class CandidateInterfaceFitError(ValueError):
    """Raised when interface-fit evidence cannot be reproduced exactly."""


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
        raise CandidateInterfaceFitError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateInterfaceFitError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise CandidateInterfaceFitError(f"artifact is not an object: {relative_path}")
    return value


def _artifact_ref(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise CandidateInterfaceFitError(
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
    blob = {
        "type": "object",
        "additionalProperties": False,
        "required": ["git_object_id", "path", "sha256", "size_bytes"],
        "properties": {
            "git_object_id": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "path": nonempty,
            "sha256": digest,
            "size_bytes": {"type": "integer", "minimum": 0},
        },
    }
    marker_match = {
        "type": "object",
        "additionalProperties": False,
        "required": ["occurrences", "path", "term"],
        "properties": {
            "occurrences": {"type": "integer", "minimum": 1},
            "path": nonempty,
            "term": nonempty,
        },
    }
    probe = {
        "type": "object",
        "additionalProperties": False,
        "required": ["matches", "probe_id", "satisfied", "terms"],
        "properties": {
            "matches": {"type": "array", "items": marker_match},
            "probe_id": nonempty,
            "satisfied": {"type": "boolean"},
            "terms": {
                "type": "array",
                "minItems": 1,
                "items": nonempty,
                "uniqueItems": True,
            },
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
            "coverage",
            "inspected_blobs",
            "missing_probe_ids",
            "plausibility_state",
            "probes",
        ],
        "properties": {
            "blob_count": {"type": "integer", "minimum": 1},
            "blob_set_digest": digest,
            "candidate_group": nonempty,
            "candidate_id": nonempty,
            "candidate_manifest_digest": digest,
            "capability_id": {
                "enum": ["deployment-admission", "distribution-admission"]
            },
            "coverage": {
                "type": "object",
                "additionalProperties": False,
                "required": ["expected", "scanned", "unreadable", "unverified"],
                "properties": {
                    "expected": {"type": "integer", "minimum": 1},
                    "scanned": {"type": "integer", "minimum": 1},
                    "unreadable": {"const": 0},
                    "unverified": {"const": 0},
                },
            },
            "inspected_blobs": {
                "type": "array",
                "minItems": 1,
                "items": blob,
            },
            "missing_probe_ids": {
                "type": "array",
                "minItems": 1,
                "items": nonempty,
                "uniqueItems": True,
            },
            "plausibility_state": {
                "const": "no_direct_candidate_level_admission_surface_observed"
            },
            "probes": {"type": "array", "minItems": 1, "items": probe},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:candidate-interface-fit-evidence:v1",
        "title": "PMORG candidate interface-fit evidence",
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
            "candidates",
            "candidate_count",
            "coverage",
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
                "minItems": 2,
                "maxItems": 2,
                "items": artifact,
            },
            "selection_policy": {
                "type": "object",
                "additionalProperties": False,
                "required": ["deployment-admission", "distribution-admission"],
                "properties": {
                    capability: {
                        "type": "array",
                        "minItems": 6,
                        "maxItems": 6,
                        "items": nonempty,
                        "uniqueItems": True,
                    }
                    for capability in sorted(_SELECTION)
                },
            },
            "candidates": {
                "type": "array",
                "minItems": 12,
                "maxItems": 12,
                "items": candidate,
            },
            "candidate_count": {"const": 12},
            "coverage": {
                "type": "object",
                "additionalProperties": False,
                "required": ["expected", "scanned", "unreadable", "unverified"],
                "properties": {
                    "expected": {"type": "integer", "minimum": 12},
                    "scanned": {"type": "integer", "minimum": 12},
                    "unreadable": {"const": 0},
                    "unverified": {"const": 0},
                },
            },
            "claim_boundary": {
                "const": "plausibility_screen_only_no_qualification_or_disposition"
            },
            "oracle_activation": {"const": False},
        },
    }


def _probe_candidate(
    capability_id: str,
    blobs: list[dict[str, Any]],
    payloads: dict[str, bytes],
) -> tuple[list[dict[str, Any]], list[str]]:
    probes: list[dict[str, Any]] = []
    missing: list[str] = []
    for probe_id, raw_terms in _PROBES[capability_id]:
        matches: list[dict[str, Any]] = []
        for blob in blobs:
            path = cast(str, blob["path"])
            payload = payloads[cast(str, blob["git_object_id"])].lower()
            for raw_term in raw_terms:
                occurrences = payload.count(raw_term)
                if occurrences:
                    matches.append(
                        {
                            "occurrences": occurrences,
                            "path": path,
                            "term": raw_term.decode("ascii"),
                        }
                    )
        satisfied = bool(matches)
        if not satisfied:
            missing.append(probe_id)
        probes.append(
            {
                "matches": matches,
                "probe_id": probe_id,
                "satisfied": satisfied,
                "terms": [term.decode("ascii") for term in raw_terms],
            }
        )
    return probes, missing


def build_candidate_interface_fit_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    candidates = cast(list[dict[str, Any]], bundle["candidates"])
    blob_sets = {
        cast(str, item["blob_set_digest"]): item
        for item in cast(list[dict[str, Any]], bundle["blob_sets"])
    }
    selected: list[dict[str, Any]] = []
    expected_total = 0
    for capability_id, groups in sorted(_SELECTION.items()):
        for candidate_group in groups:
            matches = [
                item
                for item in candidates
                if item["capability_id"] == capability_id
                and item["candidate_group"] == candidate_group
            ]
            if len(matches) != 1:
                raise CandidateInterfaceFitError(
                    "selected candidate identity is not unique: "
                    f"{capability_id}:{candidate_group}"
                )
            candidate = matches[0]
            blob_set = blob_sets.get(cast(str, candidate["blob_set_digest"]))
            if blob_set is None:
                raise CandidateInterfaceFitError(
                    "selected candidate blob set is missing"
                )
            blobs = cast(list[dict[str, Any]], blob_set["blobs"])
            object_ids = [cast(str, blob["git_object_id"]) for blob in blobs]
            payloads = _read_blobs(repository_root, object_ids)
            for blob in blobs:
                object_id = cast(str, blob["git_object_id"])
                payload = payloads[object_id]
                if sha256_digest(payload) != blob["sha256"]:
                    raise CandidateInterfaceFitError(
                        f"selected candidate blob digest drifted: {blob['path']}"
                    )
                if len(payload) != blob["size_bytes"]:
                    raise CandidateInterfaceFitError(
                        f"selected candidate blob size drifted: {blob['path']}"
                    )
            probes, missing = _probe_candidate(capability_id, blobs, payloads)
            if not missing:
                raise CandidateInterfaceFitError(
                    "selected candidate requires semantic adapter review instead of "
                    f"negative fit evidence: {candidate['candidate_id']}"
                )
            expected_total += len(blobs)
            selected.append(
                {
                    "blob_count": len(blobs),
                    "blob_set_digest": candidate["blob_set_digest"],
                    "candidate_group": candidate_group,
                    "candidate_id": candidate["candidate_id"],
                    "candidate_manifest_digest": candidate["manifest_digest"],
                    "capability_id": capability_id,
                    "coverage": {
                        "expected": len(blobs),
                        "scanned": len(blobs),
                        "unreadable": 0,
                        "unverified": 0,
                    },
                    "inspected_blobs": [
                        {
                            "git_object_id": blob["git_object_id"],
                            "path": blob["path"],
                            "sha256": blob["sha256"],
                            "size_bytes": blob["size_bytes"],
                        }
                        for blob in blobs
                    ],
                    "missing_probe_ids": missing,
                    "plausibility_state": (
                        "no_direct_candidate_level_admission_surface_observed"
                    ),
                    "probes": probes,
                }
            )
    selected.sort(key=lambda item: (item["capability_id"], item["candidate_group"]))
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
        "selection_policy": {
            capability_id: list(groups)
            for capability_id, groups in sorted(_SELECTION.items())
        },
        "candidates": selected,
        "candidate_count": len(selected),
        "coverage": {
            "expected": expected_total,
            "scanned": expected_total,
            "unreadable": 0,
            "unverified": 0,
        },
        "claim_boundary": ("plausibility_screen_only_no_qualification_or_disposition"),
        "oracle_activation": False,
    }
    validator = Draft202012Validator(evidence_schema())
    errors = sorted(validator.iter_errors(document), key=str)
    if errors:
        raise CandidateInterfaceFitError(
            f"candidate interface-fit evidence schema violation: {errors[0]}"
        )
    return {
        SCHEMA_RELATIVE: canonical_document_bytes(evidence_schema()),
        OUTPUT_RELATIVE: canonical_document_bytes(document),
    }


def write_candidate_interface_fit_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_candidate_interface_fit_evidence(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_candidate_interface_fit_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_candidate_interface_fit_evidence(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise CandidateInterfaceFitError(
                f"committed interface-fit artifact is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise CandidateInterfaceFitError(
                f"committed interface-fit artifact drifted: {relative_path}"
            )


__all__ = [
    "CandidateInterfaceFitError",
    "build_candidate_interface_fit_evidence",
    "check_candidate_interface_fit_evidence",
    "write_candidate_interface_fit_evidence",
]
