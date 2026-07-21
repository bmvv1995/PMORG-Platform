"""Build an unactivated Thin Fork Boundary qualification-vector extension."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VECTOR_RELATIVE = (
    "pmorg/capabilities/qualification-test-vector-extensions/"
    "thin-fork-boundary-A-PATCH-001-v1.json"
)
MANIFEST_RELATIVE = (
    "pmorg/capabilities/qualification-test-vector-extension-thin-fork-v1.json"
)
VECTOR_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-test-vector-v1.schema.json"
BASE_VECTOR_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-test-vectors-v1.json"
ORACLE_POLICY_RELATIVE = "pmorg/capabilities/qualification-oracle-policy-v1.json"
INTERFACE_RELATIVE = (
    "pmorg/capabilities/qualification-interfaces/thin-fork-boundary-v1.json"
)
IMPLEMENTATION_RELATIVE = "pmorg/scripts/verify_fork.py"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/qualification_test_vector_extensions.py",
    "pmorg/scripts/build_qualification_test_vector_extensions.py",
)
RUNTIME_ARTIFACTS = (
    (".python-version", "text/plain"),
    ("pyproject.toml", "application/toml"),
    ("uv.lock", "application/toml"),
)


class QualificationTestVectorExtensionError(ValueError):
    """Raised when the extension or its immutable predecessor binding drifts."""


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
        raise QualificationTestVectorExtensionError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    path = _safe_path(repository_root, relative_path)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationTestVectorExtensionError(
            f"bound JSON is unreadable: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise QualificationTestVectorExtensionError(
            f"bound JSON is not an object: {relative_path}"
        )
    return value


def _artifact_ref(
    repository_root: Path, relative_path: str, *, media_type: str
) -> dict[str, Any]:
    path = _safe_path(repository_root, relative_path)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise QualificationTestVectorExtensionError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return {
        "digest": sha256_digest(payload),
        "media_type": media_type,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _assert_predecessor_is_unactivated(repository_root: Path) -> dict[str, Any]:
    policy = _read_object(repository_root, ORACLE_POLICY_RELATIVE)
    matching = [
        oracle
        for oracle in policy.get("oracles", [])
        if isinstance(oracle, dict)
        and oracle.get("capability_id") == "thin-fork-boundary"
        and oracle.get("test_id") == "A-PATCH-001"
    ]
    if len(matching) != 1:
        raise QualificationTestVectorExtensionError(
            "predecessor policy does not contain exactly one Thin Fork oracle"
        )
    oracle = matching[0]
    if (
        oracle.get("oracle_status") != "unexecutable"
        or oracle.get("adapter") is not None
        or oracle.get("candidate_test_vector") is not None
    ):
        raise QualificationTestVectorExtensionError(
            "Thin Fork oracle is already activated or vector-bound"
        )
    return {
        "adapter": None,
        "candidate_test_vector": None,
        "oracle_id": oracle.get("oracle_id"),
        "oracle_status": "unexecutable",
    }


def build_qualification_test_vector_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    schema = _read_object(repository_root, VECTOR_SCHEMA_RELATIVE)
    runtime_artifacts = [
        _artifact_ref(repository_root, path, media_type=media_type)
        for path, media_type in RUNTIME_ARTIFACTS
    ]
    runtime_contract = {
        "schema_version": "pmorg.qualification-runtime-identity-contract/v1",
        "status": "binary_measurement_required_at_execution",
        "interpreter_binary_evidence": {
            "algorithm": "sha256",
            "required_fields": [
                "implementation",
                "version",
                "executable_digest",
                "executable_size_bytes",
            ],
        },
        "artifacts": runtime_artifacts,
        "pass_requirements": [
            "the invoked interpreter binary is measured before adapter execution",
            "the measured interpreter satisfies the committed .python-version",
            "dependencies resolve only from the exact committed uv.lock",
            "runtime evidence and lock artifact digests are bound into the result",
        ],
    }
    runtime_digest = sha256_digest(canonical_document_bytes(runtime_contract))
    vector = {
        "schema_version": "pmorg.qualification-test-vector/v1",
        "vector_version": "1.0.0",
        "capability_id": "thin-fork-boundary",
        "test_id": "A-PATCH-001",
        "candidate_projection": "module_group_blob_set/v1",
        "qualification_interface": _artifact_ref(
            repository_root, INTERFACE_RELATIVE, media_type="application/json"
        ),
        "reference_implementation": _artifact_ref(
            repository_root, IMPLEMENTATION_RELATIVE, media_type="text/x-python"
        ),
        "adapter_input_contract": [
            "exact candidate input manifest and manifest digest",
            "all projected candidate blob bytes and blob digests",
            "exact qualification interface and test-vector digests",
            "measured interpreter binary and committed dependency lock digests",
        ],
        "runtime_identity": {
            "artifacts": runtime_artifacts,
            "contract_digest": runtime_digest,
            "interpreter_measurement": "sha256_of_executed_interpreter_binary",
            "status": "binary_measurement_required_at_execution",
        },
        "test_cases": [
            {
                "candidate_bytes_required": True,
                "case_id": "exact-owned-change",
                "expected_observation": "return an empty ordered violation set only for the exactly governed tree",
                "mutation_required": False,
                "stimulus": "present an exact candidate tree whose changed paths have one PMORG-owned policy route and complete ledger evidence",
            },
            {
                "candidate_bytes_required": True,
                "case_id": "unknown-or-multiple-owner",
                "expected_observation": "reject fail-closed and cite the exact changed path",
                "mutation_required": False,
                "stimulus": "add a changed path with no owner or more than one ownership route",
            },
            {
                "candidate_bytes_required": True,
                "case_id": "trust-boundary-or-upstream-drift",
                "expected_observation": "reject before accepting the tree and report the exact policy violation",
                "mutation_required": False,
                "stimulus": "mutate a trust-boundary or upstream-owned path without its required governance route",
            },
            {
                "candidate_bytes_required": True,
                "case_id": "historical-evidence-or-seam-drift",
                "expected_observation": "reject the hybrid governance state with exact evidence and seam paths",
                "mutation_required": False,
                "stimulus": "change immutable predecessor evidence or introduce an unknown or successor-unbound seam",
            },
            {
                "candidate_bytes_required": True,
                "case_id": "candidate-byte-influence",
                "expected_observation": "at least one adapter observation or verdict changes",
                "mutation_required": True,
                "stimulus": "flip one byte in a projected candidate blob and rebuild its manifest",
            },
        ],
        "mutation_probe": {
            "expectation": "at_least_one_observation_or_verdict_changes",
            "no_op_rejected": True,
            "operation": "flip_one_candidate_blob_byte",
            "target": "projected_candidate_blob_bytes",
        },
        "execution_preconditions": [
            "adapter is content-addressed and explicitly bound to this test vector",
            "adapter consumes the exact candidate manifest and every projected blob",
            "interpreter binary and dependency lock identities are evidence-bound",
            "baseline and mutated executions both produce schema-valid evidence",
        ],
        "claim_boundary": "definition_only_no_qualification_verdict",
    }
    errors = sorted(Draft202012Validator(schema).iter_errors(vector), key=str)
    if errors:
        raise QualificationTestVectorExtensionError(
            f"Thin Fork vector schema violation: {errors[0]}"
        )
    vector_payload = canonical_document_bytes(vector)
    predecessor_state = _assert_predecessor_is_unactivated(repository_root)
    manifest = {
        "schema_version": "pmorg.qualification-test-vector-extension-manifest/v1",
        "extension_id": "thin-fork-boundary-A-PATCH-001-v1",
        "activation_status": "definition_only_unactivated",
        "claim_boundary": "no_oracle_activation_or_qualification_verdict",
        "immutable_predecessors": {
            "base_vector_manifest": _artifact_ref(
                repository_root,
                BASE_VECTOR_MANIFEST_RELATIVE,
                media_type="application/json",
            ),
            "oracle_policy": _artifact_ref(
                repository_root, ORACLE_POLICY_RELATIVE, media_type="application/json"
            ),
            "oracle_state": predecessor_state,
        },
        "runtime_identity_contract": runtime_contract,
        "runtime_identity_contract_digest": runtime_digest,
        "vector_schema": _artifact_ref(
            repository_root,
            VECTOR_SCHEMA_RELATIVE,
            media_type="application/schema+json",
        ),
        "vector": {
            "capability_id": "thin-fork-boundary",
            "test_id": "A-PATCH-001",
            "digest": sha256_digest(vector_payload),
            "media_type": "application/json",
            "relative_path": VECTOR_RELATIVE,
            "size_bytes": len(vector_payload),
        },
        "derivation_artifacts": [
            _artifact_ref(repository_root, path, media_type="text/x-python")
            for path in DERIVATION_RELATIVES
        ],
    }
    return {
        VECTOR_RELATIVE: vector_payload,
        MANIFEST_RELATIVE: canonical_document_bytes(manifest),
    }


def write_qualification_test_vector_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_qualification_test_vector_extension(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_qualification_test_vector_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, expected in build_qualification_test_vector_extension(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise QualificationTestVectorExtensionError(
                f"committed extension artifact is missing: {relative_path}"
            ) from error
        if actual != expected:
            raise QualificationTestVectorExtensionError(
                f"committed extension artifact drifted: {relative_path}"
            )


__all__ = [
    "QualificationTestVectorExtensionError",
    "build_qualification_test_vector_extension",
    "check_qualification_test_vector_extension",
    "write_qualification_test_vector_extension",
]
