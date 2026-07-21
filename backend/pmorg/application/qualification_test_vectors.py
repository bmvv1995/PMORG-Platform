"""Build and verify candidate-level qualification test-vector definitions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
INTERFACE_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-interfaces-v1.json"
VECTOR_ROOT = "pmorg/capabilities/qualification-test-vectors"
VECTOR_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-test-vector-v1.schema.json"
VECTOR_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-test-vectors-v1.json"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/qualification_test_vectors.py",
    "pmorg/scripts/build_qualification_test_vectors.py",
)
RUNTIME_ARTIFACTS = (
    (".python-version", "text/plain"),
    ("pyproject.toml", "application/toml"),
    ("uv.lock", "application/toml"),
)

VECTOR_SCHEMA_VERSION = "pmorg.qualification-test-vector/v1"
MANIFEST_SCHEMA_VERSION = "pmorg.qualification-test-vector-manifest/v1"
RUNTIME_SCHEMA_VERSION = "pmorg.qualification-runtime-identity-contract/v1"
VECTOR_VERSION = "1.0.0"


class QualificationTestVectorError(ValueError):
    """Raised when a candidate-level vector or binding is not exact."""


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
        raise QualificationTestVectorError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationTestVectorError(f"{label} is not readable JSON") from error
    if not isinstance(value, dict):
        raise QualificationTestVectorError(f"{label} must be an object")
    return value


def _artifact_ref(
    repository_root: Path,
    relative_path: str,
    *,
    media_type: str,
) -> dict[str, Any]:
    path = _safe_path(repository_root, relative_path)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise QualificationTestVectorError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return {
        "digest": sha256_digest(payload),
        "media_type": media_type,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def vector_schema() -> dict[str, Any]:
    string = {"type": "string", "minLength": 1}
    artifact = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "media_type", "relative_path", "size_bytes"],
        "properties": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "media_type": string,
            "relative_path": string,
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }
    test_case = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "candidate_bytes_required",
            "case_id",
            "expected_observation",
            "mutation_required",
            "stimulus",
        ],
        "properties": {
            "candidate_bytes_required": {"const": True},
            "case_id": string,
            "expected_observation": string,
            "mutation_required": {"type": "boolean"},
            "stimulus": string,
        },
    }
    runtime = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "artifacts",
            "contract_digest",
            "interpreter_measurement",
            "status",
        ],
        "properties": {
            "artifacts": {
                "type": "array",
                "minItems": 3,
                "maxItems": 3,
                "items": artifact,
            },
            "contract_digest": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "interpreter_measurement": {
                "const": "sha256_of_executed_interpreter_binary"
            },
            "status": {"const": "binary_measurement_required_at_execution"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:qualification-test-vector:v1",
        "title": "PMORG candidate-level qualification test vector",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "vector_version",
            "capability_id",
            "test_id",
            "candidate_projection",
            "qualification_interface",
            "reference_implementation",
            "adapter_input_contract",
            "runtime_identity",
            "test_cases",
            "mutation_probe",
            "execution_preconditions",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": VECTOR_SCHEMA_VERSION},
            "vector_version": {"const": VECTOR_VERSION},
            "capability_id": string,
            "test_id": string,
            "candidate_projection": {"const": "module_group_blob_set/v1"},
            "qualification_interface": artifact,
            "reference_implementation": artifact,
            "adapter_input_contract": {
                "type": "array",
                "minItems": 4,
                "items": string,
                "uniqueItems": True,
            },
            "runtime_identity": runtime,
            "test_cases": {
                "type": "array",
                "minItems": 4,
                "items": test_case,
            },
            "mutation_probe": {
                "type": "object",
                "additionalProperties": False,
                "required": ["expectation", "no_op_rejected", "operation", "target"],
                "properties": {
                    "expectation": {
                        "const": "at_least_one_observation_or_verdict_changes"
                    },
                    "no_op_rejected": {"const": True},
                    "operation": {"const": "flip_one_candidate_blob_byte"},
                    "target": {"const": "projected_candidate_blob_bytes"},
                },
            },
            "execution_preconditions": {
                "type": "array",
                "minItems": 4,
                "items": string,
                "uniqueItems": True,
            },
            "claim_boundary": {"const": "definition_only_no_qualification_verdict"},
        },
    }


_BLUEPRINTS: dict[tuple[str, str], dict[str, Any]] = {
    ("deployment-admission", "A-LIC-002"): {
        "implementation": "backend/pmorg/application/admission.py",
        "cases": [
            (
                "valid-development-test-admission",
                "valid signed admission for an exact synthetic payload and target",
                "allow only for the exactly bound payload and target",
                False,
            ),
            (
                "missing-or-invalid-admission",
                "remove or corrupt the admission envelope",
                "deny before deploy or startup",
                False,
            ),
            (
                "payload-or-target-drift",
                "mutate the payload or measured target after admission",
                "deny the drifted identity",
                False,
            ),
            (
                "production-or-unknown-target",
                "present production or unknown target scope",
                "deny in development_test scope",
                False,
            ),
            (
                "candidate-byte-influence",
                "flip one byte in a projected candidate blob and rebuild its manifest",
                "at least one adapter observation or verdict changes",
                True,
            ),
        ],
    },
    ("distribution-admission", "A-LIC-003"): {
        "implementation": "backend/pmorg/application/distribution_admission.py",
        "cases": [
            (
                "valid-controlled-synthetic-destination",
                "valid signed admission for the exact subset and measured destination",
                "allow only for the exactly bound subset and destination",
                False,
            ),
            (
                "missing-or-invalid-admission",
                "remove or corrupt the distribution admission envelope",
                "deny before publish or export",
                False,
            ),
            (
                "post-auth-or-redirect-drift",
                "change destination identity after auth or redirect",
                "deny or abort before any further transfer",
                False,
            ),
            (
                "production-or-unknown-destination",
                "present production or unknown destination scope",
                "deny in development_test scope",
                False,
            ),
            (
                "candidate-byte-influence",
                "flip one byte in a projected candidate blob and rebuild its manifest",
                "at least one adapter observation or verdict changes",
                True,
            ),
        ],
    },
}


def _interface_refs(repository_root: Path) -> dict[str, dict[str, Any]]:
    manifest = _read_object(
        _safe_path(repository_root, INTERFACE_MANIFEST_RELATIVE),
        label="qualification-interface manifest",
    )
    interfaces = manifest.get("interfaces")
    if not isinstance(interfaces, list):
        raise QualificationTestVectorError("qualification interfaces are missing")
    result: dict[str, dict[str, Any]] = {}
    for raw in cast(list[dict[str, Any]], interfaces):
        capability_id = raw.get("capability_id")
        relative_path = raw.get("relative_path")
        if not isinstance(capability_id, str) or not isinstance(relative_path, str):
            raise QualificationTestVectorError("qualification interface is invalid")
        actual = _artifact_ref(
            repository_root, relative_path, media_type="application/json"
        )
        expected = {
            key: raw[key]
            for key in ("digest", "media_type", "relative_path", "size_bytes")
        }
        if actual != expected or capability_id in result:
            raise QualificationTestVectorError("qualification interface drifted")
        result[capability_id] = expected
    return result


def _runtime_identity_contract(repository_root: Path) -> dict[str, Any]:
    artifacts = [
        _artifact_ref(repository_root, path, media_type=media_type)
        for path, media_type in RUNTIME_ARTIFACTS
    ]
    return {
        "schema_version": RUNTIME_SCHEMA_VERSION,
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
        "artifacts": artifacts,
        "pass_requirements": [
            "the invoked interpreter binary is measured before adapter execution",
            "the measured interpreter satisfies the committed .python-version",
            "dependencies resolve only from the exact committed uv.lock",
            "runtime evidence and lock artifact digests are bound into the result",
        ],
    }


def build_qualification_test_vectors(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    interfaces = _interface_refs(repository_root)
    runtime_contract = _runtime_identity_contract(repository_root)
    runtime_digest = sha256_digest(canonical_document_bytes(runtime_contract))
    outputs: dict[str, bytes] = {
        VECTOR_SCHEMA_RELATIVE: canonical_document_bytes(vector_schema())
    }
    references: list[dict[str, Any]] = []
    validator = Draft202012Validator(vector_schema())
    for (capability_id, test_id), blueprint in sorted(_BLUEPRINTS.items()):
        if capability_id not in interfaces:
            raise QualificationTestVectorError(
                f"qualification interface missing for {capability_id}"
            )
        runtime_identity = {
            "artifacts": runtime_contract["artifacts"],
            "contract_digest": runtime_digest,
            "interpreter_measurement": "sha256_of_executed_interpreter_binary",
            "status": "binary_measurement_required_at_execution",
        }
        document = {
            "schema_version": VECTOR_SCHEMA_VERSION,
            "vector_version": VECTOR_VERSION,
            "capability_id": capability_id,
            "test_id": test_id,
            "candidate_projection": "module_group_blob_set/v1",
            "qualification_interface": interfaces[capability_id],
            "reference_implementation": _artifact_ref(
                repository_root,
                cast(str, blueprint["implementation"]),
                media_type="text/x-python",
            ),
            "adapter_input_contract": [
                "exact candidate input manifest and manifest digest",
                "all projected candidate blob bytes and blob digests",
                "exact qualification interface and test-vector digests",
                "measured interpreter binary and committed dependency lock digests",
            ],
            "runtime_identity": runtime_identity,
            "test_cases": [
                {
                    "case_id": case_id,
                    "stimulus": stimulus,
                    "expected_observation": expected,
                    "candidate_bytes_required": True,
                    "mutation_required": mutation,
                }
                for case_id, stimulus, expected, mutation in blueprint["cases"]
            ],
            "mutation_probe": {
                "target": "projected_candidate_blob_bytes",
                "operation": "flip_one_candidate_blob_byte",
                "expectation": "at_least_one_observation_or_verdict_changes",
                "no_op_rejected": True,
            },
            "execution_preconditions": [
                "adapter is content-addressed and explicitly bound to this test vector",
                "adapter consumes the exact candidate manifest and every projected blob",
                "interpreter binary and dependency lock identities are evidence-bound",
                "baseline and mutated executions both produce schema-valid evidence",
            ],
            "claim_boundary": "definition_only_no_qualification_verdict",
        }
        errors = sorted(validator.iter_errors(document), key=str)
        if errors:
            raise QualificationTestVectorError(
                f"{capability_id} vector schema violation: {errors[0]}"
            )
        mutation_cases = [
            item for item in document["test_cases"] if item["mutation_required"]
        ]
        if len(mutation_cases) != 1:
            raise QualificationTestVectorError(
                f"{capability_id} must define exactly one mutation case"
            )
        relative_path = f"{VECTOR_ROOT}/{capability_id}-{test_id}-v1.json"
        payload = canonical_document_bytes(document)
        outputs[relative_path] = payload
        references.append(
            {
                "capability_id": capability_id,
                "test_id": test_id,
                "digest": sha256_digest(payload),
                "media_type": "application/json",
                "relative_path": relative_path,
                "size_bytes": len(payload),
            }
        )
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "vector_version": VECTOR_VERSION,
        "candidate_projection": "module_group_blob_set/v1",
        "runtime_identity_contract": runtime_contract,
        "runtime_identity_contract_digest": runtime_digest,
        "vectors": references,
        "vector_count": len(references),
        "derivation_artifacts": [
            _artifact_ref(repository_root, path, media_type="text/x-python")
            for path in DERIVATION_RELATIVES
        ],
    }
    outputs[VECTOR_MANIFEST_RELATIVE] = canonical_document_bytes(manifest)
    return outputs


def write_qualification_test_vectors(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_qualification_test_vectors(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_qualification_test_vectors(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_qualification_test_vectors(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        try:
            actual = path.read_bytes()
        except OSError as error:
            raise QualificationTestVectorError(
                f"committed test-vector artifact is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise QualificationTestVectorError(
                f"committed test-vector artifact drifted: {relative_path}"
            )


__all__ = [
    "QualificationTestVectorError",
    "build_qualification_test_vectors",
    "check_qualification_test_vectors",
    "write_qualification_test_vectors",
]
