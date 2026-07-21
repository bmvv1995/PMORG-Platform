"""Build and verify candidate-aware qualification-oracle definitions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
POLICY_RELATIVE = "pmorg/capabilities/qualification-oracle-policy-v1.json"
RESULT_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-result-v2.schema.json"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
CONTRACT_TEST_ROOT = "pmorg/capabilities/contract-tests"
SEARCH_ROOT = "pmorg/capabilities/candidate-search"
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
INTERFACE_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-interfaces-v1.json"
TEST_VECTOR_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-test-vectors-v1.json"
PYTHON_VERSION_RELATIVE = ".python-version"
PROJECT_RELATIVE = "pyproject.toml"
LOCK_RELATIVE = "uv.lock"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/admission_interface_fit_executor.py",
    "backend/pmorg/application/qualification_oracles.py",
    "pmorg/scripts/build_qualification_oracles.py",
)

POLICY_SCHEMA_VERSION = "pmorg.qualification-oracle-policy/v1"
RESULT_SCHEMA_VERSION = "pmorg.qualification-oracle-result/v2"


class QualificationOracleError(ValueError):
    """Raised when an oracle definition, binding, or result is not exact."""


@dataclass(frozen=True)
class Binding:
    relative_path: str
    argv: tuple[str, ...]


VERIFY_FORK = Binding(
    "pmorg/scripts/verify_fork.py",
    (
        "python3",
        "-B",
        "pmorg/scripts/verify_fork.py",
        "--candidate-repository-root",
        "{candidate_repository_root}",
        "--trusted-repository-root",
        "{trusted_repository_root}",
        "--protected-base-sha",
        "{protected_base_sha}",
    ),
)
VERIFY_CE_BUILD = Binding(
    "pmorg/scripts/verify_ce_build.py",
    (
        "python3",
        "-B",
        "pmorg/scripts/verify_ce_build.py",
        "--repository-root",
        "{candidate_repository_root}",
        "--revision",
        "{candidate_revision}",
    ),
)
VERIFY_CE_CONTEXTS = Binding(
    "pmorg/scripts/verify_ce_image_contexts.py",
    (
        "python3",
        "-B",
        "pmorg/scripts/verify_ce_image_contexts.py",
        "--repository-root",
        "{candidate_repository_root}",
        "--revision",
        "{candidate_revision}",
    ),
)
CHECK_CATALOG = Binding(
    "pmorg/scripts/build_capability_catalog.py",
    (
        "python3",
        "-B",
        "pmorg/scripts/build_capability_catalog.py",
        "--check",
        "--repository-root",
        "{candidate_repository_root}",
    ),
)
CHECK_SCOPES = Binding(
    "pmorg/scripts/build_source_scopes.py",
    (
        "python3",
        "-B",
        "pmorg/scripts/build_source_scopes.py",
        "--check",
        "--repository-root",
        "{candidate_repository_root}",
    ),
)
CHECK_SEARCH = Binding(
    "pmorg/scripts/build_candidate_search.py",
    (
        "python3",
        "-B",
        "pmorg/scripts/build_candidate_search.py",
        "--check",
        "--repository-root",
        "{candidate_repository_root}",
    ),
)
CHECK_QUALIFICATION = Binding(
    "backend/pmorg/tests/test_qualification_signing.py",
    (
        "python3",
        "-B",
        "-m",
        "unittest",
        "backend.pmorg.tests.test_qualification_signing",
        "-v",
    ),
)

_GLOBAL_GATE_BINDINGS: dict[tuple[str, str], tuple[Binding, ...]] = {
    ("capability-disposition-qualification", "A-PATCH-002"): (CHECK_CATALOG,),
    ("capability-disposition-qualification", "A-PATCH-003"): (
        CHECK_SCOPES,
        CHECK_SEARCH,
    ),
    ("capability-disposition-qualification", "A-PATCH-004"): (CHECK_QUALIFICATION,),
    ("capability-disposition-qualification", "A-PATCH-005"): (VERIFY_CE_BUILD,),
    ("capability-disposition-qualification", "A-PATCH-006"): (
        CHECK_SCOPES,
        CHECK_SEARCH,
        CHECK_QUALIFICATION,
    ),
    ("governed-onyx-fork", "A-FORK-001"): (VERIFY_FORK,),
    ("governed-onyx-fork", "A-SURFACE-001"): (VERIFY_FORK,),
    ("governed-onyx-fork", "A-UPSTREAM-001"): (VERIFY_FORK,),
    ("qualified-reproducible-build", "A-EVIDENCE-001"): (CHECK_QUALIFICATION,),
    ("qualified-reproducible-build", "A-LIC-001"): (
        VERIFY_CE_BUILD,
        VERIFY_CE_CONTEXTS,
        CHECK_QUALIFICATION,
    ),
    ("qualified-reproducible-build", "A-REPORT-001"): (CHECK_QUALIFICATION,),
    ("qualified-reproducible-build", "A-REPRO-001"): (
        VERIFY_CE_BUILD,
        VERIFY_CE_CONTEXTS,
    ),
    ("thin-fork-boundary", "A-PATCH-001"): (VERIFY_FORK,),
}
_ADMISSION_EXECUTABLES = {
    ("deployment-admission", "A-LIC-002"): (
        "backend/pmorg/application/admission_interface_fit_executor.py"
    ),
    ("distribution-admission", "A-LIC-003"): (
        "backend/pmorg/application/admission_interface_fit_executor.py"
    ),
}


def _global_gate_reason(capability_id: str, test_id: str) -> str:
    return (
        f"{test_id} verifies repository-, process-, build- or release-wide state for "
        f"{capability_id}; its existing invocation does not consume the candidate "
        "manifest or candidate blob bytes, so candidate influence is not falsifiable"
    )


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
        raise QualificationOracleError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationOracleError(f"{label} is not readable JSON") from error
    if not isinstance(value, dict):
        raise QualificationOracleError(f"{label} must be an object")
    return value


def _artifact_ref_for_path(
    repository_root: Path, relative_path: str, *, media_type: str
) -> dict[str, Any]:
    path = _safe_path(repository_root, relative_path)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise QualificationOracleError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return {
        "digest": sha256_digest(payload),
        "media_type": media_type,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _binding_ref(repository_root: Path, binding: Binding) -> dict[str, Any]:
    reference = _artifact_ref_for_path(
        repository_root, binding.relative_path, media_type="text/x-python"
    )
    return {"argv": list(binding.argv), **reference}


def _manifest_test_pairs(repository_root: Path) -> list[tuple[str, str]]:
    catalog = _read_object(
        _safe_path(repository_root, CATALOG_RELATIVE), label="capability catalog"
    )
    if catalog.get("catalog_version") != "1.0.0":
        raise QualificationOracleError("capability catalog version drifted")
    pairs: list[tuple[str, str]] = []
    for item in cast(list[dict[str, Any]], catalog.get("items")):
        capability_id = item.get("capability_id")
        refs = item.get("contract_tests")
        if not isinstance(capability_id, str) or not isinstance(refs, list):
            raise QualificationOracleError("capability catalog item is invalid")
        if len(refs) != 1 or not isinstance(refs[0], dict):
            raise QualificationOracleError(
                f"{capability_id} must bind exactly one test manifest"
            )
        relative_path = refs[0].get("relative_path")
        manifest = _read_object(
            _safe_path(repository_root, cast(str, relative_path)),
            label=f"{capability_id} contract-test manifest",
        )
        if manifest.get("capability_id") != capability_id:
            raise QualificationOracleError("contract-test identity drifted")
        test_ids = manifest.get("test_ids")
        if (
            not isinstance(test_ids, list)
            or not test_ids
            or test_ids != sorted(set(test_ids))
        ):
            raise QualificationOracleError(
                f"{capability_id} test IDs are not closed and ordered"
            )
        pairs.extend((capability_id, cast(str, test_id)) for test_id in test_ids)
    if pairs != sorted(set(pairs)):
        raise QualificationOracleError("contract-test pairs are not unique and ordered")
    return pairs


def _validate_candidate_projection(repository_root: Path) -> int:
    candidate_count = 0
    for evidence_path in sorted(
        _safe_path(repository_root, SEARCH_ROOT).glob("*-search-evidence-v1.json")
    ):
        evidence = _read_object(evidence_path, label="candidate-search evidence")
        ids = evidence.get("candidate_ids")
        classification_ref = evidence.get("hit_classification")
        if not isinstance(ids, list) or not isinstance(classification_ref, dict):
            raise QualificationOracleError("candidate-search projection is invalid")
        classifications = _read_object(
            _safe_path(
                repository_root, cast(str, classification_ref.get("relative_path"))
            ),
            label="candidate hit classification",
        )
        records = classifications.get("records")
        if not isinstance(records, list):
            raise QualificationOracleError("candidate classifications are missing")
        groups_by_id: dict[str, set[str]] = {cast(str, item): set() for item in ids}
        for record in records:
            if not isinstance(record, dict) or record.get("candidate_id") is None:
                continue
            candidate_id = cast(str, record["candidate_id"])
            if candidate_id not in groups_by_id:
                raise QualificationOracleError(
                    "classification has an unknown candidate"
                )
            groups_by_id[candidate_id].add(cast(str, record.get("candidate_group")))
        if any(len(groups) != 1 for groups in groups_by_id.values()):
            raise QualificationOracleError(
                "candidate ID does not project to exactly one module group"
            )
        candidate_count += len(ids)
    if candidate_count == 0:
        raise QualificationOracleError("candidate projection is empty")
    return candidate_count


def _qualification_interface_refs(
    repository_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    manifest = _read_object(
        _safe_path(repository_root, INTERFACE_MANIFEST_RELATIVE),
        label="qualification-interface manifest",
    )
    if (
        manifest.get("schema_version") != "pmorg.qualification-interface-manifest/v1"
        or manifest.get("catalog_version") != "1.0.0"
        or manifest.get("candidate_projection") != "module_group_blob_set/v1"
    ):
        raise QualificationOracleError("qualification-interface manifest drifted")
    interfaces = manifest.get("interfaces")
    if not isinstance(interfaces, list) or manifest.get("interface_count") != len(
        interfaces
    ):
        raise QualificationOracleError(
            "qualification-interface manifest coverage is invalid"
        )
    by_capability: dict[str, dict[str, Any]] = {}
    for raw in cast(list[dict[str, Any]], interfaces):
        capability_id = raw.get("capability_id")
        relative_path = raw.get("relative_path")
        if not isinstance(capability_id, str) or not isinstance(relative_path, str):
            raise QualificationOracleError(
                "qualification-interface reference is invalid"
            )
        actual = _artifact_ref_for_path(
            repository_root,
            relative_path,
            media_type="application/json",
        )
        expected = {
            key: raw[key]
            for key in ("digest", "media_type", "relative_path", "size_bytes")
        }
        if actual != expected or capability_id in by_capability:
            raise QualificationOracleError(
                "qualification-interface content binding drifted"
            )
        document = _read_object(
            _safe_path(repository_root, relative_path),
            label=f"{capability_id} qualification interface",
        )
        if (
            document.get("capability_id") != capability_id
            or document.get("candidate_projection") != "module_group_blob_set/v1"
        ):
            raise QualificationOracleError("qualification-interface identity drifted")
        by_capability[capability_id] = expected
    manifest_ref = _artifact_ref_for_path(
        repository_root,
        INTERFACE_MANIFEST_RELATIVE,
        media_type="application/json",
    )
    return manifest_ref, by_capability


def _qualification_test_vector_refs(
    repository_root: Path,
    interfaces: Mapping[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]]]:
    manifest = _read_object(
        _safe_path(repository_root, TEST_VECTOR_MANIFEST_RELATIVE),
        label="qualification test-vector manifest",
    )
    if (
        manifest.get("schema_version") != "pmorg.qualification-test-vector-manifest/v1"
        or manifest.get("candidate_projection") != "module_group_blob_set/v1"
    ):
        raise QualificationOracleError("qualification test-vector manifest drifted")
    runtime_contract = manifest.get("runtime_identity_contract")
    runtime_digest = manifest.get("runtime_identity_contract_digest")
    if not isinstance(runtime_contract, dict) or runtime_digest != sha256_digest(
        canonical_document_bytes(runtime_contract)
    ):
        raise QualificationOracleError(
            "qualification test-vector runtime contract drifted"
        )
    vectors = manifest.get("vectors")
    if not isinstance(vectors, list) or manifest.get("vector_count") != len(vectors):
        raise QualificationOracleError("qualification test-vector coverage is invalid")
    by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in cast(list[dict[str, Any]], vectors):
        capability_id = raw.get("capability_id")
        test_id = raw.get("test_id")
        relative_path = raw.get("relative_path")
        if not all(
            isinstance(value, str) for value in (capability_id, test_id, relative_path)
        ):
            raise QualificationOracleError(
                "qualification test-vector reference is invalid"
            )
        actual = _artifact_ref_for_path(
            repository_root,
            cast(str, relative_path),
            media_type="application/json",
        )
        expected = {
            key: raw[key]
            for key in ("digest", "media_type", "relative_path", "size_bytes")
        }
        pair = (cast(str, capability_id), cast(str, test_id))
        if actual != expected or pair in by_pair:
            raise QualificationOracleError(
                "qualification test-vector content binding drifted"
            )
        document = _read_object(
            _safe_path(repository_root, cast(str, relative_path)),
            label=f"{capability_id} qualification test vector",
        )
        if (
            document.get("capability_id") != capability_id
            or document.get("test_id") != test_id
            or document.get("candidate_projection") != "module_group_blob_set/v1"
            or document.get("qualification_interface")
            != interfaces.get(cast(str, capability_id))
            or document.get("claim_boundary")
            != "definition_only_no_qualification_verdict"
            or cast(dict[str, Any], document.get("runtime_identity", {})).get(
                "contract_digest"
            )
            != runtime_digest
        ):
            raise QualificationOracleError("qualification test-vector identity drifted")
        by_pair[pair] = expected
    manifest_ref = _artifact_ref_for_path(
        repository_root,
        TEST_VECTOR_MANIFEST_RELATIVE,
        media_type="application/json",
    )
    return manifest_ref, by_pair


def result_schema() -> dict[str, Any]:
    string = {"type": "string", "minLength": 1}
    nonnegative = {"type": "integer", "minimum": 0}
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    binding = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "relative_path"],
        "properties": {
            "digest": digest,
            "relative_path": string,
        },
    }
    runtime_measurement = {
        "type": "object",
        "additionalProperties": False,
        "required": ["declared_artifacts", "interpreter_binary"],
        "properties": {
            "declared_artifacts": {
                "type": "array",
                "minItems": 3,
                "maxItems": 3,
                "items": binding,
            },
            "interpreter_binary": binding,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:qualification-oracle-result:v2",
        "title": "PMORG candidate qualification oracle result",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "capability_id",
            "test_id",
            "candidate_id",
            "oracle_id",
            "oracle_status",
            "candidate_manifest_digest",
            "adapter_digest",
            "runtime_identity_digest",
            "runtime_measurement",
            "baseline_observation_digest",
            "mutation_observation_digest",
            "positive_injection_observation_digest",
            "baseline_fit",
            "mutation_fit",
            "positive_injection_fit",
            "projected_blob_count",
            "observed_blob_count",
            "unobserved_blob_count",
            "execution_exit_codes",
            "bindings",
            "failure_reasons",
            "verdict",
        ],
        "properties": {
            "schema_version": {"const": RESULT_SCHEMA_VERSION},
            "capability_id": string,
            "test_id": string,
            "candidate_id": {
                "type": "string",
                "pattern": "^candidate-[0-9a-f]{64}$",
            },
            "oracle_id": string,
            "oracle_status": {"enum": ["executable", "unexecutable"]},
            "candidate_manifest_digest": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "adapter_digest": {"oneOf": [digest, {"type": "null"}]},
            "runtime_identity_digest": {"oneOf": [digest, {"type": "null"}]},
            "runtime_measurement": {"oneOf": [runtime_measurement, {"type": "null"}]},
            "baseline_observation_digest": {"oneOf": [digest, {"type": "null"}]},
            "mutation_observation_digest": {"oneOf": [digest, {"type": "null"}]},
            "positive_injection_observation_digest": {
                "oneOf": [digest, {"type": "null"}]
            },
            "baseline_fit": {"type": ["boolean", "null"]},
            "mutation_fit": {"type": ["boolean", "null"]},
            "positive_injection_fit": {"type": ["boolean", "null"]},
            "projected_blob_count": nonnegative,
            "observed_blob_count": nonnegative,
            "unobserved_blob_count": nonnegative,
            "execution_exit_codes": {
                "type": "array",
                "items": {"type": "integer"},
            },
            "bindings": {"type": "array", "items": binding},
            "failure_reasons": {"type": "array", "items": string},
            "verdict": {"enum": ["pass", "fail"]},
        },
    }


def build_qualification_oracle_policy(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    repository_root = repository_root.resolve()
    pairs = _manifest_test_pairs(repository_root)
    expected = set(_GLOBAL_GATE_BINDINGS) | set(_ADMISSION_EXECUTABLES)
    if set(pairs) != expected:
        raise QualificationOracleError(
            "qualification-oracle coverage is not exact; "
            f"missing={sorted(set(pairs) - expected)}, "
            f"unknown={sorted(expected - set(pairs))}"
        )
    candidate_count = _validate_candidate_projection(repository_root)
    interface_manifest_ref, interfaces = _qualification_interface_refs(repository_root)
    if set(interfaces) != {capability_id for capability_id, _ in pairs}:
        raise QualificationOracleError(
            "qualification-interface capability coverage is not exact"
        )
    test_vector_manifest_ref, test_vectors = _qualification_test_vector_refs(
        repository_root, interfaces
    )
    if set(test_vectors) != set(_ADMISSION_EXECUTABLES):
        raise QualificationOracleError(
            "qualification test-vector admission coverage is not exact"
        )
    schema_bytes = canonical_document_bytes(result_schema())
    oracles: list[dict[str, Any]] = []
    for capability_id, test_id in pairs:
        key = (capability_id, test_id)
        global_bindings = _GLOBAL_GATE_BINDINGS.get(key, ())
        adapter_relative = _ADMISSION_EXECUTABLES.get(key)
        if adapter_relative is None:
            adapter = None
            bindings: list[dict[str, Any]] = []
            influence_status = "not_demonstrated"
            oracle_status = "unexecutable"
            runtime_status = "declaration_bound_binary_unattested"
            reason: str | None = _global_gate_reason(capability_id, test_id)
        else:
            adapter_ref = _artifact_ref_for_path(
                repository_root, adapter_relative, media_type="text/x-python"
            )
            adapter = adapter_ref["digest"]
            bindings = [adapter_ref, interfaces[capability_id], test_vectors[key]]
            influence_status = "live_mutation_and_positive_injection_enforced"
            oracle_status = "executable"
            runtime_status = "binary_measured_and_lock_bound_at_execution"
            reason = None
        oracles.append(
            {
                "adapter": adapter,
                "bindings": bindings,
                "candidate_test_vector": test_vectors.get(key),
                "capability_id": capability_id,
                "candidate_projection": "module_group_blob_set/v1",
                "candidate_influence_status": influence_status,
                "legacy_global_gate_bindings": [
                    _binding_ref(repository_root, binding)
                    for binding in global_bindings
                ],
                "qualification_interface": interfaces[capability_id],
                "oracle_id": f"qualification-oracle:{capability_id}:{test_id}:v1",
                "oracle_status": oracle_status,
                "runtime_identity_status": runtime_status,
                "test_id": test_id,
                "unexecutable_reason": reason,
            }
        )
    candidate_inputs = _artifact_ref_for_path(
        repository_root,
        CANDIDATE_INPUTS_RELATIVE,
        media_type="application/json",
    )
    runtime_artifacts = [
        _artifact_ref_for_path(
            repository_root, PYTHON_VERSION_RELATIVE, media_type="text/plain"
        ),
        _artifact_ref_for_path(
            repository_root, PROJECT_RELATIVE, media_type="application/toml"
        ),
        _artifact_ref_for_path(
            repository_root, LOCK_RELATIVE, media_type="application/toml"
        ),
    ]
    runtime_identity = {
        "artifacts": runtime_artifacts,
        "interpreter_declaration": PYTHON_VERSION_RELATIVE,
        "lockfile": LOCK_RELATIVE,
        "status": "binary_measurement_required_at_execution",
        "executable_requires_attested_interpreter_binary": True,
    }
    runtime_identity["digest"] = sha256_digest(
        canonical_document_bytes(runtime_identity)
    )
    derivation_artifacts = [
        _artifact_ref_for_path(
            repository_root, relative_path, media_type="text/x-python"
        )
        for relative_path in DERIVATION_RELATIVES
    ]
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_version": "1.3.0",
        "catalog_version": "1.0.0",
        "candidate_projection": {
            "candidate_count": candidate_count,
            "classification_root": SEARCH_ROOT,
            "candidate_inputs": candidate_inputs,
            "membership_rule": (
                "the complete module-group blob set bound by the candidate input "
                "manifest and its independently verified digest"
            ),
            "observation_rule": (
                "pass requires a candidate-aware adapter to consume the exact "
                "candidate manifest and all projected bytes"
            ),
            "projection_version": "module_group_blob_set/v1",
        },
        "qualification_interface_manifest": interface_manifest_ref,
        "qualification_test_vector_manifest": test_vector_manifest_ref,
        "execution_contract": {
            "environment": "offline_read_only_pinned_candidate_tree",
            "placeholder_set": [
                "candidate_manifest_path",
                "candidate_repository_root",
                "candidate_revision",
                "protected_base_sha",
                "trusted_repository_root",
            ],
            "unknown_or_unexecutable_verdict": "fail",
            "zero_exit_without_complete_blob_observation_verdict": "fail",
        },
        "runtime_identity": runtime_identity,
        "candidate_influence_contract": {
            "global_gate_or_sidecar_only_evidence": "forbidden",
            "manifest_placeholder": "candidate_manifest_path",
            "mutation_operator": "flip_one_byte_in_a_projected_candidate_blob",
            "mutation_proof_required_for_executable": True,
            "pass_condition": (
                "the baseline and mutated adapter evidence digests differ and the "
                "difference is attributable to the mutated candidate byte"
            ),
        },
        "derivation_artifacts": derivation_artifacts,
        "result_schema": {
            "digest": sha256_digest(schema_bytes),
            "media_type": "application/schema+json",
            "relative_path": RESULT_SCHEMA_RELATIVE,
            "size_bytes": len(schema_bytes),
        },
        "oracles": oracles,
        "oracle_count": len(oracles),
    }


def validate_qualification_oracle_result(
    result: Mapping[str, Any], *, repository_root: Path = REPOSITORY_ROOT
) -> None:
    schema = result_schema()
    errors = sorted(Draft202012Validator(schema).iter_errors(result), key=str)
    if errors:
        first_error = cast(Any, errors[0])
        raise QualificationOracleError(
            f"qualification-oracle result schema violation: {first_error.message}"
        )
    status = result["oracle_status"]
    verdict = result["verdict"]
    projected = result["projected_blob_count"]
    observed = result["observed_blob_count"]
    unobserved = result["unobserved_blob_count"]
    exit_codes = result["execution_exit_codes"]
    reasons = result["failure_reasons"]
    bindings = result["bindings"]
    if projected != observed + unobserved:
        raise QualificationOracleError(
            "oracle blob observation counts are inconsistent"
        )
    policy = build_qualification_oracle_policy(repository_root)
    identity = (result["capability_id"], result["test_id"], result["oracle_id"])
    oracle = next(
        (
            item
            for item in policy["oracles"]
            if (item["capability_id"], item["test_id"], item["oracle_id"]) == identity
        ),
        None,
    )
    if oracle is None:
        raise QualificationOracleError("oracle result has an unknown identity")
    if status != oracle["oracle_status"]:
        raise QualificationOracleError("oracle result status drifted from policy")
    expected_bindings = [
        {"digest": item["digest"], "relative_path": item["relative_path"]}
        for item in oracle["bindings"]
    ]
    if bindings != expected_bindings:
        raise QualificationOracleError("oracle result bindings drifted from policy")

    candidate_inputs = _read_object(
        _safe_path(repository_root, CANDIDATE_INPUTS_RELATIVE),
        label="candidate inputs",
    )
    candidates = candidate_inputs.get("candidates")
    if not isinstance(candidates, list):
        raise QualificationOracleError("candidate inputs are missing candidates")
    candidate = next(
        (
            item
            for item in cast(list[dict[str, Any]], candidates)
            if item.get("candidate_id") == result["candidate_id"]
        ),
        None,
    )
    if candidate is None:
        raise QualificationOracleError("oracle result has an unknown candidate")
    if candidate.get("capability_id") != result["capability_id"]:
        raise QualificationOracleError("oracle result candidate capability drifted")
    if candidate.get("manifest_digest") != result["candidate_manifest_digest"]:
        raise QualificationOracleError("oracle result candidate manifest drifted")

    if status == "unexecutable" and verdict != "fail":
        raise QualificationOracleError("an unexecutable oracle cannot pass")
    if status == "unexecutable":
        if any(
            result[key] is not None
            for key in (
                "adapter_digest",
                "runtime_identity_digest",
                "runtime_measurement",
                "baseline_observation_digest",
                "mutation_observation_digest",
                "positive_injection_observation_digest",
                "baseline_fit",
                "mutation_fit",
                "positive_injection_fit",
            )
        ):
            raise QualificationOracleError(
                "unexecutable oracle result cannot claim execution evidence"
            )
        return

    runtime_measurement = cast(dict[str, Any], result["runtime_measurement"])
    expected_runtime_artifacts = [
        {"digest": item["digest"], "relative_path": item["relative_path"]}
        for item in policy["runtime_identity"]["artifacts"]
    ]
    interpreter = cast(dict[str, Any], runtime_measurement["interpreter_binary"])
    if runtime_measurement["declared_artifacts"] != expected_runtime_artifacts:
        raise QualificationOracleError("runtime declaration or lock binding drifted")
    if interpreter["relative_path"] != "@runtime/executed-python-interpreter":
        raise QualificationOracleError("runtime interpreter binding is not exact")
    expected_runtime_digest = sha256_digest(
        canonical_document_bytes(runtime_measurement)
    )
    if result["runtime_identity_digest"] != expected_runtime_digest:
        raise QualificationOracleError("runtime identity digest drifted")

    baseline = result["baseline_observation_digest"]
    mutation = result["mutation_observation_digest"]
    positive = result["positive_injection_observation_digest"]
    if (
        projected == 0
        or observed != projected
        or unobserved != 0
        or exit_codes != [0, 0, 0]
        or not bindings
        or result["adapter_digest"] != oracle["adapter"]
        or baseline is None
        or mutation is None
        or positive is None
        or baseline == mutation
        or baseline == positive
        or result["positive_injection_fit"] is not True
    ):
        raise QualificationOracleError(
            "executable oracle result is not evidence-complete"
        )
    if verdict == "pass" and (result["baseline_fit"] is not True or reasons):
        raise QualificationOracleError("oracle PASS contradicts interface evidence")
    if verdict == "fail" and (result["baseline_fit"] is not False or not reasons):
        raise QualificationOracleError("oracle FAIL lacks interface evidence")


def write_qualification_oracles(repository_root: Path = REPOSITORY_ROOT) -> None:
    repository_root = repository_root.resolve()
    outputs = {
        POLICY_RELATIVE: canonical_document_bytes(
            build_qualification_oracle_policy(repository_root)
        ),
        RESULT_SCHEMA_RELATIVE: canonical_document_bytes(result_schema()),
    }
    for relative_path, payload in outputs.items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_qualification_oracles(repository_root: Path = REPOSITORY_ROOT) -> None:
    repository_root = repository_root.resolve()
    expected = {
        POLICY_RELATIVE: canonical_document_bytes(
            build_qualification_oracle_policy(repository_root)
        ),
        RESULT_SCHEMA_RELATIVE: canonical_document_bytes(result_schema()),
    }
    for relative_path, payload in expected.items():
        path = _safe_path(repository_root, relative_path)
        try:
            actual = path.read_bytes()
        except OSError as error:
            raise QualificationOracleError(
                f"committed oracle artifact is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise QualificationOracleError(
                f"committed oracle artifact drifted: {relative_path}"
            )


__all__ = [
    "QualificationOracleError",
    "build_qualification_oracle_policy",
    "check_qualification_oracles",
    "validate_qualification_oracle_result",
    "write_qualification_oracles",
]
