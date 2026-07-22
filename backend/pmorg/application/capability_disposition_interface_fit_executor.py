"""Activate candidate-aware capability-disposition interface-fit probes."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator

from pmorg.application.candidate_inputs import _read_blobs
from pmorg.application.candidate_inputs import validate_candidate_input_bundle
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import result_schema
from pmorg.application.qualification_oracles import sha256_digest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
Q7A_EVIDENCE_RELATIVE = "pmorg/capabilities/capability-disposition-qualification-interface-fit-evidence-v1.json"
INTERFACE_RELATIVE = "pmorg/capabilities/qualification-interfaces/capability-disposition-qualification-v1.json"
VECTOR_EXTENSION_RELATIVE = "pmorg/capabilities/qualification-test-vector-extension-capability-disposition-qualification-v1.json"
VECTOR_ROOT = "pmorg/capabilities/qualification-test-vector-extensions"
BASE_POLICY_RELATIVE = "pmorg/capabilities/qualification-oracle-policy-v1.json"
RESULT_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-result-v2.schema.json"
ADAPTER_RELATIVE = (
    "backend/pmorg/application/capability_disposition_interface_fit_executor.py"
)
EXTENSION_RELATIVE = "pmorg/capabilities/qualification-oracle-extension-capability-disposition-qualification-v1.json"
EXTENSION_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-extension-capability-disposition-qualification-v1.schema.json"
RUNTIME_ARTIFACT_RELATIVES = (".python-version", "pyproject.toml", "uv.lock")
DERIVATION_RELATIVES = (
    ADAPTER_RELATIVE,
    "pmorg/scripts/build_capability_disposition_interface_fit_executor.py",
)

CAPABILITY_ID = "capability-disposition-qualification"
TEST_IDS = ("A-PATCH-002", "A-PATCH-003", "A-PATCH-004", "A-PATCH-005", "A-PATCH-006")
EXPECTED_GROUPED_CANDIDATES = 48
EXPECTED_BLOB_MEMBERSHIPS = 5015
EXTENSION_SCHEMA_VERSION = "pmorg.qualification-oracle-extension/v1"
RESULT_SCHEMA_VERSION = "pmorg.qualification-oracle-result/v2"
RUNTIME_INTERPRETER_LABEL = "@runtime/executed-python-interpreter"
_REQUIRED_DECISIONS = {"allow", "deny"}
_REQUIRED_OUTPUT_KEYS = {"decision", "violations"}
_TEST_CONTRACTS: dict[str, dict[str, Any]] = {
    "A-PATCH-002": {
        "callable": "evaluate_catalog_contract",
        "parameters": {
            "candidate_blobs",
            "candidate_manifest",
            "capability_catalog",
            "contract_tests",
        },
        "guard_terms": {
            "catalog": {"catalog", "capability"},
            "contract": {"contract", "requirement", "test"},
            "identity": {"digest", "sha256", "identity"},
        },
    },
    "A-PATCH-003": {
        "callable": "evaluate_search_denominator",
        "parameters": {
            "candidate_blobs",
            "candidate_manifest",
            "candidate_search",
            "source_scope",
        },
        "guard_terms": {
            "candidate": {"candidate"},
            "denominator": {"denominator", "exhaustive"},
            "scope": {"scope", "surface"},
            "search": {"search", "query"},
        },
    },
    "A-PATCH-004": {
        "callable": "evaluate_qualification_record",
        "parameters": {
            "candidate_blobs",
            "candidate_manifest",
            "qualification_evidence",
            "qualification_payload",
            "signature_binding",
        },
        "guard_terms": {
            "canonical": {"canonical"},
            "content_address": {"digest", "sha256"},
            "evidence": {"evidence"},
            "signature": {"signature", "signed"},
        },
    },
    "A-PATCH-005": {
        "callable": "evaluate_build_disposition_inputs",
        "parameters": {
            "candidate_blobs",
            "candidate_manifest",
            "ce_build_verification",
            "disposition_inputs",
        },
        "guard_terms": {
            "build": {"build", "artifact"},
            "ce": {"ce"},
            "disposition": {"disposition"},
            "identity": {"digest", "sha256", "identity"},
        },
    },
    "A-PATCH-006": {
        "callable": "evaluate_combined_invariants",
        "parameters": {
            "candidate_blobs",
            "candidate_manifest",
            "qualification_binding",
            "search_binding",
            "scope_binding",
        },
        "guard_terms": {
            "candidate": {"candidate"},
            "qualification": {"qualification", "evidence"},
            "scope": {"scope", "surface"},
            "search": {"search", "denominator"},
        },
    },
}


class CapabilityDispositionInterfaceFitExecutorError(ValueError):
    """Raised when capability-disposition executor evidence is incomplete or ambiguous."""


def _oracle_id(test_id: str) -> str:
    return f"qualification-oracle:{CAPABILITY_ID}:{test_id}:v1"


def _vector_relative(test_id: str) -> str:
    return f"{VECTOR_ROOT}/{CAPABILITY_ID}-{test_id}-v1.json"


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise CapabilityDispositionInterfaceFitExecutorError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CapabilityDispositionInterfaceFitExecutorError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise CapabilityDispositionInterfaceFitExecutorError(
            f"artifact is not an object: {relative_path}"
        )
    return value


def _artifact_ref(
    repository_root: Path, relative_path: str, media_type: str
) -> dict[str, Any]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise CapabilityDispositionInterfaceFitExecutorError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return {
        "digest": sha256_digest(payload),
        "media_type": media_type,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _binding(reference: dict[str, Any]) -> dict[str, str]:
    return {
        "digest": cast(str, reference["digest"]),
        "relative_path": cast(str, reference["relative_path"]),
    }


def _candidate_denominator(
    repository_root: Path, bundle: dict[str, Any] | None = None
) -> dict[str, Any]:
    if bundle is None:
        bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
        validate_candidate_input_bundle(bundle)
    candidates = [
        item
        for item in cast(list[dict[str, Any]], bundle["candidates"])
        if item.get("capability_id") == CAPABILITY_ID
    ]
    memberships = sum(cast(int, item["blob_count"]) for item in candidates)
    groups = {cast(str, item["candidate_group"]) for item in candidates}
    if (
        len(candidates) != EXPECTED_GROUPED_CANDIDATES
        or len(groups) != EXPECTED_GROUPED_CANDIDATES
        or memberships != EXPECTED_BLOB_MEMBERSHIPS
    ):
        raise CapabilityDispositionInterfaceFitExecutorError(
            "Q7a candidate denominator drifted"
        )
    manifest_set = sorted(
        (
            {
                "blob_count": item["blob_count"],
                "blob_set_digest": item["blob_set_digest"],
                "candidate_group": item["candidate_group"],
                "candidate_id": item["candidate_id"],
                "candidate_manifest_digest": item["manifest_digest"],
            }
            for item in candidates
        ),
        key=lambda item: cast(str, item["candidate_id"]),
    )
    q7a_evidence = _read_object(repository_root, Q7A_EVIDENCE_RELATIVE)
    evidence_candidates = sorted(
        (
            {
                key: item[key]
                for key in (
                    "blob_count",
                    "blob_set_digest",
                    "candidate_group",
                    "candidate_id",
                    "candidate_manifest_digest",
                )
            }
            for item in cast(list[dict[str, Any]], q7a_evidence.get("candidates", []))
        ),
        key=lambda item: cast(str, item["candidate_id"]),
    )
    expected_bundle_ref = _artifact_ref(
        repository_root, CANDIDATE_INPUTS_RELATIVE, "application/json"
    )
    evidence_bundle_ref = cast(dict[str, Any], q7a_evidence.get("candidate_inputs", {}))
    if (
        q7a_evidence.get("capability_id") != CAPABILITY_ID
        or q7a_evidence.get("claim_boundary")
        != "exhaustive_plausibility_screen_only_no_qualification_or_disposition"
        or q7a_evidence.get("candidate_count") != EXPECTED_GROUPED_CANDIDATES
        or q7a_evidence.get("blob_set_scan_count") != EXPECTED_GROUPED_CANDIDATES
        or q7a_evidence.get("candidate_blob_membership_count")
        != EXPECTED_BLOB_MEMBERSHIPS
        or q7a_evidence.get("blob_set_membership_count") != EXPECTED_BLOB_MEMBERSHIPS
        or evidence_candidates != manifest_set
        or {
            key: evidence_bundle_ref.get(key)
            for key in ("digest", "relative_path", "size_bytes")
        }
        != {
            key: expected_bundle_ref[key]
            for key in ("digest", "relative_path", "size_bytes")
        }
    ):
        raise CapabilityDispositionInterfaceFitExecutorError(
            "immutable Q7a screening denominator drifted"
        )
    return {
        "candidate_input_bundle": expected_bundle_ref,
        "candidate_manifest_set_digest": sha256_digest(
            canonical_document_bytes(manifest_set)
        ),
        "grouped_candidate_count": EXPECTED_GROUPED_CANDIDATES,
        "blob_membership_count": EXPECTED_BLOB_MEMBERSHIPS,
        "candidate_projection": "module_group_blob_set/v1",
        "q7a_screening_evidence": _artifact_ref(
            repository_root, Q7A_EVIDENCE_RELATIVE, "application/json"
        ),
    }


def _candidate_and_blob_set(
    repository_root: Path, candidate_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    _candidate_denominator(repository_root, bundle)
    candidate = next(
        (
            item
            for item in cast(list[dict[str, Any]], bundle["candidates"])
            if item["candidate_id"] == candidate_id
            and item["capability_id"] == CAPABILITY_ID
        ),
        None,
    )
    if candidate is None:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "candidate is absent or belongs to another capability"
        )
    blob_set = next(
        (
            item
            for item in cast(list[dict[str, Any]], bundle["blob_sets"])
            if item["blob_set_digest"] == candidate["blob_set_digest"]
        ),
        None,
    )
    if blob_set is None or blob_set["blob_count"] != candidate["blob_count"]:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "candidate blob set drifted"
        )
    return candidate, blob_set


def _verified_candidate_blobs(
    repository_root: Path, blob_set: dict[str, Any]
) -> list[dict[str, Any]]:
    records = cast(list[dict[str, Any]], blob_set["blobs"])
    object_ids = [cast(str, record["git_object_id"]) for record in records]
    payloads = _read_blobs(repository_root, object_ids)
    observed: list[dict[str, Any]] = []
    for record in records:
        object_id = cast(str, record["git_object_id"])
        payload = payloads.get(object_id)
        if payload is None:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"candidate blob is unreadable: {record['path']}"
            )
        if sha256_digest(payload) != record["sha256"]:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"candidate blob digest drifted: {record['path']}"
            )
        if len(payload) != record["size_bytes"]:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"candidate blob size drifted: {record['path']}"
            )
        observed.append({"path": record["path"], "payload": payload})
    observed.sort(key=lambda item: cast(str, item["path"]))
    return observed


def _literal_return_shapes(function: ast.AST) -> tuple[set[str], set[str]]:
    decisions: set[str] = set()
    output_keys: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
            continue
        for raw_key, raw_value in zip(node.value.keys, node.value.values, strict=True):
            if not isinstance(raw_key, ast.Constant) or not isinstance(
                raw_key.value, str
            ):
                continue
            output_keys.add(raw_key.value)
            if (
                raw_key.value == "decision"
                and isinstance(raw_value, ast.Constant)
                and isinstance(raw_value.value, str)
            ):
                decisions.add(raw_value.value)
    return decisions, output_keys


def _surface_observation(
    test_id: str, path: str, payload: bytes
) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    try:
        source = payload.decode("utf-8")
        tree = ast.parse(source, filename=path)
    except (UnicodeDecodeError, SyntaxError):
        return None
    contract = _TEST_CONTRACTS[test_id]
    callable_name = cast(str, contract["callable"])
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != callable_name:
            continue
        function_source = ast.get_source_segment(source, node) or ""
        lowered = function_source.lower()
        parameters = {
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
        }
        decisions, output_keys = _literal_return_shapes(node)
        required_guards = cast(dict[str, set[str]], contract["guard_terms"])
        guard_terms = {
            group: sorted(term for term in terms if term in lowered)
            for group, terms in required_guards.items()
        }
        missing_guard_groups = sorted(
            group for group, terms in guard_terms.items() if not terms
        )
        missing_parameters = sorted(cast(set[str], contract["parameters"]) - parameters)
        missing_decisions = sorted(_REQUIRED_DECISIONS - decisions)
        missing_output_keys = sorted(_REQUIRED_OUTPUT_KEYS - output_keys)
        fit = not (
            missing_guard_groups
            or missing_parameters
            or missing_decisions
            or missing_output_keys
        )
        return {
            "callable": callable_name,
            "decisions": sorted(decisions),
            "fit": fit,
            "guard_terms": guard_terms,
            "missing_decisions": missing_decisions,
            "missing_guard_groups": missing_guard_groups,
            "missing_output_keys": missing_output_keys,
            "missing_parameters": missing_parameters,
            "output_keys": sorted(output_keys),
            "parameters": sorted(parameters),
            "path": path,
            "test_id": test_id,
        }
    return None


def _measure(test_id: str, blobs: list[dict[str, Any]]) -> dict[str, Any]:
    blob_index = [
        {
            "path": item["path"],
            "sha256": sha256_digest(cast(bytes, item["payload"])),
            "size_bytes": len(cast(bytes, item["payload"])),
        }
        for item in blobs
    ]
    surfaces = [
        surface
        for item in blobs
        if (
            surface := _surface_observation(
                test_id, cast(str, item["path"]), cast(bytes, item["payload"])
            )
        )
        is not None
    ]
    fit = any(cast(bool, surface["fit"]) for surface in surfaces)
    core = {
        "blob_count": len(blobs),
        "blob_index_digest": sha256_digest(canonical_document_bytes(blob_index)),
        "callable_surface_count": len(surfaces),
        "callable_surfaces": surfaces,
        "capability_id": CAPABILITY_ID,
        "fit": fit,
        "test_id": test_id,
    }
    return {**core, "observation_digest": sha256_digest(canonical_document_bytes(core))}


def _mutated_blobs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mutated = [dict(item) for item in blobs]
    target = next((item for item in mutated if cast(bytes, item["payload"])), None)
    if target is None:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "candidate has no mutable bytes"
        )
    payload = bytearray(cast(bytes, target["payload"]))
    payload[len(payload) // 2] ^= 1
    target["payload"] = bytes(payload)
    return mutated


def _positive_control_source() -> bytes:
    return b"""def evaluate_catalog_contract(*, candidate_blobs, candidate_manifest, capability_catalog, contract_tests):
    # Bind the capability catalog, requirement and contract-test identities by digest/sha256.
    if candidate_blobs and candidate_manifest and capability_catalog and contract_tests:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["catalog or contract identity mismatch"]}

def evaluate_search_denominator(*, candidate_blobs, candidate_manifest, candidate_search, source_scope):
    # Preserve the exhaustive candidate search denominator over every source scope and surface.
    if candidate_blobs and candidate_manifest and candidate_search and source_scope:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["source scope or search denominator drift"]}

def evaluate_qualification_record(*, candidate_blobs, candidate_manifest, qualification_evidence, qualification_payload, signature_binding):
    # Bind canonical qualification evidence and signed payload identities by digest/sha256.
    if candidate_blobs and candidate_manifest and qualification_evidence and qualification_payload and signature_binding:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["qualification evidence or signature binding drift"]}

def evaluate_build_disposition_inputs(*, candidate_blobs, candidate_manifest, ce_build_verification, disposition_inputs):
    # Bind CE build artifact verification and disposition inputs to exact identity digests/sha256.
    if candidate_blobs and candidate_manifest and ce_build_verification and disposition_inputs:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["CE build or disposition input identity drift"]}

def evaluate_combined_invariants(*, candidate_blobs, candidate_manifest, qualification_binding, search_binding, scope_binding):
    # Preserve candidate scope/surface, exhaustive search denominator and qualification evidence.
    if candidate_blobs and candidate_manifest and qualification_binding and search_binding and scope_binding:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["combined qualification invariant drift"]}
"""


def _positive_control_blobs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    injected = [dict(item) for item in blobs]
    injected.append(
        {
            "path": "__pmorg_positive_control__/capability_disposition_qualification.py",
            "payload": _positive_control_source(),
        }
    )
    injected.sort(key=lambda item: cast(str, item["path"]))
    return injected


def _runtime_measurement(repository_root: Path) -> tuple[dict[str, Any], str]:
    interpreter = Path(sys.executable).resolve()
    try:
        interpreter_payload = interpreter.read_bytes()
    except OSError as error:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "executed interpreter binary cannot be measured"
        ) from error
    artifacts = [
        _artifact_ref(repository_root, path, "application/octet-stream")
        for path in RUNTIME_ARTIFACT_RELATIVES
    ]
    measurement = {
        "declared_artifacts": [_binding(item) for item in artifacts],
        "interpreter_binary": {
            "digest": sha256_digest(interpreter_payload),
            "relative_path": RUNTIME_INTERPRETER_LABEL,
        },
    }
    return measurement, sha256_digest(canonical_document_bytes(measurement))


def _base_policy_states(repository_root: Path) -> list[dict[str, Any]]:
    policy = _read_object(repository_root, BASE_POLICY_RELATIVE)
    states: list[dict[str, Any]] = []
    for test_id in TEST_IDS:
        oracle = next(
            (
                item
                for item in cast(list[dict[str, Any]], policy.get("oracles", []))
                if item.get("capability_id") == CAPABILITY_ID
                and item.get("test_id") == test_id
            ),
            None,
        )
        if oracle is None:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"base capability-disposition oracle is absent: {test_id}"
            )
        expected = {
            "adapter": None,
            "candidate_test_vector": None,
            "oracle_id": _oracle_id(test_id),
            "oracle_status": "unexecutable",
            "test_id": test_id,
        }
        actual = {key: oracle.get(key) for key in expected}
        if actual != expected:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"base capability-disposition oracle state drifted: {test_id}"
            )
        states.append(actual)
    return states


def _validate_q7a_bindings(
    repository_root: Path,
    vector_extension: dict[str, Any],
    interface: dict[str, Any],
    vectors: list[dict[str, Any]],
    runtime: list[dict[str, Any]],
) -> None:
    manifest_vectors = cast(list[dict[str, Any]], vector_extension.get("vectors", []))
    if [item.get("test_id") for item in manifest_vectors] != list(TEST_IDS):
        raise CapabilityDispositionInterfaceFitExecutorError(
            "Q7a vector order or coverage drifted"
        )
    declared_implementations = cast(
        list[dict[str, Any]],
        vector_extension.get("interface_reference_implementations", []),
    )
    interface_document = _read_object(repository_root, INTERFACE_RELATIVE)
    if declared_implementations != interface_document.get("reference_implementations"):
        raise CapabilityDispositionInterfaceFitExecutorError(
            "Q7a reference implementation set drifted"
        )
    manifest_bindings = cast(
        list[dict[str, Any]],
        vector_extension.get("reference_implementation_bindings", []),
    )
    if [item.get("test_id") for item in manifest_bindings] != list(TEST_IDS):
        raise CapabilityDispositionInterfaceFitExecutorError(
            "Q7a reference implementation bindings drifted"
        )
    for index, test_id in enumerate(TEST_IDS):
        expected_ref = {
            key: manifest_vectors[index].get(key)
            for key in ("digest", "media_type", "relative_path", "size_bytes")
        }
        if vectors[index] != expected_ref:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"Q7a vector artifact drifted: {test_id}"
            )
        vector = _read_object(repository_root, _vector_relative(test_id))
        if (
            vector.get("capability_id") != CAPABILITY_ID
            or vector.get("test_id") != test_id
        ):
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"Q7a vector identity drifted: {test_id}"
            )
        if vector.get("qualification_interface") != interface:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"Q7a interface binding drifted: {test_id}"
            )
        if vector.get("reference_implementation") != manifest_bindings[index].get(
            "reference_implementation"
        ):
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"Q7a reference implementation binding drifted: {test_id}"
            )
        mutation = cast(dict[str, Any], vector.get("mutation_probe", {}))
        if mutation.get("no_op_rejected") is not True:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"Q7a no-op rejection drifted: {test_id}"
            )
    runtime_contract = cast(
        dict[str, Any], vector_extension.get("runtime_identity_contract", {})
    )
    manifest_runtime = cast(list[dict[str, Any]], runtime_contract.get("artifacts", []))
    expected_runtime = [
        {key: item.get(key) for key in ("digest", "relative_path", "size_bytes")}
        for item in manifest_runtime
    ]
    actual_runtime = [
        {key: item.get(key) for key in ("digest", "relative_path", "size_bytes")}
        for item in runtime
    ]
    if actual_runtime != expected_runtime:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "Q7a runtime contract drifted"
        )


def extension_schema() -> dict[str, Any]:
    nonempty = {"type": "string", "minLength": 1}
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    artifact = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "media_type", "relative_path", "size_bytes"],
        "properties": {
            "digest": digest,
            "media_type": nonempty,
            "relative_path": nonempty,
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }
    binding = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "relative_path"],
        "properties": {"digest": digest, "relative_path": nonempty},
    }
    predecessor = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "adapter",
            "candidate_test_vector",
            "oracle_id",
            "oracle_status",
            "test_id",
        ],
        "properties": {
            "adapter": {"type": "null"},
            "candidate_test_vector": {"type": "null"},
            "oracle_id": {"enum": [_oracle_id(item) for item in TEST_IDS]},
            "oracle_status": {"const": "unexecutable"},
            "test_id": {"enum": list(TEST_IDS)},
        },
    }
    oracle = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "adapter_digest",
            "candidate_influence_status",
            "candidate_test_vector_digest",
            "capability_id",
            "oracle_id",
            "oracle_status",
            "test_id",
        ],
        "properties": {
            "adapter_digest": digest,
            "candidate_influence_status": {"const": "live_mutation_probe_required"},
            "candidate_test_vector_digest": digest,
            "capability_id": {"const": CAPABILITY_ID},
            "oracle_id": {"enum": [_oracle_id(item) for item in TEST_IDS]},
            "oracle_status": {"const": "executable"},
            "test_id": {"enum": list(TEST_IDS)},
        },
    }
    denominator = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "candidate_input_bundle",
            "candidate_manifest_set_digest",
            "grouped_candidate_count",
            "blob_membership_count",
            "candidate_projection",
            "q7a_screening_evidence",
        ],
        "properties": {
            "candidate_input_bundle": artifact,
            "candidate_manifest_set_digest": digest,
            "grouped_candidate_count": {"const": EXPECTED_GROUPED_CANDIDATES},
            "blob_membership_count": {"const": EXPECTED_BLOB_MEMBERSHIPS},
            "candidate_projection": {"const": "module_group_blob_set/v1"},
            "q7a_screening_evidence": artifact,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:qualification-oracle-extension:capability-disposition-qualification:v1",
        "title": "PMORG capability disposition qualification candidate-aware oracle extension",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "extension_id",
            "activation_status",
            "claim_boundary",
            "base_policy",
            "candidate_denominator",
            "immutable_predecessor_states",
            "qualification_interface",
            "candidate_test_vectors",
            "adapter",
            "result_schema",
            "runtime_artifacts",
            "bindings",
            "oracles",
            "derivation_artifacts",
        ],
        "properties": {
            "schema_version": {"const": EXTENSION_SCHEMA_VERSION},
            "extension_id": {
                "const": "capability-disposition-qualification-oracles-v1"
            },
            "activation_status": {
                "const": "candidate_executors_activated_in_extension"
            },
            "claim_boundary": {
                "const": "executor_activation_only_no_candidate_reports_or_aggregate_verdict"
            },
            "base_policy": artifact,
            "candidate_denominator": denominator,
            "immutable_predecessor_states": {
                "type": "array",
                "minItems": 5,
                "maxItems": 5,
                "items": predecessor,
            },
            "qualification_interface": artifact,
            "candidate_test_vectors": {
                "type": "array",
                "minItems": 5,
                "maxItems": 5,
                "items": artifact,
            },
            "adapter": artifact,
            "result_schema": artifact,
            "runtime_artifacts": {
                "type": "array",
                "minItems": 3,
                "maxItems": 3,
                "items": artifact,
            },
            "bindings": {
                "type": "array",
                "minItems": 11,
                "maxItems": 11,
                "items": binding,
            },
            "oracles": {
                "type": "array",
                "minItems": 5,
                "maxItems": 5,
                "items": oracle,
            },
            "derivation_artifacts": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": artifact,
            },
        },
    }


def build_capability_disposition_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    vector_extension = _read_object(repository_root, VECTOR_EXTENSION_RELATIVE)
    if vector_extension.get("activation_status") != "definition_only_unactivated":
        raise CapabilityDispositionInterfaceFitExecutorError(
            "Q7a vector extension drifted"
        )
    predecessor_policy = cast(
        dict[str, Any],
        cast(dict[str, Any], vector_extension["immutable_predecessors"])[
            "oracle_policy"
        ],
    )
    base_policy = _artifact_ref(
        repository_root, BASE_POLICY_RELATIVE, "application/json"
    )
    if base_policy != predecessor_policy:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "immutable base policy drifted"
        )
    predecessor_states = _base_policy_states(repository_root)
    if (
        predecessor_states
        != vector_extension["immutable_predecessors"]["oracle_states"]
    ):
        raise CapabilityDispositionInterfaceFitExecutorError(
            "Q7a immutable oracle states drifted"
        )
    interface = _artifact_ref(repository_root, INTERFACE_RELATIVE, "application/json")
    vectors = [
        _artifact_ref(repository_root, _vector_relative(test_id), "application/json")
        for test_id in TEST_IDS
    ]
    adapter = _artifact_ref(repository_root, ADAPTER_RELATIVE, "text/x-python")
    result = _artifact_ref(
        repository_root, RESULT_SCHEMA_RELATIVE, "application/schema+json"
    )
    runtime = [
        _artifact_ref(repository_root, path, "application/octet-stream")
        for path in RUNTIME_ARTIFACT_RELATIVES
    ]
    _validate_q7a_bindings(
        repository_root, vector_extension, interface, vectors, runtime
    )
    bindings = [
        _binding(item) for item in (interface, *vectors, adapter, result, *runtime)
    ]
    oracles = [
        {
            "adapter_digest": adapter["digest"],
            "candidate_influence_status": "live_mutation_probe_required",
            "candidate_test_vector_digest": vectors[index]["digest"],
            "capability_id": CAPABILITY_ID,
            "oracle_id": _oracle_id(test_id),
            "oracle_status": "executable",
            "test_id": test_id,
        }
        for index, test_id in enumerate(TEST_IDS)
    ]
    document = {
        "schema_version": EXTENSION_SCHEMA_VERSION,
        "extension_id": "capability-disposition-qualification-oracles-v1",
        "activation_status": "candidate_executors_activated_in_extension",
        "claim_boundary": "executor_activation_only_no_candidate_reports_or_aggregate_verdict",
        "base_policy": base_policy,
        "candidate_denominator": _candidate_denominator(repository_root),
        "immutable_predecessor_states": predecessor_states,
        "qualification_interface": interface,
        "candidate_test_vectors": vectors,
        "adapter": adapter,
        "result_schema": result,
        "runtime_artifacts": runtime,
        "bindings": bindings,
        "oracles": oracles,
        "derivation_artifacts": [
            _artifact_ref(repository_root, path, "text/x-python")
            for path in DERIVATION_RELATIVES
        ],
    }
    errors = sorted(
        Draft202012Validator(extension_schema()).iter_errors(document), key=str
    )
    if errors:
        raise CapabilityDispositionInterfaceFitExecutorError(
            f"oracle extension schema violation: {errors[0]}"
        )
    return {
        EXTENSION_SCHEMA_RELATIVE: canonical_document_bytes(extension_schema()),
        EXTENSION_RELATIVE: canonical_document_bytes(document),
    }


def _validate_result(
    result: dict[str, Any],
    candidate: dict[str, Any],
    test_id: str,
    repository_root: Path,
) -> None:
    errors = sorted(Draft202012Validator(result_schema()).iter_errors(result), key=str)
    if errors:
        raise CapabilityDispositionInterfaceFitExecutorError(
            f"executor result schema violation: {errors[0]}"
        )
    extension = json.loads(
        build_capability_disposition_oracle_extension(repository_root)[
            EXTENSION_RELATIVE
        ]
    )
    oracle = next(item for item in extension["oracles"] if item["test_id"] == test_id)
    if result["bindings"] != extension["bindings"]:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "executor bindings drifted"
        )
    if result["candidate_manifest_digest"] != candidate["manifest_digest"]:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "candidate manifest binding drifted"
        )
    if result["adapter_digest"] != oracle["adapter_digest"]:
        raise CapabilityDispositionInterfaceFitExecutorError("adapter binding drifted")
    if result["baseline_observation_digest"] == result["mutation_observation_digest"]:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "mutation influence is absent"
        )
    if not result["positive_injection_fit"]:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "positive control did not fit"
        )
    if result["unobserved_blob_count"] != 0:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "candidate bytes were not all observed"
        )


def execute_capability_disposition_interface_fit(
    candidate_id: str,
    test_id: str,
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    """Execute one capability-disposition baseline, mutation and positive control."""

    if test_id not in TEST_IDS:
        raise CapabilityDispositionInterfaceFitExecutorError(
            f"unknown test id: {test_id}"
        )
    repository_root = repository_root.resolve()
    candidate, blob_set = _candidate_and_blob_set(repository_root, candidate_id)
    blobs = _verified_candidate_blobs(repository_root, blob_set)
    baseline = _measure(test_id, blobs)
    mutation = _measure(test_id, _mutated_blobs(blobs))
    positive = _measure(test_id, _positive_control_blobs(blobs))
    if baseline["observation_digest"] == mutation["observation_digest"]:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "candidate byte mutation did not change an observation"
        )
    if not positive["fit"]:
        raise CapabilityDispositionInterfaceFitExecutorError(
            "conforming positive control did not change interface fit"
        )
    extension = json.loads(
        build_capability_disposition_oracle_extension(repository_root)[
            EXTENSION_RELATIVE
        ]
    )
    oracle = next(item for item in extension["oracles"] if item["test_id"] == test_id)
    runtime_measurement, runtime_digest = _runtime_measurement(repository_root)
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "capability_id": CAPABILITY_ID,
        "test_id": test_id,
        "candidate_id": candidate_id,
        "oracle_id": _oracle_id(test_id),
        "oracle_status": "executable",
        "candidate_manifest_digest": candidate["manifest_digest"],
        "adapter_digest": oracle["adapter_digest"],
        "runtime_identity_digest": runtime_digest,
        "runtime_measurement": runtime_measurement,
        "baseline_observation_digest": baseline["observation_digest"],
        "mutation_observation_digest": mutation["observation_digest"],
        "positive_injection_observation_digest": positive["observation_digest"],
        "baseline_fit": baseline["fit"],
        "mutation_fit": mutation["fit"],
        "positive_injection_fit": positive["fit"],
        "projected_blob_count": len(blobs),
        "observed_blob_count": len(blobs),
        "unobserved_blob_count": 0,
        "execution_exit_codes": [0, 0, 0],
        "bindings": extension["bindings"],
        "failure_reasons": (
            []
            if baseline["fit"]
            else [
                f"candidate exposes no callable surface satisfying the exact {test_id} capability-disposition interface"
            ]
        ),
        "verdict": "pass" if baseline["fit"] else "fail",
    }
    _validate_result(result, candidate, test_id, repository_root)
    return result


def write_capability_disposition_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_capability_disposition_oracle_extension(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_capability_disposition_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_capability_disposition_oracle_extension(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"committed oracle extension is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise CapabilityDispositionInterfaceFitExecutorError(
                f"committed oracle extension drifted: {relative_path}"
            )


__all__ = [
    "CapabilityDispositionInterfaceFitExecutorError",
    "TEST_IDS",
    "build_capability_disposition_oracle_extension",
    "check_capability_disposition_oracle_extension",
    "execute_capability_disposition_interface_fit",
    "extension_schema",
    "write_capability_disposition_oracle_extension",
]
