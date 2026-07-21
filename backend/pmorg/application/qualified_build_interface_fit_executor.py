"""Activate candidate-aware governed Onyx fork interface-fit probes."""

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
INTERFACE_RELATIVE = (
    "pmorg/capabilities/qualification-interfaces/qualified-reproducible-build-v1.json"
)
VECTOR_EXTENSION_RELATIVE = (
    "pmorg/capabilities/qualification-test-vector-extension-qualified-build-v1.json"
)
VECTOR_ROOT = "pmorg/capabilities/qualification-test-vector-extensions"
BASE_POLICY_RELATIVE = "pmorg/capabilities/qualification-oracle-policy-v1.json"
RESULT_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-result-v2.schema.json"
ADAPTER_RELATIVE = "backend/pmorg/application/qualified_build_interface_fit_executor.py"
EXTENSION_RELATIVE = (
    "pmorg/capabilities/qualification-oracle-extension-qualified-build-v1.json"
)
EXTENSION_SCHEMA_RELATIVE = (
    "pmorg/capabilities/qualification-oracle-extension-qualified-build-v1.schema.json"
)
RUNTIME_ARTIFACT_RELATIVES = (".python-version", "pyproject.toml", "uv.lock")
DERIVATION_RELATIVES = (
    ADAPTER_RELATIVE,
    "pmorg/scripts/build_qualified_build_interface_fit_executor.py",
)

CAPABILITY_ID = "qualified-reproducible-build"
TEST_IDS = ("A-EVIDENCE-001", "A-LIC-001", "A-REPORT-001", "A-REPRO-001")
EXTENSION_SCHEMA_VERSION = "pmorg.qualification-oracle-extension/v1"
RESULT_SCHEMA_VERSION = "pmorg.qualification-oracle-result/v2"
RUNTIME_INTERPRETER_LABEL = "@runtime/executed-python-interpreter"
_REQUIRED_DECISIONS = {"allow", "deny"}
_REQUIRED_OUTPUT_KEYS = {"decision", "violations"}
_TEST_CONTRACTS: dict[str, dict[str, Any]] = {
    "A-EVIDENCE-001": {
        "callable": "evaluate_qualified_evidence",
        "parameters": {
            "artifact_set",
            "bqa",
            "build_inputs",
            "candidate_blobs",
            "candidate_manifest",
            "evidence_bundle",
        },
        "guard_terms": {
            "artifacts": {"artifact"},
            "bqa": {"bqa"},
            "digest_binding": {"digest", "sha256"},
            "evidence": {"evidence"},
        },
    },
    "A-LIC-001": {
        "callable": "evaluate_qualified_license",
        "parameters": {
            "candidate_blobs",
            "candidate_manifest",
            "ce_boundary",
            "copies",
            "egress",
            "imports",
            "source_paths",
        },
        "guard_terms": {
            "ce_ee": {"ce", "ee"},
            "copies_imports": {"copy", "import"},
            "egress": {"egress"},
            "license": {"license"},
        },
    },
    "A-REPORT-001": {
        "callable": "evaluate_qualified_report",
        "parameters": {
            "artifact_set",
            "bqa_report",
            "build_manifest",
            "candidate_blobs",
            "candidate_manifest",
            "evidence_bundle",
        },
        "guard_terms": {
            "artifacts": {"artifact"},
            "bqa": {"bqa"},
            "digest_binding": {"digest", "sha256"},
            "report_manifest": {"manifest", "report"},
        },
    },
    "A-REPRO-001": {
        "callable": "evaluate_qualified_reproducibility",
        "parameters": {
            "build_spec",
            "candidate_blobs",
            "candidate_manifest",
            "offline_inputs",
            "rebuild_one",
            "rebuild_two",
        },
        "guard_terms": {
            "determinism": {"byte", "deterministic", "identical"},
            "digest_binding": {"digest", "sha256"},
            "offline": {"offline", "pinned"},
            "rebuild": {"rebuild"},
        },
    },
}


class QualifiedBuildInterfaceFitExecutorError(ValueError):
    """Raised when qualified-build executor evidence is incomplete or ambiguous."""


def _oracle_id(test_id: str) -> str:
    return f"qualification-oracle:{CAPABILITY_ID}:{test_id}:v1"


def _vector_relative(test_id: str) -> str:
    return f"{VECTOR_ROOT}/{CAPABILITY_ID}-{test_id}-v1.json"


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise QualifiedBuildInterfaceFitExecutorError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualifiedBuildInterfaceFitExecutorError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise QualifiedBuildInterfaceFitExecutorError(
            f"artifact is not an object: {relative_path}"
        )
    return value


def _artifact_ref(
    repository_root: Path, relative_path: str, media_type: str
) -> dict[str, Any]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise QualifiedBuildInterfaceFitExecutorError(
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


def _candidate_and_blob_set(
    repository_root: Path, candidate_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
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
        raise QualifiedBuildInterfaceFitExecutorError(
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
        raise QualifiedBuildInterfaceFitExecutorError("candidate blob set drifted")
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
            raise QualifiedBuildInterfaceFitExecutorError(
                f"candidate blob is unreadable: {record['path']}"
            )
        if sha256_digest(payload) != record["sha256"]:
            raise QualifiedBuildInterfaceFitExecutorError(
                f"candidate blob digest drifted: {record['path']}"
            )
        if len(payload) != record["size_bytes"]:
            raise QualifiedBuildInterfaceFitExecutorError(
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
        raise QualifiedBuildInterfaceFitExecutorError("candidate has no mutable bytes")
    payload = bytearray(cast(bytes, target["payload"]))
    payload[len(payload) // 2] ^= 1
    target["payload"] = bytes(payload)
    return mutated


def _positive_control_source() -> bytes:
    return b"""def evaluate_qualified_evidence(*, artifact_set, bqa, build_inputs, candidate_blobs, candidate_manifest, evidence_bundle):
    # Bind every artifact, BQA and evidence field to exact build inputs by digest/sha256.
    if artifact_set and bqa and build_inputs and candidate_blobs and candidate_manifest and evidence_bundle:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["missing evidence digest binding"]}

def evaluate_qualified_license(*, candidate_blobs, candidate_manifest, ce_boundary, copies, egress, imports, source_paths):
    # Enforce the CE/EE license boundary; reject an EE import, copy or unknown egress.
    if candidate_blobs and candidate_manifest and ce_boundary == "ce" and source_paths and not imports and not copies and not egress:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["CE license boundary violation"]}

def evaluate_qualified_report(*, artifact_set, bqa_report, build_manifest, candidate_blobs, candidate_manifest, evidence_bundle):
    # Bind every report/BQA manifest field and artifact to exact bytes by digest/sha256.
    if artifact_set and bqa_report and build_manifest and candidate_blobs and candidate_manifest and evidence_bundle:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["incomplete report digest binding"]}

def evaluate_qualified_reproducibility(*, build_spec, candidate_blobs, candidate_manifest, offline_inputs, rebuild_one, rebuild_two):
    # Require pinned offline inputs and deterministic byte-identical rebuild digest/sha256 values.
    if build_spec and candidate_blobs and candidate_manifest and offline_inputs and rebuild_one == rebuild_two:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["rebuild bytes are not identical"]}
"""


def _positive_control_blobs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    injected = [dict(item) for item in blobs]
    injected.append(
        {
            "path": "__pmorg_positive_control__/qualified_reproducible_build.py",
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
        raise QualifiedBuildInterfaceFitExecutorError(
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
            raise QualifiedBuildInterfaceFitExecutorError(
                f"base qualified-build oracle is absent: {test_id}"
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
            raise QualifiedBuildInterfaceFitExecutorError(
                f"base qualified-build oracle state drifted: {test_id}"
            )
        states.append(actual)
    return states


def _validate_q6a_bindings(
    repository_root: Path,
    vector_extension: dict[str, Any],
    interface: dict[str, Any],
    vectors: list[dict[str, Any]],
    runtime: list[dict[str, Any]],
) -> None:
    manifest_vectors = cast(list[dict[str, Any]], vector_extension.get("vectors", []))
    if [item.get("test_id") for item in manifest_vectors] != list(TEST_IDS):
        raise QualifiedBuildInterfaceFitExecutorError(
            "Q6a vector order or coverage drifted"
        )
    declared_implementations = cast(
        list[dict[str, Any]],
        vector_extension.get("interface_reference_implementations", []),
    )
    interface_document = _read_object(repository_root, INTERFACE_RELATIVE)
    if declared_implementations != interface_document.get("reference_implementations"):
        raise QualifiedBuildInterfaceFitExecutorError(
            "Q6a reference implementation set drifted"
        )
    manifest_bindings = cast(
        list[dict[str, Any]],
        vector_extension.get("reference_implementation_bindings", []),
    )
    if [item.get("test_id") for item in manifest_bindings] != list(TEST_IDS):
        raise QualifiedBuildInterfaceFitExecutorError(
            "Q6a reference implementation bindings drifted"
        )
    for index, test_id in enumerate(TEST_IDS):
        expected_ref = {
            key: manifest_vectors[index].get(key)
            for key in ("digest", "media_type", "relative_path", "size_bytes")
        }
        if vectors[index] != expected_ref:
            raise QualifiedBuildInterfaceFitExecutorError(
                f"Q6a vector artifact drifted: {test_id}"
            )
        vector = _read_object(repository_root, _vector_relative(test_id))
        if (
            vector.get("capability_id") != CAPABILITY_ID
            or vector.get("test_id") != test_id
        ):
            raise QualifiedBuildInterfaceFitExecutorError(
                f"Q6a vector identity drifted: {test_id}"
            )
        if vector.get("qualification_interface") != interface:
            raise QualifiedBuildInterfaceFitExecutorError(
                f"Q6a interface binding drifted: {test_id}"
            )
        if vector.get("reference_implementation") != manifest_bindings[index].get(
            "reference_implementation"
        ):
            raise QualifiedBuildInterfaceFitExecutorError(
                f"Q6a reference implementation binding drifted: {test_id}"
            )
        mutation = cast(dict[str, Any], vector.get("mutation_probe", {}))
        if mutation.get("no_op_rejected") is not True:
            raise QualifiedBuildInterfaceFitExecutorError(
                f"Q6a no-op rejection drifted: {test_id}"
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
        raise QualifiedBuildInterfaceFitExecutorError("Q6a runtime contract drifted")


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
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:qualification-oracle-extension:qualified-build:v1",
        "title": "PMORG qualified reproducible build candidate-aware oracle extension",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "extension_id",
            "activation_status",
            "claim_boundary",
            "base_policy",
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
            "extension_id": {"const": "qualified-reproducible-build-oracles-v1"},
            "activation_status": {
                "const": "candidate_executors_activated_in_extension"
            },
            "claim_boundary": {
                "const": "executor_activation_only_no_candidate_reports_or_aggregate_verdict"
            },
            "base_policy": artifact,
            "immutable_predecessor_states": {
                "type": "array",
                "minItems": 4,
                "maxItems": 4,
                "items": predecessor,
            },
            "qualification_interface": artifact,
            "candidate_test_vectors": {
                "type": "array",
                "minItems": 4,
                "maxItems": 4,
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
                "minItems": 10,
                "maxItems": 10,
                "items": binding,
            },
            "oracles": {
                "type": "array",
                "minItems": 4,
                "maxItems": 4,
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


def build_qualified_build_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    vector_extension = _read_object(repository_root, VECTOR_EXTENSION_RELATIVE)
    if vector_extension.get("activation_status") != "definition_only_unactivated":
        raise QualifiedBuildInterfaceFitExecutorError("Q6a vector extension drifted")
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
        raise QualifiedBuildInterfaceFitExecutorError("immutable base policy drifted")
    predecessor_states = _base_policy_states(repository_root)
    if (
        predecessor_states
        != vector_extension["immutable_predecessors"]["oracle_states"]
    ):
        raise QualifiedBuildInterfaceFitExecutorError(
            "Q6a immutable oracle states drifted"
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
    _validate_q6a_bindings(
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
        "extension_id": "qualified-reproducible-build-oracles-v1",
        "activation_status": "candidate_executors_activated_in_extension",
        "claim_boundary": "executor_activation_only_no_candidate_reports_or_aggregate_verdict",
        "base_policy": base_policy,
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
        raise QualifiedBuildInterfaceFitExecutorError(
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
        raise QualifiedBuildInterfaceFitExecutorError(
            f"executor result schema violation: {errors[0]}"
        )
    extension = json.loads(
        build_qualified_build_oracle_extension(repository_root)[EXTENSION_RELATIVE]
    )
    oracle = next(item for item in extension["oracles"] if item["test_id"] == test_id)
    if result["bindings"] != extension["bindings"]:
        raise QualifiedBuildInterfaceFitExecutorError("executor bindings drifted")
    if result["candidate_manifest_digest"] != candidate["manifest_digest"]:
        raise QualifiedBuildInterfaceFitExecutorError(
            "candidate manifest binding drifted"
        )
    if result["adapter_digest"] != oracle["adapter_digest"]:
        raise QualifiedBuildInterfaceFitExecutorError("adapter binding drifted")
    if result["baseline_observation_digest"] == result["mutation_observation_digest"]:
        raise QualifiedBuildInterfaceFitExecutorError("mutation influence is absent")
    if not result["positive_injection_fit"]:
        raise QualifiedBuildInterfaceFitExecutorError("positive control did not fit")
    if result["unobserved_blob_count"] != 0:
        raise QualifiedBuildInterfaceFitExecutorError(
            "candidate bytes were not all observed"
        )


def execute_qualified_build_interface_fit(
    candidate_id: str,
    test_id: str,
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    """Execute one qualified-build baseline, mutation and positive control."""

    if test_id not in TEST_IDS:
        raise QualifiedBuildInterfaceFitExecutorError(f"unknown test id: {test_id}")
    repository_root = repository_root.resolve()
    candidate, blob_set = _candidate_and_blob_set(repository_root, candidate_id)
    blobs = _verified_candidate_blobs(repository_root, blob_set)
    baseline = _measure(test_id, blobs)
    mutation = _measure(test_id, _mutated_blobs(blobs))
    positive = _measure(test_id, _positive_control_blobs(blobs))
    if baseline["observation_digest"] == mutation["observation_digest"]:
        raise QualifiedBuildInterfaceFitExecutorError(
            "candidate byte mutation did not change an observation"
        )
    if not positive["fit"]:
        raise QualifiedBuildInterfaceFitExecutorError(
            "conforming positive control did not change interface fit"
        )
    extension = json.loads(
        build_qualified_build_oracle_extension(repository_root)[EXTENSION_RELATIVE]
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
                f"candidate exposes no callable surface satisfying the exact {test_id} qualified-build interface"
            ]
        ),
        "verdict": "pass" if baseline["fit"] else "fail",
    }
    _validate_result(result, candidate, test_id, repository_root)
    return result


def write_qualified_build_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_qualified_build_oracle_extension(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_qualified_build_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_qualified_build_oracle_extension(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise QualifiedBuildInterfaceFitExecutorError(
                f"committed oracle extension is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise QualifiedBuildInterfaceFitExecutorError(
                f"committed oracle extension drifted: {relative_path}"
            )


__all__ = [
    "QualifiedBuildInterfaceFitExecutorError",
    "TEST_IDS",
    "build_qualified_build_oracle_extension",
    "check_qualified_build_oracle_extension",
    "execute_qualified_build_interface_fit",
    "extension_schema",
    "write_qualified_build_oracle_extension",
]
