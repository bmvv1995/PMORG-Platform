"""Activate and execute candidate-aware Thin Fork interface-fit probes."""

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
    "pmorg/capabilities/qualification-interfaces/thin-fork-boundary-v1.json"
)
VECTOR_EXTENSION_RELATIVE = (
    "pmorg/capabilities/qualification-test-vector-extension-thin-fork-v1.json"
)
VECTOR_RELATIVE = (
    "pmorg/capabilities/qualification-test-vector-extensions/"
    "thin-fork-boundary-A-PATCH-001-v1.json"
)
BASE_POLICY_RELATIVE = "pmorg/capabilities/qualification-oracle-policy-v1.json"
RESULT_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-result-v2.schema.json"
ADAPTER_RELATIVE = "backend/pmorg/application/thin_fork_interface_fit_executor.py"
EXTENSION_RELATIVE = (
    "pmorg/capabilities/qualification-oracle-extension-thin-fork-v1.json"
)
EXTENSION_SCHEMA_RELATIVE = (
    "pmorg/capabilities/qualification-oracle-extension-thin-fork-v1.schema.json"
)
RUNTIME_ARTIFACT_RELATIVES = (".python-version", "pyproject.toml", "uv.lock")
DERIVATION_RELATIVES = (
    ADAPTER_RELATIVE,
    "pmorg/scripts/build_thin_fork_interface_fit_executor.py",
)

CAPABILITY_ID = "thin-fork-boundary"
TEST_ID = "A-PATCH-001"
ORACLE_ID = "qualification-oracle:thin-fork-boundary:A-PATCH-001:v1"
EXTENSION_SCHEMA_VERSION = "pmorg.qualification-oracle-extension/v1"
RESULT_SCHEMA_VERSION = "pmorg.qualification-oracle-result/v2"
RUNTIME_INTERPRETER_LABEL = "@runtime/executed-python-interpreter"
_CALLABLE = "evaluate_thin_fork_boundary"
_REQUIRED_PARAMETERS = {
    "base_tree",
    "candidate_blobs",
    "candidate_manifest",
    "candidate_tree",
    "ownership_allowlists",
    "patch_ledger",
    "protector_evidence",
}
_REQUIRED_DECISIONS = {"allow", "deny"}
_REQUIRED_OUTPUT_KEYS = {"decision", "violations"}
_REQUIRED_GUARD_TERMS = {
    "historical_evidence": {"evidence", "predecessor", "successor"},
    "ownership": {"owner", "ownership"},
    "seam": {"seam"},
    "trust_boundary": {"boundary", "trust"},
    "upstream": {"ledger", "patch", "upstream"},
}


class ThinForkInterfaceFitExecutorError(ValueError):
    """Raised when Thin Fork executor evidence is incomplete or ambiguous."""


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise ThinForkInterfaceFitExecutorError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ThinForkInterfaceFitExecutorError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise ThinForkInterfaceFitExecutorError(
            f"artifact is not an object: {relative_path}"
        )
    return value


def _artifact_ref(
    repository_root: Path, relative_path: str, media_type: str
) -> dict[str, Any]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise ThinForkInterfaceFitExecutorError(
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
        raise ThinForkInterfaceFitExecutorError(
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
        raise ThinForkInterfaceFitExecutorError("candidate blob set drifted")
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
            raise ThinForkInterfaceFitExecutorError(
                f"candidate blob is unreadable: {record['path']}"
            )
        if sha256_digest(payload) != record["sha256"]:
            raise ThinForkInterfaceFitExecutorError(
                f"candidate blob digest drifted: {record['path']}"
            )
        if len(payload) != record["size_bytes"]:
            raise ThinForkInterfaceFitExecutorError(
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


def _surface_observation(path: str, payload: bytes) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    try:
        source = payload.decode("utf-8")
        tree = ast.parse(source, filename=path)
    except (UnicodeDecodeError, SyntaxError):
        return None
    lowered = source.lower()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != _CALLABLE:
            continue
        parameters = {
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
        }
        decisions, output_keys = _literal_return_shapes(node)
        guard_terms = {
            group: sorted(term for term in terms if term in lowered)
            for group, terms in _REQUIRED_GUARD_TERMS.items()
        }
        missing_guard_groups = sorted(
            group for group, terms in guard_terms.items() if not terms
        )
        missing_parameters = sorted(_REQUIRED_PARAMETERS - parameters)
        missing_decisions = sorted(_REQUIRED_DECISIONS - decisions)
        missing_output_keys = sorted(_REQUIRED_OUTPUT_KEYS - output_keys)
        fit = not (
            missing_guard_groups
            or missing_parameters
            or missing_decisions
            or missing_output_keys
        )
        return {
            "callable": _CALLABLE,
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
        }
    return None


def _measure(blobs: list[dict[str, Any]]) -> dict[str, Any]:
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
                cast(str, item["path"]), cast(bytes, item["payload"])
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
    }
    return {**core, "observation_digest": sha256_digest(canonical_document_bytes(core))}


def _mutated_blobs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mutated = [dict(item) for item in blobs]
    target = next((item for item in mutated if cast(bytes, item["payload"])), None)
    if target is None:
        raise ThinForkInterfaceFitExecutorError("candidate has no mutable bytes")
    payload = bytearray(cast(bytes, target["payload"]))
    payload[len(payload) // 2] ^= 1
    target["payload"] = bytes(payload)
    return mutated


def _positive_control_source() -> bytes:
    return b"""def evaluate_thin_fork_boundary(*, base_tree, candidate_blobs, candidate_manifest, candidate_tree, ownership_allowlists, patch_ledger, protector_evidence):
    # Enforce owner/ownership, trust boundary, upstream patch ledger, seam,
    # predecessor/successor and immutable evidence routes.
    if not ownership_allowlists or not patch_ledger or not protector_evidence:
        return {"decision": "deny", "violations": ["fail-closed governance"]}
    if base_tree == candidate_tree:
        return {"decision": "allow", "violations": []}
    return {"decision": "deny", "violations": ["changed path requires one route"]}
"""


def _positive_control_blobs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    injected = [dict(item) for item in blobs]
    injected.append(
        {
            "path": "__pmorg_positive_control__/thin_fork_boundary.py",
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
        raise ThinForkInterfaceFitExecutorError(
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


def _base_policy_state(repository_root: Path) -> dict[str, Any]:
    policy = _read_object(repository_root, BASE_POLICY_RELATIVE)
    oracle = next(
        (
            item
            for item in cast(list[dict[str, Any]], policy.get("oracles", []))
            if item.get("capability_id") == CAPABILITY_ID
            and item.get("test_id") == TEST_ID
        ),
        None,
    )
    if oracle is None:
        raise ThinForkInterfaceFitExecutorError("base Thin Fork oracle is absent")
    expected = {
        "adapter": None,
        "candidate_test_vector": None,
        "oracle_status": "unexecutable",
    }
    actual = {key: oracle.get(key) for key in expected}
    if actual != expected:
        raise ThinForkInterfaceFitExecutorError("base Thin Fork oracle state drifted")
    return actual


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
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:qualification-oracle-extension:thin-fork:v1",
        "title": "PMORG Thin Fork candidate-aware oracle extension",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "extension_id",
            "activation_status",
            "claim_boundary",
            "base_policy",
            "immutable_predecessor_state",
            "qualification_interface",
            "candidate_test_vector",
            "adapter",
            "result_schema",
            "runtime_artifacts",
            "bindings",
            "oracle",
            "derivation_artifacts",
        ],
        "properties": {
            "schema_version": {"const": EXTENSION_SCHEMA_VERSION},
            "extension_id": {"const": "thin-fork-boundary-A-PATCH-001-oracle-v1"},
            "activation_status": {"const": "candidate_executor_activated_in_extension"},
            "claim_boundary": {
                "const": "executor_activation_only_no_candidate_reports_or_aggregate_verdict"
            },
            "base_policy": artifact,
            "immutable_predecessor_state": {
                "type": "object",
                "additionalProperties": False,
                "required": ["adapter", "candidate_test_vector", "oracle_status"],
                "properties": {
                    "adapter": {"type": "null"},
                    "candidate_test_vector": {"type": "null"},
                    "oracle_status": {"const": "unexecutable"},
                },
            },
            "qualification_interface": artifact,
            "candidate_test_vector": artifact,
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
                "minItems": 7,
                "maxItems": 7,
                "items": binding,
            },
            "oracle": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "oracle_id",
                    "capability_id",
                    "test_id",
                    "oracle_status",
                    "candidate_influence_status",
                    "adapter_digest",
                    "candidate_test_vector_digest",
                ],
                "properties": {
                    "oracle_id": {"const": ORACLE_ID},
                    "capability_id": {"const": CAPABILITY_ID},
                    "test_id": {"const": TEST_ID},
                    "oracle_status": {"const": "executable"},
                    "candidate_influence_status": {
                        "const": "live_mutation_probe_required"
                    },
                    "adapter_digest": digest,
                    "candidate_test_vector_digest": digest,
                },
            },
            "derivation_artifacts": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": artifact,
            },
        },
    }


def build_thin_fork_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    vector_extension = _read_object(repository_root, VECTOR_EXTENSION_RELATIVE)
    if vector_extension.get("activation_status") != "definition_only_unactivated":
        raise ThinForkInterfaceFitExecutorError("Q4a vector extension drifted")
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
        raise ThinForkInterfaceFitExecutorError("immutable base policy drifted")
    interface = _artifact_ref(repository_root, INTERFACE_RELATIVE, "application/json")
    vector = _artifact_ref(repository_root, VECTOR_RELATIVE, "application/json")
    adapter = _artifact_ref(repository_root, ADAPTER_RELATIVE, "text/x-python")
    result = _artifact_ref(
        repository_root, RESULT_SCHEMA_RELATIVE, "application/schema+json"
    )
    runtime = [
        _artifact_ref(repository_root, path, "application/octet-stream")
        for path in RUNTIME_ARTIFACT_RELATIVES
    ]
    bindings = [
        _binding(item) for item in (interface, vector, adapter, result, *runtime)
    ]
    document = {
        "schema_version": EXTENSION_SCHEMA_VERSION,
        "extension_id": "thin-fork-boundary-A-PATCH-001-oracle-v1",
        "activation_status": "candidate_executor_activated_in_extension",
        "claim_boundary": "executor_activation_only_no_candidate_reports_or_aggregate_verdict",
        "base_policy": base_policy,
        "immutable_predecessor_state": _base_policy_state(repository_root),
        "qualification_interface": interface,
        "candidate_test_vector": vector,
        "adapter": adapter,
        "result_schema": result,
        "runtime_artifacts": runtime,
        "bindings": bindings,
        "oracle": {
            "oracle_id": ORACLE_ID,
            "capability_id": CAPABILITY_ID,
            "test_id": TEST_ID,
            "oracle_status": "executable",
            "candidate_influence_status": "live_mutation_probe_required",
            "adapter_digest": adapter["digest"],
            "candidate_test_vector_digest": vector["digest"],
        },
        "derivation_artifacts": [
            _artifact_ref(repository_root, path, "text/x-python")
            for path in DERIVATION_RELATIVES
        ],
    }
    errors = sorted(
        Draft202012Validator(extension_schema()).iter_errors(document), key=str
    )
    if errors:
        raise ThinForkInterfaceFitExecutorError(
            f"oracle extension schema violation: {errors[0]}"
        )
    return {
        EXTENSION_SCHEMA_RELATIVE: canonical_document_bytes(extension_schema()),
        EXTENSION_RELATIVE: canonical_document_bytes(document),
    }


def _validate_result(
    result: dict[str, Any], candidate: dict[str, Any], repository_root: Path
) -> None:
    errors = sorted(Draft202012Validator(result_schema()).iter_errors(result), key=str)
    if errors:
        raise ThinForkInterfaceFitExecutorError(
            f"executor result schema violation: {errors[0]}"
        )
    extension = json.loads(
        build_thin_fork_oracle_extension(repository_root)[EXTENSION_RELATIVE]
    )
    expected_bindings = cast(list[dict[str, str]], extension["bindings"])
    if result["bindings"] != expected_bindings:
        raise ThinForkInterfaceFitExecutorError("executor bindings drifted")
    if result["candidate_manifest_digest"] != candidate["manifest_digest"]:
        raise ThinForkInterfaceFitExecutorError("candidate manifest binding drifted")
    if result["adapter_digest"] != extension["oracle"]["adapter_digest"]:
        raise ThinForkInterfaceFitExecutorError("adapter binding drifted")
    if result["baseline_observation_digest"] == result["mutation_observation_digest"]:
        raise ThinForkInterfaceFitExecutorError("mutation influence is absent")
    if not result["positive_injection_fit"]:
        raise ThinForkInterfaceFitExecutorError("positive control did not fit")
    if result["unobserved_blob_count"] != 0:
        raise ThinForkInterfaceFitExecutorError("candidate bytes were not all observed")


def execute_thin_fork_interface_fit(
    candidate_id: str, *, repository_root: Path = REPOSITORY_ROOT
) -> dict[str, Any]:
    """Execute baseline, live mutation and conforming positive control."""

    repository_root = repository_root.resolve()
    candidate, blob_set = _candidate_and_blob_set(repository_root, candidate_id)
    blobs = _verified_candidate_blobs(repository_root, blob_set)
    baseline = _measure(blobs)
    mutation = _measure(_mutated_blobs(blobs))
    positive = _measure(_positive_control_blobs(blobs))
    if baseline["observation_digest"] == mutation["observation_digest"]:
        raise ThinForkInterfaceFitExecutorError(
            "candidate byte mutation did not change an observation"
        )
    if not positive["fit"]:
        raise ThinForkInterfaceFitExecutorError(
            "conforming positive control did not change interface fit"
        )
    extension = json.loads(
        build_thin_fork_oracle_extension(repository_root)[EXTENSION_RELATIVE]
    )
    runtime_measurement, runtime_digest = _runtime_measurement(repository_root)
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "capability_id": CAPABILITY_ID,
        "test_id": TEST_ID,
        "candidate_id": candidate_id,
        "oracle_id": ORACLE_ID,
        "oracle_status": "executable",
        "candidate_manifest_digest": candidate["manifest_digest"],
        "adapter_digest": extension["oracle"]["adapter_digest"],
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
                "candidate exposes no callable surface satisfying the exact Thin Fork interface"
            ]
        ),
        "verdict": "pass" if baseline["fit"] else "fail",
    }
    _validate_result(result, candidate, repository_root)
    return result


def write_thin_fork_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_thin_fork_oracle_extension(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_thin_fork_oracle_extension(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_thin_fork_oracle_extension(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise ThinForkInterfaceFitExecutorError(
                f"committed oracle extension is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise ThinForkInterfaceFitExecutorError(
                f"committed oracle extension drifted: {relative_path}"
            )


__all__ = [
    "ThinForkInterfaceFitExecutorError",
    "build_thin_fork_oracle_extension",
    "check_thin_fork_oracle_extension",
    "execute_thin_fork_interface_fit",
    "extension_schema",
    "write_thin_fork_oracle_extension",
]
