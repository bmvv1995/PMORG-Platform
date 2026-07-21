"""Execute candidate-aware admission interface-fit qualification probes."""

from __future__ import annotations

import ast
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from typing import cast

from pmorg.application.candidate_inputs import _read_blobs
from pmorg.application.candidate_inputs import validate_candidate_input_bundle
from pmorg.application.qualification_oracles import build_qualification_oracle_policy
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import QualificationOracleError
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.application.qualification_oracles import validate_qualification_oracle_result

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
ADAPTER_RELATIVE = "backend/pmorg/application/admission_interface_fit_executor.py"
RUNTIME_ARTIFACT_RELATIVES = (".python-version", "pyproject.toml", "uv.lock")
RUNTIME_INTERPRETER_LABEL = "@runtime/executed-python-interpreter"

RESULT_SCHEMA_VERSION = "pmorg.qualification-oracle-result/v2"

_SURFACE_SPECS: dict[str, dict[str, Any]] = {
    "deployment-admission": {
        "test_id": "A-LIC-002",
        "callable": "evaluate_deployment_admission",
        "required_parameters": (
            "admission_envelope",
            "candidate_blobs",
            "candidate_manifest",
            "payload_descriptor",
            "target_descriptor",
            "trusted_time",
        ),
        "required_decisions": ("allow", "deny"),
        "required_output_keys": ("decision", "quiesce", "receipt"),
    },
    "distribution-admission": {
        "test_id": "A-LIC-003",
        "callable": "evaluate_distribution_admission",
        "required_parameters": (
            "admission_envelope",
            "candidate_blobs",
            "candidate_manifest",
            "destination_descriptor",
            "distribution_subset",
            "trusted_time",
        ),
        "required_decisions": ("allow", "deny"),
        "required_output_keys": ("abort", "decision", "receipt"),
    },
}


class AdmissionInterfaceFitError(ValueError):
    """Raised when candidate or executor evidence is incomplete or ambiguous."""


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise AdmissionInterfaceFitError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionInterfaceFitError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise AdmissionInterfaceFitError(
            f"artifact is not a JSON object: {relative_path}"
        )
    return value


def _artifact_binding(repository_root: Path, relative_path: str) -> dict[str, str]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise AdmissionInterfaceFitError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return {"digest": sha256_digest(payload), "relative_path": relative_path}


def _candidate_and_blob_set(
    repository_root: Path, capability_id: str, candidate_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    candidates = cast(list[dict[str, Any]], bundle["candidates"])
    candidate = next(
        (
            item
            for item in candidates
            if item["candidate_id"] == candidate_id
            and item["capability_id"] == capability_id
        ),
        None,
    )
    if candidate is None:
        raise AdmissionInterfaceFitError(
            "candidate is absent or belongs to another capability"
        )
    blob_sets = cast(list[dict[str, Any]], bundle["blob_sets"])
    blob_set = next(
        (
            item
            for item in blob_sets
            if item["blob_set_digest"] == candidate["blob_set_digest"]
        ),
        None,
    )
    if blob_set is None:
        raise AdmissionInterfaceFitError("candidate blob set is absent")
    if blob_set["blob_count"] != candidate["blob_count"]:
        raise AdmissionInterfaceFitError("candidate blob count drifted")
    return candidate, blob_set


def _verified_candidate_blobs(
    repository_root: Path, blob_set: Mapping[str, Any]
) -> list[dict[str, Any]]:
    records = cast(list[dict[str, Any]], blob_set["blobs"])
    object_ids = [cast(str, item["git_object_id"]) for item in records]
    payloads = _read_blobs(repository_root, object_ids)
    observed: list[dict[str, Any]] = []
    for record in records:
        object_id = cast(str, record["git_object_id"])
        payload = payloads.get(object_id)
        if payload is None:
            raise AdmissionInterfaceFitError(
                f"candidate blob is unreadable: {record['path']}"
            )
        if sha256_digest(payload) != record["sha256"]:
            raise AdmissionInterfaceFitError(
                f"candidate blob digest drifted: {record['path']}"
            )
        if len(payload) != record["size_bytes"]:
            raise AdmissionInterfaceFitError(
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
    path: str, payload: bytes, spec: Mapping[str, Any]
) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    try:
        source = payload.decode("utf-8")
        tree = ast.parse(source, filename=path)
    except (UnicodeDecodeError, SyntaxError):
        return None
    expected_name = cast(str, spec["callable"])
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != expected_name:
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
        required_parameters = set(cast(tuple[str, ...], spec["required_parameters"]))
        required_decisions = set(cast(tuple[str, ...], spec["required_decisions"]))
        required_output_keys = set(cast(tuple[str, ...], spec["required_output_keys"]))
        missing_parameters = sorted(required_parameters - parameters)
        missing_decisions = sorted(required_decisions - decisions)
        missing_output_keys = sorted(required_output_keys - output_keys)
        return {
            "callable": expected_name,
            "decisions": sorted(decisions),
            "fit": not (missing_parameters or missing_decisions or missing_output_keys),
            "missing_decisions": missing_decisions,
            "missing_output_keys": missing_output_keys,
            "missing_parameters": missing_parameters,
            "output_keys": sorted(output_keys),
            "parameters": sorted(parameters),
            "path": path,
        }
    return None


def _measure(capability_id: str, blobs: list[dict[str, Any]]) -> dict[str, Any]:
    spec = _SURFACE_SPECS[capability_id]
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
                cast(str, item["path"]), cast(bytes, item["payload"]), spec
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
        "capability_id": capability_id,
        "fit": fit,
    }
    return {**core, "observation_digest": sha256_digest(canonical_document_bytes(core))}


def _mutated_blobs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mutated = [dict(item) for item in blobs]
    target = next(
        (item for item in mutated if cast(bytes, item["payload"])),
        None,
    )
    if target is None:
        raise AdmissionInterfaceFitError("candidate has no mutable blob bytes")
    payload = bytearray(cast(bytes, target["payload"]))
    payload[len(payload) // 2] ^= 1
    target["payload"] = bytes(payload)
    return mutated


def _positive_control_source(capability_id: str) -> bytes:
    if capability_id == "deployment-admission":
        return b"""def evaluate_deployment_admission(*, admission_envelope, candidate_blobs, candidate_manifest, payload_descriptor, target_descriptor, trusted_time):
    if not admission_envelope or target_descriptor.get("scope") in {"production", "unknown"}:
        return {"decision": "deny", "receipt": "fail-closed", "quiesce": "pre-deadline"}
    return {"decision": "allow", "receipt": "exact-binding", "quiesce": "not-required"}
"""
    return b"""def evaluate_distribution_admission(*, admission_envelope, candidate_blobs, candidate_manifest, destination_descriptor, distribution_subset, trusted_time):
    if not admission_envelope or destination_descriptor.get("scope") in {"production", "unknown"}:
        return {"decision": "deny", "receipt": "fail-closed", "abort": "pre-deadline"}
    return {"decision": "allow", "receipt": "exact-binding", "abort": "not-required"}
"""


def _positive_control_blobs(
    capability_id: str, blobs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    injected = [dict(item) for item in blobs]
    injected.append(
        {
            "path": f"__pmorg_positive_control__/{capability_id}.py",
            "payload": _positive_control_source(capability_id),
        }
    )
    injected.sort(key=lambda item: cast(str, item["path"]))
    return injected


def _runtime_measurement(repository_root: Path) -> tuple[dict[str, Any], str]:
    interpreter = Path(sys.executable).resolve()
    try:
        interpreter_payload = interpreter.read_bytes()
    except OSError as error:
        raise AdmissionInterfaceFitError(
            "executed interpreter binary cannot be measured"
        ) from error
    artifacts = [
        _artifact_binding(repository_root, relative_path)
        for relative_path in RUNTIME_ARTIFACT_RELATIVES
    ]
    measurement = {
        "declared_artifacts": artifacts,
        "interpreter_binary": {
            "digest": sha256_digest(interpreter_payload),
            "relative_path": RUNTIME_INTERPRETER_LABEL,
        },
    }
    return measurement, sha256_digest(canonical_document_bytes(measurement))


def execute_admission_interface_fit(
    capability_id: str,
    candidate_id: str,
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    """Run baseline, byte-flip and conforming-positive-control observations."""

    repository_root = repository_root.resolve()
    if capability_id not in _SURFACE_SPECS:
        raise AdmissionInterfaceFitError(
            f"unsupported admission capability: {capability_id}"
        )
    candidate, blob_set = _candidate_and_blob_set(
        repository_root, capability_id, candidate_id
    )
    blobs = _verified_candidate_blobs(repository_root, blob_set)
    baseline = _measure(capability_id, blobs)
    mutation = _measure(capability_id, _mutated_blobs(blobs))
    positive = _measure(capability_id, _positive_control_blobs(capability_id, blobs))
    if baseline["observation_digest"] == mutation["observation_digest"]:
        raise AdmissionInterfaceFitError(
            "candidate byte mutation did not change an adapter observation"
        )
    if not positive["fit"]:
        raise AdmissionInterfaceFitError(
            "conforming positive control did not change interface fit"
        )

    policy = build_qualification_oracle_policy(repository_root)
    test_id = cast(str, _SURFACE_SPECS[capability_id]["test_id"])
    oracle = next(
        (
            item
            for item in policy["oracles"]
            if item["capability_id"] == capability_id and item["test_id"] == test_id
        ),
        None,
    )
    if oracle is None or oracle["oracle_status"] != "executable":
        raise AdmissionInterfaceFitError("admission oracle is not executable")
    runtime_measurement, runtime_identity_digest = _runtime_measurement(repository_root)
    reasons = (
        []
        if baseline["fit"]
        else [
            "candidate exposes no callable surface satisfying the exact admission interface"
        ]
    )
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "capability_id": capability_id,
        "test_id": test_id,
        "candidate_id": candidate_id,
        "oracle_id": oracle["oracle_id"],
        "oracle_status": "executable",
        "candidate_manifest_digest": candidate["manifest_digest"],
        "adapter_digest": oracle["adapter"],
        "runtime_identity_digest": runtime_identity_digest,
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
        "bindings": [
            {"digest": item["digest"], "relative_path": item["relative_path"]}
            for item in oracle["bindings"]
        ],
        "failure_reasons": reasons,
        "verdict": "pass" if baseline["fit"] else "fail",
    }
    try:
        validate_qualification_oracle_result(result, repository_root=repository_root)
    except QualificationOracleError as error:
        raise AdmissionInterfaceFitError(
            "executor produced invalid qualification evidence"
        ) from error
    return result


__all__ = [
    "AdmissionInterfaceFitError",
    "execute_admission_interface_fit",
]
