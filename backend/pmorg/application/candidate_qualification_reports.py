"""Execute admission qualification oracles over the complete candidate denominator."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.application.admission_interface_fit_executor import _measure
from pmorg.application.admission_interface_fit_executor import _mutated_blobs
from pmorg.application.admission_interface_fit_executor import _positive_control_blobs
from pmorg.application.admission_interface_fit_executor import _runtime_measurement
from pmorg.application.admission_interface_fit_executor import _SURFACE_SPECS
from pmorg.application.admission_interface_fit_executor import _verified_candidate_blobs
from pmorg.application.candidate_inputs import validate_candidate_input_bundle
from pmorg.application.qualification_oracles import build_qualification_oracle_policy
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import result_schema
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.contracts.types import CandidateQualificationReport

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
POLICY_RELATIVE = "pmorg/capabilities/qualification-oracle-policy-v1.json"
RESULT_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-result-v2.schema.json"
REPORT_SCHEMA_RELATIVE = (
    "backend/pmorg/contracts/schemas/candidate-qualification-report-v1.schema.json"
)
INDEX_RELATIVE = "pmorg/capabilities/candidate-qualification-reports-v1.json"
INDEX_SCHEMA_RELATIVE = (
    "pmorg/capabilities/candidate-qualification-reports-v1.schema.json"
)
RESULT_ROOT_RELATIVE = "pmorg/capabilities/candidate-qualification-results"
REPORT_ROOT_RELATIVE = "pmorg/capabilities/candidate-qualification-reports"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/candidate_qualification_reports.py",
    "pmorg/scripts/build_candidate_qualification_reports.py",
)

INDEX_SCHEMA_VERSION = "pmorg.candidate-qualification-report-index/v1"
INDEX_VERSION = "1.0.0"
REPORT_SCHEMA_VERSION = "pmorg.candidate-qualification-report/v1"
RESULT_SCHEMA_VERSION = "pmorg.qualification-oracle-result/v2"
CAPABILITY_COUNTS = {
    "deployment-admission": 82,
    "distribution-admission": 104,
}
CAPABILITIES = tuple(CAPABILITY_COUNTS)
SOURCE_SCOPE_RELATIVES = {
    "ce": "pmorg/capabilities/source-scopes/onyx-ce-source-scope-v1.json",
    "ee": "pmorg/capabilities/source-scopes/onyx-ee-source-scope-v1.json",
}


class CandidateQualificationReportError(ValueError):
    """Raised when qualification execution or committed evidence is incomplete."""


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise CandidateQualificationReportError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateQualificationReportError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise CandidateQualificationReportError(
            f"artifact is not a JSON object: {relative_path}"
        )
    return value


def _artifact_ref(
    repository_root: Path,
    relative_path: str,
    *,
    logical_name: str,
    media_type: str = "application/json",
) -> dict[str, Any]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise CandidateQualificationReportError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return {
        "digest": sha256_digest(payload),
        "logical_name": logical_name,
        "media_type": media_type,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _payload_ref(
    relative_path: str,
    payload: bytes,
    *,
    logical_name: str,
) -> dict[str, Any]:
    return {
        "digest": sha256_digest(payload),
        "logical_name": logical_name,
        "media_type": "application/json",
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _contract_test_refs(
    repository_root: Path, catalog: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    items = cast(list[dict[str, Any]], catalog.get("items", []))
    refs: dict[str, dict[str, Any]] = {}
    for item in items:
        capability_id = item.get("capability_id")
        if capability_id not in CAPABILITIES:
            continue
        contract_tests = cast(list[dict[str, Any]], item.get("contract_tests", []))
        if len(contract_tests) != 1:
            raise CandidateQualificationReportError(
                f"{capability_id} must bind exactly one contract-test manifest"
            )
        ref = contract_tests[0]
        observed = _artifact_ref(
            repository_root,
            cast(str, ref["relative_path"]),
            logical_name=cast(str, ref["logical_name"]),
        )
        if observed != ref:
            raise CandidateQualificationReportError(
                f"{capability_id} contract-test manifest binding drifted"
            )
        refs[cast(str, capability_id)] = observed
    if set(refs) != set(CAPABILITIES):
        raise CandidateQualificationReportError(
            "admission contract-test manifest coverage is incomplete"
        )
    return refs


def _source_scope_map(repository_root: Path) -> dict[str, dict[str, Any]]:
    scopes = {
        surface: _read_object(repository_root, relative_path)
        for surface, relative_path in SOURCE_SCOPE_RELATIVES.items()
    }
    for surface, scope in scopes.items():
        if scope.get("scope_kind") != f"onyx_{surface}":
            raise CandidateQualificationReportError(
                f"{surface} source-scope kind drifted"
            )
    return scopes


def _result_and_report_paths(capability_id: str, candidate_id: str) -> tuple[str, str]:
    result = f"{RESULT_ROOT_RELATIVE}/{capability_id}/{candidate_id}.json"
    report = f"{REPORT_ROOT_RELATIVE}/{capability_id}/{candidate_id}.json"
    return result, report


def _test_vector_ref(
    repository_root: Path, oracle: Mapping[str, Any]
) -> dict[str, Any]:
    ref = cast(dict[str, Any], oracle["candidate_test_vector"])
    return _artifact_ref(
        repository_root,
        cast(str, ref["relative_path"]),
        logical_name=(
            f"{oracle['capability_id']}-{oracle['test_id']}-qualification-test-vector"
        ),
    )


def _result_document(
    *,
    capability_id: str,
    candidate: Mapping[str, Any],
    oracle: Mapping[str, Any],
    baseline: Mapping[str, Any],
    mutation: Mapping[str, Any],
    positive: Mapping[str, Any],
    runtime_measurement: Mapping[str, Any],
    runtime_identity_digest: str,
    blob_count: int,
) -> dict[str, Any]:
    reasons = (
        []
        if baseline["fit"]
        else [
            "candidate exposes no callable surface satisfying the exact admission interface"
        ]
    )
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "capability_id": capability_id,
        "test_id": _SURFACE_SPECS[capability_id]["test_id"],
        "candidate_id": candidate["candidate_id"],
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
        "projected_blob_count": blob_count,
        "observed_blob_count": blob_count,
        "unobserved_blob_count": 0,
        "execution_exit_codes": [0, 0, 0],
        "bindings": [
            {"digest": item["digest"], "relative_path": item["relative_path"]}
            for item in oracle["bindings"]
        ],
        "failure_reasons": reasons,
        "verdict": "pass" if baseline["fit"] else "fail",
    }


def _report_document(
    *,
    repository_root: Path,
    candidate: Mapping[str, Any],
    blob_set: Mapping[str, Any],
    catalog_hash: str,
    policy_ref: Mapping[str, Any],
    contract_test_ref: Mapping[str, Any],
    test_vector_ref: Mapping[str, Any],
    result_ref: Mapping[str, Any],
    result: Mapping[str, Any],
    source_scope: Mapping[str, Any],
) -> dict[str, Any]:
    source_snapshot = cast(dict[str, Any], candidate["source_inventory"])
    if source_snapshot != source_scope["path_inventory"]:
        raise CandidateQualificationReportError(
            "candidate source inventory drifted from its source scope"
        )
    paths = sorted(
        cast(str, blob["path"])
        for blob in cast(list[dict[str, Any]], blob_set["blobs"])
    )
    failed = 1 if result["verdict"] == "fail" else 0
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "catalog_hash": catalog_hash,
        "capability_id": candidate["capability_id"],
        "candidate_id": candidate["candidate_id"],
        "source_ref": {
            "repository": candidate["source_repository"],
            "commit": candidate["source_commit"],
            "paths": paths,
            "tree_hash": source_scope["tree_hash"],
            "source_snapshot": source_snapshot,
        },
        "qualification_policy": dict(policy_ref),
        "required_test_manifest": dict(contract_test_ref),
        "expected_test_count": 1,
        "executed_test_count": 1,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "failed_test_count": failed,
        "test_evidence": [
            {
                "test_id": result["test_id"],
                "test_manifest": dict(test_vector_ref),
                "result": dict(result_ref),
                "verdict": result["verdict"],
            }
        ],
        "verdict": result["verdict"],
    }
    try:
        CandidateQualificationReport.model_validate(report)
    except ValidationError as error:
        raise CandidateQualificationReportError(
            "executor produced an invalid CandidateQualificationReport"
        ) from error
    contract_schema = _read_object(repository_root, REPORT_SCHEMA_RELATIVE)
    errors = sorted(Draft202012Validator(contract_schema).iter_errors(report), key=str)
    if errors:
        raise CandidateQualificationReportError(
            f"CandidateQualificationReport schema violation: {errors[0]}"
        )
    return report


def index_schema() -> dict[str, Any]:
    nonempty = {"type": "string", "minLength": 1}
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    artifact = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "digest",
            "logical_name",
            "media_type",
            "relative_path",
            "size_bytes",
        ],
        "properties": {
            "digest": digest,
            "logical_name": nonempty,
            "media_type": nonempty,
            "relative_path": nonempty,
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }
    entry = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "candidate_group",
            "candidate_id",
            "candidate_manifest_digest",
            "capability_id",
            "report",
            "result",
            "source_surface",
            "verdict",
        ],
        "properties": {
            "candidate_group": nonempty,
            "candidate_id": {
                "type": "string",
                "pattern": "^candidate-[0-9a-f]{64}$",
            },
            "candidate_manifest_digest": digest,
            "capability_id": {"enum": list(CAPABILITIES)},
            "report": artifact,
            "result": artifact,
            "source_surface": {"enum": ["ce", "ee"]},
            "verdict": {"enum": ["pass", "fail"]},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:candidate-qualification-report-index:v1",
        "title": "PMORG admission candidate qualification report index",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "index_version",
            "catalog_hash",
            "source_repository",
            "source_commit",
            "source_tree_id",
            "candidate_inputs",
            "qualification_policy",
            "result_schema",
            "report_schema",
            "derivation_artifacts",
            "capability_report_counts",
            "report_count",
            "executed_test_count",
            "failed_test_count",
            "passed_test_count",
            "missing_test_count",
            "duplicate_test_count",
            "runtime_identity_digests",
            "entries",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": INDEX_SCHEMA_VERSION},
            "index_version": {"const": INDEX_VERSION},
            "catalog_hash": digest,
            "source_repository": nonempty,
            "source_commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "source_tree_id": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "candidate_inputs": artifact,
            "qualification_policy": artifact,
            "result_schema": artifact,
            "report_schema": artifact,
            "derivation_artifacts": {
                "type": "array",
                "minItems": len(DERIVATION_RELATIVES),
                "maxItems": len(DERIVATION_RELATIVES),
                "items": artifact,
            },
            "capability_report_counts": {
                "type": "object",
                "additionalProperties": False,
                "required": list(CAPABILITIES),
                "properties": {
                    capability_id: {"const": count}
                    for capability_id, count in CAPABILITY_COUNTS.items()
                },
            },
            "report_count": {"const": sum(CAPABILITY_COUNTS.values())},
            "executed_test_count": {"const": sum(CAPABILITY_COUNTS.values())},
            "failed_test_count": {"type": "integer", "minimum": 0},
            "passed_test_count": {"type": "integer", "minimum": 0},
            "missing_test_count": {"const": 0},
            "duplicate_test_count": {"const": 0},
            "runtime_identity_digests": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1,
                "items": digest,
                "uniqueItems": True,
            },
            "entries": {
                "type": "array",
                "minItems": sum(CAPABILITY_COUNTS.values()),
                "maxItems": sum(CAPABILITY_COUNTS.values()),
                "items": entry,
            },
            "claim_boundary": {
                "const": "candidate_qualification_only_no_disposition_or_admission"
            },
        },
    }


def build_candidate_qualification_report_outputs(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    """Execute both admission oracles and return all content-addressed outputs."""

    repository_root = repository_root.resolve()
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    candidates = sorted(
        (
            item
            for item in cast(list[dict[str, Any]], bundle["candidates"])
            if item["capability_id"] in CAPABILITIES
        ),
        key=lambda item: (item["capability_id"], item["candidate_id"]),
    )
    observed_counts = {
        capability_id: sum(
            item["capability_id"] == capability_id for item in candidates
        )
        for capability_id in CAPABILITIES
    }
    if observed_counts != CAPABILITY_COUNTS:
        raise CandidateQualificationReportError(
            f"admission candidate denominator drifted: {observed_counts}"
        )
    blob_sets = {
        item["blob_set_digest"]: item
        for item in cast(list[dict[str, Any]], bundle["blob_sets"])
    }
    catalog = _read_object(repository_root, CATALOG_RELATIVE)
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    contract_test_refs = _contract_test_refs(repository_root, catalog)
    source_scopes = _source_scope_map(repository_root)
    policy = build_qualification_oracle_policy(repository_root)
    policy_ref = _artifact_ref(
        repository_root,
        POLICY_RELATIVE,
        logical_name="qualification-oracle-policy-v1",
    )
    oracles = {
        item["capability_id"]: item
        for item in cast(list[dict[str, Any]], policy["oracles"])
        if item["capability_id"] in CAPABILITIES
    }
    if set(oracles) != set(CAPABILITIES) or any(
        item["oracle_status"] != "executable" for item in oracles.values()
    ):
        raise CandidateQualificationReportError(
            "admission qualification oracle activation is incomplete"
        )
    runtime_measurement, runtime_identity_digest = _runtime_measurement(repository_root)
    result_validator = Draft202012Validator(result_schema())
    blob_cache: dict[str, list[dict[str, Any]]] = {}
    measurement_cache: dict[
        tuple[str, str], tuple[dict[str, Any], dict[str, Any], dict[str, Any]]
    ] = {}
    outputs: dict[str, bytes] = {
        INDEX_SCHEMA_RELATIVE: canonical_document_bytes(index_schema())
    }
    entries: list[dict[str, Any]] = []
    failed = 0
    passed = 0
    for candidate in candidates:
        capability_id = cast(str, candidate["capability_id"])
        blob_set_digest = cast(str, candidate["blob_set_digest"])
        blob_set = blob_sets.get(blob_set_digest)
        if blob_set is None:
            raise CandidateQualificationReportError("candidate blob set is absent")
        blobs = blob_cache.get(blob_set_digest)
        if blobs is None:
            blobs = _verified_candidate_blobs(repository_root, blob_set)
            blob_cache[blob_set_digest] = blobs
        measurement_key = (capability_id, blob_set_digest)
        measurements = measurement_cache.get(measurement_key)
        if measurements is None:
            baseline = _measure(capability_id, blobs)
            mutation = _measure(capability_id, _mutated_blobs(blobs))
            positive = _measure(
                capability_id, _positive_control_blobs(capability_id, blobs)
            )
            if baseline["observation_digest"] == mutation["observation_digest"]:
                raise CandidateQualificationReportError(
                    "candidate byte mutation did not change an observation"
                )
            if positive["fit"] is not True:
                raise CandidateQualificationReportError(
                    "conforming positive control did not establish interface fit"
                )
            measurements = (baseline, mutation, positive)
            measurement_cache[measurement_key] = measurements
        baseline, mutation, positive = measurements
        oracle = oracles[capability_id]
        result = _result_document(
            capability_id=capability_id,
            candidate=candidate,
            oracle=oracle,
            baseline=baseline,
            mutation=mutation,
            positive=positive,
            runtime_measurement=runtime_measurement,
            runtime_identity_digest=runtime_identity_digest,
            blob_count=len(blobs),
        )
        result_errors = sorted(result_validator.iter_errors(result), key=str)
        if result_errors:
            raise CandidateQualificationReportError(
                f"oracle result schema violation: {result_errors[0]}"
            )
        result_path, report_path = _result_and_report_paths(
            capability_id, cast(str, candidate["candidate_id"])
        )
        result_payload = canonical_document_bytes(result)
        result_ref = _payload_ref(
            result_path,
            result_payload,
            logical_name=f"{candidate['candidate_id']}-qualification-oracle-result",
        )
        test_vector_ref = _test_vector_ref(repository_root, oracle)
        report = _report_document(
            repository_root=repository_root,
            candidate=candidate,
            blob_set=blob_set,
            catalog_hash=catalog_hash,
            policy_ref=policy_ref,
            contract_test_ref=contract_test_refs[capability_id],
            test_vector_ref=test_vector_ref,
            result_ref=result_ref,
            result=result,
            source_scope=source_scopes[cast(str, candidate["source_surface"])],
        )
        report_payload = canonical_document_bytes(report)
        report_ref = _payload_ref(
            report_path,
            report_payload,
            logical_name=f"{candidate['candidate_id']}-qualification-report",
        )
        outputs[result_path] = result_payload
        outputs[report_path] = report_payload
        entries.append(
            {
                "candidate_group": candidate["candidate_group"],
                "candidate_id": candidate["candidate_id"],
                "candidate_manifest_digest": candidate["manifest_digest"],
                "capability_id": capability_id,
                "report": report_ref,
                "result": result_ref,
                "source_surface": candidate["source_surface"],
                "verdict": result["verdict"],
            }
        )
        if result["verdict"] == "fail":
            failed += 1
        else:
            passed += 1
    index = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "index_version": INDEX_VERSION,
        "catalog_hash": catalog_hash,
        "source_repository": bundle["source_repository"],
        "source_commit": bundle["source_commit"],
        "source_tree_id": bundle["source_tree_id"],
        "candidate_inputs": _artifact_ref(
            repository_root,
            CANDIDATE_INPUTS_RELATIVE,
            logical_name="candidate-inputs-v1",
        ),
        "qualification_policy": policy_ref,
        "result_schema": _artifact_ref(
            repository_root,
            RESULT_SCHEMA_RELATIVE,
            logical_name="qualification-oracle-result-v2-schema",
            media_type="application/schema+json",
        ),
        "report_schema": _artifact_ref(
            repository_root,
            REPORT_SCHEMA_RELATIVE,
            logical_name="candidate-qualification-report-v1-schema",
            media_type="application/schema+json",
        ),
        "derivation_artifacts": [
            _artifact_ref(
                repository_root,
                relative_path,
                logical_name=Path(relative_path).name,
                media_type="text/x-python",
            )
            for relative_path in DERIVATION_RELATIVES
        ],
        "capability_report_counts": observed_counts,
        "report_count": len(entries),
        "executed_test_count": len(entries),
        "failed_test_count": failed,
        "passed_test_count": passed,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "runtime_identity_digests": [runtime_identity_digest],
        "entries": entries,
        "claim_boundary": "candidate_qualification_only_no_disposition_or_admission",
    }
    errors = sorted(Draft202012Validator(index_schema()).iter_errors(index), key=str)
    if errors:
        raise CandidateQualificationReportError(
            f"qualification report index schema violation: {errors[0]}"
        )
    outputs[INDEX_RELATIVE] = canonical_document_bytes(index)
    return outputs


def _verified_payload(
    repository_root: Path, ref: Mapping[str, Any], *, label: str
) -> bytes:
    relative_path = ref.get("relative_path")
    if not isinstance(relative_path, str) or not relative_path:
        raise CandidateQualificationReportError(f"{label} has no relative path")
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise CandidateQualificationReportError(f"{label} is missing") from error
    if ref.get("digest") != sha256_digest(payload):
        raise CandidateQualificationReportError(f"{label} digest drifted")
    if ref.get("size_bytes") != len(payload):
        raise CandidateQualificationReportError(f"{label} size drifted")
    return payload


def _verified_ref(
    repository_root: Path, ref: Mapping[str, Any], *, label: str
) -> dict[str, Any]:
    payload = _verified_payload(repository_root, ref, label=label)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateQualificationReportError(f"{label} is not JSON") from error
    if not isinstance(value, dict):
        raise CandidateQualificationReportError(f"{label} is not an object")
    return value


def check_candidate_qualification_reports(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    """Validate the complete committed evidence graph without replaying history."""

    repository_root = repository_root.resolve()
    expected_schema = canonical_document_bytes(index_schema())
    try:
        committed_schema = _safe_path(
            repository_root, INDEX_SCHEMA_RELATIVE
        ).read_bytes()
    except OSError as error:
        raise CandidateQualificationReportError(
            "committed index schema is missing"
        ) from error
    if committed_schema != expected_schema:
        raise CandidateQualificationReportError("committed index schema drifted")
    index = _read_object(repository_root, INDEX_RELATIVE)
    errors = sorted(Draft202012Validator(index_schema()).iter_errors(index), key=str)
    if errors:
        raise CandidateQualificationReportError(
            f"committed qualification index is invalid: {errors[0]}"
        )
    bundle = _verified_ref(
        repository_root, index["candidate_inputs"], label="candidate inputs"
    )
    validate_candidate_input_bundle(bundle)
    catalog = _read_object(repository_root, CATALOG_RELATIVE)
    if index["catalog_hash"] != sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    ):
        raise CandidateQualificationReportError("capability catalog binding drifted")
    contract_test_refs = _contract_test_refs(repository_root, catalog)
    source_scopes = _source_scope_map(repository_root)
    candidates = {
        (item["capability_id"], item["candidate_id"]): item
        for item in cast(list[dict[str, Any]], bundle["candidates"])
        if item["capability_id"] in CAPABILITIES
    }
    expected_ids = set(candidates)
    entries = cast(list[dict[str, Any]], index["entries"])
    observed_ids = [(item["capability_id"], item["candidate_id"]) for item in entries]
    if observed_ids != sorted(expected_ids) or len(observed_ids) != len(
        set(observed_ids)
    ):
        raise CandidateQualificationReportError(
            "committed reports do not exactly cover the admission denominator"
        )
    policy = _verified_ref(
        repository_root, index["qualification_policy"], label="qualification policy"
    )
    oracles = {
        item["capability_id"]: item
        for item in cast(list[dict[str, Any]], policy["oracles"])
        if item["capability_id"] in CAPABILITIES
    }
    report_schema = _verified_ref(
        repository_root, index["report_schema"], label="report schema"
    )
    result_schema_document = _verified_ref(
        repository_root, index["result_schema"], label="result schema"
    )
    report_validator = Draft202012Validator(report_schema)
    result_validator = Draft202012Validator(result_schema_document)
    runtime_digests: set[str] = set()
    result_paths: set[str] = set()
    report_paths: set[str] = set()
    failed = 0
    passed = 0
    for entry in entries:
        identity = (entry["capability_id"], entry["candidate_id"])
        candidate = candidates[identity]
        result = _verified_ref(
            repository_root, entry["result"], label=f"{entry['candidate_id']} result"
        )
        report = _verified_ref(
            repository_root, entry["report"], label=f"{entry['candidate_id']} report"
        )
        result_paths.add(cast(str, entry["result"]["relative_path"]))
        report_paths.add(cast(str, entry["report"]["relative_path"]))
        result_errors = sorted(result_validator.iter_errors(result), key=str)
        report_errors = sorted(report_validator.iter_errors(report), key=str)
        if result_errors:
            raise CandidateQualificationReportError(
                f"committed result is invalid: {result_errors[0]}"
            )
        if report_errors:
            raise CandidateQualificationReportError(
                f"committed report is invalid: {report_errors[0]}"
            )
        try:
            CandidateQualificationReport.model_validate(report)
        except ValidationError as error:
            raise CandidateQualificationReportError(
                "committed report fails the contract model"
            ) from error
        oracle = oracles[cast(str, entry["capability_id"])]
        evidence = cast(list[dict[str, Any]], report["test_evidence"])
        blob_sets = cast(list[dict[str, Any]], bundle["blob_sets"])
        blob_set = next(
            item
            for item in blob_sets
            if item["blob_set_digest"] == candidate["blob_set_digest"]
        )
        expected_paths = sorted(
            cast(str, blob["path"])
            for blob in cast(list[dict[str, Any]], blob_set["blobs"])
        )
        source_scope = source_scopes[cast(str, candidate["source_surface"])]
        source_ref = cast(dict[str, Any], report["source_ref"])
        _verified_payload(
            repository_root,
            cast(dict[str, Any], source_ref["source_snapshot"]),
            label="candidate source snapshot",
        )
        _verified_payload(
            repository_root,
            cast(dict[str, Any], report["required_test_manifest"]),
            label="required test manifest",
        )
        if (
            entry["candidate_manifest_digest"] != candidate["manifest_digest"]
            or result["candidate_id"] != candidate["candidate_id"]
            or result["candidate_manifest_digest"] != candidate["manifest_digest"]
            or result["capability_id"] != candidate["capability_id"]
            or result["oracle_id"] != oracle["oracle_id"]
            or result["adapter_digest"] != oracle["adapter"]
            or result["bindings"]
            != [
                {
                    "digest": binding["digest"],
                    "relative_path": binding["relative_path"],
                }
                for binding in oracle["bindings"]
            ]
            or result["verdict"] != entry["verdict"]
            or report["candidate_id"] != candidate["candidate_id"]
            or report["capability_id"] != candidate["capability_id"]
            or report["catalog_hash"] != index["catalog_hash"]
            or report["qualification_policy"] != index["qualification_policy"]
            or report["required_test_manifest"]
            != contract_test_refs[cast(str, candidate["capability_id"])]
            or report["verdict"] != entry["verdict"]
            or report["executed_test_count"] != 1
            or report["expected_test_count"] != 1
            or report["missing_test_count"] != 0
            or report["duplicate_test_count"] != 0
            or len(evidence) != 1
            or evidence[0]["result"] != entry["result"]
            or evidence[0]["test_manifest"] != _test_vector_ref(repository_root, oracle)
            or evidence[0]["verdict"] != entry["verdict"]
            or evidence[0]["test_id"] != result["test_id"]
            or source_ref["repository"] != candidate["source_repository"]
            or source_ref["commit"] != candidate["source_commit"]
            or source_ref["paths"] != expected_paths
            or source_ref["tree_hash"] != source_scope["tree_hash"]
            or source_ref["source_snapshot"] != candidate["source_inventory"]
            or result["observed_blob_count"] != candidate["blob_count"]
            or result["projected_blob_count"] != candidate["blob_count"]
            or result["unobserved_blob_count"] != 0
            or result["baseline_observation_digest"]
            == result["mutation_observation_digest"]
            or result["positive_injection_fit"] is not True
            or result["oracle_status"] != "executable"
            or result["execution_exit_codes"] != [0, 0, 0]
            or (entry["verdict"] == "pass" and result["baseline_fit"] is not True)
            or (entry["verdict"] == "fail" and result["baseline_fit"] is not False)
            or (entry["verdict"] == "pass" and result["failure_reasons"])
            or (entry["verdict"] == "fail" and not result["failure_reasons"])
            or report["failed_test_count"] != (1 if entry["verdict"] == "fail" else 0)
        ):
            raise CandidateQualificationReportError(
                f"candidate qualification evidence drifted: {entry['candidate_id']}"
            )
        runtime_measurement = result["runtime_measurement"]
        if (
            runtime_measurement["declared_artifacts"]
            != [
                {
                    "digest": artifact["digest"],
                    "relative_path": artifact["relative_path"],
                }
                for artifact in policy["runtime_identity"]["artifacts"]
            ]
            or runtime_measurement["interpreter_binary"]["relative_path"]
            != "@runtime/executed-python-interpreter"
        ):
            raise CandidateQualificationReportError(
                "committed runtime declaration binding drifted"
            )
        if result["runtime_identity_digest"] != sha256_digest(
            canonical_document_bytes(runtime_measurement)
        ):
            raise CandidateQualificationReportError(
                "committed runtime identity digest drifted"
            )
        runtime_digests.add(cast(str, result["runtime_identity_digest"]))
        if entry["verdict"] == "fail":
            failed += 1
        else:
            passed += 1
    if (
        sorted(runtime_digests) != index["runtime_identity_digests"]
        or failed != index["failed_test_count"]
        or passed != index["passed_test_count"]
        or failed + passed != index["executed_test_count"]
    ):
        raise CandidateQualificationReportError(
            "qualification report index counters or runtime identities drifted"
        )
    committed_result_paths = {
        path.relative_to(repository_root).as_posix()
        for path in _safe_path(repository_root, RESULT_ROOT_RELATIVE).rglob("*.json")
    }
    committed_report_paths = {
        path.relative_to(repository_root).as_posix()
        for path in _safe_path(repository_root, REPORT_ROOT_RELATIVE).rglob("*.json")
    }
    if committed_result_paths != result_paths or committed_report_paths != report_paths:
        raise CandidateQualificationReportError(
            "qualification evidence directories contain missing or unindexed files"
        )
    for artifact in cast(list[dict[str, Any]], index["derivation_artifacts"]):
        _verified_payload(repository_root, artifact, label="derivation artifact")


def write_candidate_qualification_reports(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    """Execute and commit the complete admission qualification evidence graph."""

    repository_root = repository_root.resolve()
    outputs = build_candidate_qualification_report_outputs(repository_root)
    expected_paths = set(outputs)
    for root_relative in (RESULT_ROOT_RELATIVE, REPORT_ROOT_RELATIVE):
        root = _safe_path(repository_root, root_relative)
        if root.exists():
            for path in root.rglob("*.json"):
                relative_path = path.relative_to(repository_root).as_posix()
                if relative_path not in expected_paths:
                    path.unlink()
    for relative_path, payload in outputs.items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


__all__ = [
    "CandidateQualificationReportError",
    "build_candidate_qualification_report_outputs",
    "check_candidate_qualification_reports",
    "index_schema",
    "write_candidate_qualification_reports",
]
