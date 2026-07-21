"""Execute Thin Fork qualification over the complete 55-candidate denominator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from typing import cast
from typing import Mapping

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.application.candidate_inputs import validate_candidate_input_bundle
from pmorg.application.candidate_qualification_reports import _artifact_ref
from pmorg.application.candidate_qualification_reports import _payload_ref
from pmorg.application.candidate_qualification_reports import _read_object
from pmorg.application.candidate_qualification_reports import _safe_path
from pmorg.application.candidate_qualification_reports import _source_scope_map
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import result_schema
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.application.thin_fork_interface_fit_executor import (
    build_thin_fork_oracle_extension,
)
from pmorg.application.thin_fork_interface_fit_executor import (
    execute_thin_fork_interface_fit,
)
from pmorg.contracts.types import CandidateQualificationReport

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
EXTENSION_RELATIVE = (
    "pmorg/capabilities/qualification-oracle-extension-thin-fork-v1.json"
)
VECTOR_RELATIVE = (
    "pmorg/capabilities/qualification-test-vector-extensions/"
    "thin-fork-boundary-A-PATCH-001-v1.json"
)
CONTRACT_TEST_RELATIVE = "pmorg/capabilities/contract-tests/thin-fork-boundary.json"
RESULT_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-result-v2.schema.json"
REPORT_SCHEMA_RELATIVE = (
    "backend/pmorg/contracts/schemas/candidate-qualification-report-v1.schema.json"
)
INDEX_RELATIVE = "pmorg/capabilities/thin-fork-candidate-qualification-reports-v1.json"
INDEX_SCHEMA_RELATIVE = (
    "pmorg/capabilities/thin-fork-candidate-qualification-reports-v1.schema.json"
)
RESULT_ROOT_RELATIVE = "pmorg/capabilities/thin-fork-candidate-qualification-results"
REPORT_ROOT_RELATIVE = "pmorg/capabilities/thin-fork-candidate-qualification-reports"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/thin_fork_candidate_qualification_reports.py",
    "pmorg/scripts/build_thin_fork_candidate_qualification_reports.py",
)

INDEX_SCHEMA_VERSION = "pmorg.thin-fork-candidate-qualification-report-index/v1"
INDEX_VERSION = "1.0.0"
CAPABILITY_ID = "thin-fork-boundary"
REPORT_COUNT = 55


class ThinForkCandidateQualificationReportError(ValueError):
    """Raised when Thin Fork qualification evidence is incomplete or drifted."""


def _contract_test_ref(repository_root: Path) -> dict[str, Any]:
    catalog = _read_object(repository_root, CATALOG_RELATIVE)
    item = next(
        (
            entry
            for entry in cast(list[dict[str, Any]], catalog["items"])
            if entry["capability_id"] == CAPABILITY_ID
        ),
        None,
    )
    if item is None or len(cast(list[Any], item.get("contract_tests", []))) != 1:
        raise ThinForkCandidateQualificationReportError(
            "Thin Fork contract-test binding is incomplete"
        )
    expected = cast(list[dict[str, Any]], item["contract_tests"])[0]
    observed = _artifact_ref(
        repository_root,
        CONTRACT_TEST_RELATIVE,
        logical_name=cast(str, expected["logical_name"]),
    )
    if observed != expected:
        raise ThinForkCandidateQualificationReportError(
            "Thin Fork contract-test binding drifted"
        )
    return observed


def _result_and_report_paths(candidate_id: str) -> tuple[str, str]:
    return (
        f"{RESULT_ROOT_RELATIVE}/{candidate_id}.json",
        f"{REPORT_ROOT_RELATIVE}/{candidate_id}.json",
    )


def _verified_payload(
    repository_root: Path, reference: Mapping[str, Any], *, label: str
) -> bytes:
    relative_path = reference.get("relative_path")
    if not isinstance(relative_path, str) or not relative_path:
        raise ThinForkCandidateQualificationReportError(f"{label} has no relative path")
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise ThinForkCandidateQualificationReportError(
            f"{label} is missing"
        ) from error
    if reference.get("digest") != sha256_digest(payload):
        raise ThinForkCandidateQualificationReportError(f"{label} digest drifted")
    if reference.get("size_bytes") != len(payload):
        raise ThinForkCandidateQualificationReportError(f"{label} size drifted")
    return payload


def _report_document(
    *,
    repository_root: Path,
    candidate: dict[str, Any],
    blob_set: dict[str, Any],
    catalog_hash: str,
    extension_ref: dict[str, Any],
    contract_test_ref: dict[str, Any],
    vector_ref: dict[str, Any],
    result_ref: dict[str, Any],
    result: dict[str, Any],
    source_scope: dict[str, Any],
) -> dict[str, Any]:
    source_snapshot = cast(dict[str, Any], candidate["source_inventory"])
    if source_snapshot != source_scope["path_inventory"]:
        raise ThinForkCandidateQualificationReportError(
            "candidate source inventory drifted from source scope"
        )
    paths = sorted(
        cast(str, blob["path"])
        for blob in cast(list[dict[str, Any]], blob_set["blobs"])
    )
    failed = 1 if result["verdict"] == "fail" else 0
    report = {
        "schema_version": "pmorg.candidate-qualification-report/v1",
        "catalog_hash": catalog_hash,
        "capability_id": CAPABILITY_ID,
        "candidate_id": candidate["candidate_id"],
        "source_ref": {
            "repository": candidate["source_repository"],
            "commit": candidate["source_commit"],
            "paths": paths,
            "tree_hash": source_scope["tree_hash"],
            "source_snapshot": source_snapshot,
        },
        "qualification_policy": dict(extension_ref),
        "required_test_manifest": dict(contract_test_ref),
        "expected_test_count": 1,
        "executed_test_count": 1,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "failed_test_count": failed,
        "test_evidence": [
            {
                "test_id": "A-PATCH-001",
                "test_manifest": dict(vector_ref),
                "result": dict(result_ref),
                "verdict": result["verdict"],
            }
        ],
        "verdict": result["verdict"],
    }
    try:
        CandidateQualificationReport.model_validate(report)
    except ValidationError as error:
        raise ThinForkCandidateQualificationReportError(
            "executor produced an invalid CandidateQualificationReport"
        ) from error
    schema = _read_object(repository_root, REPORT_SCHEMA_RELATIVE)
    errors = sorted(Draft202012Validator(schema).iter_errors(report), key=str)
    if errors:
        raise ThinForkCandidateQualificationReportError(
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
            "report",
            "result",
            "source_surface",
            "verdict",
        ],
        "properties": {
            "candidate_group": nonempty,
            "candidate_id": {"type": "string", "pattern": "^candidate-[0-9a-f]{64}$"},
            "candidate_manifest_digest": digest,
            "report": artifact,
            "result": artifact,
            "source_surface": {"enum": ["ce", "ee"]},
            "verdict": {"enum": ["pass", "fail"]},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:thin-fork-candidate-qualification-report-index:v1",
        "title": "PMORG Thin Fork candidate qualification report index",
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
            "oracle_extension",
            "result_schema",
            "report_schema",
            "derivation_artifacts",
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
            "oracle_extension": artifact,
            "result_schema": artifact,
            "report_schema": artifact,
            "derivation_artifacts": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": artifact,
            },
            "report_count": {"const": REPORT_COUNT},
            "executed_test_count": {"const": REPORT_COUNT},
            "failed_test_count": {"type": "integer", "minimum": 0},
            "passed_test_count": {"type": "integer", "minimum": 0},
            "missing_test_count": {"const": 0},
            "duplicate_test_count": {"const": 0},
            "runtime_identity_digests": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1,
                "uniqueItems": True,
                "items": digest,
            },
            "entries": {
                "type": "array",
                "minItems": REPORT_COUNT,
                "maxItems": REPORT_COUNT,
                "items": entry,
            },
            "claim_boundary": {
                "const": "thin_fork_candidate_qualification_only_no_disposition"
            },
        },
    }


def build_thin_fork_candidate_qualification_outputs(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    candidates = sorted(
        (
            item
            for item in cast(list[dict[str, Any]], bundle["candidates"])
            if item["capability_id"] == CAPABILITY_ID
        ),
        key=lambda item: cast(str, item["candidate_id"]),
    )
    if len(candidates) != REPORT_COUNT:
        raise ThinForkCandidateQualificationReportError(
            f"Thin Fork candidate denominator drifted: {len(candidates)}"
        )
    blob_sets = {
        item["blob_set_digest"]: item
        for item in cast(list[dict[str, Any]], bundle["blob_sets"])
    }
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    contract_ref = _contract_test_ref(repository_root)
    source_scopes = _source_scope_map(repository_root)
    extension_bytes = build_thin_fork_oracle_extension(repository_root)[
        EXTENSION_RELATIVE
    ]
    if _safe_path(repository_root, EXTENSION_RELATIVE).read_bytes() != extension_bytes:
        raise ThinForkCandidateQualificationReportError(
            "committed Thin Fork oracle extension drifted"
        )
    extension = json.loads(extension_bytes)
    if extension["oracle"]["oracle_status"] != "executable":
        raise ThinForkCandidateQualificationReportError(
            "Thin Fork oracle extension is not executable"
        )
    extension_ref = _artifact_ref(
        repository_root,
        EXTENSION_RELATIVE,
        logical_name="qualification-oracle-extension-thin-fork-v1",
    )
    vector_ref = _artifact_ref(
        repository_root,
        VECTOR_RELATIVE,
        logical_name="thin-fork-boundary-A-PATCH-001-qualification-test-vector",
    )
    outputs: dict[str, bytes] = {
        INDEX_SCHEMA_RELATIVE: canonical_document_bytes(index_schema())
    }
    entries: list[dict[str, Any]] = []
    failed = 0
    passed = 0
    runtime_digests: set[str] = set()
    for candidate in candidates:
        candidate_id = cast(str, candidate["candidate_id"])
        blob_set = blob_sets.get(candidate["blob_set_digest"])
        if blob_set is None:
            raise ThinForkCandidateQualificationReportError(
                "candidate blob set is absent"
            )
        result = execute_thin_fork_interface_fit(
            candidate_id, repository_root=repository_root
        )
        result_path, report_path = _result_and_report_paths(candidate_id)
        result_payload = canonical_document_bytes(result)
        result_ref = _payload_ref(
            result_path,
            result_payload,
            logical_name=f"{candidate_id}-thin-fork-oracle-result",
        )
        report = _report_document(
            repository_root=repository_root,
            candidate=candidate,
            blob_set=blob_set,
            catalog_hash=catalog_hash,
            extension_ref=extension_ref,
            contract_test_ref=contract_ref,
            vector_ref=vector_ref,
            result_ref=result_ref,
            result=result,
            source_scope=source_scopes[cast(str, candidate["source_surface"])],
        )
        report_payload = canonical_document_bytes(report)
        report_ref = _payload_ref(
            report_path,
            report_payload,
            logical_name=f"{candidate_id}-thin-fork-qualification-report",
        )
        outputs[result_path] = result_payload
        outputs[report_path] = report_payload
        entries.append(
            {
                "candidate_group": candidate["candidate_group"],
                "candidate_id": candidate_id,
                "candidate_manifest_digest": candidate["manifest_digest"],
                "report": report_ref,
                "result": result_ref,
                "source_surface": candidate["source_surface"],
                "verdict": result["verdict"],
            }
        )
        runtime_digests.add(cast(str, result["runtime_identity_digest"]))
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
        "oracle_extension": extension_ref,
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
                path,
                logical_name=Path(path).name,
                media_type="text/x-python",
            )
            for path in DERIVATION_RELATIVES
        ],
        "report_count": len(entries),
        "executed_test_count": len(entries),
        "failed_test_count": failed,
        "passed_test_count": passed,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "runtime_identity_digests": sorted(runtime_digests),
        "entries": entries,
        "claim_boundary": "thin_fork_candidate_qualification_only_no_disposition",
    }
    errors = sorted(Draft202012Validator(index_schema()).iter_errors(index), key=str)
    if errors:
        raise ThinForkCandidateQualificationReportError(
            f"Thin Fork qualification index schema violation: {errors[0]}"
        )
    outputs[INDEX_RELATIVE] = canonical_document_bytes(index)
    return outputs


def write_thin_fork_candidate_qualification_reports(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    outputs = build_thin_fork_candidate_qualification_outputs(repository_root)
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


def check_thin_fork_candidate_qualification_reports(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    schema = canonical_document_bytes(index_schema())
    if _safe_path(repository_root, INDEX_SCHEMA_RELATIVE).read_bytes() != schema:
        raise ThinForkCandidateQualificationReportError(
            "committed index schema drifted"
        )
    index = _read_object(repository_root, INDEX_RELATIVE)
    errors = sorted(Draft202012Validator(index_schema()).iter_errors(index), key=str)
    if errors:
        raise ThinForkCandidateQualificationReportError(
            f"committed Thin Fork index is invalid: {errors[0]}"
        )
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    expected_extension_bytes = build_thin_fork_oracle_extension(repository_root)[
        EXTENSION_RELATIVE
    ]
    if (
        _safe_path(repository_root, EXTENSION_RELATIVE).read_bytes()
        != expected_extension_bytes
    ):
        raise ThinForkCandidateQualificationReportError(
            "committed Thin Fork oracle extension drifted"
        )
    extension = json.loads(expected_extension_bytes)
    extension_ref = _artifact_ref(
        repository_root,
        EXTENSION_RELATIVE,
        logical_name="qualification-oracle-extension-thin-fork-v1",
    )
    contract_ref = _contract_test_ref(repository_root)
    vector_ref = _artifact_ref(
        repository_root,
        VECTOR_RELATIVE,
        logical_name="thin-fork-boundary-A-PATCH-001-qualification-test-vector",
    )
    expected_index_bindings = {
        "candidate_inputs": _artifact_ref(
            repository_root,
            CANDIDATE_INPUTS_RELATIVE,
            logical_name="candidate-inputs-v1",
        ),
        "oracle_extension": extension_ref,
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
    }
    if (
        index["catalog_hash"] != catalog_hash
        or index["source_repository"] != bundle["source_repository"]
        or index["source_commit"] != bundle["source_commit"]
        or index["source_tree_id"] != bundle["source_tree_id"]
        or any(index[key] != value for key, value in expected_index_bindings.items())
    ):
        raise ThinForkCandidateQualificationReportError(
            "committed Thin Fork index binding drifted"
        )
    candidates = {
        item["candidate_id"]: item
        for item in cast(list[dict[str, Any]], bundle["candidates"])
        if item["capability_id"] == CAPABILITY_ID
    }
    entries = cast(list[dict[str, Any]], index["entries"])
    if [item["candidate_id"] for item in entries] != sorted(candidates):
        raise ThinForkCandidateQualificationReportError(
            "committed reports do not exactly cover the Thin Fork denominator"
        )
    result_validator = Draft202012Validator(result_schema())
    report_validator = Draft202012Validator(
        _read_object(repository_root, REPORT_SCHEMA_RELATIVE)
    )
    source_scopes = _source_scope_map(repository_root)
    blob_sets = {
        item["blob_set_digest"]: item
        for item in cast(list[dict[str, Any]], bundle["blob_sets"])
    }
    failed = 0
    passed = 0
    runtime_digests: set[str] = set()
    result_paths: set[str] = set()
    report_paths: set[str] = set()
    for entry in entries:
        candidate = candidates[entry["candidate_id"]]
        result_path = cast(str, entry["result"]["relative_path"])
        report_path = cast(str, entry["report"]["relative_path"])
        expected_result_path, expected_report_path = _result_and_report_paths(
            cast(str, candidate["candidate_id"])
        )
        if result_path != expected_result_path or report_path != expected_report_path:
            raise ThinForkCandidateQualificationReportError(
                "candidate evidence path drifted"
            )
        if result_path in result_paths or report_path in report_paths:
            raise ThinForkCandidateQualificationReportError(
                "candidate evidence path is duplicated"
            )
        result_paths.add(result_path)
        report_paths.add(report_path)
        result_payload = _verified_payload(
            repository_root, entry["result"], label="candidate result"
        )
        report_payload = _verified_payload(
            repository_root, entry["report"], label="candidate report"
        )
        result = json.loads(result_payload)
        report = json.loads(report_payload)
        if list(result_validator.iter_errors(result)):
            raise ThinForkCandidateQualificationReportError("result schema drifted")
        if list(report_validator.iter_errors(report)):
            raise ThinForkCandidateQualificationReportError("report schema drifted")
        try:
            CandidateQualificationReport.model_validate(report)
        except ValidationError as error:
            raise ThinForkCandidateQualificationReportError(
                "committed report fails the contract model"
            ) from error
        blob_set = blob_sets[candidate["blob_set_digest"]]
        expected_paths = sorted(
            cast(str, blob["path"])
            for blob in cast(list[dict[str, Any]], blob_set["blobs"])
        )
        source_scope = source_scopes[cast(str, candidate["source_surface"])]
        source_ref = cast(dict[str, Any], report["source_ref"])
        evidence = cast(list[dict[str, Any]], report["test_evidence"])
        expected_bindings = cast(list[dict[str, Any]], extension["bindings"])
        if (
            entry["candidate_group"] != candidate["candidate_group"]
            or entry["candidate_manifest_digest"] != candidate["manifest_digest"]
            or entry["source_surface"] != candidate["source_surface"]
            or result["candidate_id"] != candidate["candidate_id"]
            or result["candidate_manifest_digest"] != candidate["manifest_digest"]
            or result["capability_id"] != CAPABILITY_ID
            or result["test_id"] != "A-PATCH-001"
            or result["oracle_id"] != extension["oracle"]["oracle_id"]
            or result["adapter_digest"] != extension["oracle"]["adapter_digest"]
            or result["bindings"] != expected_bindings
            or result["verdict"] != entry["verdict"]
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
            or report["candidate_id"] != candidate["candidate_id"]
            or report["capability_id"] != CAPABILITY_ID
            or report["catalog_hash"] != catalog_hash
            or report["qualification_policy"] != extension_ref
            or report["required_test_manifest"] != contract_ref
            or report["verdict"] != entry["verdict"]
            or report["expected_test_count"] != 1
            or report["executed_test_count"] != 1
            or report["missing_test_count"] != 0
            or report["duplicate_test_count"] != 0
            or report["failed_test_count"] != (1 if entry["verdict"] == "fail" else 0)
            or len(evidence) != 1
            or evidence[0]["test_id"] != "A-PATCH-001"
            or evidence[0]["test_manifest"] != vector_ref
            or evidence[0]["result"] != entry["result"]
            or evidence[0]["verdict"] != entry["verdict"]
            or source_ref["repository"] != candidate["source_repository"]
            or source_ref["commit"] != candidate["source_commit"]
            or source_ref["paths"] != expected_paths
            or source_ref["tree_hash"] != source_scope["tree_hash"]
            or source_ref["source_snapshot"] != candidate["source_inventory"]
        ):
            raise ThinForkCandidateQualificationReportError(
                f"candidate qualification evidence drifted: {entry['candidate_id']}"
            )
        runtime_measurement = cast(dict[str, Any], result["runtime_measurement"])
        expected_runtime_artifacts = [
            {"digest": artifact["digest"], "relative_path": artifact["relative_path"]}
            for artifact in cast(list[dict[str, Any]], extension["runtime_artifacts"])
        ]
        if (
            runtime_measurement["declared_artifacts"] != expected_runtime_artifacts
            or runtime_measurement["interpreter_binary"]["relative_path"]
            != "@runtime/executed-python-interpreter"
            or result["runtime_identity_digest"]
            != sha256_digest(canonical_document_bytes(runtime_measurement))
        ):
            raise ThinForkCandidateQualificationReportError(
                "committed runtime identity binding drifted"
            )
        runtime_digests.add(cast(str, result["runtime_identity_digest"]))
        if result["verdict"] == "fail":
            failed += 1
        else:
            passed += 1
    if failed != index["failed_test_count"] or passed != index["passed_test_count"]:
        raise ThinForkCandidateQualificationReportError("verdict counts drifted")
    if sorted(runtime_digests) != index["runtime_identity_digests"]:
        raise ThinForkCandidateQualificationReportError("runtime identity drifted")
    committed_result_paths = {
        path.relative_to(repository_root).as_posix()
        for path in _safe_path(repository_root, RESULT_ROOT_RELATIVE).rglob("*.json")
    }
    committed_report_paths = {
        path.relative_to(repository_root).as_posix()
        for path in _safe_path(repository_root, REPORT_ROOT_RELATIVE).rglob("*.json")
    }
    if committed_result_paths != result_paths or committed_report_paths != report_paths:
        raise ThinForkCandidateQualificationReportError(
            "qualification evidence directories contain missing or unindexed files"
        )
    for artifact in cast(list[dict[str, Any]], index["derivation_artifacts"]):
        _verified_payload(repository_root, artifact, label="derivation artifact")


__all__ = [
    "ThinForkCandidateQualificationReportError",
    "build_thin_fork_candidate_qualification_outputs",
    "check_thin_fork_candidate_qualification_reports",
    "index_schema",
    "write_thin_fork_candidate_qualification_reports",
]
