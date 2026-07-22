"""Execute capability-disposition qualification over the complete Q7a denominator."""

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
from pmorg.application.capability_disposition_interface_fit_executor import (
    build_capability_disposition_oracle_extension,
)
from pmorg.application.capability_disposition_interface_fit_executor import (
    execute_capability_disposition_interface_fit,
)
from pmorg.application.capability_disposition_interface_fit_executor import TEST_IDS
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import result_schema
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.contracts.types import CandidateQualificationReport

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
EXTENSION_RELATIVE = "pmorg/capabilities/qualification-oracle-extension-capability-disposition-qualification-v1.json"
VECTOR_ROOT_RELATIVE = "pmorg/capabilities/qualification-test-vector-extensions"
CONTRACT_TEST_RELATIVE = (
    "pmorg/capabilities/contract-tests/capability-disposition-qualification.json"
)
Q7A_EVIDENCE_RELATIVE = (
    "pmorg/capabilities/"
    "capability-disposition-qualification-interface-fit-evidence-v1.json"
)
VECTOR_EXTENSION_RELATIVE = (
    "pmorg/capabilities/"
    "qualification-test-vector-extension-capability-disposition-qualification-v1.json"
)
REFERENCE_IMPLEMENTATION_RELATIVES = (
    "backend/pmorg/application/qualification.py",
    "backend/pmorg/application/qualification_oracles.py",
)
RESULT_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-result-v2.schema.json"
REPORT_SCHEMA_RELATIVE = (
    "backend/pmorg/contracts/schemas/candidate-qualification-report-v1.schema.json"
)
INDEX_RELATIVE = "pmorg/capabilities/capability-disposition-qualification-candidate-qualification-reports-v1.json"
INDEX_SCHEMA_RELATIVE = "pmorg/capabilities/capability-disposition-qualification-candidate-qualification-reports-v1.schema.json"
RESULT_ROOT_RELATIVE = "pmorg/capabilities/capability-disposition-qualification-candidate-qualification-results"
REPORT_ROOT_RELATIVE = "pmorg/capabilities/capability-disposition-qualification-candidate-qualification-reports"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/capability_disposition_qualification_candidate_qualification_reports.py",
    "pmorg/scripts/build_capability_disposition_qualification_candidate_qualification_reports.py",
)

INDEX_SCHEMA_VERSION = (
    "pmorg.capability-disposition-qualification-candidate-qualification-report-index/v1"
)
INDEX_VERSION = "1.0.0"
CAPABILITY_ID = "capability-disposition-qualification"
REPORT_COUNT = 48
TEST_COUNT = len(TEST_IDS)
RESULT_COUNT = REPORT_COUNT * TEST_COUNT
BLOB_MEMBERSHIP_COUNT = 5015


class CapabilityDispositionQualificationCandidateQualificationReportError(ValueError):
    """Raised when Capability Disposition Qualification qualification evidence is incomplete or drifted."""


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
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "Capability Disposition Qualification contract-test binding is incomplete"
        )
    expected = cast(list[dict[str, Any]], item["contract_tests"])[0]
    observed = _artifact_ref(
        repository_root,
        CONTRACT_TEST_RELATIVE,
        logical_name=cast(str, expected["logical_name"]),
    )
    if observed != expected:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "Capability Disposition Qualification contract-test binding drifted"
        )
    return observed


def _vector_relative(test_id: str) -> str:
    return f"{VECTOR_ROOT_RELATIVE}/{CAPABILITY_ID}-{test_id}-v1.json"


def _reference_implementation_refs(repository_root: Path) -> list[dict[str, Any]]:
    refs = [
        _artifact_ref(
            repository_root,
            path,
            logical_name=Path(path).stem,
            media_type="text/x-python",
        )
        for path in REFERENCE_IMPLEMENTATION_RELATIVES
    ]
    declared = _read_object(repository_root, VECTOR_EXTENSION_RELATIVE).get(
        "interface_reference_implementations"
    )
    stripped = [
        {
            key: reference[key]
            for key in ("digest", "media_type", "relative_path", "size_bytes")
        }
        for reference in refs
    ]
    if declared != stripped:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "Q7a reference implementation binding drifted"
        )
    return refs


def _result_path(candidate_id: str, test_id: str) -> str:
    return f"{RESULT_ROOT_RELATIVE}/{candidate_id}/{test_id}.json"


def _report_path(candidate_id: str) -> str:
    return f"{REPORT_ROOT_RELATIVE}/{candidate_id}.json"


def _verified_payload(
    repository_root: Path, reference: Mapping[str, Any], *, label: str
) -> bytes:
    relative_path = reference.get("relative_path")
    if not isinstance(relative_path, str) or not relative_path:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            f"{label} has no relative path"
        )
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            f"{label} is missing"
        ) from error
    if reference.get("digest") != sha256_digest(payload):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            f"{label} digest drifted"
        )
    if reference.get("size_bytes") != len(payload):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            f"{label} size drifted"
        )
    return payload


def _report_document(
    *,
    repository_root: Path,
    candidate: dict[str, Any],
    blob_set: dict[str, Any],
    catalog_hash: str,
    extension_ref: dict[str, Any],
    contract_test_ref: dict[str, Any],
    vector_refs: Mapping[str, dict[str, Any]],
    result_refs: Mapping[str, dict[str, Any]],
    results: Mapping[str, dict[str, Any]],
    source_scope: dict[str, Any],
) -> dict[str, Any]:
    source_snapshot = cast(dict[str, Any], candidate["source_inventory"])
    if source_snapshot != source_scope["path_inventory"]:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "candidate source inventory drifted from source scope"
        )
    paths = sorted(
        cast(str, blob["path"])
        for blob in cast(list[dict[str, Any]], blob_set["blobs"])
    )
    failed = sum(result["verdict"] == "fail" for result in results.values())
    verdict = "pass" if failed == 0 else "fail"
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
        "expected_test_count": TEST_COUNT,
        "executed_test_count": TEST_COUNT,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "failed_test_count": failed,
        "test_evidence": [
            {
                "test_id": test_id,
                "test_manifest": dict(vector_refs[test_id]),
                "result": dict(result_refs[test_id]),
                "verdict": results[test_id]["verdict"],
            }
            for test_id in TEST_IDS
        ],
        "verdict": verdict,
    }
    try:
        CandidateQualificationReport.model_validate(report)
    except ValidationError as error:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "executor produced an invalid CandidateQualificationReport"
        ) from error
    schema = _read_object(repository_root, REPORT_SCHEMA_RELATIVE)
    errors = sorted(Draft202012Validator(schema).iter_errors(report), key=str)
    if errors:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
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
            "results",
            "source_surface",
            "verdict",
        ],
        "properties": {
            "candidate_group": nonempty,
            "candidate_id": {"type": "string", "pattern": "^candidate-[0-9a-f]{64}$"},
            "candidate_manifest_digest": digest,
            "report": artifact,
            "results": {
                "type": "array",
                "minItems": TEST_COUNT,
                "maxItems": TEST_COUNT,
                "items": artifact,
            },
            "source_surface": {"enum": ["ce", "ee"]},
            "verdict": {"enum": ["pass", "fail"]},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:capability-disposition-qualification-candidate-qualification-report-index:v1",
        "title": "PMORG Capability Disposition Qualification candidate qualification report index",
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
            "q7a_screening_evidence",
            "reference_implementations",
            "oracle_extension",
            "result_schema",
            "report_schema",
            "derivation_artifacts",
            "report_count",
            "projected_blob_membership_count",
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
            "q7a_screening_evidence": artifact,
            "reference_implementations": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": artifact,
            },
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
            "projected_blob_membership_count": {"const": BLOB_MEMBERSHIP_COUNT},
            "executed_test_count": {"const": RESULT_COUNT},
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
                "const": "candidate_qualification_only_no_disposition_or_aggregate_verdict"
            },
        },
    }


def build_capability_disposition_qualification_candidate_qualification_outputs(
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
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            f"Capability Disposition Qualification candidate denominator drifted: {len(candidates)}"
        )
    if (
        len({cast(str, item["candidate_group"]) for item in candidates}) != REPORT_COUNT
        or sum(cast(int, item["blob_count"]) for item in candidates)
        != BLOB_MEMBERSHIP_COUNT
    ):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "Q7a grouped candidate or blob membership denominator drifted"
        )
    blob_sets = {
        item["blob_set_digest"]: item
        for item in cast(list[dict[str, Any]], bundle["blob_sets"])
    }
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    contract_ref = _contract_test_ref(repository_root)
    q7a_evidence_ref = _artifact_ref(
        repository_root,
        Q7A_EVIDENCE_RELATIVE,
        logical_name="capability-disposition-qualification-interface-fit-evidence-v1",
    )
    reference_implementations = _reference_implementation_refs(repository_root)
    source_scopes = _source_scope_map(repository_root)
    extension_bytes = build_capability_disposition_oracle_extension(repository_root)[
        EXTENSION_RELATIVE
    ]
    if _safe_path(repository_root, EXTENSION_RELATIVE).read_bytes() != extension_bytes:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "committed Capability Disposition Qualification oracle extension drifted"
        )
    extension = json.loads(extension_bytes)
    oracles = cast(list[dict[str, Any]], extension.get("oracles", []))
    if [oracle.get("test_id") for oracle in oracles] != list(TEST_IDS) or any(
        oracle.get("oracle_status") != "executable" for oracle in oracles
    ):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "Capability Disposition Qualification oracle extension is not completely executable"
        )
    extension_ref = _artifact_ref(
        repository_root,
        EXTENSION_RELATIVE,
        logical_name="qualification-oracle-extension-capability-disposition-qualification-v1",
    )
    vector_refs = {
        test_id: _artifact_ref(
            repository_root,
            _vector_relative(test_id),
            logical_name=f"{CAPABILITY_ID}-{test_id}-qualification-test-vector",
        )
        for test_id in TEST_IDS
    }
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
            raise CapabilityDispositionQualificationCandidateQualificationReportError(
                "candidate blob set is absent"
            )
        results: dict[str, dict[str, Any]] = {}
        result_refs: dict[str, dict[str, Any]] = {}
        for test_id in TEST_IDS:
            result = execute_capability_disposition_interface_fit(
                candidate_id, test_id, repository_root=repository_root
            )
            result_path = _result_path(candidate_id, test_id)
            result_payload = canonical_document_bytes(result)
            result_ref = _payload_ref(
                result_path,
                result_payload,
                logical_name=f"{candidate_id}-{test_id}-capability-disposition-qualification-oracle-result",
            )
            outputs[result_path] = result_payload
            results[test_id] = result
            result_refs[test_id] = result_ref
            runtime_digests.add(cast(str, result["runtime_identity_digest"]))
            if result["verdict"] == "fail":
                failed += 1
            else:
                passed += 1
        report_path = _report_path(candidate_id)
        report = _report_document(
            repository_root=repository_root,
            candidate=candidate,
            blob_set=blob_set,
            catalog_hash=catalog_hash,
            extension_ref=extension_ref,
            contract_test_ref=contract_ref,
            vector_refs=vector_refs,
            result_refs=result_refs,
            results=results,
            source_scope=source_scopes[cast(str, candidate["source_surface"])],
        )
        report_payload = canonical_document_bytes(report)
        report_ref = _payload_ref(
            report_path,
            report_payload,
            logical_name=f"{candidate_id}-capability-disposition-qualification-report",
        )
        outputs[report_path] = report_payload
        report_verdict = cast(str, report["verdict"])
        entries.append(
            {
                "candidate_group": candidate["candidate_group"],
                "candidate_id": candidate_id,
                "candidate_manifest_digest": candidate["manifest_digest"],
                "report": report_ref,
                "results": [result_refs[test_id] for test_id in TEST_IDS],
                "source_surface": candidate["source_surface"],
                "verdict": report_verdict,
            }
        )
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
        "q7a_screening_evidence": q7a_evidence_ref,
        "reference_implementations": reference_implementations,
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
        "projected_blob_membership_count": sum(
            cast(int, candidate["blob_count"]) for candidate in candidates
        ),
        "executed_test_count": len(entries) * TEST_COUNT,
        "failed_test_count": failed,
        "passed_test_count": passed,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "runtime_identity_digests": sorted(runtime_digests),
        "entries": entries,
        "claim_boundary": "candidate_qualification_only_no_disposition_or_aggregate_verdict",
    }
    errors = sorted(Draft202012Validator(index_schema()).iter_errors(index), key=str)
    if errors:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            f"Capability Disposition Qualification qualification index schema violation: {errors[0]}"
        )
    outputs[INDEX_RELATIVE] = canonical_document_bytes(index)
    return outputs


def write_capability_disposition_qualification_candidate_qualification_reports(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    outputs = (
        build_capability_disposition_qualification_candidate_qualification_outputs(
            repository_root
        )
    )
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


def check_capability_disposition_qualification_candidate_qualification_reports(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    schema = canonical_document_bytes(index_schema())
    if _safe_path(repository_root, INDEX_SCHEMA_RELATIVE).read_bytes() != schema:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "committed index schema drifted"
        )
    index = _read_object(repository_root, INDEX_RELATIVE)
    errors = sorted(Draft202012Validator(index_schema()).iter_errors(index), key=str)
    if errors:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            f"committed Capability Disposition Qualification index is invalid: {errors[0]}"
        )
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    expected_extension_bytes = build_capability_disposition_oracle_extension(
        repository_root
    )[EXTENSION_RELATIVE]
    if (
        _safe_path(repository_root, EXTENSION_RELATIVE).read_bytes()
        != expected_extension_bytes
    ):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "committed Capability Disposition Qualification oracle extension drifted"
        )
    extension = json.loads(expected_extension_bytes)
    extension_ref = _artifact_ref(
        repository_root,
        EXTENSION_RELATIVE,
        logical_name="qualification-oracle-extension-capability-disposition-qualification-v1",
    )
    contract_ref = _contract_test_ref(repository_root)
    vector_refs = {
        test_id: _artifact_ref(
            repository_root,
            _vector_relative(test_id),
            logical_name=f"{CAPABILITY_ID}-{test_id}-qualification-test-vector",
        )
        for test_id in TEST_IDS
    }
    oracles = {
        cast(str, oracle["test_id"]): oracle
        for oracle in cast(list[dict[str, Any]], extension.get("oracles", []))
    }
    if set(oracles) != set(TEST_IDS):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "committed Capability Disposition Qualification oracle coverage drifted"
        )
    expected_index_bindings = {
        "candidate_inputs": _artifact_ref(
            repository_root,
            CANDIDATE_INPUTS_RELATIVE,
            logical_name="candidate-inputs-v1",
        ),
        "q7a_screening_evidence": _artifact_ref(
            repository_root,
            Q7A_EVIDENCE_RELATIVE,
            logical_name="capability-disposition-qualification-interface-fit-evidence-v1",
        ),
        "reference_implementations": _reference_implementation_refs(repository_root),
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
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "committed Capability Disposition Qualification index binding drifted"
        )
    candidates = {
        item["candidate_id"]: item
        for item in cast(list[dict[str, Any]], bundle["candidates"])
        if item["capability_id"] == CAPABILITY_ID
    }
    entries = cast(list[dict[str, Any]], index["entries"])
    if (
        len(candidates) != REPORT_COUNT
        or len({cast(str, item["candidate_group"]) for item in candidates.values()})
        != REPORT_COUNT
        or sum(cast(int, item["blob_count"]) for item in candidates.values())
        != BLOB_MEMBERSHIP_COUNT
        or index["projected_blob_membership_count"] != BLOB_MEMBERSHIP_COUNT
    ):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "committed Q7a denominator drifted"
        )
    if [item["candidate_id"] for item in entries] != sorted(candidates):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "committed reports do not exactly cover the Capability Disposition Qualification denominator"
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
        report_path = cast(str, entry["report"]["relative_path"])
        expected_report_path = _report_path(cast(str, candidate["candidate_id"]))
        result_refs = cast(list[dict[str, Any]], entry["results"])
        if (
            report_path != expected_report_path
            or len(result_refs) != TEST_COUNT
            or [ref["relative_path"] for ref in result_refs]
            != [
                _result_path(cast(str, candidate["candidate_id"]), test_id)
                for test_id in TEST_IDS
            ]
        ):
            raise CapabilityDispositionQualificationCandidateQualificationReportError(
                "candidate evidence path drifted"
            )
        candidate_result_paths = {
            cast(str, reference["relative_path"]) for reference in result_refs
        }
        if (
            len(candidate_result_paths) != TEST_COUNT
            or candidate_result_paths & result_paths
            or report_path in report_paths
        ):
            raise CapabilityDispositionQualificationCandidateQualificationReportError(
                "candidate evidence path is duplicated"
            )
        result_paths.update(candidate_result_paths)
        report_paths.add(report_path)
        report_payload = _verified_payload(
            repository_root, entry["report"], label="candidate report"
        )
        report = json.loads(report_payload)
        if list(report_validator.iter_errors(report)):
            raise CapabilityDispositionQualificationCandidateQualificationReportError(
                "report schema drifted"
            )
        try:
            CandidateQualificationReport.model_validate(report)
        except ValidationError as error:
            raise CapabilityDispositionQualificationCandidateQualificationReportError(
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
        results: dict[str, dict[str, Any]] = {}
        for test_id, result_ref in zip(TEST_IDS, result_refs, strict=True):
            result_payload = _verified_payload(
                repository_root, result_ref, label=f"candidate result {test_id}"
            )
            result = json.loads(result_payload)
            if list(result_validator.iter_errors(result)):
                raise CapabilityDispositionQualificationCandidateQualificationReportError(
                    f"result schema drifted: {test_id}"
                )
            oracle = oracles[test_id]
            if (
                result["candidate_id"] != candidate["candidate_id"]
                or result["candidate_manifest_digest"] != candidate["manifest_digest"]
                or result["capability_id"] != CAPABILITY_ID
                or result["test_id"] != test_id
                or result["oracle_id"] != oracle["oracle_id"]
                or result["adapter_digest"] != oracle["adapter_digest"]
                or result["bindings"] != expected_bindings
                or result["observed_blob_count"] != candidate["blob_count"]
                or result["projected_blob_count"] != candidate["blob_count"]
                or result["unobserved_blob_count"] != 0
                or result["baseline_observation_digest"]
                == result["mutation_observation_digest"]
                or result["positive_injection_fit"] is not True
                or result["oracle_status"] != "executable"
                or result["execution_exit_codes"] != [0, 0, 0]
                or (result["verdict"] == "pass" and result["baseline_fit"] is not True)
                or (result["verdict"] == "fail" and result["baseline_fit"] is not False)
                or (result["verdict"] == "pass" and result["failure_reasons"])
                or (result["verdict"] == "fail" and not result["failure_reasons"])
            ):
                raise CapabilityDispositionQualificationCandidateQualificationReportError(
                    f"candidate result evidence drifted: {entry['candidate_id']}:{test_id}"
                )
            runtime_measurement = cast(dict[str, Any], result["runtime_measurement"])
            expected_runtime_artifacts = [
                {
                    "digest": artifact["digest"],
                    "relative_path": artifact["relative_path"],
                }
                for artifact in cast(
                    list[dict[str, Any]], extension["runtime_artifacts"]
                )
            ]
            if (
                runtime_measurement["declared_artifacts"] != expected_runtime_artifacts
                or runtime_measurement["interpreter_binary"]["relative_path"]
                != "@runtime/executed-python-interpreter"
                or result["runtime_identity_digest"]
                != sha256_digest(canonical_document_bytes(runtime_measurement))
            ):
                raise CapabilityDispositionQualificationCandidateQualificationReportError(
                    "committed runtime identity binding drifted"
                )
            runtime_digests.add(cast(str, result["runtime_identity_digest"]))
            if result["verdict"] == "fail":
                failed += 1
            else:
                passed += 1
            results[test_id] = result
        report_verdict = (
            "pass"
            if all(results[test_id]["verdict"] == "pass" for test_id in TEST_IDS)
            else "fail"
        )
        failed_for_report = sum(
            results[test_id]["verdict"] == "fail" for test_id in TEST_IDS
        )
        if (
            entry["candidate_group"] != candidate["candidate_group"]
            or entry["candidate_manifest_digest"] != candidate["manifest_digest"]
            or entry["source_surface"] != candidate["source_surface"]
            or entry["verdict"] != report_verdict
            or report["candidate_id"] != candidate["candidate_id"]
            or report["capability_id"] != CAPABILITY_ID
            or report["catalog_hash"] != catalog_hash
            or report["qualification_policy"] != extension_ref
            or report["required_test_manifest"] != contract_ref
            or report["verdict"] != report_verdict
            or report["expected_test_count"] != TEST_COUNT
            or report["executed_test_count"] != TEST_COUNT
            or report["missing_test_count"] != 0
            or report["duplicate_test_count"] != 0
            or report["failed_test_count"] != failed_for_report
            or len(evidence) != TEST_COUNT
            or [item["test_id"] for item in evidence] != list(TEST_IDS)
            or any(
                item["test_manifest"] != vector_refs[test_id]
                or item["result"] != result_refs[index]
                or item["verdict"] != results[test_id]["verdict"]
                for index, (test_id, item) in enumerate(
                    zip(TEST_IDS, evidence, strict=True)
                )
            )
            or source_ref["repository"] != candidate["source_repository"]
            or source_ref["commit"] != candidate["source_commit"]
            or source_ref["paths"] != expected_paths
            or source_ref["tree_hash"] != source_scope["tree_hash"]
            or source_ref["source_snapshot"] != candidate["source_inventory"]
        ):
            raise CapabilityDispositionQualificationCandidateQualificationReportError(
                f"candidate qualification evidence drifted: {entry['candidate_id']}"
            )
    if (
        failed + passed != RESULT_COUNT
        or failed != index["failed_test_count"]
        or passed != index["passed_test_count"]
    ):
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "verdict counts drifted"
        )
    if sorted(runtime_digests) != index["runtime_identity_digests"]:
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "runtime identity drifted"
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
        raise CapabilityDispositionQualificationCandidateQualificationReportError(
            "qualification evidence directories contain missing or unindexed files"
        )
    for artifact in cast(list[dict[str, Any]], index["derivation_artifacts"]):
        _verified_payload(repository_root, artifact, label="derivation artifact")
    _verified_payload(
        repository_root,
        cast(dict[str, Any], index["q7a_screening_evidence"]),
        label="Q7a screening evidence",
    )
    for artifact in cast(list[dict[str, Any]], index["reference_implementations"]):
        _verified_payload(repository_root, artifact, label="reference implementation")


__all__ = [
    "CapabilityDispositionQualificationCandidateQualificationReportError",
    "build_capability_disposition_qualification_candidate_qualification_outputs",
    "check_capability_disposition_qualification_candidate_qualification_reports",
    "index_schema",
    "write_capability_disposition_qualification_candidate_qualification_reports",
]
