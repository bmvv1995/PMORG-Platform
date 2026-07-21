"""Execute and bind post-disposition admission qualification suites."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.application.admission_interface_fit_executor import _runtime_measurement
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.contracts.types import PostDispositionQualificationReport

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
PATCH_LEDGER_RELATIVE = "pmorg/patch-ledger.json"
REPORT_SCHEMA_RELATIVE = (
    "backend/pmorg/contracts/schemas/post-disposition-qualification-v1.schema.json"
)
INDEX_RELATIVE = "pmorg/capabilities/post-disposition-qualification-v1.json"
INDEX_SCHEMA_RELATIVE = (
    "pmorg/capabilities/post-disposition-qualification-v1.schema.json"
)
MANIFEST_SCHEMA_RELATIVE = (
    "pmorg/capabilities/post-disposition-test-manifest-v1.schema.json"
)
RESULT_SCHEMA_RELATIVE = (
    "pmorg/capabilities/post-disposition-test-result-v1.schema.json"
)
MANIFEST_ROOT_RELATIVE = "pmorg/capabilities/post-disposition-test-manifests"
RESULT_ROOT_RELATIVE = "pmorg/capabilities/post-disposition-test-results"
REPORT_ROOT_RELATIVE = "pmorg/capabilities/post-disposition-qualification-reports"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/post_disposition_qualification.py",
    "pmorg/scripts/build_post_disposition_qualification.py",
)

INDEX_SCHEMA_VERSION = "pmorg.post-disposition-qualification-index/v1"
MANIFEST_SCHEMA_VERSION = "pmorg.post-disposition-test-manifest/v1"
RESULT_SCHEMA_VERSION = "pmorg.post-disposition-test-result/v1"
REPORT_SCHEMA_VERSION = "pmorg.post-disposition-qualification/v1"
INDEX_VERSION = "1.0.0"
CLAIM_BOUNDARY = "post_disposition_qualification_only_no_disposition_record"

CAPABILITY_SPECS: dict[str, dict[str, Any]] = {
    "deployment-admission": {
        "requirement_ids": ["A-LIC-002", "PLT-007"],
        "implementation_paths": [
            "backend/pmorg/application/admission.py",
            "backend/pmorg/application/qualification.py",
            "backend/pmorg/application/rbdp.py",
            "backend/pmorg/contracts/types.py",
        ],
        "ledger_ids": ["PL-020"],
        "test_file": "backend/pmorg/tests/test_deployment_admission.py",
        "test_class": "pmorg.tests.test_deployment_admission.TestDeploymentAdmission",
        "test_methods": [
            "test_round_trip_reconstructs_all_exact_bindings_and_allows_deploy",
            "test_absent_invalid_and_expiring_admissions_fail_closed",
            "test_payload_target_measurement_and_signature_drift_are_rejected",
            "test_production_unknown_and_deadline_escape_are_rejected",
            "test_ephemeral_keys_are_mandatory_and_evidence_drift_fails",
        ],
    },
    "distribution-admission": {
        "requirement_ids": ["A-LIC-003", "PLT-008"],
        "implementation_paths": [
            "backend/pmorg/application/admission.py",
            "backend/pmorg/application/distribution_admission.py",
            "backend/pmorg/application/qualification.py",
            "backend/pmorg/application/rbdp.py",
            "backend/pmorg/contracts/types.py",
        ],
        "ledger_ids": ["PL-020", "PL-021"],
        "test_file": "backend/pmorg/tests/test_distribution_admission.py",
        "test_class": "pmorg.tests.test_distribution_admission.TestDistributionAdmission",
        "test_methods": [
            "test_round_trip_reconstructs_subset_and_allows_publish",
            "test_missing_invalid_and_predeadline_transfer_abort_fail_closed",
            "test_auth_and_redirect_destination_drift_is_denied_or_aborted",
            "test_payload_metadata_destination_and_measurement_drift_are_rejected",
            "test_ephemeral_keys_evidence_and_deadline_escape_are_rejected",
        ],
    },
}


class PostDispositionQualificationError(ValueError):
    """Raised when Q3c execution or committed evidence is incomplete."""


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise PostDispositionQualificationError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PostDispositionQualificationError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise PostDispositionQualificationError(
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
        raise PostDispositionQualificationError(
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


def _path_binding(repository_root: Path, relative_path: str) -> dict[str, Any]:
    payload = _safe_path(repository_root, relative_path).read_bytes()
    return {
        "digest": sha256_digest(payload),
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _catalog_hash(repository_root: Path) -> str:
    _read_object(repository_root, CATALOG_RELATIVE)
    return sha256_digest(_safe_path(repository_root, CATALOG_RELATIVE).read_bytes())


def _selected_ledger_entries(
    repository_root: Path, ledger_ids: list[str]
) -> list[dict[str, Any]]:
    ledger = _read_object(repository_root, PATCH_LEDGER_RELATIVE)
    by_id = {
        cast(str, item["id"]): item
        for item in cast(list[dict[str, Any]], ledger.get("entries", []))
    }
    if any(ledger_id not in by_id for ledger_id in ledger_ids):
        raise PostDispositionQualificationError(
            "selected patch-ledger entry is missing"
        )
    return [by_id[ledger_id] for ledger_id in ledger_ids]


def _manifest_document(repository_root: Path, capability_id: str) -> dict[str, Any]:
    spec = CAPABILITY_SPECS[capability_id]
    implementation_bindings = [
        _path_binding(repository_root, relative_path)
        for relative_path in cast(list[str], spec["implementation_paths"])
    ]
    test_file = cast(str, spec["test_file"])
    test_file_binding = _path_binding(repository_root, test_file)
    ledger_ids = cast(list[str], spec["ledger_ids"])
    ledger_entries = _selected_ledger_entries(repository_root, ledger_ids)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "capability_id": capability_id,
        "requirement_ids": spec["requirement_ids"],
        "implementation_bindings": implementation_bindings,
        "implementation_path_set_hash": sha256_digest(
            canonical_document_bytes(implementation_bindings)
        ),
        "patch_ledger_entry_ids": ledger_ids,
        "patch_ledger_set_hash": sha256_digest(
            canonical_document_bytes(ledger_entries)
        ),
        "test_file": test_file_binding,
        "runner": {
            "framework": "python-unittest",
            "execution_mode": "isolated-test-method",
            "pythonpath": "backend",
        },
        "test_cases": [
            {
                "fully_qualified_name": f"{spec['test_class']}.{method}",
                "test_id": f"{capability_id}::{method}",
            }
            for method in cast(list[str], spec["test_methods"])
        ],
        "expected_test_count": len(cast(list[str], spec["test_methods"])),
    }


def _run_test_case(fully_qualified_name: str) -> dict[str, int | str]:
    suite = unittest.defaultTestLoader.loadTestsFromName(fully_qualified_name)
    result = unittest.TestResult()
    suite.run(result)
    failure_count = len(result.failures)
    error_count = len(result.errors)
    unexpected_success_count = len(result.unexpectedSuccesses)
    verdict = (
        "pass"
        if result.testsRun == 1
        and failure_count == 0
        and error_count == 0
        and unexpected_success_count == 0
        else "fail"
    )
    return {
        "error_count": error_count,
        "expected_failure_count": len(result.expectedFailures),
        "failure_count": failure_count,
        "skipped_count": len(result.skipped),
        "tests_run": result.testsRun,
        "unexpected_success_count": unexpected_success_count,
        "verdict": verdict,
    }


def execute_live_suites() -> dict[str, list[dict[str, int | str]]]:
    """Execute every committed admission post-disposition test method."""
    return {
        capability_id: [
            {
                "fully_qualified_name": case["fully_qualified_name"],
                "test_id": case["test_id"],
                **_run_test_case(cast(str, case["fully_qualified_name"])),
            }
            for case in _manifest_document(REPOSITORY_ROOT, capability_id)["test_cases"]
        ]
        for capability_id in CAPABILITY_SPECS
    }


def _manifest_schema() -> dict[str, Any]:
    binding = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "relative_path", "size_bytes"],
        "properties": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "relative_path": {"type": "string", "minLength": 1},
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:evidence:post-disposition-test-manifest:v1",
        "title": "PMORG post-disposition test manifest",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "capability_id",
            "requirement_ids",
            "implementation_bindings",
            "implementation_path_set_hash",
            "patch_ledger_entry_ids",
            "patch_ledger_set_hash",
            "test_file",
            "runner",
            "test_cases",
            "expected_test_count",
        ],
        "properties": {
            "schema_version": {"const": MANIFEST_SCHEMA_VERSION},
            "capability_id": {"enum": sorted(CAPABILITY_SPECS)},
            "requirement_ids": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"type": "string", "minLength": 1},
            },
            "implementation_bindings": {
                "type": "array",
                "minItems": 1,
                "items": binding,
            },
            "implementation_path_set_hash": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "patch_ledger_entry_ids": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"type": "string", "pattern": "^PL-[0-9]{3}$"},
            },
            "patch_ledger_set_hash": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "test_file": binding,
            "runner": {
                "type": "object",
                "additionalProperties": False,
                "required": ["framework", "execution_mode", "pythonpath"],
                "properties": {
                    "framework": {"const": "python-unittest"},
                    "execution_mode": {"const": "isolated-test-method"},
                    "pythonpath": {"const": "backend"},
                },
            },
            "test_cases": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["fully_qualified_name", "test_id"],
                    "properties": {
                        "fully_qualified_name": {"type": "string", "minLength": 1},
                        "test_id": {"type": "string", "minLength": 1},
                    },
                },
            },
            "expected_test_count": {"type": "integer", "minimum": 1},
        },
    }


def _result_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    runtime_artifact = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "relative_path"],
        "properties": {
            "digest": digest,
            "relative_path": {"type": "string", "minLength": 1},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:evidence:post-disposition-test-result:v1",
        "title": "PMORG post-disposition test result",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "capability_id",
            "test_id",
            "fully_qualified_name",
            "test_manifest_digest",
            "implementation_path_set_hash",
            "patch_ledger_set_hash",
            "runtime_identity_digest",
            "runtime_measurement",
            "tests_run",
            "failure_count",
            "error_count",
            "skipped_count",
            "expected_failure_count",
            "unexpected_success_count",
            "verdict",
        ],
        "properties": {
            "schema_version": {"const": RESULT_SCHEMA_VERSION},
            "capability_id": {"enum": sorted(CAPABILITY_SPECS)},
            "test_id": {"type": "string", "minLength": 1},
            "fully_qualified_name": {"type": "string", "minLength": 1},
            "test_manifest_digest": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "implementation_path_set_hash": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "patch_ledger_set_hash": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "runtime_identity_digest": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "runtime_measurement": {
                "type": "object",
                "additionalProperties": False,
                "required": ["declared_artifacts", "interpreter_binary"],
                "properties": {
                    "declared_artifacts": {
                        "type": "array",
                        "minItems": 3,
                        "maxItems": 3,
                        "items": runtime_artifact,
                    },
                    "interpreter_binary": runtime_artifact,
                },
            },
            "tests_run": {"const": 1},
            "failure_count": {"type": "integer", "minimum": 0},
            "error_count": {"type": "integer", "minimum": 0},
            "skipped_count": {"type": "integer", "minimum": 0},
            "expected_failure_count": {"type": "integer", "minimum": 0},
            "unexpected_success_count": {"type": "integer", "minimum": 0},
            "verdict": {"enum": ["pass", "fail"]},
        },
    }


def _index_schema() -> dict[str, Any]:
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
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "logical_name": {"type": "string", "minLength": 1},
            "media_type": {"enum": ["application/json", "text/x-python"]},
            "relative_path": {"type": "string", "minLength": 1},
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:evidence:post-disposition-qualification-index:v1",
        "title": "PMORG post-disposition qualification index",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "index_version",
            "claim_boundary",
            "catalog_hash",
            "capability_count",
            "expected_test_count",
            "executed_test_count",
            "failed_test_count",
            "missing_test_count",
            "duplicate_test_count",
            "runtime_identity_digests",
            "entries",
            "derivation_artifacts",
        ],
        "properties": {
            "schema_version": {"const": INDEX_SCHEMA_VERSION},
            "index_version": {"const": INDEX_VERSION},
            "claim_boundary": {"const": CLAIM_BOUNDARY},
            "catalog_hash": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "capability_count": {"const": 2},
            "expected_test_count": {"const": 10},
            "executed_test_count": {"const": 10},
            "failed_test_count": {"const": 0},
            "missing_test_count": {"const": 0},
            "duplicate_test_count": {"const": 0},
            "runtime_identity_digests": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            },
            "entries": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["capability_id", "manifest", "report", "results"],
                    "properties": {
                        "capability_id": {"enum": sorted(CAPABILITY_SPECS)},
                        "manifest": artifact,
                        "report": artifact,
                        "results": {
                            "type": "array",
                            "minItems": 5,
                            "maxItems": 5,
                            "items": artifact,
                        },
                    },
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


def build_post_disposition_qualification(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    """Execute the exact two admission suites and build all Q3c evidence."""
    catalog_hash = _catalog_hash(repository_root)
    runtime_measurement, runtime_identity_digest = _runtime_measurement(repository_root)
    documents: dict[str, bytes] = {
        INDEX_SCHEMA_RELATIVE: canonical_document_bytes(_index_schema()),
        MANIFEST_SCHEMA_RELATIVE: canonical_document_bytes(_manifest_schema()),
        RESULT_SCHEMA_RELATIVE: canonical_document_bytes(_result_schema()),
    }
    index_entries: list[dict[str, Any]] = []
    failed_test_count = 0

    for capability_id in CAPABILITY_SPECS:
        manifest = _manifest_document(repository_root, capability_id)
        manifest_relative = f"{MANIFEST_ROOT_RELATIVE}/{capability_id}.json"
        manifest_payload = canonical_document_bytes(manifest)
        documents[manifest_relative] = manifest_payload
        manifest_ref = _payload_ref(
            manifest_relative,
            manifest_payload,
            logical_name=f"{capability_id}-post-disposition-test-manifest",
        )
        result_refs: list[dict[str, Any]] = []
        test_evidence: list[dict[str, Any]] = []
        for case in cast(list[dict[str, Any]], manifest["test_cases"]):
            observed = _run_test_case(cast(str, case["fully_qualified_name"]))
            failed_test_count += int(observed["verdict"] == "fail")
            result = {
                "schema_version": RESULT_SCHEMA_VERSION,
                "capability_id": capability_id,
                "test_id": case["test_id"],
                "fully_qualified_name": case["fully_qualified_name"],
                "test_manifest_digest": manifest_ref["digest"],
                "implementation_path_set_hash": manifest[
                    "implementation_path_set_hash"
                ],
                "patch_ledger_set_hash": manifest["patch_ledger_set_hash"],
                "runtime_identity_digest": runtime_identity_digest,
                "runtime_measurement": runtime_measurement,
                **observed,
            }
            result_relative = (
                f"{RESULT_ROOT_RELATIVE}/{capability_id}/"
                f"{cast(str, case['test_id']).split('::', 1)[1]}.json"
            )
            result_payload = canonical_document_bytes(result)
            documents[result_relative] = result_payload
            result_ref = _payload_ref(
                result_relative,
                result_payload,
                logical_name=f"{case['test_id']}-result",
            )
            result_refs.append(result_ref)
            test_evidence.append(
                {
                    "test_id": case["test_id"],
                    "test_manifest": manifest_ref,
                    "result": result_ref,
                    "verdict": observed["verdict"],
                }
            )

        capability_failed = sum(item["verdict"] == "fail" for item in test_evidence)
        report = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "catalog_hash": catalog_hash,
            "capability_id": capability_id,
            "implementation_path_set_hash": manifest["implementation_path_set_hash"],
            "patch_ledger_set_hash": manifest["patch_ledger_set_hash"],
            "required_test_manifest": manifest_ref,
            "expected_test_count": manifest["expected_test_count"],
            "executed_test_count": len(test_evidence),
            "missing_test_count": 0,
            "duplicate_test_count": 0,
            "failed_test_count": capability_failed,
            "test_evidence": test_evidence,
            "verdict": "fail" if capability_failed else "pass",
        }
        report_relative = f"{REPORT_ROOT_RELATIVE}/{capability_id}.json"
        report_payload = canonical_document_bytes(report)
        documents[report_relative] = report_payload
        report_ref = _payload_ref(
            report_relative,
            report_payload,
            logical_name=f"{capability_id}-post-disposition-qualification-report",
        )
        index_entries.append(
            {
                "capability_id": capability_id,
                "manifest": manifest_ref,
                "report": report_ref,
                "results": result_refs,
            }
        )

    derivation_artifacts = [
        _artifact_ref(
            repository_root,
            relative_path,
            logical_name=Path(relative_path).name,
            media_type="text/x-python",
        )
        for relative_path in DERIVATION_RELATIVES
    ]
    index = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "index_version": INDEX_VERSION,
        "claim_boundary": CLAIM_BOUNDARY,
        "catalog_hash": catalog_hash,
        "capability_count": len(CAPABILITY_SPECS),
        "expected_test_count": 10,
        "executed_test_count": 10,
        "failed_test_count": failed_test_count,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "runtime_identity_digests": [runtime_identity_digest],
        "entries": index_entries,
        "derivation_artifacts": derivation_artifacts,
    }
    documents[INDEX_RELATIVE] = canonical_document_bytes(index)
    return documents


def write_post_disposition_qualification(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    for relative_path, payload in build_post_disposition_qualification(
        repository_root
    ).items():
        destination = _safe_path(repository_root, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


def validate_post_disposition_qualification(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    """Validate the committed Q3c evidence graph without replacing its runtime."""
    index = _read_object(repository_root, INDEX_RELATIVE)
    try:
        Draft202012Validator(
            _read_object(repository_root, INDEX_SCHEMA_RELATIVE)
        ).validate(index)
    except Exception as error:
        raise PostDispositionQualificationError(
            "post-disposition qualification index schema validation failed"
        ) from error
    if index.get("claim_boundary") != CLAIM_BOUNDARY:
        raise PostDispositionQualificationError("Q3c claim boundary drifted")
    if [entry["capability_id"] for entry in index["entries"]] != list(CAPABILITY_SPECS):
        raise PostDispositionQualificationError("Q3c capability order drifted")

    manifest_schema = _read_object(repository_root, MANIFEST_SCHEMA_RELATIVE)
    result_schema = _read_object(repository_root, RESULT_SCHEMA_RELATIVE)
    report_schema = _read_object(repository_root, REPORT_SCHEMA_RELATIVE)
    observed_runtime_digests: set[str] = set()
    total_executed = 0
    total_failed = 0

    for entry in cast(list[dict[str, Any]], index["entries"]):
        capability_id = cast(str, entry["capability_id"])
        manifest_ref = cast(dict[str, Any], entry["manifest"])
        report_ref = cast(dict[str, Any], entry["report"])
        if (
            _artifact_ref(
                repository_root,
                cast(str, manifest_ref["relative_path"]),
                logical_name=cast(str, manifest_ref["logical_name"]),
            )
            != manifest_ref
        ):
            raise PostDispositionQualificationError("Q3c manifest binding drifted")
        manifest = _read_object(
            repository_root, cast(str, manifest_ref["relative_path"])
        )
        Draft202012Validator(manifest_schema).validate(manifest)
        if manifest != _manifest_document(repository_root, capability_id):
            raise PostDispositionQualificationError(
                f"{capability_id} test manifest derivation drifted"
            )
        if (
            _artifact_ref(
                repository_root,
                cast(str, report_ref["relative_path"]),
                logical_name=cast(str, report_ref["logical_name"]),
            )
            != report_ref
        ):
            raise PostDispositionQualificationError("Q3c report binding drifted")
        report = _read_object(repository_root, cast(str, report_ref["relative_path"]))
        Draft202012Validator(report_schema).validate(report)
        try:
            PostDispositionQualificationReport.model_validate(report)
        except ValidationError as error:
            raise PostDispositionQualificationError(
                f"{capability_id} report model validation failed"
            ) from error
        if (
            report["capability_id"] != capability_id
            or report["catalog_hash"] != index["catalog_hash"]
            or report["required_test_manifest"] != manifest_ref
            or report["implementation_path_set_hash"]
            != manifest["implementation_path_set_hash"]
            or report["patch_ledger_set_hash"] != manifest["patch_ledger_set_hash"]
        ):
            raise PostDispositionQualificationError(
                f"{capability_id} report identity binding drifted"
            )
        result_refs = cast(list[dict[str, Any]], entry["results"])
        evidence = cast(list[dict[str, Any]], report["test_evidence"])
        if len(result_refs) != 5 or len(evidence) != 5:
            raise PostDispositionQualificationError(
                f"{capability_id} must retain exactly five executed tests"
            )
        expected_cases = {
            cast(str, case["test_id"]): cast(str, case["fully_qualified_name"])
            for case in cast(list[dict[str, Any]], manifest["test_cases"])
        }
        if [item["test_id"] for item in evidence] != list(expected_cases):
            raise PostDispositionQualificationError(
                f"{capability_id} test evidence coverage drifted"
            )
        for result_ref, test_item in zip(result_refs, evidence, strict=True):
            if (
                test_item["result"] != result_ref
                or test_item["test_manifest"] != manifest_ref
            ):
                raise PostDispositionQualificationError(
                    f"{capability_id} test evidence reference drifted"
                )
            if (
                _artifact_ref(
                    repository_root,
                    cast(str, result_ref["relative_path"]),
                    logical_name=cast(str, result_ref["logical_name"]),
                )
                != result_ref
            ):
                raise PostDispositionQualificationError("Q3c result binding drifted")
            result = _read_object(
                repository_root, cast(str, result_ref["relative_path"])
            )
            Draft202012Validator(result_schema).validate(result)
            if (
                result["capability_id"] != capability_id
                or result["test_id"] != test_item["test_id"]
                or result["fully_qualified_name"]
                != expected_cases[cast(str, test_item["test_id"])]
                or result["test_manifest_digest"] != manifest_ref["digest"]
                or result["implementation_path_set_hash"]
                != manifest["implementation_path_set_hash"]
                or result["patch_ledger_set_hash"] != manifest["patch_ledger_set_hash"]
                or result["verdict"] != test_item["verdict"]
            ):
                raise PostDispositionQualificationError(
                    f"{capability_id} test result identity drifted"
                )
            runtime_measurement = cast(dict[str, Any], result["runtime_measurement"])
            declared_artifacts = cast(
                list[dict[str, Any]], runtime_measurement["declared_artifacts"]
            )
            if [item["relative_path"] for item in declared_artifacts] != [
                ".python-version",
                "pyproject.toml",
                "uv.lock",
            ]:
                raise PostDispositionQualificationError(
                    f"{capability_id} runtime declaration set drifted"
                )
            for artifact in declared_artifacts:
                relative_path = cast(str, artifact["relative_path"])
                if artifact["digest"] != sha256_digest(
                    _safe_path(repository_root, relative_path).read_bytes()
                ):
                    raise PostDispositionQualificationError(
                        f"{capability_id} runtime declaration digest drifted"
                    )
            if (
                runtime_measurement["interpreter_binary"]["relative_path"]
                != "@runtime/executed-python-interpreter"
            ):
                raise PostDispositionQualificationError(
                    f"{capability_id} interpreter identity path drifted"
                )
            if result["runtime_identity_digest"] != sha256_digest(
                canonical_document_bytes(runtime_measurement)
            ):
                raise PostDispositionQualificationError(
                    f"{capability_id} runtime identity digest drifted"
                )
            observed_runtime_digests.add(cast(str, result["runtime_identity_digest"]))
            if (
                result["tests_run"] != 1
                or result["failure_count"] != 0
                or result["error_count"] != 0
                or result["skipped_count"] != 0
                or result["expected_failure_count"] != 0
                or result["unexpected_success_count"] != 0
                or result["verdict"] != "pass"
            ):
                raise PostDispositionQualificationError(
                    f"{capability_id} committed test result is not an exact PASS"
                )
        if (
            report["expected_test_count"] != 5
            or report["executed_test_count"] != 5
            or report["missing_test_count"] != 0
            or report["duplicate_test_count"] != 0
            or report["failed_test_count"] != 0
            or report["verdict"] != "pass"
        ):
            raise PostDispositionQualificationError(
                f"{capability_id} post-disposition verdict is not a complete PASS"
            )
        total_executed += cast(int, report["executed_test_count"])
        total_failed += cast(int, report["failed_test_count"])

    for ref in cast(list[dict[str, Any]], index["derivation_artifacts"]):
        if (
            _artifact_ref(
                repository_root,
                cast(str, ref["relative_path"]),
                logical_name=cast(str, ref["logical_name"]),
                media_type="text/x-python",
            )
            != ref
        ):
            raise PostDispositionQualificationError("Q3c derivation binding drifted")
    if (
        total_executed != index["executed_test_count"]
        or total_failed != index["failed_test_count"]
        or sorted(observed_runtime_digests) != index["runtime_identity_digests"]
    ):
        raise PostDispositionQualificationError("Q3c index counters drifted")

    expected_files = {
        INDEX_RELATIVE,
        INDEX_SCHEMA_RELATIVE,
        MANIFEST_SCHEMA_RELATIVE,
        RESULT_SCHEMA_RELATIVE,
        *[cast(str, entry["manifest"]["relative_path"]) for entry in index["entries"]],
        *[cast(str, entry["report"]["relative_path"]) for entry in index["entries"]],
        *[
            cast(str, ref["relative_path"])
            for entry in index["entries"]
            for ref in entry["results"]
        ],
    }
    roots = [
        Path(MANIFEST_ROOT_RELATIVE),
        Path(RESULT_ROOT_RELATIVE),
        Path(REPORT_ROOT_RELATIVE),
    ]
    observed_files = {
        path.relative_to(repository_root).as_posix()
        for root in roots
        for path in _safe_path(repository_root, root.as_posix()).rglob("*.json")
    }
    indexed_generated_files = {
        path
        for path in expected_files
        if any(path.startswith(f"{root}/") for root in roots)
    }
    if observed_files != indexed_generated_files:
        raise PostDispositionQualificationError(
            "Q3c committed evidence directory is not byte-closed"
        )
    return index
