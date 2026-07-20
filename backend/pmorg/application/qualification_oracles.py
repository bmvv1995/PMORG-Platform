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
RESULT_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-oracle-result-v1.schema.json"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
CONTRACT_TEST_ROOT = "pmorg/capabilities/contract-tests"
SEARCH_ROOT = "pmorg/capabilities/candidate-search"

POLICY_SCHEMA_VERSION = "pmorg.qualification-oracle-policy/v1"
RESULT_SCHEMA_VERSION = "pmorg.qualification-oracle-result/v1"


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

_EXECUTABLE_BINDINGS: dict[tuple[str, str], tuple[Binding, ...]] = {
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
_UNEXECUTABLE_REASONS = {
    ("deployment-admission", "A-LIC-002"): (
        "deployment admission implementation and candidate-aware adapter are absent"
    ),
    ("distribution-admission", "A-LIC-003"): (
        "distribution admission implementation and candidate-aware adapter are absent"
    ),
}


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


def _artifact_ref(repository_root: Path, binding: Binding) -> dict[str, Any]:
    path = _safe_path(repository_root, binding.relative_path)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise QualificationOracleError(
            f"oracle binding is missing: {binding.relative_path}"
        ) from error
    return {
        "argv": list(binding.argv),
        "digest": sha256_digest(payload),
        "media_type": "text/x-python",
        "relative_path": binding.relative_path,
        "size_bytes": len(payload),
    }


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


def result_schema() -> dict[str, Any]:
    string = {"type": "string", "minLength": 1}
    nonnegative = {"type": "integer", "minimum": 0}
    binding = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "relative_path"],
        "properties": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "relative_path": string,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:qualification-oracle-result:v1",
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
            "candidate_id": string,
            "oracle_id": string,
            "oracle_status": {"enum": ["executable", "unexecutable"]},
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
    expected = set(_EXECUTABLE_BINDINGS) | set(_UNEXECUTABLE_REASONS)
    if set(pairs) != expected:
        raise QualificationOracleError(
            "qualification-oracle coverage is not exact; "
            f"missing={sorted(set(pairs) - expected)}, "
            f"unknown={sorted(expected - set(pairs))}"
        )
    candidate_count = _validate_candidate_projection(repository_root)
    schema_bytes = canonical_document_bytes(result_schema())
    oracles: list[dict[str, Any]] = []
    for capability_id, test_id in pairs:
        key = (capability_id, test_id)
        bindings = _EXECUTABLE_BINDINGS.get(key, ())
        status = "executable" if bindings else "unexecutable"
        oracles.append(
            {
                "bindings": [
                    _artifact_ref(repository_root, binding) for binding in bindings
                ],
                "capability_id": capability_id,
                "candidate_projection": "module_group_blob_set/v1",
                "oracle_id": f"qualification-oracle:{capability_id}:{test_id}:v1",
                "oracle_status": status,
                "test_id": test_id,
                "unexecutable_reason": _UNEXECUTABLE_REASONS.get(key),
            }
        )
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_version": "1.0.0",
        "catalog_version": "1.0.0",
        "candidate_projection": {
            "candidate_count": candidate_count,
            "classification_root": SEARCH_ROOT,
            "membership_rule": (
                "all raw-hit blobs mapped to the candidate ID and its single "
                "candidate_group"
            ),
            "observation_rule": (
                "pass requires every projected candidate blob to be observed "
                "by every bound invocation"
            ),
            "projection_version": "module_group_blob_set/v1",
        },
        "execution_contract": {
            "environment": "offline_read_only_pinned_candidate_tree",
            "placeholder_set": [
                "candidate_repository_root",
                "candidate_revision",
                "protected_base_sha",
                "trusted_repository_root",
            ],
            "unknown_or_unexecutable_verdict": "fail",
            "zero_exit_without_complete_blob_observation_verdict": "fail",
        },
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
    if status == "unexecutable" and verdict != "fail":
        raise QualificationOracleError("an unexecutable oracle cannot pass")
    if verdict == "pass" and (
        projected == 0
        or unobserved != 0
        or not exit_codes
        or any(code != 0 for code in exit_codes)
        or not bindings
        or reasons
    ):
        raise QualificationOracleError("oracle PASS is not evidence-complete")
    policy = build_qualification_oracle_policy(repository_root)
    keys = {
        (oracle["capability_id"], oracle["test_id"], oracle["oracle_id"])
        for oracle in policy["oracles"]
    }
    identity = (result["capability_id"], result["test_id"], result["oracle_id"])
    if identity not in keys:
        raise QualificationOracleError("oracle result has an unknown identity")


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
