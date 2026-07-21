"""Build and verify Governed Fork post-disposition qualification evidence."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from typing import cast
from typing import Mapping

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.contracts.types import PostDispositionQualificationReport

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BASE_PLATFORM_COMMIT = "7778c8ecf965460811284cea9c721682cd3f42ae"
Q5D_EVIDENCE_COMMIT = "4e78c6293a0f6b17d86764688bf23f5b357db890"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
PATCH_LEDGER_RELATIVE = "pmorg/patch-ledger.json"
REPORT_SCHEMA_RELATIVE = (
    "backend/pmorg/contracts/schemas/post-disposition-qualification-v1.schema.json"
)
VERIFY_FORK_RELATIVE = "pmorg/scripts/verify_fork.py"
VERIFY_FORK_TEST_RELATIVE = "pmorg/tests/test_verify_fork.py"
RUNNER_RELATIVE = "pmorg/scripts/run_governed_fork_post_disposition_suite.py"
BUILD_SCRIPT_RELATIVE = (
    "pmorg/scripts/build_governed_fork_post_disposition_qualification.py"
)
APPLICATION_RELATIVE = (
    "backend/pmorg/application/governed_fork_post_disposition_qualification.py"
)
INDEX_RELATIVE = (
    "pmorg/capabilities/governed-fork-post-disposition-qualification-v1.json"
)
INDEX_SCHEMA_RELATIVE = (
    "pmorg/capabilities/governed-fork-post-disposition-qualification-v1.schema.json"
)
MANIFEST_RELATIVE = (
    "pmorg/capabilities/governed-fork-post-disposition-test-manifest-v1.json"
)
MANIFEST_SCHEMA_RELATIVE = (
    "pmorg/capabilities/governed-fork-post-disposition-test-manifest-v1.schema.json"
)
RESULT_SCHEMA_RELATIVE = (
    "pmorg/capabilities/governed-fork-post-disposition-test-result-v1.schema.json"
)
SUITE_RECEIPT_RELATIVE = (
    "pmorg/capabilities/governed-fork-post-disposition-suite-receipt-v1.json"
)
SUITE_RECEIPT_SCHEMA_RELATIVE = (
    "pmorg/capabilities/governed-fork-post-disposition-suite-receipt-v1.schema.json"
)
REPORT_RELATIVE = (
    "pmorg/capabilities/governed-fork-post-disposition-qualification-report-v1.json"
)
RESULT_ROOT_RELATIVE = "pmorg/capabilities/governed-fork-post-disposition-test-results"
RUNTIME_RELATIVES = (".python-version", "pyproject.toml", "uv.lock")
DERIVATION_RELATIVES = (
    APPLICATION_RELATIVE,
    RUNNER_RELATIVE,
    BUILD_SCRIPT_RELATIVE,
)

CAPABILITY_ID = "governed-onyx-fork"
REQUIREMENT_IDS = ["A-FORK-001", "A-SURFACE-001", "A-UPSTREAM-001", "PLT-001"]
LEDGER_IDS = ["PL-000"]
TEST_COUNT = 87
INDEX_VERSION = "1.0.0"
CLAIM_BOUNDARY = "governed_fork_post_disposition_qualification_only_no_disposition"

ALLOWED_SLICE_PATHS = {
    APPLICATION_RELATIVE,
    BUILD_SCRIPT_RELATIVE,
    INDEX_RELATIVE,
    INDEX_SCHEMA_RELATIVE,
    MANIFEST_RELATIVE,
    MANIFEST_SCHEMA_RELATIVE,
    PATCH_LEDGER_RELATIVE,
    REPORT_RELATIVE,
    RESULT_SCHEMA_RELATIVE,
    RUNNER_RELATIVE,
    SUITE_RECEIPT_RELATIVE,
    SUITE_RECEIPT_SCHEMA_RELATIVE,
    "backend/pmorg/tests/test_governed_fork_post_disposition_qualification.py",
}
VALIDATOR_MUTABLE_PATHS = {
    APPLICATION_RELATIVE,
    "backend/pmorg/tests/test_governed_fork_post_disposition_qualification.py",
}
ARCHIVAL_SLICE_PATHS = (
    ALLOWED_SLICE_PATHS - VALIDATOR_MUTABLE_PATHS - {PATCH_LEDGER_RELATIVE}
)
LEDGER_TOP_LEVEL_PINS = (
    "schema_version",
    "upstream_commit",
    "ownership_roots_ref",
    "seam_allowlist_ref",
    "upstream_patch_record_schema_version",
    "specification_commit",
)


class GovernedForkPostDispositionQualificationError(ValueError):
    """Raised when Governed Fork PDQ evidence is incomplete or drifted."""


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    path = (repository_root / relative_path).resolve()
    try:
        path.relative_to(repository_root.resolve())
    except ValueError as error:
        raise GovernedForkPostDispositionQualificationError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return path


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GovernedForkPostDispositionQualificationError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise GovernedForkPostDispositionQualificationError(
            f"artifact is not an object: {relative_path}"
        )
    return value


def _payload_ref(
    relative_path: str,
    payload: bytes,
    *,
    logical_name: str,
    media_type: str = "application/json",
) -> dict[str, Any]:
    return {
        "digest": sha256_digest(payload),
        "logical_name": logical_name,
        "media_type": media_type,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _artifact_ref(
    repository_root: Path,
    relative_path: str,
    *,
    logical_name: str,
    media_type: str = "application/json",
) -> dict[str, Any]:
    payload = _safe_path(repository_root, relative_path).read_bytes()
    return _payload_ref(
        relative_path,
        payload,
        logical_name=logical_name,
        media_type=media_type,
    )


def _binding(repository_root: Path, relative_path: str) -> dict[str, Any]:
    payload = _safe_path(repository_root, relative_path).read_bytes()
    return {
        "digest": sha256_digest(payload),
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


def _verified_payload(
    repository_root: Path, reference: Mapping[str, Any], *, label: str
) -> bytes:
    relative_path = reference.get("relative_path")
    if not isinstance(relative_path, str) or not relative_path:
        raise GovernedForkPostDispositionQualificationError(
            f"{label} has no relative path"
        )
    payload = _safe_path(repository_root, relative_path).read_bytes()
    if reference.get("digest") != sha256_digest(payload):
        raise GovernedForkPostDispositionQualificationError(f"{label} digest drifted")
    if reference.get("size_bytes") != len(payload):
        raise GovernedForkPostDispositionQualificationError(f"{label} size drifted")
    return payload


def _historical_blob(
    repository_root: Path, relative_path: str, *, commit: str
) -> bytes:
    try:
        return subprocess.run(
            ["git", "show", f"{commit}:{relative_path}"],
            cwd=repository_root,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise GovernedForkPostDispositionQualificationError(
            f"Governed Fork historical path is absent from {commit}: {relative_path}"
        ) from error


def _git_blob(repository_root: Path, relative_path: str) -> bytes:
    return _historical_blob(repository_root, relative_path, commit=BASE_PLATFORM_COMMIT)


def _assert_trust_boundary_immutable(repository_root: Path) -> None:
    for relative_path in (VERIFY_FORK_RELATIVE, VERIFY_FORK_TEST_RELATIVE):
        if _safe_path(repository_root, relative_path).read_bytes() != _git_blob(
            repository_root, relative_path
        ):
            raise GovernedForkPostDispositionQualificationError(
                f"trusted Governed Fork path changed in PDQ slice: {relative_path}"
            )


def _historical_result_paths(repository_root: Path) -> set[str]:
    try:
        completed = subprocess.run(
            [
                "git",
                "ls-tree",
                "-r",
                "--name-only",
                Q5D_EVIDENCE_COMMIT,
                "--",
                RESULT_ROOT_RELATIVE,
            ],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise GovernedForkPostDispositionQualificationError(
            "cannot enumerate historical Q5d result paths"
        ) from error
    return {line for line in completed.stdout.splitlines() if line}


def _assert_archival_evidence_immutable(repository_root: Path) -> None:
    historical_paths = ARCHIVAL_SLICE_PATHS | _historical_result_paths(repository_root)
    for relative_path in sorted(historical_paths):
        try:
            live = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise GovernedForkPostDispositionQualificationError(
                f"Q5d archival evidence is missing: {relative_path}"
            ) from error
        historical = _historical_blob(
            repository_root, relative_path, commit=Q5D_EVIDENCE_COMMIT
        )
        if live != historical:
            raise GovernedForkPostDispositionQualificationError(
                f"Q5d archival evidence drifted: {relative_path}"
            )


def _assert_append_only_sequence(*, base: Any, live: Any, label: str) -> None:
    if not isinstance(base, list) or not isinstance(live, list):
        raise GovernedForkPostDispositionQualificationError(
            f"Q5d patch ledger {label} is not a list"
        )
    if len(live) < len(base) or live[: len(base)] != base:
        raise GovernedForkPostDispositionQualificationError(
            f"Q5d patch ledger {label} history is not an exact prefix"
        )
    identifiers: list[str] = []
    for item in live:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise GovernedForkPostDispositionQualificationError(
                f"Q5d patch ledger {label} contains an invalid ID"
            )
        identifiers.append(cast(str, item["id"]))
    if len(identifiers) != len(set(identifiers)):
        raise GovernedForkPostDispositionQualificationError(
            f"Q5d patch ledger {label} IDs are not unique"
        )


def _assert_patch_ledger_append_only(repository_root: Path) -> None:
    try:
        base = json.loads(
            _historical_blob(
                repository_root,
                PATCH_LEDGER_RELATIVE,
                commit=Q5D_EVIDENCE_COMMIT,
            )
        )
        live = json.loads(
            _safe_path(repository_root, PATCH_LEDGER_RELATIVE).read_bytes()
        )
    except (OSError, json.JSONDecodeError) as error:
        raise GovernedForkPostDispositionQualificationError(
            "Q5d patch ledger cannot be read as JSON"
        ) from error
    if not isinstance(base, dict) or not isinstance(live, dict):
        raise GovernedForkPostDispositionQualificationError(
            "Q5d patch ledger is not an object"
        )
    if set(live) != set(base):
        raise GovernedForkPostDispositionQualificationError(
            "Q5d patch ledger top-level structure drifted"
        )
    for key in LEDGER_TOP_LEVEL_PINS:
        if live.get(key) != base.get(key):
            raise GovernedForkPostDispositionQualificationError(
                f"Q5d patch ledger top-level pin drifted: {key}"
            )
    _assert_append_only_sequence(
        base=base.get("entries"), live=live.get("entries"), label="entries"
    )
    _assert_append_only_sequence(
        base=base.get("upstream_patch_records"),
        live=live.get("upstream_patch_records"),
        label="upstream_patch_records",
    )


def _assert_historical_integrity(repository_root: Path) -> None:
    """Bind only Q5d evidence, static trust files, and append-only registries."""

    _assert_archival_evidence_immutable(repository_root)
    _assert_patch_ledger_append_only(repository_root)


def _ledger_entries(repository_root: Path) -> list[dict[str, Any]]:
    ledger = _read_object(repository_root, PATCH_LEDGER_RELATIVE)
    by_id = {
        item["id"]: item
        for item in cast(list[dict[str, Any]], ledger.get("entries", []))
    }
    if any(item not in by_id for item in LEDGER_IDS):
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork patch-ledger ownership is missing"
        )
    return [by_id[item] for item in LEDGER_IDS]


def _run_runner(
    repository_root: Path, *, list_only: bool = False
) -> dict[str, Any] | list[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    command = [sys.executable, "-B", RUNNER_RELATIVE]
    if list_only:
        completed = subprocess.run(
            [*command, "--list"],
            cwd=repository_root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        value = json.loads(completed.stdout)
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise GovernedForkPostDispositionQualificationError(
                "Governed Fork runner emitted an invalid test list"
            )
        return cast(list[str], value)
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "suite-receipt.json"
        subprocess.run(
            [*command, "--output", str(output)],
            cwd=repository_root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        value = json.loads(output.read_bytes())
    if not isinstance(value, dict):
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork runner emitted an invalid suite receipt"
        )
    return cast(dict[str, Any], value)


def _test_id(fully_qualified_name: str) -> str:
    class_name, method_name = fully_qualified_name.rsplit(".", 2)[-2:]
    return f"{CAPABILITY_ID}::{class_name}.{method_name}"


def _result_path(fully_qualified_name: str) -> str:
    class_name, method_name = fully_qualified_name.rsplit(".", 2)[-2:]
    return f"{RESULT_ROOT_RELATIVE}/{class_name}__{method_name}.json"


def _manifest_document(
    repository_root: Path, test_identities: list[str]
) -> dict[str, Any]:
    implementation_bindings = [_binding(repository_root, VERIFY_FORK_RELATIVE)]
    ledger_entries = _ledger_entries(repository_root)
    return {
        "schema_version": "pmorg.governed-fork-post-disposition-test-manifest/v1",
        "capability_id": CAPABILITY_ID,
        "requirement_ids": REQUIREMENT_IDS,
        "pmorg_platform_commit": BASE_PLATFORM_COMMIT,
        "implementation_bindings": implementation_bindings,
        "implementation_path_set_hash": sha256_digest(
            canonical_document_bytes(implementation_bindings)
        ),
        "patch_ledger_entry_ids": LEDGER_IDS,
        "patch_ledger_set_hash": sha256_digest(
            canonical_document_bytes(ledger_entries)
        ),
        "runner": _binding(repository_root, RUNNER_RELATIVE),
        "execution": {
            "framework": "python-unittest",
            "mode": "single-process-complete-module",
            "suite": "pmorg.tests.test_verify_fork",
        },
        "test_cases": [
            {
                "fully_qualified_name": identity,
                "test_id": _test_id(identity),
            }
            for identity in test_identities
        ],
        "expected_test_count": TEST_COUNT,
    }


def _runtime_measurement(
    repository_root: Path, receipt: Mapping[str, Any]
) -> tuple[dict[str, Any], str]:
    declared = [
        {
            "digest": _binding(repository_root, relative_path)["digest"],
            "relative_path": relative_path,
        }
        for relative_path in RUNTIME_RELATIVES
    ]
    measurement = {
        "declared_artifacts": declared,
        "interpreter_binary": receipt["interpreter_binary"],
    }
    return measurement, sha256_digest(canonical_document_bytes(measurement))


def _artifact_schema() -> dict[str, Any]:
    return {
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
            "media_type": {"type": "string", "minLength": 1},
            "relative_path": {"type": "string", "minLength": 1},
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }


def manifest_schema() -> dict[str, Any]:
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
        "$id": "urn:pmorg:governed-fork-post-disposition-test-manifest:v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "capability_id",
            "requirement_ids",
            "pmorg_platform_commit",
            "implementation_bindings",
            "implementation_path_set_hash",
            "patch_ledger_entry_ids",
            "patch_ledger_set_hash",
            "runner",
            "execution",
            "test_cases",
            "expected_test_count",
        ],
        "properties": {
            "schema_version": {
                "const": "pmorg.governed-fork-post-disposition-test-manifest/v1"
            },
            "capability_id": {"const": CAPABILITY_ID},
            "requirement_ids": {"const": REQUIREMENT_IDS},
            "pmorg_platform_commit": {"const": BASE_PLATFORM_COMMIT},
            "implementation_bindings": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1,
                "items": binding,
            },
            "implementation_path_set_hash": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "patch_ledger_entry_ids": {"const": LEDGER_IDS},
            "patch_ledger_set_hash": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "runner": binding,
            "execution": {
                "type": "object",
                "additionalProperties": False,
                "required": ["framework", "mode", "suite"],
                "properties": {
                    "framework": {"const": "python-unittest"},
                    "mode": {"const": "single-process-complete-module"},
                    "suite": {"const": "pmorg.tests.test_verify_fork"},
                },
            },
            "test_cases": {
                "type": "array",
                "minItems": TEST_COUNT,
                "maxItems": TEST_COUNT,
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
            "expected_test_count": {"const": TEST_COUNT},
        },
    }


def suite_receipt_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:governed-fork-post-disposition-suite-receipt:v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "pmorg_platform_commit",
            "suite",
            "test_count",
            "tests",
            "interpreter_binary",
        ],
        "properties": {
            "schema_version": {
                "const": "pmorg.governed-fork-post-disposition-suite-receipt/v1"
            },
            "pmorg_platform_commit": {"const": BASE_PLATFORM_COMMIT},
            "suite": {"const": "pmorg.tests.test_verify_fork"},
            "test_count": {"const": TEST_COUNT},
            "tests": {
                "type": "array",
                "minItems": TEST_COUNT,
                "maxItems": TEST_COUNT,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["fully_qualified_name", "status"],
                    "properties": {
                        "fully_qualified_name": {"type": "string", "minLength": 1},
                        "status": {"const": "pass"},
                    },
                },
            },
            "interpreter_binary": {
                "type": "object",
                "additionalProperties": False,
                "required": ["digest", "relative_path"],
                "properties": {
                    "digest": {
                        "type": "string",
                        "pattern": "^sha256:[0-9a-f]{64}$",
                    },
                    "relative_path": {"const": "@runtime/executed-python-interpreter"},
                },
            },
        },
    }


def result_schema() -> dict[str, Any]:
    runtime_binding = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "relative_path"],
        "properties": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "relative_path": {"type": "string", "minLength": 1},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:governed-fork-post-disposition-test-result:v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "capability_id",
            "test_id",
            "fully_qualified_name",
            "test_manifest_digest",
            "suite_receipt_digest",
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
            "schema_version": {
                "const": "pmorg.governed-fork-post-disposition-test-result/v1"
            },
            "capability_id": {"const": CAPABILITY_ID},
            "test_id": {"type": "string", "minLength": 1},
            "fully_qualified_name": {"type": "string", "minLength": 1},
            "test_manifest_digest": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "suite_receipt_digest": {
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
                        "items": runtime_binding,
                    },
                    "interpreter_binary": runtime_binding,
                },
            },
            "tests_run": {"const": 1},
            "failure_count": {"const": 0},
            "error_count": {"const": 0},
            "skipped_count": {"const": 0},
            "expected_failure_count": {"const": 0},
            "unexpected_success_count": {"const": 0},
            "verdict": {"const": "pass"},
        },
    }


def index_schema() -> dict[str, Any]:
    artifact = _artifact_schema()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:governed-fork-post-disposition-qualification-index:v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "index_version",
            "claim_boundary",
            "catalog_hash",
            "pmorg_platform_commit",
            "manifest",
            "suite_receipt",
            "report",
            "results",
            "expected_test_count",
            "executed_test_count",
            "failed_test_count",
            "missing_test_count",
            "duplicate_test_count",
            "runtime_identity_digests",
            "derivation_artifacts",
        ],
        "properties": {
            "schema_version": {
                "const": "pmorg.governed-fork-post-disposition-qualification-index/v1"
            },
            "index_version": {"const": INDEX_VERSION},
            "claim_boundary": {"const": CLAIM_BOUNDARY},
            "catalog_hash": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "pmorg_platform_commit": {"const": BASE_PLATFORM_COMMIT},
            "manifest": artifact,
            "suite_receipt": artifact,
            "report": artifact,
            "results": {
                "type": "array",
                "minItems": TEST_COUNT,
                "maxItems": TEST_COUNT,
                "items": artifact,
            },
            "expected_test_count": {"const": TEST_COUNT},
            "executed_test_count": {"const": TEST_COUNT},
            "failed_test_count": {"const": 0},
            "missing_test_count": {"const": 0},
            "duplicate_test_count": {"const": 0},
            "runtime_identity_digests": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1,
                "items": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                },
            },
            "derivation_artifacts": {
                "type": "array",
                "minItems": 3,
                "maxItems": 3,
                "items": artifact,
            },
        },
    }


def build_governed_fork_post_disposition_qualification(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    _assert_trust_boundary_immutable(repository_root)
    _assert_historical_integrity(repository_root)
    identities = cast(list[str], _run_runner(repository_root, list_only=True))
    if len(identities) != TEST_COUNT:
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ test denominator drifted"
        )
    manifest = _manifest_document(repository_root, identities)
    manifest_payload = canonical_document_bytes(manifest)
    manifest_ref = _payload_ref(
        MANIFEST_RELATIVE,
        manifest_payload,
        logical_name="governed-fork-post-disposition-test-manifest",
    )
    receipt = cast(dict[str, Any], _run_runner(repository_root))
    if [item["fully_qualified_name"] for item in receipt["tests"]] != identities:
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ execution denominator drifted"
        )
    receipt_payload = canonical_document_bytes(receipt)
    receipt_ref = _payload_ref(
        SUITE_RECEIPT_RELATIVE,
        receipt_payload,
        logical_name="governed-fork-post-disposition-suite-receipt",
    )
    runtime_measurement, runtime_digest = _runtime_measurement(repository_root, receipt)
    outputs: dict[str, bytes] = {
        INDEX_SCHEMA_RELATIVE: canonical_document_bytes(index_schema()),
        MANIFEST_SCHEMA_RELATIVE: canonical_document_bytes(manifest_schema()),
        RESULT_SCHEMA_RELATIVE: canonical_document_bytes(result_schema()),
        SUITE_RECEIPT_SCHEMA_RELATIVE: canonical_document_bytes(suite_receipt_schema()),
        MANIFEST_RELATIVE: manifest_payload,
        SUITE_RECEIPT_RELATIVE: receipt_payload,
    }
    result_refs: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for item in cast(list[dict[str, Any]], receipt["tests"]):
        identity = cast(str, item["fully_qualified_name"])
        test_id = _test_id(identity)
        result = {
            "schema_version": "pmorg.governed-fork-post-disposition-test-result/v1",
            "capability_id": CAPABILITY_ID,
            "test_id": test_id,
            "fully_qualified_name": identity,
            "test_manifest_digest": manifest_ref["digest"],
            "suite_receipt_digest": receipt_ref["digest"],
            "implementation_path_set_hash": manifest["implementation_path_set_hash"],
            "patch_ledger_set_hash": manifest["patch_ledger_set_hash"],
            "runtime_identity_digest": runtime_digest,
            "runtime_measurement": runtime_measurement,
            "tests_run": 1,
            "failure_count": 0,
            "error_count": 0,
            "skipped_count": 0,
            "expected_failure_count": 0,
            "unexpected_success_count": 0,
            "verdict": "pass",
        }
        relative_path = _result_path(identity)
        payload = canonical_document_bytes(result)
        outputs[relative_path] = payload
        reference = _payload_ref(
            relative_path,
            payload,
            logical_name=f"{test_id}-result",
        )
        result_refs.append(reference)
        evidence.append(
            {
                "test_id": test_id,
                "test_manifest": manifest_ref,
                "result": reference,
                "verdict": "pass",
            }
        )
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    report = {
        "schema_version": "pmorg.post-disposition-qualification/v1",
        "catalog_hash": catalog_hash,
        "capability_id": CAPABILITY_ID,
        "implementation_path_set_hash": manifest["implementation_path_set_hash"],
        "patch_ledger_set_hash": manifest["patch_ledger_set_hash"],
        "required_test_manifest": manifest_ref,
        "expected_test_count": TEST_COUNT,
        "executed_test_count": TEST_COUNT,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "failed_test_count": 0,
        "test_evidence": evidence,
        "verdict": "pass",
    }
    try:
        PostDispositionQualificationReport.model_validate(report)
    except ValidationError as error:
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ report failed the contract model"
        ) from error
    report_schema = _read_object(repository_root, REPORT_SCHEMA_RELATIVE)
    errors = list(Draft202012Validator(report_schema).iter_errors(report))
    if errors:
        raise GovernedForkPostDispositionQualificationError(
            f"Governed Fork PDQ report schema failed: {errors[0]}"
        )
    report_payload = canonical_document_bytes(report)
    outputs[REPORT_RELATIVE] = report_payload
    report_ref = _payload_ref(
        REPORT_RELATIVE,
        report_payload,
        logical_name="governed-fork-post-disposition-qualification-report",
    )
    derivation_refs = [
        _artifact_ref(
            repository_root,
            relative_path,
            logical_name=Path(relative_path).name,
            media_type="text/x-python",
        )
        for relative_path in DERIVATION_RELATIVES
    ]
    index = {
        "schema_version": (
            "pmorg.governed-fork-post-disposition-qualification-index/v1"
        ),
        "index_version": INDEX_VERSION,
        "claim_boundary": CLAIM_BOUNDARY,
        "catalog_hash": catalog_hash,
        "pmorg_platform_commit": BASE_PLATFORM_COMMIT,
        "manifest": manifest_ref,
        "suite_receipt": receipt_ref,
        "report": report_ref,
        "results": result_refs,
        "expected_test_count": TEST_COUNT,
        "executed_test_count": TEST_COUNT,
        "failed_test_count": 0,
        "missing_test_count": 0,
        "duplicate_test_count": 0,
        "runtime_identity_digests": [runtime_digest],
        "derivation_artifacts": derivation_refs,
    }
    errors = list(Draft202012Validator(index_schema()).iter_errors(index))
    if errors:
        raise GovernedForkPostDispositionQualificationError(
            f"Governed Fork PDQ index schema failed: {errors[0]}"
        )
    outputs[INDEX_RELATIVE] = canonical_document_bytes(index)
    return outputs


def write_governed_fork_post_disposition_qualification(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    outputs = build_governed_fork_post_disposition_qualification(repository_root)
    expected_paths = set(outputs)
    result_root = _safe_path(repository_root, RESULT_ROOT_RELATIVE)
    if result_root.exists():
        for path in result_root.rglob("*.json"):
            if path.relative_to(repository_root).as_posix() not in expected_paths:
                path.unlink()
    for relative_path, payload in outputs.items():
        destination = _safe_path(repository_root, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


def check_governed_fork_post_disposition_qualification(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    _assert_trust_boundary_immutable(repository_root)
    _assert_historical_integrity(repository_root)
    expected_schemas = {
        INDEX_SCHEMA_RELATIVE: index_schema(),
        MANIFEST_SCHEMA_RELATIVE: manifest_schema(),
        RESULT_SCHEMA_RELATIVE: result_schema(),
        SUITE_RECEIPT_SCHEMA_RELATIVE: suite_receipt_schema(),
    }
    for relative_path, schema in expected_schemas.items():
        if _safe_path(repository_root, relative_path).read_bytes() != (
            canonical_document_bytes(schema)
        ):
            raise GovernedForkPostDispositionQualificationError(
                f"committed schema drifted: {relative_path}"
            )
    index = _read_object(repository_root, INDEX_RELATIVE)
    Draft202012Validator(index_schema()).validate(index)
    identities = cast(list[str], _run_runner(repository_root, list_only=True))
    manifest = json.loads(
        _verified_payload(repository_root, index["manifest"], label="PDQ manifest")
    )
    if manifest != _manifest_document(repository_root, identities):
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ manifest derivation drifted"
        )
    receipt = json.loads(
        _verified_payload(
            repository_root, index["suite_receipt"], label="PDQ suite receipt"
        )
    )
    Draft202012Validator(suite_receipt_schema()).validate(receipt)
    if [item["fully_qualified_name"] for item in receipt["tests"]] != identities:
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ receipt denominator drifted"
        )
    runtime_measurement, runtime_digest = _runtime_measurement(repository_root, receipt)
    if index["runtime_identity_digests"] != [runtime_digest]:
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ runtime identity drifted"
        )
    result_refs = cast(list[dict[str, Any]], index["results"])
    report = json.loads(
        _verified_payload(repository_root, index["report"], label="PDQ report")
    )
    try:
        PostDispositionQualificationReport.model_validate(report)
    except ValidationError as error:
        raise GovernedForkPostDispositionQualificationError(
            "committed Governed Fork PDQ report failed the contract model"
        ) from error
    Draft202012Validator(
        _read_object(repository_root, REPORT_SCHEMA_RELATIVE)
    ).validate(report)
    evidence = cast(list[dict[str, Any]], report["test_evidence"])
    if len(result_refs) != TEST_COUNT or len(evidence) != TEST_COUNT:
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ result coverage drifted"
        )
    observed_paths: set[str] = set()
    for identity, reference, item in zip(
        identities, result_refs, evidence, strict=True
    ):
        payload = _verified_payload(repository_root, reference, label="PDQ result")
        result = json.loads(payload)
        Draft202012Validator(result_schema()).validate(result)
        expected_id = _test_id(identity)
        if (
            reference["relative_path"] != _result_path(identity)
            or reference["relative_path"] in observed_paths
            or result["fully_qualified_name"] != identity
            or result["test_id"] != expected_id
            or result["test_manifest_digest"] != index["manifest"]["digest"]
            or result["suite_receipt_digest"] != index["suite_receipt"]["digest"]
            or result["implementation_path_set_hash"]
            != manifest["implementation_path_set_hash"]
            or result["patch_ledger_set_hash"] != manifest["patch_ledger_set_hash"]
            or result["runtime_identity_digest"] != runtime_digest
            or result["runtime_measurement"] != runtime_measurement
            or item["test_id"] != expected_id
            or item["test_manifest"] != index["manifest"]
            or item["result"] != reference
            or item["verdict"] != "pass"
        ):
            raise GovernedForkPostDispositionQualificationError(
                f"Governed Fork PDQ evidence drifted: {identity}"
            )
        observed_paths.add(cast(str, reference["relative_path"]))
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    if (
        report["catalog_hash"] != catalog_hash
        or report["capability_id"] != CAPABILITY_ID
        or report["implementation_path_set_hash"]
        != manifest["implementation_path_set_hash"]
        or report["patch_ledger_set_hash"] != manifest["patch_ledger_set_hash"]
        or report["required_test_manifest"] != index["manifest"]
        or report["expected_test_count"] != TEST_COUNT
        or report["executed_test_count"] != TEST_COUNT
        or report["missing_test_count"] != 0
        or report["duplicate_test_count"] != 0
        or report["failed_test_count"] != 0
        or report["verdict"] != "pass"
    ):
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ report counters or bindings drifted"
        )
    committed_paths = {
        path.relative_to(repository_root).as_posix()
        for path in _safe_path(repository_root, RESULT_ROOT_RELATIVE).rglob("*.json")
    }
    if committed_paths != observed_paths:
        raise GovernedForkPostDispositionQualificationError(
            "Governed Fork PDQ result directory is not byte-closed"
        )
    for reference in cast(list[dict[str, Any]], index["derivation_artifacts"]):
        relative_path = cast(str, reference["relative_path"])
        if relative_path == APPLICATION_RELATIVE:
            payload = _historical_blob(
                repository_root,
                relative_path,
                commit=Q5D_EVIDENCE_COMMIT,
            )
            if reference.get("digest") != sha256_digest(payload) or reference.get(
                "size_bytes"
            ) != len(payload):
                raise GovernedForkPostDispositionQualificationError(
                    "historical Q5d validator derivation reference drifted"
                )
        else:
            _verified_payload(
                repository_root, reference, label="PDQ derivation artifact"
            )


__all__ = [
    "GovernedForkPostDispositionQualificationError",
    "build_governed_fork_post_disposition_qualification",
    "check_governed_fork_post_disposition_qualification",
    "index_schema",
    "manifest_schema",
    "result_schema",
    "suite_receipt_schema",
    "write_governed_fork_post_disposition_qualification",
]
