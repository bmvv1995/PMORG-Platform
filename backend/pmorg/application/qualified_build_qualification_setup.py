"""Build unactivated qualified-build vectors and exhaustive screening evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator

from pmorg.application.candidate_inputs import _read_blobs
from pmorg.application.candidate_inputs import PINNED_SOURCE_COMMIT
from pmorg.application.candidate_inputs import PINNED_SOURCE_REPOSITORY
from pmorg.application.candidate_inputs import PINNED_SOURCE_TREE
from pmorg.application.candidate_inputs import validate_candidate_input_bundle

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CAPABILITY_ID = "qualified-reproducible-build"
TEST_IDS = ("A-EVIDENCE-001", "A-LIC-001", "A-REPORT-001", "A-REPRO-001")
EXPECTED_CANDIDATES = 46
EXPECTED_MEMBERSHIPS = 4522

VECTOR_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-test-vector-v1.schema.json"
BASE_VECTOR_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-test-vectors-v1.json"
ORACLE_POLICY_RELATIVE = "pmorg/capabilities/qualification-oracle-policy-v1.json"
INTERFACE_RELATIVE = (
    "pmorg/capabilities/qualification-interfaces/qualified-reproducible-build-v1.json"
)
IMPLEMENTATION_RELATIVES = (
    "pmorg/scripts/build_ce_artifact.py",
    "pmorg/scripts/verify_ce_build.py",
)
IMPLEMENTATION_BY_TEST = {
    "A-EVIDENCE-001": "pmorg/scripts/build_ce_artifact.py",
    "A-LIC-001": "pmorg/scripts/verify_ce_build.py",
    "A-REPORT-001": "pmorg/scripts/build_ce_artifact.py",
    "A-REPRO-001": "pmorg/scripts/verify_ce_build.py",
}
CANDIDATE_INPUTS_RELATIVE = "pmorg/capabilities/candidate-inputs-v1.json"
SEARCH_EVIDENCE_RELATIVE = "pmorg/capabilities/candidate-search/qualified-reproducible-build-search-evidence-v1.json"
HIT_CLASSIFICATION_RELATIVE = "pmorg/capabilities/candidate-search/qualified-reproducible-build-hit-classification-v1.json"
VECTOR_MANIFEST_RELATIVE = (
    "pmorg/capabilities/qualification-test-vector-extension-qualified-build-v1.json"
)
VECTOR_RELATIVES = {
    test_id: (
        "pmorg/capabilities/qualification-test-vector-extensions/"
        f"qualified-reproducible-build-{test_id}-v1.json"
    )
    for test_id in TEST_IDS
}
EVIDENCE_RELATIVE = "pmorg/capabilities/qualified-build-interface-fit-evidence-v1.json"
EVIDENCE_SCHEMA_RELATIVE = (
    "pmorg/capabilities/qualified-build-interface-fit-evidence-v1.schema.json"
)
DERIVATION_RELATIVES = (
    "backend/pmorg/application/qualified_build_qualification_setup.py",
    "pmorg/scripts/build_qualified_build_qualification_setup.py",
)
RUNTIME_ARTIFACTS = (
    (".python-version", "text/plain"),
    ("pyproject.toml", "application/toml"),
    ("uv.lock", "application/toml"),
)

_SIGNALS = {
    "evidence_binding": ("attestation", "bqa", "digest", "evidence", "sha256", "sign"),
    "license_boundary": ("ce", "ee", "license", "licensed"),
    "reporting": ("artifact", "build", "manifest", "receipt", "report"),
    "reproducibility": ("deterministic", "lock", "offline", "reproducible"),
    "runtime_toolchain": ("python", "runtime", "toolchain"),
}
_TOKEN_PATTERNS = {
    term: re.compile(
        rb"(?<![a-z0-9_])" + re.escape(term.encode("ascii")) + rb"(?![a-z0-9_])"
    )
    for terms in _SIGNALS.values()
    for term in terms
}


class QualifiedBuildQualificationSetupError(ValueError):
    """Raised when Q6a evidence cannot be reproduced exactly."""


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
        raise QualifiedBuildQualificationSetupError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualifiedBuildQualificationSetupError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise QualifiedBuildQualificationSetupError(
            f"artifact is not an object: {relative_path}"
        )
    return value


def _artifact_ref(
    repository_root: Path, relative_path: str, *, media_type: str | None = None
) -> dict[str, Any]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise QualifiedBuildQualificationSetupError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    result: dict[str, Any] = {
        "digest": sha256_digest(payload),
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }
    if media_type is not None:
        result["media_type"] = media_type
    return result


def _oracle_states(repository_root: Path) -> list[dict[str, Any]]:
    policy = _read_object(repository_root, ORACLE_POLICY_RELATIVE)
    states: list[dict[str, Any]] = []
    for test_id in TEST_IDS:
        matching = [
            oracle
            for oracle in policy.get("oracles", [])
            if isinstance(oracle, dict)
            and oracle.get("capability_id") == CAPABILITY_ID
            and oracle.get("test_id") == test_id
        ]
        if len(matching) != 1:
            raise QualifiedBuildQualificationSetupError(
                f"policy does not contain exactly one {test_id} oracle"
            )
        oracle = matching[0]
        if (
            oracle.get("oracle_status") != "unexecutable"
            or oracle.get("adapter") is not None
            or oracle.get("candidate_test_vector") is not None
        ):
            raise QualifiedBuildQualificationSetupError(
                f"{test_id} oracle is already activated or vector-bound"
            )
        states.append(
            {
                "adapter": None,
                "candidate_test_vector": None,
                "oracle_id": oracle.get("oracle_id"),
                "oracle_status": "unexecutable",
                "test_id": test_id,
            }
        )
    return states


def _runtime_contract(repository_root: Path) -> dict[str, Any]:
    artifacts = [
        _artifact_ref(repository_root, path, media_type=media_type)
        for path, media_type in RUNTIME_ARTIFACTS
    ]
    return {
        "schema_version": "pmorg.qualification-runtime-identity-contract/v1",
        "status": "binary_measurement_required_at_execution",
        "interpreter_binary_evidence": {
            "algorithm": "sha256",
            "required_fields": [
                "implementation",
                "version",
                "executable_digest",
                "executable_size_bytes",
            ],
        },
        "artifacts": artifacts,
        "pass_requirements": [
            "the invoked interpreter binary is measured before adapter execution",
            "the measured interpreter satisfies the committed .python-version",
            "dependencies resolve only from the exact committed uv.lock",
            "runtime evidence and lock artifact digests are bound into the result",
        ],
    }


_TEST_SEMANTICS = {
    "A-EVIDENCE-001": (
        "present a candidate build that binds every source, build input, artifact and BQA evidence field by content digest",
        "accept the conforming injected build and emit a complete content-addressed evidence bundle",
        "mutate an evidence digest or detach a BQA field from its exact build input",
        "reject fail-closed and cite the exact missing or inconsistent evidence binding",
    ),
    "A-LIC-001": (
        "present a candidate build that admits only the declared CE surface and rejects EE paths, imports, copies and unknown egress",
        "accept the conforming CE-only injected build with no license-boundary violation",
        "inject an EE path, import, copy or undeclared egress into the projected candidate bytes",
        "reject fail-closed and cite the exact CE boundary violation",
    ),
    "A-REPORT-001": (
        "present a candidate build whose artifact set, build manifest and signed BQA report are complete and content-addressed",
        "accept the conforming injected report and bind every reported artifact to exact bytes",
        "omit an artifact or report a digest that does not match the emitted bytes",
        "reject fail-closed and cite the exact incomplete or inconsistent report field",
    ),
    "A-REPRO-001": (
        "present a candidate build that consumes pinned offline inputs and produces byte-identical independent rebuilds",
        "accept the conforming injected build only when two independent rebuild artifact sets are byte-identical",
        "introduce an unpinned input, nondeterministic value or byte-divergent rebuild output",
        "reject fail-closed and cite the exact reproducibility divergence",
    ),
}


def _build_vectors(repository_root: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    schema = _read_object(repository_root, VECTOR_SCHEMA_RELATIVE)
    interface = _read_object(repository_root, INTERFACE_RELATIVE)
    interface_tests = tuple(
        item.get("test_id")
        for item in interface.get("test_properties", [])
        if isinstance(item, dict)
    )
    if interface_tests != TEST_IDS:
        raise QualifiedBuildQualificationSetupError(
            "qualification interface test properties drifted"
        )
    declared_implementations = cast(
        list[dict[str, Any]], interface.get("reference_implementations", [])
    )
    expected_implementations = [
        _artifact_ref(repository_root, path, media_type="text/x-python")
        for path in IMPLEMENTATION_RELATIVES
    ]
    if declared_implementations != expected_implementations:
        raise QualifiedBuildQualificationSetupError(
            "qualification interface reference implementations drifted"
        )
    runtime_contract = _runtime_contract(repository_root)
    runtime_digest = sha256_digest(canonical_document_bytes(runtime_contract))
    runtime_artifacts = cast(list[dict[str, Any]], runtime_contract["artifacts"])
    outputs: dict[str, bytes] = {}
    vector_refs: list[dict[str, Any]] = []
    for test_id in TEST_IDS:
        (
            positive_stimulus,
            positive_observation,
            negative_stimulus,
            negative_observation,
        ) = _TEST_SEMANTICS[test_id]
        vector = {
            "schema_version": "pmorg.qualification-test-vector/v1",
            "vector_version": "1.0.0",
            "capability_id": CAPABILITY_ID,
            "test_id": test_id,
            "candidate_projection": "module_group_blob_set/v1",
            "qualification_interface": _artifact_ref(
                repository_root, INTERFACE_RELATIVE, media_type="application/json"
            ),
            "reference_implementation": _artifact_ref(
                repository_root,
                IMPLEMENTATION_BY_TEST[test_id],
                media_type="text/x-python",
            ),
            "adapter_input_contract": [
                "exact candidate input manifest and manifest digest",
                "all projected candidate blob bytes and blob digests",
                "exact qualification interface and test-vector digests",
                "measured interpreter binary and committed dependency lock digests",
            ],
            "runtime_identity": {
                "artifacts": runtime_artifacts,
                "contract_digest": runtime_digest,
                "interpreter_measurement": "sha256_of_executed_interpreter_binary",
                "status": "binary_measurement_required_at_execution",
            },
            "test_cases": [
                {
                    "candidate_bytes_required": True,
                    "case_id": "conforming-positive-injection",
                    "expected_observation": positive_observation,
                    "mutation_required": False,
                    "stimulus": positive_stimulus,
                },
                {
                    "candidate_bytes_required": True,
                    "case_id": "fail-closed-policy-violation",
                    "expected_observation": negative_observation,
                    "mutation_required": False,
                    "stimulus": negative_stimulus,
                },
                {
                    "candidate_bytes_required": True,
                    "case_id": "candidate-byte-influence",
                    "expected_observation": "at least one adapter observation or verdict changes",
                    "mutation_required": True,
                    "stimulus": "flip one byte in a projected candidate blob and rebuild its manifest",
                },
                {
                    "candidate_bytes_required": True,
                    "case_id": "runtime-and-lock-binding",
                    "expected_observation": "reject before verdict when interpreter or dependency-lock identity drifts",
                    "mutation_required": False,
                    "stimulus": "execute with a mismatched interpreter binary or dependency lock",
                },
            ],
            "mutation_probe": {
                "expectation": "at_least_one_observation_or_verdict_changes",
                "no_op_rejected": True,
                "operation": "flip_one_candidate_blob_byte",
                "target": "projected_candidate_blob_bytes",
            },
            "execution_preconditions": [
                "adapter is content-addressed and explicitly bound to this test vector",
                "adapter consumes the exact candidate manifest and every projected blob",
                "interpreter binary and dependency lock identities are evidence-bound",
                "baseline, positive-control and mutated executions produce schema-valid evidence",
            ],
            "claim_boundary": "definition_only_no_qualification_verdict",
        }
        errors = sorted(Draft202012Validator(schema).iter_errors(vector), key=str)
        if errors:
            raise QualifiedBuildQualificationSetupError(
                f"{test_id} vector schema violation: {errors[0]}"
            )
        payload = canonical_document_bytes(vector)
        relative_path = VECTOR_RELATIVES[test_id]
        outputs[relative_path] = payload
        vector_refs.append(
            {
                "capability_id": CAPABILITY_ID,
                "digest": sha256_digest(payload),
                "media_type": "application/json",
                "relative_path": relative_path,
                "size_bytes": len(payload),
                "test_id": test_id,
            }
        )
    manifest = {
        "schema_version": "pmorg.qualification-test-vector-extension-manifest/v1",
        "extension_id": "qualified-reproducible-build-v1",
        "activation_status": "definition_only_unactivated",
        "claim_boundary": "no_oracle_activation_or_qualification_verdict",
        "qualification_interface": _artifact_ref(
            repository_root, INTERFACE_RELATIVE, media_type="application/json"
        ),
        "interface_reference_implementations": expected_implementations,
        "reference_implementation_bindings": [
            {
                "reference_implementation": _artifact_ref(
                    repository_root,
                    IMPLEMENTATION_BY_TEST[test_id],
                    media_type="text/x-python",
                ),
                "test_id": test_id,
            }
            for test_id in TEST_IDS
        ],
        "falsifiability_contract": {
            "candidate_influence_both_directions": True,
            "mutation_can_flip_verdict": True,
            "no_op_rejected": True,
            "positive_injection_can_fit": True,
            "runtime_identity_required_at_execution": True,
        },
        "immutable_predecessors": {
            "base_vector_manifest": _artifact_ref(
                repository_root,
                BASE_VECTOR_MANIFEST_RELATIVE,
                media_type="application/json",
            ),
            "oracle_policy": _artifact_ref(
                repository_root, ORACLE_POLICY_RELATIVE, media_type="application/json"
            ),
            "oracle_states": _oracle_states(repository_root),
        },
        "runtime_identity_contract": runtime_contract,
        "runtime_identity_contract_digest": runtime_digest,
        "vector_schema": _artifact_ref(
            repository_root,
            VECTOR_SCHEMA_RELATIVE,
            media_type="application/schema+json",
        ),
        "vectors": vector_refs,
        "derivation_artifacts": [
            _artifact_ref(repository_root, path, media_type="text/x-python")
            for path in DERIVATION_RELATIVES
        ],
    }
    outputs[VECTOR_MANIFEST_RELATIVE] = canonical_document_bytes(manifest)
    return outputs, manifest


def _coverage_schema(total: int | None = None) -> dict[str, Any]:
    count: dict[str, Any] = {"type": "integer", "minimum": 1}
    if total is not None:
        count = {"const": total}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["expected", "scanned", "unreadable", "unverified"],
        "properties": {
            "expected": count,
            "scanned": count,
            "unreadable": {"const": 0},
            "unverified": {"const": 0},
        },
    }


def evidence_schema() -> dict[str, Any]:
    nonempty = {"type": "string", "minLength": 1}
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    artifact = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "relative_path", "size_bytes"],
        "properties": {
            "digest": digest,
            "relative_path": nonempty,
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }
    signal = {
        "type": "object",
        "additionalProperties": False,
        "required": ["categories", "git_object_id", "path", "sha256"],
        "properties": {
            "categories": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"enum": sorted(_SIGNALS)},
            },
            "git_object_id": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "path": nonempty,
            "sha256": digest,
        },
    }
    scan = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "blob_count",
            "blob_index_digest",
            "blob_set_digest",
            "candidate_group",
            "coverage",
            "scan_digest",
            "signal_paths",
            "source_surface",
        ],
        "properties": {
            "blob_count": {"type": "integer", "minimum": 1},
            "blob_index_digest": digest,
            "blob_set_digest": digest,
            "candidate_group": nonempty,
            "coverage": _coverage_schema(),
            "scan_digest": digest,
            "signal_paths": {"type": "array", "items": signal},
            "source_surface": {"enum": ["ce", "ee"]},
        },
    }
    candidate = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "blob_count",
            "blob_set_digest",
            "candidate_group",
            "candidate_id",
            "candidate_manifest_digest",
            "plausibility_state",
            "scan_digest",
            "signal_path_count",
        ],
        "properties": {
            "blob_count": {"type": "integer", "minimum": 1},
            "blob_set_digest": digest,
            "candidate_group": nonempty,
            "candidate_id": nonempty,
            "candidate_manifest_digest": digest,
            "plausibility_state": {
                "enum": [
                    "lexical_signals_present_no_fit_inference",
                    "no_lexical_signal_present_no_fit_inference",
                ]
            },
            "scan_digest": digest,
            "signal_path_count": {"type": "integer", "minimum": 0},
        },
    }
    oracle_state = {
        "type": "object",
        "additionalProperties": False,
        "required": ["adapter", "candidate_test_vector", "oracle_status", "test_id"],
        "properties": {
            "adapter": {"type": "null"},
            "candidate_test_vector": {"type": "null"},
            "oracle_status": {"const": "unexecutable"},
            "test_id": {"enum": list(TEST_IDS)},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:qualified-build-interface-fit-evidence:v1",
        "title": "PMORG exhaustive qualified-build interface-fit screening evidence",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "evidence_version",
            "capability_id",
            "source_repository",
            "source_commit",
            "source_tree_id",
            "candidate_inputs",
            "candidate_search_evidence",
            "hit_classification",
            "raw_results_digest",
            "qualification_interface",
            "test_vector_extension",
            "test_vectors",
            "oracle_policy",
            "derivation_artifacts",
            "selection_policy",
            "falsifiability_contract",
            "candidate_count",
            "candidate_blob_membership_count",
            "blob_set_scan_count",
            "blob_set_membership_count",
            "coverage",
            "blob_set_scans",
            "candidates",
            "active_oracle_states",
            "claim_boundary",
            "oracle_activation",
        ],
        "properties": {
            "schema_version": {
                "const": "pmorg.qualified-build-interface-fit-evidence/v1"
            },
            "evidence_version": {"const": "1.0.0"},
            "capability_id": {"const": CAPABILITY_ID},
            "source_repository": {"const": PINNED_SOURCE_REPOSITORY},
            "source_commit": {"const": PINNED_SOURCE_COMMIT},
            "source_tree_id": {"const": PINNED_SOURCE_TREE},
            "candidate_inputs": artifact,
            "candidate_search_evidence": artifact,
            "hit_classification": artifact,
            "raw_results_digest": digest,
            "qualification_interface": artifact,
            "test_vector_extension": artifact,
            "test_vectors": {
                "type": "array",
                "minItems": 4,
                "maxItems": 4,
                "items": artifact,
            },
            "oracle_policy": artifact,
            "derivation_artifacts": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": artifact,
            },
            "selection_policy": {
                "const": "all_46_candidates_from_qualified_reproducible_build_hit_classification"
            },
            "falsifiability_contract": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "candidate_influence_both_directions",
                    "mutation_can_flip_verdict",
                    "no_op_rejected",
                    "positive_injection_can_fit",
                    "runtime_identity_required_at_execution",
                ],
                "properties": {
                    "candidate_influence_both_directions": {"const": True},
                    "mutation_can_flip_verdict": {"const": True},
                    "no_op_rejected": {"const": True},
                    "positive_injection_can_fit": {"const": True},
                    "runtime_identity_required_at_execution": {"const": True},
                },
            },
            "candidate_count": {"const": EXPECTED_CANDIDATES},
            "candidate_blob_membership_count": {"const": EXPECTED_MEMBERSHIPS},
            "blob_set_scan_count": {"const": EXPECTED_CANDIDATES},
            "blob_set_membership_count": {"const": EXPECTED_MEMBERSHIPS},
            "coverage": _coverage_schema(EXPECTED_MEMBERSHIPS),
            "blob_set_scans": {
                "type": "array",
                "minItems": EXPECTED_CANDIDATES,
                "maxItems": EXPECTED_CANDIDATES,
                "items": scan,
            },
            "candidates": {
                "type": "array",
                "minItems": EXPECTED_CANDIDATES,
                "maxItems": EXPECTED_CANDIDATES,
                "items": candidate,
            },
            "active_oracle_states": {
                "type": "array",
                "minItems": 4,
                "maxItems": 4,
                "items": oracle_state,
            },
            "claim_boundary": {
                "const": "exhaustive_plausibility_screen_only_no_qualification_or_disposition"
            },
            "oracle_activation": {"const": False},
        },
    }


def _blob_index(blob_set: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "git_object_id": blob["git_object_id"],
            "path": blob["path"],
            "sha256": blob["sha256"],
            "size_bytes": blob["size_bytes"],
        }
        for blob in cast(list[dict[str, Any]], blob_set["blobs"])
    ]


def _scan_blob_set(repository_root: Path, blob_set: dict[str, Any]) -> dict[str, Any]:
    blobs = cast(list[dict[str, Any]], blob_set["blobs"])
    object_ids = [cast(str, blob["git_object_id"]) for blob in blobs]
    payloads = _read_blobs(repository_root, object_ids)
    signal_paths: list[dict[str, Any]] = []
    for blob in blobs:
        object_id = cast(str, blob["git_object_id"])
        payload = payloads[object_id]
        if sha256_digest(payload) != blob["sha256"]:
            raise QualifiedBuildQualificationSetupError(
                f"candidate blob digest drifted: {blob['path']}"
            )
        if len(payload) != blob["size_bytes"]:
            raise QualifiedBuildQualificationSetupError(
                f"candidate blob size drifted: {blob['path']}"
            )
        lowered = payload.lower()
        categories = sorted(
            category
            for category, terms in _SIGNALS.items()
            if any(_TOKEN_PATTERNS[term].search(lowered) for term in terms)
        )
        if categories:
            signal_paths.append(
                {
                    "categories": categories,
                    "git_object_id": object_id,
                    "path": blob["path"],
                    "sha256": blob["sha256"],
                }
            )
    scan_core = {
        "blob_count": len(blobs),
        "blob_index_digest": sha256_digest(
            canonical_document_bytes(_blob_index(blob_set))
        ),
        "blob_set_digest": blob_set["blob_set_digest"],
        "candidate_group": blob_set["candidate_group"],
        "coverage": {
            "expected": len(blobs),
            "scanned": len(blobs),
            "unreadable": 0,
            "unverified": 0,
        },
        "signal_paths": signal_paths,
        "source_surface": blob_set["source_surface"],
    }
    return {
        **scan_core,
        "scan_digest": sha256_digest(canonical_document_bytes(scan_core)),
    }


def _build_screening(
    repository_root: Path,
    vector_outputs: dict[str, bytes],
    vector_manifest: dict[str, Any],
) -> dict[str, bytes]:
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    search_evidence = _read_object(repository_root, SEARCH_EVIDENCE_RELATIVE)
    classification = _read_object(repository_root, HIT_CLASSIFICATION_RELATIVE)
    if classification.get(
        "candidate_count"
    ) != EXPECTED_CANDIDATES or classification.get(
        "raw_results_digest"
    ) != search_evidence.get("raw_results", {}).get("digest"):
        raise QualifiedBuildQualificationSetupError(
            "qualified-build classification denominator drifted"
        )
    selected = [
        candidate
        for candidate in cast(list[dict[str, Any]], bundle["candidates"])
        if candidate["capability_id"] == CAPABILITY_ID
    ]
    selected.sort(
        key=lambda item: (
            cast(str, item["candidate_group"]),
            cast(str, item["candidate_id"]),
        )
    )
    expected_ids = sorted(cast(list[str], search_evidence.get("candidate_ids", [])))
    actual_ids = sorted(cast(str, item["candidate_id"]) for item in selected)
    if actual_ids != expected_ids or len(actual_ids) != EXPECTED_CANDIDATES:
        raise QualifiedBuildQualificationSetupError(
            "candidate inputs do not equal the committed 46-candidate denominator"
        )
    referenced_digests = {cast(str, item["blob_set_digest"]) for item in selected}
    blob_sets = [
        item
        for item in cast(list[dict[str, Any]], bundle["blob_sets"])
        if item["blob_set_digest"] in referenced_digests
    ]
    blob_sets.sort(key=lambda item: cast(str, item["candidate_group"]))
    scans = [_scan_blob_set(repository_root, item) for item in blob_sets]
    scans_by_digest = {cast(str, scan["blob_set_digest"]): scan for scan in scans}
    candidate_records: list[dict[str, Any]] = []
    for candidate in selected:
        scan = scans_by_digest.get(cast(str, candidate["blob_set_digest"]))
        if scan is None:
            raise QualifiedBuildQualificationSetupError(
                "candidate references an unscanned blob set"
            )
        signal_count = len(cast(list[dict[str, Any]], scan["signal_paths"]))
        candidate_records.append(
            {
                "blob_count": candidate["blob_count"],
                "blob_set_digest": candidate["blob_set_digest"],
                "candidate_group": candidate["candidate_group"],
                "candidate_id": candidate["candidate_id"],
                "candidate_manifest_digest": candidate["manifest_digest"],
                "plausibility_state": (
                    "lexical_signals_present_no_fit_inference"
                    if signal_count
                    else "no_lexical_signal_present_no_fit_inference"
                ),
                "scan_digest": scan["scan_digest"],
                "signal_path_count": signal_count,
            }
        )
    memberships = sum(cast(int, item["blob_count"]) for item in selected)
    scan_memberships = sum(cast(int, scan["blob_count"]) for scan in scans)
    if memberships != EXPECTED_MEMBERSHIPS or scan_memberships != EXPECTED_MEMBERSHIPS:
        raise QualifiedBuildQualificationSetupError(
            "qualified-build projected membership denominator drifted"
        )
    vector_refs = [
        {
            "digest": sha256_digest(vector_outputs[VECTOR_RELATIVES[test_id]]),
            "relative_path": VECTOR_RELATIVES[test_id],
            "size_bytes": len(vector_outputs[VECTOR_RELATIVES[test_id]]),
        }
        for test_id in TEST_IDS
    ]
    states = [
        {
            "adapter": state["adapter"],
            "candidate_test_vector": state["candidate_test_vector"],
            "oracle_status": state["oracle_status"],
            "test_id": state["test_id"],
        }
        for state in cast(
            list[dict[str, Any]],
            vector_manifest["immutable_predecessors"]["oracle_states"],
        )
    ]
    document = {
        "schema_version": "pmorg.qualified-build-interface-fit-evidence/v1",
        "evidence_version": "1.0.0",
        "capability_id": CAPABILITY_ID,
        "source_repository": PINNED_SOURCE_REPOSITORY,
        "source_commit": PINNED_SOURCE_COMMIT,
        "source_tree_id": PINNED_SOURCE_TREE,
        "candidate_inputs": _artifact_ref(repository_root, CANDIDATE_INPUTS_RELATIVE),
        "candidate_search_evidence": _artifact_ref(
            repository_root, SEARCH_EVIDENCE_RELATIVE
        ),
        "hit_classification": _artifact_ref(
            repository_root, HIT_CLASSIFICATION_RELATIVE
        ),
        "raw_results_digest": classification["raw_results_digest"],
        "qualification_interface": _artifact_ref(repository_root, INTERFACE_RELATIVE),
        "test_vector_extension": {
            "digest": sha256_digest(vector_outputs[VECTOR_MANIFEST_RELATIVE]),
            "relative_path": VECTOR_MANIFEST_RELATIVE,
            "size_bytes": len(vector_outputs[VECTOR_MANIFEST_RELATIVE]),
        },
        "test_vectors": vector_refs,
        "oracle_policy": _artifact_ref(repository_root, ORACLE_POLICY_RELATIVE),
        "derivation_artifacts": [
            _artifact_ref(repository_root, path) for path in DERIVATION_RELATIVES
        ],
        "selection_policy": "all_46_candidates_from_qualified_reproducible_build_hit_classification",
        "falsifiability_contract": vector_manifest["falsifiability_contract"],
        "candidate_count": len(candidate_records),
        "candidate_blob_membership_count": memberships,
        "blob_set_scan_count": len(scans),
        "blob_set_membership_count": scan_memberships,
        "coverage": {
            "expected": scan_memberships,
            "scanned": scan_memberships,
            "unreadable": 0,
            "unverified": 0,
        },
        "blob_set_scans": scans,
        "candidates": candidate_records,
        "active_oracle_states": states,
        "claim_boundary": "exhaustive_plausibility_screen_only_no_qualification_or_disposition",
        "oracle_activation": False,
    }
    schema = evidence_schema()
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=str)
    if errors:
        raise QualifiedBuildQualificationSetupError(
            f"qualified-build screening schema violation: {errors[0]}"
        )
    return {
        EVIDENCE_SCHEMA_RELATIVE: canonical_document_bytes(schema),
        EVIDENCE_RELATIVE: canonical_document_bytes(document),
    }


def build_qualified_build_qualification_setup(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    vector_outputs, vector_manifest = _build_vectors(repository_root)
    return {
        **vector_outputs,
        **_build_screening(repository_root, vector_outputs, vector_manifest),
    }


def write_qualified_build_qualification_setup(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_qualified_build_qualification_setup(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_qualified_build_qualification_setup(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_qualified_build_qualification_setup(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise QualifiedBuildQualificationSetupError(
                f"committed Q6a artifact is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise QualifiedBuildQualificationSetupError(
                f"committed Q6a artifact drifted: {relative_path}"
            )


__all__ = [
    "QualifiedBuildQualificationSetupError",
    "build_qualified_build_qualification_setup",
    "check_qualified_build_qualification_setup",
    "evidence_schema",
    "write_qualified_build_qualification_setup",
]
