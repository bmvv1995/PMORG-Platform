"""Build exhaustive, byte-closed Thin Fork interface-fit screening evidence."""

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
ORACLE_POLICY_RELATIVE = "pmorg/capabilities/qualification-oracle-policy-v1.json"
SEARCH_EVIDENCE_RELATIVE = (
    "pmorg/capabilities/candidate-search/thin-fork-boundary-search-evidence-v1.json"
)
OUTPUT_RELATIVE = "pmorg/capabilities/thin-fork-interface-fit-evidence-v1.json"
SCHEMA_RELATIVE = "pmorg/capabilities/thin-fork-interface-fit-evidence-v1.schema.json"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/thin_fork_interface_fit.py",
    "pmorg/scripts/build_thin_fork_interface_fit.py",
)

SCHEMA_VERSION = "pmorg.thin-fork-interface-fit-evidence/v1"
EVIDENCE_VERSION = "1.0.0"
CAPABILITY_ID = "thin-fork-boundary"
TEST_ID = "A-PATCH-001"

# Lexical discovery signals only; none of these are qualification predicates.
_SIGNALS = {
    "historical_evidence": ("evidence", "immutable", "predecessor", "successor"),
    "ownership_routing": ("allowlist", "owner", "owned", "ownership", "pmorg"),
    "seam_governance": ("seam", "seams"),
    "trust_boundary": ("boundary", "protected", "trust"),
    "upstream_governance": ("ledger", "patch", "upstream"),
}
_TOKEN_PATTERNS = {
    term: re.compile(
        rb"(?<![a-z0-9_])" + re.escape(term.encode("ascii")) + rb"(?![a-z0-9_])"
    )
    for terms in _SIGNALS.values()
    for term in terms
}


class ThinForkInterfaceFitError(ValueError):
    """Raised when Thin Fork screening evidence cannot be reproduced exactly."""


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
        raise ThinForkInterfaceFitError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ThinForkInterfaceFitError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise ThinForkInterfaceFitError(f"artifact is not an object: {relative_path}")
    return value


def _artifact_ref(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise ThinForkInterfaceFitError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return {
        "digest": sha256_digest(payload),
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }


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
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:thin-fork-interface-fit-evidence:v1",
        "title": "PMORG exhaustive Thin Fork interface-fit screening evidence",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "evidence_version",
            "capability_id",
            "test_id",
            "source_repository",
            "source_commit",
            "source_tree_id",
            "candidate_inputs",
            "candidate_search_evidence",
            "qualification_interface",
            "test_vector_extension",
            "test_vector",
            "oracle_policy",
            "derivation_artifacts",
            "selection_policy",
            "candidate_count",
            "candidate_blob_membership_count",
            "blob_set_scan_count",
            "blob_set_membership_count",
            "coverage",
            "blob_set_scans",
            "candidates",
            "active_oracle_state",
            "claim_boundary",
            "oracle_activation",
        ],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "evidence_version": {"const": EVIDENCE_VERSION},
            "capability_id": {"const": CAPABILITY_ID},
            "test_id": {"const": TEST_ID},
            "source_repository": {"const": PINNED_SOURCE_REPOSITORY},
            "source_commit": {"const": PINNED_SOURCE_COMMIT},
            "source_tree_id": {"const": PINNED_SOURCE_TREE},
            "candidate_inputs": artifact,
            "candidate_search_evidence": artifact,
            "qualification_interface": artifact,
            "test_vector_extension": artifact,
            "test_vector": artifact,
            "oracle_policy": artifact,
            "derivation_artifacts": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": artifact,
            },
            "selection_policy": {
                "const": "all_discovered_thin_fork_boundary_candidate_manifests"
            },
            "candidate_count": {"const": 55},
            "candidate_blob_membership_count": {"const": 5155},
            "blob_set_scan_count": {"const": 55},
            "blob_set_membership_count": {"const": 5155},
            "coverage": _coverage_schema(5155),
            "blob_set_scans": {
                "type": "array",
                "minItems": 55,
                "maxItems": 55,
                "items": scan,
            },
            "candidates": {
                "type": "array",
                "minItems": 55,
                "maxItems": 55,
                "items": candidate,
            },
            "active_oracle_state": {
                "type": "object",
                "additionalProperties": False,
                "required": ["adapter", "candidate_test_vector", "oracle_status"],
                "properties": {
                    "adapter": {"type": "null"},
                    "candidate_test_vector": {"type": "null"},
                    "oracle_status": {"const": "unexecutable"},
                },
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
            raise ThinForkInterfaceFitError(
                f"candidate blob digest drifted: {blob['path']}"
            )
        if len(payload) != blob["size_bytes"]:
            raise ThinForkInterfaceFitError(
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


def _active_oracle_state(repository_root: Path) -> dict[str, Any]:
    extension = _read_object(repository_root, VECTOR_EXTENSION_RELATIVE)
    if extension.get("activation_status") != "definition_only_unactivated":
        raise ThinForkInterfaceFitError("Thin Fork vector extension became active")
    predecessors = cast(dict[str, Any], extension.get("immutable_predecessors", {}))
    state = cast(dict[str, Any], predecessors.get("oracle_state", {}))
    expected = {
        "adapter": None,
        "candidate_test_vector": None,
        "oracle_status": "unexecutable",
    }
    actual = {key: state.get(key) for key in expected}
    if actual != expected:
        raise ThinForkInterfaceFitError("Thin Fork predecessor oracle state drifted")
    return actual


def build_thin_fork_interface_fit_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    bundle = _read_object(repository_root, CANDIDATE_INPUTS_RELATIVE)
    validate_candidate_input_bundle(bundle)
    selected = [
        candidate
        for candidate in cast(list[dict[str, Any]], bundle["candidates"])
        if candidate["capability_id"] == CAPABILITY_ID
    ]
    selected.sort(key=lambda item: cast(str, item["candidate_group"]))
    referenced_digests = {
        cast(str, candidate["blob_set_digest"]) for candidate in selected
    }
    selected_blob_sets = [
        blob_set
        for blob_set in cast(list[dict[str, Any]], bundle["blob_sets"])
        if blob_set["blob_set_digest"] in referenced_digests
    ]
    selected_blob_sets.sort(key=lambda item: cast(str, item["candidate_group"]))
    scans = [_scan_blob_set(repository_root, item) for item in selected_blob_sets]
    scans_by_digest = {cast(str, scan["blob_set_digest"]): scan for scan in scans}
    candidate_records: list[dict[str, Any]] = []
    for candidate in selected:
        scan = scans_by_digest.get(cast(str, candidate["blob_set_digest"]))
        if scan is None:
            raise ThinForkInterfaceFitError(
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
    candidate_memberships = sum(
        cast(int, candidate["blob_count"]) for candidate in selected
    )
    blob_set_memberships = sum(cast(int, scan["blob_count"]) for scan in scans)
    document = {
        "schema_version": SCHEMA_VERSION,
        "evidence_version": EVIDENCE_VERSION,
        "capability_id": CAPABILITY_ID,
        "test_id": TEST_ID,
        "source_repository": PINNED_SOURCE_REPOSITORY,
        "source_commit": PINNED_SOURCE_COMMIT,
        "source_tree_id": PINNED_SOURCE_TREE,
        "candidate_inputs": _artifact_ref(repository_root, CANDIDATE_INPUTS_RELATIVE),
        "candidate_search_evidence": _artifact_ref(
            repository_root, SEARCH_EVIDENCE_RELATIVE
        ),
        "qualification_interface": _artifact_ref(repository_root, INTERFACE_RELATIVE),
        "test_vector_extension": _artifact_ref(
            repository_root, VECTOR_EXTENSION_RELATIVE
        ),
        "test_vector": _artifact_ref(repository_root, VECTOR_RELATIVE),
        "oracle_policy": _artifact_ref(repository_root, ORACLE_POLICY_RELATIVE),
        "derivation_artifacts": [
            _artifact_ref(repository_root, path) for path in DERIVATION_RELATIVES
        ],
        "selection_policy": "all_discovered_thin_fork_boundary_candidate_manifests",
        "candidate_count": len(candidate_records),
        "candidate_blob_membership_count": candidate_memberships,
        "blob_set_scan_count": len(scans),
        "blob_set_membership_count": blob_set_memberships,
        "coverage": {
            "expected": blob_set_memberships,
            "scanned": blob_set_memberships,
            "unreadable": 0,
            "unverified": 0,
        },
        "blob_set_scans": scans,
        "candidates": candidate_records,
        "active_oracle_state": _active_oracle_state(repository_root),
        "claim_boundary": (
            "exhaustive_plausibility_screen_only_no_qualification_or_disposition"
        ),
        "oracle_activation": False,
    }
    errors = sorted(
        Draft202012Validator(evidence_schema()).iter_errors(document), key=str
    )
    if errors:
        raise ThinForkInterfaceFitError(
            f"Thin Fork interface-fit schema violation: {errors[0]}"
        )
    return {
        SCHEMA_RELATIVE: canonical_document_bytes(evidence_schema()),
        OUTPUT_RELATIVE: canonical_document_bytes(document),
    }


def write_thin_fork_interface_fit_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_thin_fork_interface_fit_evidence(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_thin_fork_interface_fit_evidence(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_thin_fork_interface_fit_evidence(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise ThinForkInterfaceFitError(
                f"committed Thin Fork evidence is missing: {relative_path}"
            ) from error
        if actual != payload:
            raise ThinForkInterfaceFitError(
                f"committed Thin Fork evidence drifted: {relative_path}"
            )


__all__ = [
    "ThinForkInterfaceFitError",
    "build_thin_fork_interface_fit_evidence",
    "check_thin_fork_interface_fit_evidence",
    "evidence_schema",
    "write_thin_fork_interface_fit_evidence",
]
