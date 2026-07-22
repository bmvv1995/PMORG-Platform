"""Build, validate, sign, and verify the bounded Q7e disposition record."""

from __future__ import annotations

import base64
import binascii
import json
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from typing import cast

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.application import capability_dispositions as shared
from pmorg.application.capability_disposition_post_disposition_qualification import (
    check_capability_disposition_post_disposition_qualification,
)
from pmorg.application.capability_disposition_qualification_candidate_qualification_reports import (
    check_capability_disposition_qualification_candidate_qualification_reports,
)
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import key_id
from pmorg.application.rbdp import pre_authentication_encoding
from pmorg.application.rbdp import private_key_from_env
from pmorg.application.rbdp import public_key_from_env
from pmorg.contracts.types import ArtifactDescriptor
from pmorg.contracts.types import CapabilityDispositionRecord
from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import DsseSignature
from pmorg.contracts.types import EvidenceBundleIndex

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BASE_PLATFORM_COMMIT = "76e21b64f5cc98d22e5cd2c197fb7344c8dc54dc"
CAPABILITY_ID = "capability-disposition-qualification"
REQUIREMENT_IDS = [
    "A-PATCH-002",
    "A-PATCH-003",
    "A-PATCH-004",
    "A-PATCH-005",
    "A-PATCH-006",
    "PLT-006",
]
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
SCREENING_RELATIVE = (
    "pmorg/capabilities/"
    "capability-disposition-qualification-interface-fit-evidence-v1.json"
)
SEARCH_RELATIVE = (
    "pmorg/capabilities/candidate-search/"
    "capability-disposition-qualification-search-evidence-v1.json"
)
CQR_INDEX_RELATIVE = (
    "pmorg/capabilities/"
    "capability-disposition-qualification-candidate-qualification-reports-v1.json"
)
PDQ_INDEX_RELATIVE = (
    "pmorg/capabilities/capability-disposition-post-disposition-qualification-v1.json"
)
PDQ_REPORT_RELATIVE = (
    "pmorg/capabilities/"
    "capability-disposition-post-disposition-qualification-report-v1.json"
)
SUBJECT_RELATIVE = "pmorg/capabilities/dispositions/subject-ce-source-artifact-v1.json"
PATCH_LEDGER_RELATIVE = "pmorg/patch-ledger.json"
RECORD_RELATIVE = (
    "pmorg/capabilities/dispositions/records/capability-disposition-qualification.json"
)
EVIDENCE_RELATIVE = (
    "pmorg/capabilities/dispositions/evidence/capability-disposition-qualification.json"
)
SNAPSHOT_ROOT_RELATIVE = (
    "pmorg/capabilities/dispositions/implementation-snapshots/"
    "capability-disposition-qualification"
)
IMPLEMENTATION_PATHS = (
    "backend/pmorg/application/qualification.py",
    "backend/pmorg/application/qualification_oracles.py",
)
CLAIM_BOUNDARY = (
    "single_capability_disposition_qualification_disposition_no_catalog_completion"
)
PAYLOAD_TYPE = shared.PAYLOAD_TYPE
PRIVATE_KEY_ENV = shared.PRIVATE_KEY_ENV
PUBLIC_KEY_ENV = shared.PUBLIC_KEY_ENV
RECORD_SCHEMA_VERSION = shared.RECORD_SCHEMA_VERSION
EXPECTED_ARTIFACT_SET_HASH = (
    "sha256:6e7f49edaff89b6c06f2006b3c0f1b69b857bb037434c21efeb9a765222ec75e"
)
EXPECTED_IMPLEMENTATION_SET_HASH = (
    "sha256:33b28a16a9117f65bf3562fd3aff838c4d698b65e7fea12d02c5aa588efcba6d"
)
EXPECTED_INPUT_DIGESTS = {
    CATALOG_RELATIVE: (
        "sha256:1bc2c22639e5e1e22920673bb5f4423b59bda6ab05732cb3c1300499db7b6693"
    ),
    SCREENING_RELATIVE: (
        "sha256:5b31e01e0f50954966ef07072c8188994fe90009cc082628f74a2656b7face4c"
    ),
    SEARCH_RELATIVE: (
        "sha256:2ca4064226466489351763d75e94caa9fcc800dc90507c97cd52ce4747a171ec"
    ),
    CQR_INDEX_RELATIVE: (
        "sha256:f5d20309e65aaea447e25335ade97c81bf4255de287dd2fed554f2688049882a"
    ),
    PDQ_INDEX_RELATIVE: (
        "sha256:fc9931600c35015cbe408d388f275c6cfd5dd5d45083383a20d4c58777ccf7bc"
    ),
    PDQ_REPORT_RELATIVE: (
        "sha256:113479d6db7cad725e5fb06911f670132d04bb5043869d581263a1e99f87a1a6"
    ),
    SUBJECT_RELATIVE: (
        "sha256:a13482ea50a3d07d966c8aadf99af69bd9225549d792e1f4eaa39da24d804ab8"
    ),
}
EXPECTED_LEDGER_ENTRY = {
    "id": "PL-047",
    "classification": "PMORG-owned",
    "paths": [
        "backend/pmorg/application/capability_disposition_qualification_disposition.py",
        "backend/pmorg/tests/test_capability_disposition_qualification_disposition.py",
        "pmorg/scripts/build_capability_disposition_qualification_disposition.py",
    ],
    "requirements": REQUIREMENT_IDS,
    "reason": (
        "Emit one bounded, deterministic and signable CapabilityDispositionRecord "
        "for capability-disposition-qualification, binding the exact 48 Q7c "
        "candidate qualification reports and exact 12/12 PASS Q7d report; preserve "
        "all predecessors byte-identically, keep the DSSE key and generated "
        "signature ephemeral, and make no aggregate, catalog-completion, admission, "
        "release, trust, workflow or G3-A claim."
    ),
    "verification": [
        (
            "PMORG_PROTECTED_BASE_SHA="
            f"{BASE_PLATFORM_COMMIT} python3 -B pmorg/scripts/verify_fork.py"
        ),
        (
            "PYTHONPATH=backend python3 -B -m unittest "
            "backend.pmorg.tests."
            "test_capability_disposition_qualification_disposition -v"
        ),
        (
            "PYTHONPATH=backend python3 -B "
            "pmorg/scripts/build_capability_disposition_qualification_disposition.py "
            "--check"
        ),
        (
            "PYTHONPATH=backend python3 -B -m unittest discover "
            "-s backend/pmorg/tests -t backend -p 'test_*.py' -v"
        ),
    ],
}


class CapabilityDispositionQualificationDispositionError(
    shared.CapabilityDispositionError
):
    """Raised when the bounded Q7e record, evidence, or signature drifts."""


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    return shared._safe_path(repository_root, relative_path)


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    return shared._read_object(repository_root, relative_path)


def _artifact_ref(
    repository_root: Path,
    relative_path: str,
    *,
    logical_name: str,
    media_type: str = "application/json",
) -> dict[str, Any]:
    return shared._artifact_ref(
        repository_root,
        relative_path,
        logical_name=logical_name,
        media_type=media_type,
    )


def _payload_ref(
    relative_path: str,
    payload: bytes,
    *,
    logical_name: str,
    media_type: str = "application/json",
) -> dict[str, Any]:
    return shared._payload_ref(
        relative_path,
        payload,
        logical_name=logical_name,
        media_type=media_type,
    )


def _base_blob(repository_root: Path, relative_path: str) -> tuple[str, bytes]:
    try:
        object_id = subprocess.run(
            [
                "git",
                "rev-parse",
                f"{BASE_PLATFORM_COMMIT}:{relative_path}",
            ],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        payload = subprocess.run(
            ["git", "cat-file", "blob", object_id],
            cwd=repository_root,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise CapabilityDispositionQualificationDispositionError(
            f"Q7e base path is absent: {relative_path}"
        ) from error
    try:
        live_payload = _safe_path(repository_root, relative_path).read_bytes()
    except OSError as error:
        raise CapabilityDispositionQualificationDispositionError(
            f"Q7e bound path is missing: {relative_path}"
        ) from error
    if live_payload != payload:
        raise CapabilityDispositionQualificationDispositionError(
            f"Q7e exact-base path drifted: {relative_path}"
        )
    return object_id, payload


def _assert_input_identities(repository_root: Path) -> None:
    for relative_path, expected_digest in EXPECTED_INPUT_DIGESTS.items():
        try:
            payload = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise CapabilityDispositionQualificationDispositionError(
                f"Q7e input is missing: {relative_path}"
            ) from error
        if sha256_digest(payload) != expected_digest:
            raise CapabilityDispositionQualificationDispositionError(
                f"Q7e input identity drifted: {relative_path}"
            )


def _assert_ledger_append_only(repository_root: Path) -> None:
    try:
        base = json.loads(
            subprocess.run(
                [
                    "git",
                    "show",
                    f"{BASE_PLATFORM_COMMIT}:{PATCH_LEDGER_RELATIVE}",
                ],
                cwd=repository_root,
                check=True,
                capture_output=True,
            ).stdout
        )
        live = json.loads(
            _safe_path(repository_root, PATCH_LEDGER_RELATIVE).read_bytes()
        )
    except (subprocess.CalledProcessError, OSError, json.JSONDecodeError) as error:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e patch ledger cannot be read"
        ) from error
    if not isinstance(base, dict) or not isinstance(live, dict):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e patch ledger is not an object"
        )
    if set(live) != set(base):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e patch ledger top-level structure drifted"
        )
    for key in shared.THIN_FORK_LEDGER_TOP_LEVEL_PINS:
        if live.get(key) != base.get(key):
            raise CapabilityDispositionQualificationDispositionError(
                f"Q7e patch ledger top-level pin drifted: {key}"
            )
    base_entries = base.get("entries")
    live_entries = live.get("entries")
    base_upstream = base.get("upstream_patch_records")
    live_upstream = live.get("upstream_patch_records")
    shared._assert_append_only_sequence(
        base=base_entries,
        live=live_entries,
        sequence_name="entries",
    )
    shared._assert_append_only_sequence(
        base=base_upstream,
        live=live_upstream,
        sequence_name="upstream_patch_records",
    )
    if not isinstance(base_entries, list) or not isinstance(live_entries, list):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e patch ledger entries are not lists"
        )
    if (
        len(live_entries) <= len(base_entries)
        or live_entries[len(base_entries)] != EXPECTED_LEDGER_ENTRY
    ):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e PL-047 ownership entry is absent or drifted"
        )


def _assert_predecessors(repository_root: Path) -> None:
    check_capability_disposition_qualification_candidate_qualification_reports(
        repository_root
    )
    check_capability_disposition_post_disposition_qualification(repository_root)
    _assert_input_identities(repository_root)
    _assert_ledger_append_only(repository_root)


def _subject(
    repository_root: Path,
) -> tuple[str, dict[str, Any]]:
    _, payload = _base_blob(repository_root, SUBJECT_RELATIVE)
    subject = cast(dict[str, Any], json.loads(payload))
    descriptor = ArtifactDescriptor.model_validate(subject["artifact_descriptor"])
    artifact_set_hash = shared.artifact_set_digest_from_descriptors([descriptor])
    if artifact_set_hash != EXPECTED_ARTIFACT_SET_HASH:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e reused subject artifact set drifted"
        )
    return (
        artifact_set_hash,
        _payload_ref(
            SUBJECT_RELATIVE,
            payload,
            logical_name="capability-disposition-subject-ce-source-artifact",
        ),
    )


def _implementation_snapshot(
    repository_root: Path, relative_path: str
) -> tuple[str, bytes, dict[str, Any], dict[str, Any]]:
    object_id, payload = _base_blob(repository_root, relative_path)
    content_hash = sha256_digest(payload)
    snapshot = {
        "schema_version": "pmorg.implementation-path-snapshot/v1",
        "repository": shared.REPOSITORY_URL,
        "commit": BASE_PLATFORM_COMMIT,
        "path": relative_path,
        "git_blob_id": object_id,
        "content_hash": content_hash,
        "size_bytes": len(payload),
        "ownership_class": "pmorg_owned",
        "license_class": "pmorg",
    }
    safe_name = relative_path.replace("/", "__") + ".json"
    output_relative = f"{SNAPSHOT_ROOT_RELATIVE}/{safe_name}"
    output = canonical_document_bytes(snapshot)
    source_ref = {
        "repository": shared.REPOSITORY_URL,
        "commit": BASE_PLATFORM_COMMIT,
        "paths": [relative_path],
        "tree_hash": sha256_digest(
            canonical_json_bytes(
                {
                    "commit": BASE_PLATFORM_COMMIT,
                    "paths": [
                        {
                            "path": relative_path,
                            "git_blob_id": object_id,
                            "content_hash": content_hash,
                        }
                    ],
                }
            )
        ),
        "source_snapshot": _payload_ref(
            output_relative,
            output,
            logical_name=f"{CAPABILITY_ID}-{safe_name}-source-snapshot",
        ),
    }
    implementation_ref = {
        "path": relative_path,
        "content_hash": content_hash,
        "source_ref": source_ref,
        "ownership_class": "pmorg_owned",
        "license_class": "pmorg",
        "provenance_inventory_item": _payload_ref(
            output_relative,
            output,
            logical_name=f"{CAPABILITY_ID}-{safe_name}-provenance-item",
        ),
    }
    binding = {
        "digest": content_hash,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }
    return output_relative, output, implementation_ref, binding


def _candidates(
    repository_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    screening = _read_object(repository_root, SCREENING_RELATIVE)
    search_ref = cast(dict[str, Any], screening["candidate_search_evidence"])
    if search_ref.get("relative_path") != SEARCH_RELATIVE:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e candidate search reference drifted"
        )
    search_payload = _safe_path(repository_root, SEARCH_RELATIVE).read_bytes()
    if search_ref.get("digest") != sha256_digest(search_payload) or search_ref.get(
        "size_bytes"
    ) != len(search_payload):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e candidate search content binding drifted"
        )
    search = cast(dict[str, Any], json.loads(search_payload))
    index = _read_object(repository_root, CQR_INDEX_RELATIVE)
    entries = cast(list[dict[str, Any]], index["entries"])
    by_id = {cast(str, entry["candidate_id"]): entry for entry in entries}
    candidate_ids = cast(list[str], search["candidate_ids"])
    if (
        len(candidate_ids) != 48
        or len(set(candidate_ids)) != 48
        or len(entries) != 48
        or len(by_id) != 48
        or set(candidate_ids) != set(by_id)
        or index.get("report_count") != 48
        or index.get("projected_blob_membership_count") != 5015
        or index.get("executed_test_count") != 240
        or index.get("failed_test_count") != 240
        or index.get("passed_test_count") != 0
        or index.get("missing_test_count") != 0
        or index.get("duplicate_test_count") != 0
    ):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e 48/5015/240 candidate denominator drifted"
        )
    candidates: list[dict[str, Any]] = []
    report_refs: list[dict[str, Any]] = []
    for candidate_id in candidate_ids:
        entry = by_id[candidate_id]
        report_ref = cast(dict[str, Any], entry["report"])
        report_path = cast(str, report_ref["relative_path"])
        report_payload = _safe_path(repository_root, report_path).read_bytes()
        if report_ref.get("digest") != sha256_digest(report_payload) or report_ref.get(
            "size_bytes"
        ) != len(report_payload):
            raise CapabilityDispositionQualificationDispositionError(
                f"Q7e CQR binding drifted: {candidate_id}"
            )
        report = cast(dict[str, Any], json.loads(report_payload))
        if (
            entry.get("verdict") != "fail"
            or len(cast(list[Any], entry.get("results", []))) != 5
            or report.get("candidate_id") != candidate_id
            or report.get("capability_id") != CAPABILITY_ID
            or report.get("expected_test_count") != 5
            or report.get("executed_test_count") != 5
            or report.get("failed_test_count") != 5
            or report.get("missing_test_count") != 0
            or report.get("duplicate_test_count") != 0
            or report.get("verdict") != "fail"
            or len(cast(list[Any], report.get("test_evidence", []))) != 5
        ):
            raise CapabilityDispositionQualificationDispositionError(
                f"Q7e candidate is not the observed 5/5 FAIL: {candidate_id}"
            )
        source_surface = cast(str, entry["source_surface"])
        if source_surface not in {"ce", "ee"}:
            raise CapabilityDispositionQualificationDispositionError(
                f"Q7e candidate surface drifted: {candidate_id}"
            )
        candidates.append(
            {
                "candidate_id": candidate_id,
                "source_ref": report["source_ref"],
                "onyx_surface": source_surface,
                "license_class": (
                    "mit-expat" if source_surface == "ce" else "onyx-enterprise"
                ),
                "qualification": "fail",
                "qualification_report": report,
            }
        )
        report_refs.append(report_ref)
    return search, candidates, report_refs


def _post_disposition_report(repository_root: Path) -> dict[str, Any]:
    index = _read_object(repository_root, PDQ_INDEX_RELATIVE)
    report = _read_object(repository_root, PDQ_REPORT_RELATIVE)
    report_ref = cast(dict[str, Any], index["report"])
    if (
        report_ref.get("relative_path") != PDQ_REPORT_RELATIVE
        or report_ref.get("digest") != EXPECTED_INPUT_DIGESTS[PDQ_REPORT_RELATIVE]
        or index.get("pmorg_platform_commit")
        != "d3cb3ceee627024404af0588103168367c0f5faa"
        or index.get("expected_test_count") != 12
        or index.get("executed_test_count") != 12
        or index.get("failed_test_count") != 0
        or index.get("missing_test_count") != 0
        or index.get("duplicate_test_count") != 0
        or report.get("capability_id") != CAPABILITY_ID
        or report.get("implementation_path_set_hash")
        != EXPECTED_IMPLEMENTATION_SET_HASH
        or report.get("expected_test_count") != 12
        or report.get("executed_test_count") != 12
        or report.get("failed_test_count") != 0
        or report.get("missing_test_count") != 0
        or report.get("duplicate_test_count") != 0
        or report.get("verdict") != "pass"
    ):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e exact Q7d 12/12 PASS binding drifted"
        )
    return report


def build_capability_disposition_qualification_disposition(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    """Build one bounded Q7e disposition without a catalog aggregate."""

    repository_root = repository_root.resolve()
    _assert_predecessors(repository_root)
    artifact_set_hash, subject_ref = _subject(repository_root)
    catalog = _read_object(repository_root, CATALOG_RELATIVE)
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    try:
        catalog_item = next(
            item
            for item in cast(list[dict[str, Any]], catalog["items"])
            if item["capability_id"] == CAPABILITY_ID
        )
    except (KeyError, StopIteration) as error:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e capability is absent from the catalog"
        ) from error
    if (
        catalog_hash != EXPECTED_INPUT_DIGESTS[CATALOG_RELATIVE]
        or catalog.get("pmorg_spec_commit") != shared.SPEC_COMMIT
        or catalog_item.get("pmorg_requirement_ids") != REQUIREMENT_IDS
    ):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e catalog binding drifted"
        )
    search, candidates, report_refs = _candidates(repository_root)
    post_report = _post_disposition_report(repository_root)

    documents: dict[str, bytes] = {}
    implementation_refs: list[dict[str, Any]] = []
    implementation_bindings: list[dict[str, Any]] = []
    snapshot_refs: list[dict[str, Any]] = []
    for relative_path in IMPLEMENTATION_PATHS:
        output_relative, output, implementation_ref, binding = _implementation_snapshot(
            repository_root, relative_path
        )
        documents[output_relative] = output
        implementation_refs.append(implementation_ref)
        implementation_bindings.append(binding)
        snapshot_refs.append(
            _payload_ref(
                output_relative,
                output,
                logical_name=f"{CAPABILITY_ID}-{Path(output_relative).name}",
            )
        )
    implementation_set_hash = sha256_digest(
        canonical_document_bytes(implementation_bindings)
    )
    if (
        implementation_set_hash != EXPECTED_IMPLEMENTATION_SET_HASH
        or post_report["implementation_path_set_hash"] != implementation_set_hash
    ):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e implementation pair does not match Q7d"
        )

    evidence_entries = [
        subject_ref,
        _artifact_ref(
            repository_root, CATALOG_RELATIVE, logical_name="capability-catalog"
        ),
        _artifact_ref(
            repository_root,
            SCREENING_RELATIVE,
            logical_name="capability-disposition-qualification-interface-fit-evidence",
        ),
        _artifact_ref(
            repository_root,
            SEARCH_RELATIVE,
            logical_name="capability-disposition-qualification-candidate-search-evidence",
        ),
        _artifact_ref(
            repository_root,
            CQR_INDEX_RELATIVE,
            logical_name="capability-disposition-qualification-candidate-qualification-index",
        ),
        _artifact_ref(
            repository_root,
            PDQ_INDEX_RELATIVE,
            logical_name="capability-disposition-qualification-post-disposition-index",
        ),
        _artifact_ref(
            repository_root,
            PDQ_REPORT_RELATIVE,
            logical_name="capability-disposition-qualification-post-disposition-report",
        ),
        *snapshot_refs,
        *report_refs,
    ]
    if len(evidence_entries) != 57:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e evidence bundle is not exactly 57 references"
        )
    evidence_index = EvidenceBundleIndex.model_validate(
        {
            "schema_version": "pmorg.evidence-bundle-index/v1",
            "bundle_kind": CLAIM_BOUNDARY,
            "subject_binding_hash": artifact_set_hash,
            "entries": evidence_entries,
            "entry_count": len(evidence_entries),
        }
    )
    evidence_payload = canonical_document_bytes(evidence_index.model_dump(mode="json"))
    documents[EVIDENCE_RELATIVE] = evidence_payload
    evidence_ref = _payload_ref(
        EVIDENCE_RELATIVE,
        evidence_payload,
        logical_name=(
            "capability-disposition-qualification-capability-disposition-evidence-index"
        ),
    )
    record = CapabilityDispositionRecord.model_validate(
        {
            "schema_version": RECORD_SCHEMA_VERSION,
            "catalog_version": cast(str, catalog["catalog_version"]),
            "catalog_hash": catalog_hash,
            "pmorg_spec_commit": shared.SPEC_COMMIT,
            "pmorg_platform_commit": BASE_PLATFORM_COMMIT,
            "onyx_commit": shared.ONYX_COMMIT,
            "artifact_set_hash": artifact_set_hash,
            "onyx_surface": "ce",
            "usage_mode": "development_test",
            "capability_id": CAPABILITY_ID,
            "pmorg_requirement_ids": REQUIREMENT_IDS,
            "candidate_search_outcome": "candidates_found",
            "candidate_search_evidence": search,
            "candidates": candidates,
            "disposition": "pmorg_independent",
            "selected_candidate_ids": [],
            "implementation_path_set_hash": implementation_set_hash,
            "implementation_refs": implementation_refs,
            "patch_ledger_set_hash": shared._empty_patch_set_hash(),
            "patch_ledger_refs": [],
            "post_disposition_qualification": post_report,
            "rationale": (
                "All 48 discovered capability-disposition-qualification candidates "
                "were executed against the exact candidate-aware A-PATCH-002..006 "
                "oracles and failed (240/240 FAIL); the PMORG-owned qualification "
                "implementation pair passed its exact bounded 12-test "
                "post-disposition qualification suite, so no passing reusable "
                "candidate, selected candidate, patch, or deviation exists."
            ),
            "deviation_decision_envelope": None,
            "record_evidence_bundle_index": evidence_ref,
        }
    )
    documents[RECORD_RELATIVE] = canonical_document_bytes(
        record.model_dump(mode="json")
    )
    return documents


def write_capability_disposition_qualification_disposition(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    outputs = build_capability_disposition_qualification_disposition(repository_root)
    expected_paths = set(outputs)
    snapshot_root = _safe_path(repository_root, SNAPSHOT_ROOT_RELATIVE)
    if snapshot_root.exists():
        for path in snapshot_root.rglob("*.json"):
            relative_path = path.relative_to(repository_root).as_posix()
            if relative_path not in expected_paths:
                path.unlink()
    for relative_path, payload in outputs.items():
        destination = _safe_path(repository_root, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


def validate_capability_disposition_qualification_record(
    value: CapabilityDispositionRecord | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> CapabilityDispositionRecord:
    repository_root = repository_root.resolve()
    try:
        record = CapabilityDispositionRecord.model_validate(value)
        Draft202012Validator(
            shared._contract_schema(repository_root, RECORD_SCHEMA_VERSION)
        ).validate(record.model_dump(mode="json"))
    except Exception as error:
        if isinstance(error, CapabilityDispositionQualificationDispositionError):
            raise
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e capability disposition schema failed"
        ) from error
    if record.capability_id != CAPABILITY_ID:
        raise CapabilityDispositionQualificationDispositionError(
            "record is not the bounded capability-disposition-qualification capability"
        )
    expected = CapabilityDispositionRecord.model_validate_json(
        build_capability_disposition_qualification_disposition(repository_root)[
            RECORD_RELATIVE
        ]
    )
    if record != expected:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e capability disposition derivation drifted"
        )
    shared._walk_embedded_refs(repository_root, record.model_dump(mode="json"))
    return record


def validate_capability_disposition_qualification_disposition(
    repository_root: Path = REPOSITORY_ROOT,
) -> CapabilityDispositionRecord:
    repository_root = repository_root.resolve()
    expected = build_capability_disposition_qualification_disposition(repository_root)
    for relative_path, payload in expected.items():
        try:
            observed = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise CapabilityDispositionQualificationDispositionError(
                f"Q7e disposition artifact is missing: {relative_path}"
            ) from error
        if observed != payload:
            raise CapabilityDispositionQualificationDispositionError(
                f"Q7e disposition artifact drifted: {relative_path}"
            )
    observed_snapshot_entries = {
        path.relative_to(repository_root).as_posix()
        for path in _safe_path(repository_root, SNAPSHOT_ROOT_RELATIVE).rglob("*")
    }
    expected_snapshots = {
        path for path in expected if path.startswith(f"{SNAPSHOT_ROOT_RELATIVE}/")
    }
    if observed_snapshot_entries != expected_snapshots:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e implementation snapshot directory is not byte-closed"
        )
    record = CapabilityDispositionRecord.model_validate_json(
        _safe_path(repository_root, RECORD_RELATIVE).read_bytes()
    )
    return validate_capability_disposition_qualification_record(
        record, repository_root=repository_root
    )


def sign_capability_disposition_qualification_disposition(
    value: CapabilityDispositionRecord | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    record = validate_capability_disposition_qualification_record(
        value, repository_root=repository_root
    )
    private_key = private_key_from_env(name=PRIVATE_KEY_ENV, environ=environ)
    payload = canonical_json_bytes(record.model_dump(mode="json"))
    signature = private_key.sign(pre_authentication_encoding(PAYLOAD_TYPE, payload))
    return DsseEnvelope(
        payloadType=PAYLOAD_TYPE,
        payload=base64.b64encode(payload).decode("ascii"),
        signatures=[
            DsseSignature(
                keyid=key_id(private_key.public_key()),
                sig=base64.b64encode(signature).decode("ascii"),
            )
        ],
    )


def _decode_base64(value: str, *, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise CapabilityDispositionQualificationDispositionError(
            f"{label} is not canonical base64"
        ) from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise CapabilityDispositionQualificationDispositionError(
            f"{label} is not canonical base64"
        )
    return decoded


def verify_capability_disposition_qualification_disposition(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    environ: Mapping[str, str] | None = None,
) -> CapabilityDispositionRecord:
    try:
        validated = DsseEnvelope.model_validate(envelope)
    except ValidationError as error:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e DSSE envelope schema failed"
        ) from error
    if validated.payloadType != PAYLOAD_TYPE:
        raise CapabilityDispositionQualificationDispositionError(
            "unexpected Q7e capability disposition payload type"
        )
    if len(validated.signatures) != 1:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e capability disposition requires exactly one signature"
        )
    payload = _decode_base64(validated.payload, label="DSSE payload")
    signature = _decode_base64(validated.signatures[0].sig, label="DSSE signature")
    public_key = public_key_from_env(name=PUBLIC_KEY_ENV, environ=environ)
    if validated.signatures[0].keyid != key_id(public_key):
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e DSSE key identity mismatch"
        )
    try:
        public_key.verify(signature, pre_authentication_encoding(PAYLOAD_TYPE, payload))
    except InvalidSignature as error:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e capability disposition signature is invalid"
        ) from error
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e capability disposition payload is not JSON"
        ) from error
    if canonical_json_bytes(decoded) != payload:
        raise CapabilityDispositionQualificationDispositionError(
            "Q7e capability disposition payload is not canonical"
        )
    return validate_capability_disposition_qualification_record(
        cast(dict[str, Any], decoded), repository_root=repository_root
    )


__all__ = [
    "BASE_PLATFORM_COMMIT",
    "CAPABILITY_ID",
    "CLAIM_BOUNDARY",
    "CapabilityDispositionQualificationDispositionError",
    "EVIDENCE_RELATIVE",
    "EXPECTED_IMPLEMENTATION_SET_HASH",
    "IMPLEMENTATION_PATHS",
    "PAYLOAD_TYPE",
    "PRIVATE_KEY_ENV",
    "PUBLIC_KEY_ENV",
    "RECORD_RELATIVE",
    "REQUIREMENT_IDS",
    "SNAPSHOT_ROOT_RELATIVE",
    "build_capability_disposition_qualification_disposition",
    "sign_capability_disposition_qualification_disposition",
    "validate_capability_disposition_qualification_disposition",
    "validate_capability_disposition_qualification_record",
    "verify_capability_disposition_qualification_disposition",
    "write_capability_disposition_qualification_disposition",
]
