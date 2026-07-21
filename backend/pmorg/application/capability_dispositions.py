"""Build, sign, and verify bounded admission capability dispositions."""

from __future__ import annotations

import base64
import binascii
import json
import os
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from typing import cast

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import key_id
from pmorg.application.rbdp import pre_authentication_encoding
from pmorg.application.rbdp import private_key_from_env
from pmorg.application.rbdp import public_key_from_env
from pmorg.contracts.types import ArtifactDescriptor
from pmorg.contracts.types import CapabilityDispositionRecord
from pmorg.contracts.types import CapabilityDispositionReport
from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import DsseSignature
from pmorg.contracts.types import EvidenceBundleIndex

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BASE_PLATFORM_COMMIT = "7e262835c4d69dd51a8b6fbb401d7d1a8b7a2d0b"
SPEC_COMMIT = "05bc4df345d2d65e05b510135a4d99c9edbf886e"
ONYX_COMMIT = "1da679cefc96165c6b9b64c3bc769584b88f88c2"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
QUALIFICATION_INDEX_RELATIVE = (
    "pmorg/capabilities/candidate-qualification-reports-v1.json"
)
POST_INDEX_RELATIVE = "pmorg/capabilities/post-disposition-qualification-v1.json"
PATCH_LEDGER_RELATIVE = "pmorg/patch-ledger.json"
SUBJECT_RELATIVE = "pmorg/capabilities/dispositions/subject-ce-source-artifact-v1.json"
RECORD_ROOT_RELATIVE = "pmorg/capabilities/dispositions/records"
EVIDENCE_ROOT_RELATIVE = "pmorg/capabilities/dispositions/evidence"
SNAPSHOT_ROOT_RELATIVE = "pmorg/capabilities/dispositions/implementation-snapshots"
BUNDLE_RELATIVE = "pmorg/capabilities/dispositions/evidence-bundle-v1.json"
REPORT_RELATIVE = "pmorg/capabilities/capability-disposition-report-v1.json"
RECORD_SCHEMA_VERSION = "pmorg.capability-disposition/v1"
REPORT_SCHEMA_VERSION = "pmorg.capability-disposition-report/v1"
PAYLOAD_TYPE = "application/vnd.pmorg.capability-disposition.v1+json"
PRIVATE_KEY_ENV = "PMORG_CAPABILITY_DISPOSITION_TEST_ED25519_PRIVATE_KEY"
PUBLIC_KEY_ENV = "PMORG_CAPABILITY_DISPOSITION_TEST_ED25519_PUBLIC_KEY"
CLAIM_BOUNDARY = "two_admission_dispositions_only_no_catalog_completion_or_release"
REPOSITORY_URL = "https://github.com/bmvv1995/PMORG-Platform.git"

CAPABILITIES: dict[str, dict[str, Any]] = {
    "deployment-admission": {
        "requirements": ["A-LIC-002", "PLT-007"],
        "search": (
            "pmorg/capabilities/candidate-search/"
            "deployment-admission-search-evidence-v1.json"
        ),
        "report_root": (
            "pmorg/capabilities/candidate-qualification-reports/deployment-admission"
        ),
        "post_report": (
            "pmorg/capabilities/post-disposition-qualification-reports/"
            "deployment-admission.json"
        ),
    },
    "distribution-admission": {
        "requirements": ["A-LIC-003", "PLT-008"],
        "search": (
            "pmorg/capabilities/candidate-search/"
            "distribution-admission-search-evidence-v1.json"
        ),
        "report_root": (
            "pmorg/capabilities/candidate-qualification-reports/distribution-admission"
        ),
        "post_report": (
            "pmorg/capabilities/post-disposition-qualification-reports/"
            "distribution-admission.json"
        ),
    },
}


class CapabilityDispositionError(ValueError):
    """Raised when disposition evidence, semantics, or signatures drift."""


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    path = (repository_root / relative_path).resolve()
    try:
        path.relative_to(repository_root.resolve())
    except ValueError as error:
        raise CapabilityDispositionError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return path


def _read_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_safe_path(repository_root, relative_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CapabilityDispositionError(
            f"artifact is not readable JSON: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise CapabilityDispositionError(f"artifact is not an object: {relative_path}")
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
        raise CapabilityDispositionError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    return _payload_ref(
        relative_path, payload, logical_name=logical_name, media_type=media_type
    )


def _payload_ref(
    relative_path: str,
    payload: bytes,
    *,
    logical_name: str,
    media_type: str = "application/json",
) -> dict[str, Any]:
    return {
        "logical_name": logical_name,
        "media_type": media_type,
        "digest": sha256_digest(payload),
        "size_bytes": len(payload),
        "relative_path": relative_path,
    }


def _git(*arguments: str, repository_root: Path) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _base_blob(repository_root: Path, relative_path: str) -> tuple[str, bytes]:
    try:
        object_id = _git(
            "rev-parse",
            f"{BASE_PLATFORM_COMMIT}:{relative_path}",
            repository_root=repository_root,
        )
        payload = subprocess.run(
            ["git", "cat-file", "blob", object_id],
            cwd=repository_root,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise CapabilityDispositionError(
            f"implementation path is absent from disposition base: {relative_path}"
        ) from error
    if _safe_path(repository_root, relative_path).read_bytes() != payload:
        raise CapabilityDispositionError(
            f"implementation path drifted from disposition base: {relative_path}"
        )
    return object_id, payload


def _subject_artifact(repository_root: Path) -> tuple[dict[str, Any], str]:
    with tempfile.TemporaryDirectory() as temporary_directory:
        child_environment = os.environ.copy()
        child_environment.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [
                "python3",
                "-B",
                "pmorg/scripts/build_ce_artifact.py",
                "--revision",
                BASE_PLATFORM_COMMIT,
                "--output",
                str(Path(temporary_directory) / "pmorg-ce-source.tar"),
            ],
            cwd=repository_root,
            env=child_environment,
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(completed.stdout)
    descriptor = ArtifactDescriptor(
        artifact_id="pmorg-ce-source",
        component="pmorg-platform",
        artifact_kind="package",
        media_type="application/vnd.pmorg.onyx-ce-source.v1+tar",
        platform="source",
        digest=f"sha256:{result['artifact_sha256']}",
        size_bytes=result["artifact_size"],
    )
    subject = {
        "schema_version": "pmorg.capability-disposition-subject/v1",
        "claim_boundary": CLAIM_BOUNDARY,
        "pmorg_platform_commit": BASE_PLATFORM_COMMIT,
        "pmorg_spec_commit": SPEC_COMMIT,
        "onyx_commit": ONYX_COMMIT,
        "onyx_surface": "ce",
        "usage_mode": "development_test",
        "artifact_descriptor": descriptor.model_dump(mode="json"),
        "artifact_file_count": result["file_count"],
        "artifact_manifest_digest": f"sha256:{result['manifest_sha256']}",
    }
    return subject, artifact_set_digest_from_descriptors([descriptor])


def artifact_set_digest_from_descriptors(
    descriptors: list[ArtifactDescriptor],
) -> str:
    """Use the BuildQualificationManifest artifact-set algorithm exactly."""

    payload = canonical_json_bytes(
        [descriptor.model_dump(mode="json") for descriptor in descriptors]
    )
    return sha256_digest(payload)


def _implementation_snapshot(
    repository_root: Path, capability_id: str, relative_path: str
) -> tuple[str, bytes, dict[str, Any]]:
    object_id, payload = _base_blob(repository_root, relative_path)
    snapshot = {
        "schema_version": "pmorg.implementation-path-snapshot/v1",
        "repository": REPOSITORY_URL,
        "commit": BASE_PLATFORM_COMMIT,
        "path": relative_path,
        "git_blob_id": object_id,
        "content_hash": sha256_digest(payload),
        "size_bytes": len(payload),
        "ownership_class": "pmorg_owned",
        "license_class": "pmorg",
    }
    safe_name = relative_path.replace("/", "__") + ".json"
    output_relative = f"{SNAPSHOT_ROOT_RELATIVE}/{capability_id}/{safe_name}"
    output = canonical_document_bytes(snapshot)
    tree_hash = sha256_digest(
        canonical_json_bytes(
            {
                "commit": BASE_PLATFORM_COMMIT,
                "paths": [
                    {
                        "path": relative_path,
                        "git_blob_id": object_id,
                        "content_hash": snapshot["content_hash"],
                    }
                ],
            }
        )
    )
    return (
        output_relative,
        output,
        {
            "path": relative_path,
            "content_hash": snapshot["content_hash"],
            "source_ref": {
                "repository": REPOSITORY_URL,
                "commit": BASE_PLATFORM_COMMIT,
                "paths": [relative_path],
                "tree_hash": tree_hash,
                "source_snapshot": _payload_ref(
                    output_relative,
                    output,
                    logical_name=f"{capability_id}-{safe_name}-source-snapshot",
                ),
            },
            "ownership_class": "pmorg_owned",
            "license_class": "pmorg",
            "provenance_inventory_item": _payload_ref(
                output_relative,
                output,
                logical_name=f"{capability_id}-{safe_name}-provenance-item",
            ),
        },
    )


def _contract_schema(repository_root: Path, schema_version: str) -> dict[str, Any]:
    manifest = _read_object(repository_root, "backend/pmorg/contracts/manifest.json")
    try:
        entry = next(
            item
            for item in cast(list[dict[str, Any]], manifest["contracts"])
            if item["schema_version"] == schema_version
        )
    except (KeyError, StopIteration) as error:
        raise CapabilityDispositionError(
            f"contract is absent from manifest: {schema_version}"
        ) from error
    relative = f"backend/pmorg/contracts/{entry['schema_path']}"
    payload = _safe_path(repository_root, relative).read_bytes()
    if sha256_digest(payload) != entry["schema_sha256"]:
        raise CapabilityDispositionError(f"schema digest drifted: {schema_version}")
    if manifest.get("wire_surface") != "pmorg-contracts/1.0":
        raise CapabilityDispositionError("contract wire surface drifted")
    return cast(dict[str, Any], json.loads(payload))


def _empty_patch_set_hash() -> str:
    return sha256_digest(canonical_json_bytes([]))


def _capability_inputs(
    repository_root: Path, capability_id: str
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
]:
    spec = CAPABILITIES[capability_id]
    search = _read_object(repository_root, cast(str, spec["search"]))
    qualification_index = _read_object(repository_root, QUALIFICATION_INDEX_RELATIVE)
    unordered_entries = [
        item
        for item in cast(list[dict[str, Any]], qualification_index["entries"])
        if item["capability_id"] == capability_id
    ]
    by_candidate_id = {item["candidate_id"]: item for item in unordered_entries}
    if set(by_candidate_id) != set(search["candidate_ids"]) or len(
        by_candidate_id
    ) != len(unordered_entries):
        raise CapabilityDispositionError(
            f"{capability_id} qualification denominator drifted"
        )
    entries = [
        by_candidate_id[candidate_id] for candidate_id in search["candidate_ids"]
    ]
    candidates: list[dict[str, Any]] = []
    report_refs: list[dict[str, Any]] = []
    for entry in entries:
        report_ref = cast(dict[str, Any], entry["report"])
        report = _read_object(repository_root, cast(str, report_ref["relative_path"]))
        if (
            report["candidate_id"] != entry["candidate_id"]
            or report["verdict"] != "fail"
        ):
            raise CapabilityDispositionError(
                f"{capability_id} candidate report is not the observed FAIL"
            )
        candidates.append(
            {
                "candidate_id": entry["candidate_id"],
                "source_ref": report["source_ref"],
                "onyx_surface": entry["source_surface"],
                "license_class": (
                    "mit-expat"
                    if entry["source_surface"] == "ce"
                    else "onyx-enterprise"
                ),
                "qualification": "fail",
                "qualification_report": report,
            }
        )
        report_refs.append(report_ref)
    post_report = _read_object(repository_root, cast(str, spec["post_report"]))
    if post_report["verdict"] != "pass":
        raise CapabilityDispositionError(
            f"{capability_id} post-disposition qualification is not PASS"
        )
    return search, candidates, report_refs, post_report


def build_capability_dispositions(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    """Build two bounded admission disposition records and aggregate evidence."""

    subject, artifact_set_hash = _subject_artifact(repository_root)
    subject_payload = canonical_document_bytes(subject)
    documents: dict[str, bytes] = {SUBJECT_RELATIVE: subject_payload}
    subject_ref = _payload_ref(
        SUBJECT_RELATIVE,
        subject_payload,
        logical_name="capability-disposition-subject-ce-source-artifact",
    )
    catalog = _read_object(repository_root, CATALOG_RELATIVE)
    catalog_hash = sha256_digest(
        _safe_path(repository_root, CATALOG_RELATIVE).read_bytes()
    )
    if catalog["pmorg_spec_commit"] != SPEC_COMMIT:
        raise CapabilityDispositionError("catalog specification binding drifted")
    catalog_items = {
        item["capability_id"]: item
        for item in cast(list[dict[str, Any]], catalog["items"])
    }
    q3c_index = _read_object(repository_root, POST_INDEX_RELATIVE)
    records: list[tuple[str, bytes, dict[str, Any]]] = []
    evidence_index_refs: list[dict[str, Any]] = []

    for capability_id, spec in CAPABILITIES.items():
        search, candidates, candidate_report_refs, post_report = _capability_inputs(
            repository_root, capability_id
        )
        q3c_entry = next(
            item
            for item in cast(list[dict[str, Any]], q3c_index["entries"])
            if item["capability_id"] == capability_id
        )
        manifest = _read_object(
            repository_root, cast(str, q3c_entry["manifest"]["relative_path"])
        )
        implementation_refs: list[dict[str, Any]] = []
        snapshot_refs: list[dict[str, Any]] = []
        for binding in cast(list[dict[str, Any]], manifest["implementation_bindings"]):
            relative, payload, implementation_ref = _implementation_snapshot(
                repository_root, capability_id, cast(str, binding["relative_path"])
            )
            if implementation_ref["content_hash"] != binding["digest"]:
                raise CapabilityDispositionError(
                    f"{capability_id} Q3c implementation binding drifted"
                )
            documents[relative] = payload
            implementation_refs.append(implementation_ref)
            snapshot_refs.append(
                _payload_ref(
                    relative,
                    payload,
                    logical_name=f"{capability_id}-{Path(relative).name}-snapshot",
                )
            )

        evidence_entries = [
            subject_ref,
            _artifact_ref(
                repository_root,
                CATALOG_RELATIVE,
                logical_name="capability-catalog",
            ),
            _artifact_ref(
                repository_root,
                cast(str, spec["search"]),
                logical_name=f"{capability_id}-candidate-search-evidence",
            ),
            _artifact_ref(
                repository_root,
                QUALIFICATION_INDEX_RELATIVE,
                logical_name="candidate-qualification-report-index",
            ),
            _artifact_ref(
                repository_root,
                POST_INDEX_RELATIVE,
                logical_name="post-disposition-qualification-index",
            ),
            _artifact_ref(
                repository_root,
                cast(str, spec["post_report"]),
                logical_name=f"{capability_id}-post-disposition-qualification-report",
            ),
            *snapshot_refs,
            *candidate_report_refs,
        ]
        evidence_index = EvidenceBundleIndex.model_validate(
            {
                "schema_version": "pmorg.evidence-bundle-index/v1",
                "bundle_kind": f"capability-disposition:{capability_id}:v1",
                "subject_binding_hash": artifact_set_hash,
                "entries": evidence_entries,
                "entry_count": len(evidence_entries),
            }
        )
        evidence_relative = f"{EVIDENCE_ROOT_RELATIVE}/{capability_id}.json"
        evidence_payload = canonical_document_bytes(
            evidence_index.model_dump(mode="json")
        )
        documents[evidence_relative] = evidence_payload
        evidence_ref = _payload_ref(
            evidence_relative,
            evidence_payload,
            logical_name=f"{capability_id}-capability-disposition-evidence-index",
        )
        evidence_index_refs.append(evidence_ref)
        record = CapabilityDispositionRecord.model_validate(
            {
                "schema_version": RECORD_SCHEMA_VERSION,
                "catalog_version": cast(str, catalog["catalog_version"]),
                "catalog_hash": catalog_hash,
                "pmorg_spec_commit": SPEC_COMMIT,
                "pmorg_platform_commit": BASE_PLATFORM_COMMIT,
                "onyx_commit": ONYX_COMMIT,
                "artifact_set_hash": artifact_set_hash,
                "onyx_surface": "ce",
                "usage_mode": "development_test",
                "capability_id": capability_id,
                "pmorg_requirement_ids": cast(list[str], spec["requirements"]),
                "candidate_search_outcome": "candidates_found",
                "candidate_search_evidence": search,
                "candidates": candidates,
                "disposition": "pmorg_independent",
                "selected_candidate_ids": [],
                "implementation_path_set_hash": post_report[
                    "implementation_path_set_hash"
                ],
                "implementation_refs": implementation_refs,
                "patch_ledger_set_hash": _empty_patch_set_hash(),
                "patch_ledger_refs": [],
                "post_disposition_qualification": post_report,
                "rationale": (
                    f"All {len(candidates)} discovered Onyx candidates were executed "
                    "against the exact candidate-level admission interface and failed; "
                    "the selected PMORG-owned implementation passed its exact five-test "
                    "post-disposition adversarial suite, so no passing reusable candidate "
                    "or deviation decision exists."
                ),
                "deviation_decision_envelope": None,
                "record_evidence_bundle_index": evidence_ref,
            }
        )
        if (
            record.pmorg_requirement_ids
            != catalog_items[capability_id]["pmorg_requirement_ids"]
        ):
            raise CapabilityDispositionError(
                f"{capability_id} requirement binding drifted"
            )
        record_relative = f"{RECORD_ROOT_RELATIVE}/{capability_id}.json"
        record_payload = canonical_document_bytes(record.model_dump(mode="json"))
        documents[record_relative] = record_payload
        record_ref = _payload_ref(
            record_relative,
            record_payload,
            logical_name=f"{capability_id}-capability-disposition-record",
        )
        records.append((record_relative, record_payload, record_ref))

    bundle_entries = [
        subject_ref,
        _artifact_ref(
            repository_root, CATALOG_RELATIVE, logical_name="capability-catalog"
        ),
        _artifact_ref(
            repository_root,
            QUALIFICATION_INDEX_RELATIVE,
            logical_name="candidate-qualification-report-index",
        ),
        _artifact_ref(
            repository_root,
            POST_INDEX_RELATIVE,
            logical_name="post-disposition-qualification-index",
        ),
        *evidence_index_refs,
        *[record_ref for _, _, record_ref in records],
    ]
    bundle = EvidenceBundleIndex.model_validate(
        {
            "schema_version": "pmorg.evidence-bundle-index/v1",
            "bundle_kind": "bounded-admission-capability-dispositions/v1",
            "subject_binding_hash": artifact_set_hash,
            "entries": bundle_entries,
            "entry_count": len(bundle_entries),
        }
    )
    bundle_payload = canonical_document_bytes(bundle.model_dump(mode="json"))
    documents[BUNDLE_RELATIVE] = bundle_payload
    bundle_ref = _payload_ref(
        BUNDLE_RELATIVE,
        bundle_payload,
        logical_name="bounded-admission-capability-disposition-evidence-bundle",
    )
    report = CapabilityDispositionReport.model_validate(
        {
            "schema_version": REPORT_SCHEMA_VERSION,
            "catalog_version": cast(str, catalog["catalog_version"]),
            "pmorg_spec_commit": SPEC_COMMIT,
            "pmorg_platform_commit": BASE_PLATFORM_COMMIT,
            "subject_artifact_set_hash": artifact_set_hash,
            "onyx_surface": "ce",
            "usage_mode": "development_test",
            "catalog_hash": catalog_hash,
            "catalog_item_count": cast(int, catalog["item_count"]),
            "catalog_requirement_count": cast(int, catalog["mapped_requirement_count"]),
            "record_refs": [record_ref for _, _, record_ref in records],
            "record_count": len(records),
            "covered_count": len(records),
            "missing_count": cast(int, catalog["item_count"]) - len(records),
            "duplicate_count": 0,
            "unmapped_requirement_count": cast(
                int, catalog["unmapped_requirement_count"]
            ),
            "unknown_requirement_count": cast(
                int, catalog["unknown_requirement_count"]
            ),
            "requirement_ref_mismatch_count": 0,
            "dangling_evidence_count": 0,
            "records_and_evidence_bundle_index": bundle_ref,
        }
    )
    documents[REPORT_RELATIVE] = canonical_document_bytes(
        report.model_dump(mode="json")
    )
    return documents


def write_capability_dispositions(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    for relative_path, payload in build_capability_dispositions(
        repository_root
    ).items():
        destination = _safe_path(repository_root, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


def _verify_ref(repository_root: Path, reference: Mapping[str, Any]) -> None:
    relative_path = cast(str, reference["relative_path"])
    expected = _artifact_ref(
        repository_root,
        relative_path,
        logical_name=cast(str, reference["logical_name"]),
        media_type=cast(str, reference["media_type"]),
    )
    if expected != dict(reference):
        raise CapabilityDispositionError(f"evidence binding drifted: {relative_path}")


def _walk_embedded_refs(repository_root: Path, value: Any) -> None:
    if isinstance(value, dict):
        if set(value) == {
            "logical_name",
            "media_type",
            "digest",
            "size_bytes",
            "relative_path",
        }:
            _verify_ref(repository_root, value)
            return
        for item in value.values():
            _walk_embedded_refs(repository_root, item)
    elif isinstance(value, list):
        for item in value:
            _walk_embedded_refs(repository_root, item)


def validate_capability_disposition_record(
    value: CapabilityDispositionRecord | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> CapabilityDispositionRecord:
    """Validate one record against committed schemas and bounded Q3 evidence."""

    try:
        record = CapabilityDispositionRecord.model_validate(value)
        Draft202012Validator(
            _contract_schema(repository_root, RECORD_SCHEMA_VERSION)
        ).validate(record.model_dump(mode="json"))
    except (ValidationError, Exception) as error:
        if isinstance(error, CapabilityDispositionError):
            raise
        raise CapabilityDispositionError(
            "capability disposition schema failed"
        ) from error
    if record.capability_id not in CAPABILITIES:
        raise CapabilityDispositionError("record capability is outside bounded slice")
    expected_documents = build_capability_dispositions(repository_root)
    relative_path = f"{RECORD_ROOT_RELATIVE}/{record.capability_id}.json"
    expected = CapabilityDispositionRecord.model_validate_json(
        expected_documents[relative_path]
    )
    if record != expected:
        raise CapabilityDispositionError(
            f"{record.capability_id} disposition derivation drifted"
        )
    _walk_embedded_refs(repository_root, record.model_dump(mode="json"))
    return record


def validate_capability_dispositions(
    repository_root: Path = REPOSITORY_ROOT,
) -> CapabilityDispositionReport:
    """Validate the exact committed records, report, and byte-closed outputs."""

    expected = build_capability_dispositions(repository_root)
    for relative_path, payload in expected.items():
        try:
            observed = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise CapabilityDispositionError(
                f"generated disposition artifact is missing: {relative_path}"
            ) from error
        if observed != payload:
            raise CapabilityDispositionError(
                f"generated disposition artifact drifted: {relative_path}"
            )
    for capability_id in CAPABILITIES:
        record = _read_object(
            repository_root, f"{RECORD_ROOT_RELATIVE}/{capability_id}.json"
        )
        validate_capability_disposition_record(record, repository_root=repository_root)
    report_value = _read_object(repository_root, REPORT_RELATIVE)
    try:
        report = CapabilityDispositionReport.model_validate(report_value)
        Draft202012Validator(
            _contract_schema(repository_root, REPORT_SCHEMA_VERSION)
        ).validate(report_value)
    except Exception as error:
        raise CapabilityDispositionError("disposition report schema failed") from error
    if (
        report.record_count != 2
        or report.covered_count != 2
        or report.missing_count != 4
        or report.subject_artifact_set_hash
        != _read_object(repository_root, BUNDLE_RELATIVE)["subject_binding_hash"]
    ):
        raise CapabilityDispositionError("bounded disposition report counters drifted")
    generated_root = _safe_path(repository_root, "pmorg/capabilities/dispositions")
    observed_paths = {
        path.relative_to(repository_root).as_posix()
        for path in generated_root.rglob("*.json")
    }
    expected_paths = {
        path for path in expected if path.startswith("pmorg/capabilities/dispositions/")
    }
    if observed_paths != expected_paths:
        raise CapabilityDispositionError(
            "disposition evidence directory is not byte-closed"
        )
    return report


def sign_capability_disposition(
    value: CapabilityDispositionRecord | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    """Sign one validated record with environment-only Ed25519 key material."""

    record = validate_capability_disposition_record(
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
        raise CapabilityDispositionError(f"{label} is not canonical base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise CapabilityDispositionError(f"{label} is not canonical base64")
    return decoded


def verify_capability_disposition(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    environ: Mapping[str, str] | None = None,
) -> CapabilityDispositionRecord:
    """Verify DSSE bytes, signer identity, schema, evidence, and semantics."""

    validated = DsseEnvelope.model_validate(envelope)
    if validated.payloadType != PAYLOAD_TYPE:
        raise CapabilityDispositionError(
            "unexpected capability disposition payload type"
        )
    if len(validated.signatures) != 1:
        raise CapabilityDispositionError(
            "capability disposition requires exactly one signature"
        )
    payload = _decode_base64(validated.payload, label="DSSE payload")
    signature = _decode_base64(validated.signatures[0].sig, label="DSSE signature")
    public_key = public_key_from_env(name=PUBLIC_KEY_ENV, environ=environ)
    if validated.signatures[0].keyid != key_id(public_key):
        raise CapabilityDispositionError("DSSE key identity mismatch")
    try:
        public_key.verify(signature, pre_authentication_encoding(PAYLOAD_TYPE, payload))
    except InvalidSignature as error:
        raise CapabilityDispositionError(
            "capability disposition signature is invalid"
        ) from error
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CapabilityDispositionError(
            "capability disposition payload is not JSON"
        ) from error
    if canonical_json_bytes(decoded) != payload:
        raise CapabilityDispositionError(
            "capability disposition payload is not canonical"
        )
    return validate_capability_disposition_record(
        cast(dict[str, Any], decoded), repository_root=repository_root
    )


__all__ = [
    "BASE_PLATFORM_COMMIT",
    "CAPABILITIES",
    "CapabilityDispositionError",
    "PAYLOAD_TYPE",
    "PRIVATE_KEY_ENV",
    "PUBLIC_KEY_ENV",
    "build_capability_dispositions",
    "sign_capability_disposition",
    "validate_capability_disposition_record",
    "validate_capability_dispositions",
    "verify_capability_disposition",
    "write_capability_dispositions",
]
