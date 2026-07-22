"""Build, validate, sign, and verify the terminal catalog-completion aggregate."""

from __future__ import annotations

import base64
import binascii
import json
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated
from typing import Any
from typing import cast
from typing import Literal

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from pydantic import Field
from pydantic import PositiveInt
from pydantic import ValidationError

from pmorg.application import capability_dispositions as shared
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import key_id
from pmorg.application.rbdp import pre_authentication_encoding
from pmorg.application.rbdp import private_key_from_env
from pmorg.application.rbdp import public_key_from_env
from pmorg.contracts.types import CapabilityDispositionRecord
from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import DsseSignature
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import EvidenceBundleIndex
from pmorg.contracts.types import GitSha
from pmorg.contracts.types import Sha256Digest
from pmorg.contracts.types import StrictContract

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BASE_PLATFORM_COMMIT = "7b3470cadba39c6033d11424dfb6e0a65c8ac389"
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
APPLICABLE_REQUIREMENT_SET_RELATIVE = "pmorg/baseline-manifest.json"
PATCH_LEDGER_RELATIVE = "pmorg/patch-ledger.json"
SCHEMA_RELATIVE = (
    "pmorg/capabilities/catalog-completion/catalog-completion-aggregate-v1.schema.json"
)
RECORD_RELATIVE = (
    "pmorg/capabilities/catalog-completion/catalog-completion-aggregate-v1.json"
)
CLAIM_BOUNDARY = (
    "catalog_completion_only_no_admission_release_build_qualification_production_or_g3a"
)
COMPLETION_CLAIM = (
    "all_catalog_capabilities_carry_signed_dispositions_covering_"
    "all_mapped_requirements_21_of_21"
)
PAYLOAD_TYPE = "application/vnd.pmorg.catalog-completion-aggregate+json"
PRIVATE_KEY_ENV = shared.PRIVATE_KEY_ENV
PUBLIC_KEY_ENV = shared.PUBLIC_KEY_ENV
SCHEMA_VERSION = "pmorg.catalog-completion-aggregate/v1"
GATE_CLASS = "completion-claim"
EXPECTED_DISPOSITION_COUNT = 6
EXPECTED_REQUIREMENT_COUNT = 21
CAPABILITY_ORDER = (
    "capability-disposition-qualification",
    "deployment-admission",
    "distribution-admission",
    "governed-onyx-fork",
    "qualified-reproducible-build",
    "thin-fork-boundary",
)
EXPECTED_REQUIREMENT_IDS = (
    "A-EVIDENCE-001",
    "A-FORK-001",
    "A-LIC-001",
    "A-LIC-002",
    "A-LIC-003",
    "A-PATCH-001",
    "A-PATCH-002",
    "A-PATCH-003",
    "A-PATCH-004",
    "A-PATCH-005",
    "A-PATCH-006",
    "A-REPORT-001",
    "A-REPRO-001",
    "A-SURFACE-001",
    "A-UPSTREAM-001",
    "PLT-001",
    "PLT-004",
    "PLT-005",
    "PLT-006",
    "PLT-007",
    "PLT-008",
)
SCOPE_EXCLUSIONS = (
    "admission",
    "release",
    "build_qualification",
    "production",
    "g3a",
)
RECORD_RELATIVES = {
    capability_id: f"pmorg/capabilities/dispositions/records/{capability_id}.json"
    for capability_id in CAPABILITY_ORDER
}
EVIDENCE_RELATIVES = {
    capability_id: f"pmorg/capabilities/dispositions/evidence/{capability_id}.json"
    for capability_id in CAPABILITY_ORDER
}
LEGACY_AGGREGATE_PREDECESSORS = (
    "pmorg/capabilities/capability-disposition-report-v1.json",
    "pmorg/capabilities/dispositions/evidence-bundle-v1.json",
)
EXPECTED_LEDGER_ENTRY = {
    "id": "PL-048",
    "classification": "PMORG-owned",
    "paths": [
        "backend/pmorg/application/catalog_completion_aggregate.py",
        "backend/pmorg/tests/test_catalog_completion_aggregate.py",
        RECORD_RELATIVE,
        SCHEMA_RELATIVE,
        "pmorg/scripts/build_catalog_completion_aggregate.py",
    ],
    "requirements": list(EXPECTED_REQUIREMENT_IDS),
    "reason": (
        "Emit one terminal, deterministic and signable catalog-completion aggregate "
        "that binds by digest the exact six committed capability disposition records, "
        "their six evidence indexes, the capability catalog and its applicable "
        "requirement set; prove exact 21/21 mapped-requirement coverage while "
        "preserving every predecessor byte-identically; keep DSSE key material and "
        "signatures ephemeral and make no admission, release, build-qualification, "
        "production or G3-A claim."
    ),
    "verification": [
        (
            "PMORG_PROTECTED_BASE_SHA="
            f"{BASE_PLATFORM_COMMIT} python3 -B pmorg/scripts/verify_fork.py"
        ),
        (
            "PYTHONPATH=backend python3 -B -m unittest "
            "pmorg.tests.test_catalog_completion_aggregate -v"
        ),
        (
            "PYTHONPATH=backend python3 -B "
            "pmorg/scripts/build_catalog_completion_aggregate.py --check"
        ),
        (
            "PYTHONPATH=backend python3 -B -m unittest discover "
            "-s backend/pmorg/tests -t backend -p 'test_*.py' -v"
        ),
    ],
}


class CatalogCompletionAggregateError(RuntimeError):
    """Raised when the terminal aggregate or one of its bindings drifts."""


class DispositionPlatformAnchor(StrictContract):
    """Identity carried by one already-committed disposition record."""

    pmorg_spec_commit: GitSha
    pmorg_platform_commit: GitSha
    onyx_commit: GitSha
    artifact_set_hash: Sha256Digest


class CatalogDispositionBinding(StrictContract):
    """Digest and platform binding for one catalog capability disposition."""

    capability_id: Annotated[str, Field(min_length=1)]
    pmorg_requirement_ids: Annotated[list[str], Field(min_length=1)]
    disposition: Literal["pmorg_independent"]
    platform_anchor: DispositionPlatformAnchor
    record: EvidenceArtifactRef
    evidence_bundle: EvidenceArtifactRef
    evidence_subject_binding_hash: Sha256Digest
    evidence_entry_count: PositiveInt


class CatalogCompletionAggregateRecord(StrictContract):
    """The sole Slice 1 catalog-completion claim."""

    schema_version: Literal["pmorg.catalog-completion-aggregate/v1"]
    gate_class: Literal["completion-claim"]
    claim_boundary: Literal[
        "catalog_completion_only_no_admission_release_build_qualification_"
        "production_or_g3a"
    ]
    completion_claim: Literal[
        "all_catalog_capabilities_carry_signed_dispositions_covering_"
        "all_mapped_requirements_21_of_21"
    ]
    completion_status: Literal["complete"]
    pmorg_platform_commit: GitSha
    pmorg_spec_commit: GitSha
    onyx_commit: GitSha
    catalog_version: Annotated[str, Field(min_length=1)]
    catalog_hash: Sha256Digest
    catalog: EvidenceArtifactRef
    applicable_requirement_set: EvidenceArtifactRef
    disposition_bindings: Annotated[
        list[CatalogDispositionBinding],
        Field(
            min_length=EXPECTED_DISPOSITION_COUNT, max_length=EXPECTED_DISPOSITION_COUNT
        ),
    ]
    disposition_count: PositiveInt
    disposition_binding_set_hash: Sha256Digest
    expected_requirement_count: PositiveInt
    covered_requirement_count: PositiveInt
    covered_requirement_ids: Annotated[
        list[str], Field(min_length=EXPECTED_REQUIREMENT_COUNT)
    ]
    missing_requirement_ids: list[str]
    duplicate_requirement_ids: list[str]
    unknown_requirement_ids: list[str]
    scope_exclusions: Annotated[
        list[str],
        Field(min_length=len(SCOPE_EXCLUSIONS), max_length=len(SCOPE_EXCLUSIONS)),
    ]


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    return shared._safe_path(repository_root, relative_path)


def _base_payload(repository_root: Path, relative_path: str) -> bytes:
    try:
        payload = subprocess.run(
            ["git", "show", f"{BASE_PLATFORM_COMMIT}:{relative_path}"],
            cwd=repository_root,
            check=True,
            capture_output=True,
        ).stdout
        live_payload = _safe_path(repository_root, relative_path).read_bytes()
    except (subprocess.CalledProcessError, OSError) as error:
        raise CatalogCompletionAggregateError(
            f"catalog-completion bound path is missing: {relative_path}"
        ) from error
    if live_payload != payload:
        raise CatalogCompletionAggregateError(
            f"catalog-completion bound path drifted: {relative_path}"
        )
    return payload


def _read_bound_object(repository_root: Path, relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(_base_payload(repository_root, relative_path))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogCompletionAggregateError(
            f"catalog-completion bound JSON is invalid: {relative_path}"
        ) from error
    if not isinstance(value, dict):
        raise CatalogCompletionAggregateError(
            f"catalog-completion bound JSON is not an object: {relative_path}"
        )
    return cast(dict[str, Any], value)


def _artifact_ref(
    repository_root: Path, relative_path: str, *, logical_name: str
) -> EvidenceArtifactRef:
    payload = _base_payload(repository_root, relative_path)
    return EvidenceArtifactRef(
        logical_name=logical_name,
        media_type="application/json",
        digest=sha256_digest(payload),
        size_bytes=len(payload),
        relative_path=relative_path,
    )


def _assert_ledger_append_only(repository_root: Path) -> None:
    try:
        base = json.loads(
            subprocess.run(
                ["git", "show", f"{BASE_PLATFORM_COMMIT}:{PATCH_LEDGER_RELATIVE}"],
                cwd=repository_root,
                check=True,
                capture_output=True,
            ).stdout
        )
        live = json.loads(
            _safe_path(repository_root, PATCH_LEDGER_RELATIVE).read_bytes()
        )
    except (subprocess.CalledProcessError, OSError, json.JSONDecodeError) as error:
        raise CatalogCompletionAggregateError(
            "catalog-completion patch ledger cannot be read"
        ) from error
    if (
        not isinstance(base, dict)
        or not isinstance(live, dict)
        or set(base) != set(live)
    ):
        raise CatalogCompletionAggregateError(
            "catalog-completion patch ledger structure drifted"
        )
    for key in shared.THIN_FORK_LEDGER_TOP_LEVEL_PINS:
        if live.get(key) != base.get(key):
            raise CatalogCompletionAggregateError(
                f"catalog-completion patch ledger pin drifted: {key}"
            )
    shared._assert_append_only_sequence(
        base=base.get("entries"),
        live=live.get("entries"),
        sequence_name="entries",
    )
    shared._assert_append_only_sequence(
        base=base.get("upstream_patch_records"),
        live=live.get("upstream_patch_records"),
        sequence_name="upstream_patch_records",
    )
    base_entries = base.get("entries")
    live_entries = live.get("entries")
    if not isinstance(base_entries, list) or not isinstance(live_entries, list):
        raise CatalogCompletionAggregateError(
            "catalog-completion patch ledger entries are not lists"
        )
    if (
        len(live_entries) <= len(base_entries)
        or live_entries[len(base_entries)] != EXPECTED_LEDGER_ENTRY
        or sum(entry.get("id") == "PL-048" for entry in live_entries) != 1
    ):
        raise CatalogCompletionAggregateError(
            "catalog-completion PL-048 ownership entry is absent or drifted"
        )


def _catalog_contract(
    repository_root: Path,
) -> tuple[
    dict[str, Any],
    EvidenceArtifactRef,
    EvidenceArtifactRef,
    dict[str, list[str]],
]:
    catalog = _read_bound_object(repository_root, CATALOG_RELATIVE)
    catalog_ref = _artifact_ref(
        repository_root, CATALOG_RELATIVE, logical_name="capability-catalog"
    )
    items = catalog.get("items")
    if not isinstance(items, list):
        raise CatalogCompletionAggregateError("capability catalog items are absent")
    capability_ids = [
        item.get("capability_id") for item in items if isinstance(item, dict)
    ]
    requirement_map: dict[str, list[str]] = {}
    flattened: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise CatalogCompletionAggregateError("capability catalog item is invalid")
        capability_id = item.get("capability_id")
        requirement_ids = item.get("pmorg_requirement_ids")
        if not isinstance(capability_id, str) or not isinstance(requirement_ids, list):
            raise CatalogCompletionAggregateError(
                "capability catalog mapping is invalid"
            )
        if not requirement_ids or not all(
            isinstance(requirement_id, str) for requirement_id in requirement_ids
        ):
            raise CatalogCompletionAggregateError(
                f"capability catalog requirements are invalid: {capability_id}"
            )
        typed_requirement_ids = cast(list[str], requirement_ids)
        requirement_map[capability_id] = typed_requirement_ids
        flattened.extend(typed_requirement_ids)
    duplicates = sorted(
        requirement_id
        for requirement_id in set(flattened)
        if flattened.count(requirement_id) != 1
    )
    if (
        catalog.get("schema_version") != "pmorg.capability-catalog/v1"
        or catalog.get("item_count") != EXPECTED_DISPOSITION_COUNT
        or len(items) != EXPECTED_DISPOSITION_COUNT
        or tuple(capability_ids) != CAPABILITY_ORDER
        or len(requirement_map) != EXPECTED_DISPOSITION_COUNT
        or catalog.get("expected_requirement_count") != EXPECTED_REQUIREMENT_COUNT
        or catalog.get("mapped_requirement_count") != EXPECTED_REQUIREMENT_COUNT
        or catalog.get("unmapped_requirement_count") != 0
        or catalog.get("unknown_requirement_count") != 0
        or catalog.get("duplicate_capability_id_count") != 0
        or duplicates
        or tuple(sorted(flattened)) != EXPECTED_REQUIREMENT_IDS
    ):
        raise CatalogCompletionAggregateError(
            "capability catalog is not the exact six-capability 21/21 mapping"
        )
    applicable_value = catalog.get("applicable_requirement_set")
    try:
        applicable_ref = EvidenceArtifactRef.model_validate(applicable_value)
    except ValidationError as error:
        raise CatalogCompletionAggregateError(
            "capability catalog applicable requirement set is invalid"
        ) from error
    if applicable_ref.relative_path != APPLICABLE_REQUIREMENT_SET_RELATIVE:
        raise CatalogCompletionAggregateError(
            "capability catalog applicable requirement path drifted"
        )
    observed_applicable_ref = _artifact_ref(
        repository_root,
        APPLICABLE_REQUIREMENT_SET_RELATIVE,
        logical_name=applicable_ref.logical_name,
    )
    if observed_applicable_ref != applicable_ref:
        raise CatalogCompletionAggregateError(
            "capability catalog applicable requirement binding drifted"
        )
    return catalog, catalog_ref, applicable_ref, requirement_map


def _disposition_binding(
    repository_root: Path,
    capability_id: str,
    expected_requirement_ids: list[str],
) -> CatalogDispositionBinding:
    record_relative = RECORD_RELATIVES[capability_id]
    evidence_relative = EVIDENCE_RELATIVES[capability_id]
    record_value = _read_bound_object(repository_root, record_relative)
    evidence_value = _read_bound_object(repository_root, evidence_relative)
    try:
        record = CapabilityDispositionRecord.model_validate(record_value)
        Draft202012Validator(
            shared._contract_schema(repository_root, record.schema_version)
        ).validate(record.model_dump(mode="json"))
        evidence = EvidenceBundleIndex.model_validate(evidence_value)
    except Exception as error:
        raise CatalogCompletionAggregateError(
            f"committed disposition schema failed: {capability_id}"
        ) from error
    record_ref = _artifact_ref(
        repository_root,
        record_relative,
        logical_name=f"{capability_id}-capability-disposition-record",
    )
    evidence_ref = _artifact_ref(
        repository_root,
        evidence_relative,
        logical_name=f"{capability_id}-capability-disposition-evidence-index",
    )
    if (
        record.capability_id != capability_id
        or record.pmorg_requirement_ids != expected_requirement_ids
        or record.disposition != "pmorg_independent"
        or record.record_evidence_bundle_index.relative_path != evidence_relative
        or record.record_evidence_bundle_index.digest != evidence_ref.digest
        or record.record_evidence_bundle_index.size_bytes != evidence_ref.size_bytes
        or evidence.subject_binding_hash != record.artifact_set_hash
        or evidence.entry_count != len(evidence.entries)
        or len({entry.relative_path for entry in evidence.entries})
        != len(evidence.entries)
    ):
        raise CatalogCompletionAggregateError(
            f"committed disposition binding drifted: {capability_id}"
        )
    return CatalogDispositionBinding(
        capability_id=capability_id,
        pmorg_requirement_ids=expected_requirement_ids,
        disposition="pmorg_independent",
        platform_anchor=DispositionPlatformAnchor(
            pmorg_spec_commit=record.pmorg_spec_commit,
            pmorg_platform_commit=record.pmorg_platform_commit,
            onyx_commit=record.onyx_commit,
            artifact_set_hash=record.artifact_set_hash,
        ),
        record=record_ref,
        evidence_bundle=evidence_ref,
        evidence_subject_binding_hash=cast(str, evidence.subject_binding_hash),
        evidence_entry_count=evidence.entry_count,
    )


def build_catalog_completion_aggregate(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    """Build the terminal claim from committed records without re-qualification."""

    repository_root = repository_root.resolve()
    _assert_ledger_append_only(repository_root)
    catalog, catalog_ref, applicable_ref, requirement_map = _catalog_contract(
        repository_root
    )
    bindings = [
        _disposition_binding(
            repository_root, capability_id, requirement_map[capability_id]
        )
        for capability_id in CAPABILITY_ORDER
    ]
    spec_commits = {binding.platform_anchor.pmorg_spec_commit for binding in bindings}
    onyx_commits = {binding.platform_anchor.onyx_commit for binding in bindings}
    if spec_commits != {catalog.get("pmorg_spec_commit")} or len(onyx_commits) != 1:
        raise CatalogCompletionAggregateError(
            "disposition platform anchors do not share the catalog identity"
        )
    binding_payload = [binding.model_dump(mode="json") for binding in bindings]
    binding_set_hash = sha256_digest(canonical_document_bytes(binding_payload))
    record = CatalogCompletionAggregateRecord(
        schema_version=SCHEMA_VERSION,
        gate_class=GATE_CLASS,
        claim_boundary=CLAIM_BOUNDARY,
        completion_claim=COMPLETION_CLAIM,
        completion_status="complete",
        pmorg_platform_commit=BASE_PLATFORM_COMMIT,
        pmorg_spec_commit=next(iter(spec_commits)),
        onyx_commit=next(iter(onyx_commits)),
        catalog_version=cast(str, catalog["catalog_version"]),
        catalog_hash=catalog_ref.digest,
        catalog=catalog_ref,
        applicable_requirement_set=applicable_ref,
        disposition_bindings=bindings,
        disposition_count=len(bindings),
        disposition_binding_set_hash=binding_set_hash,
        expected_requirement_count=EXPECTED_REQUIREMENT_COUNT,
        covered_requirement_count=EXPECTED_REQUIREMENT_COUNT,
        covered_requirement_ids=list(EXPECTED_REQUIREMENT_IDS),
        missing_requirement_ids=[],
        duplicate_requirement_ids=[],
        unknown_requirement_ids=[],
        scope_exclusions=list(SCOPE_EXCLUSIONS),
    )
    schema_payload = canonical_document_bytes(
        CatalogCompletionAggregateRecord.model_json_schema()
    )
    record_payload = canonical_document_bytes(record.model_dump(mode="json"))
    return {
        SCHEMA_RELATIVE: schema_payload,
        RECORD_RELATIVE: record_payload,
    }


def write_catalog_completion_aggregate(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_catalog_completion_aggregate(
        repository_root
    ).items():
        destination = _safe_path(repository_root, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


def validate_catalog_completion_aggregate_record(
    value: CatalogCompletionAggregateRecord | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> CatalogCompletionAggregateRecord:
    repository_root = repository_root.resolve()
    expected_outputs = build_catalog_completion_aggregate(repository_root)
    try:
        record = CatalogCompletionAggregateRecord.model_validate(value)
        schema = json.loads(expected_outputs[SCHEMA_RELATIVE])
        Draft202012Validator(schema).validate(record.model_dump(mode="json"))
    except Exception as error:
        if isinstance(error, CatalogCompletionAggregateError):
            raise
        raise CatalogCompletionAggregateError(
            "catalog-completion aggregate schema failed"
        ) from error
    expected = CatalogCompletionAggregateRecord.model_validate_json(
        expected_outputs[RECORD_RELATIVE]
    )
    if record != expected:
        raise CatalogCompletionAggregateError(
            "catalog-completion aggregate derivation drifted"
        )
    return record


def validate_catalog_completion_aggregate(
    repository_root: Path = REPOSITORY_ROOT,
) -> CatalogCompletionAggregateRecord:
    repository_root = repository_root.resolve()
    expected = build_catalog_completion_aggregate(repository_root)
    for relative_path, payload in expected.items():
        try:
            observed = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise CatalogCompletionAggregateError(
                f"catalog-completion aggregate artifact is missing: {relative_path}"
            ) from error
        if observed != payload:
            raise CatalogCompletionAggregateError(
                f"catalog-completion aggregate artifact drifted: {relative_path}"
            )
    record = CatalogCompletionAggregateRecord.model_validate_json(
        _safe_path(repository_root, RECORD_RELATIVE).read_bytes()
    )
    return validate_catalog_completion_aggregate_record(
        record, repository_root=repository_root
    )


def sign_catalog_completion_aggregate(
    value: CatalogCompletionAggregateRecord | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    record = validate_catalog_completion_aggregate_record(
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
        raise CatalogCompletionAggregateError(
            f"{label} is not canonical base64"
        ) from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise CatalogCompletionAggregateError(f"{label} is not canonical base64")
    return decoded


def verify_catalog_completion_aggregate(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    environ: Mapping[str, str] | None = None,
) -> CatalogCompletionAggregateRecord:
    try:
        validated = DsseEnvelope.model_validate(envelope)
    except ValidationError as error:
        raise CatalogCompletionAggregateError(
            "catalog-completion DSSE envelope schema failed"
        ) from error
    if validated.payloadType != PAYLOAD_TYPE:
        raise CatalogCompletionAggregateError(
            "unexpected catalog-completion payload type"
        )
    if len(validated.signatures) != 1:
        raise CatalogCompletionAggregateError(
            "catalog-completion aggregate requires exactly one signature"
        )
    payload = _decode_base64(validated.payload, label="DSSE payload")
    signature = _decode_base64(validated.signatures[0].sig, label="DSSE signature")
    public_key = public_key_from_env(name=PUBLIC_KEY_ENV, environ=environ)
    if validated.signatures[0].keyid != key_id(public_key):
        raise CatalogCompletionAggregateError(
            "catalog-completion DSSE key identity mismatch"
        )
    try:
        public_key.verify(signature, pre_authentication_encoding(PAYLOAD_TYPE, payload))
    except InvalidSignature as error:
        raise CatalogCompletionAggregateError(
            "catalog-completion aggregate signature is invalid"
        ) from error
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogCompletionAggregateError(
            "catalog-completion aggregate payload is not JSON"
        ) from error
    if canonical_json_bytes(decoded) != payload:
        raise CatalogCompletionAggregateError(
            "catalog-completion aggregate payload is not canonical"
        )
    return validate_catalog_completion_aggregate_record(
        cast(dict[str, Any], decoded), repository_root=repository_root
    )


__all__ = [
    "APPLICABLE_REQUIREMENT_SET_RELATIVE",
    "BASE_PLATFORM_COMMIT",
    "CAPABILITY_ORDER",
    "CATALOG_RELATIVE",
    "CLAIM_BOUNDARY",
    "COMPLETION_CLAIM",
    "CatalogCompletionAggregateError",
    "CatalogCompletionAggregateRecord",
    "EVIDENCE_RELATIVES",
    "EXPECTED_REQUIREMENT_IDS",
    "GATE_CLASS",
    "LEGACY_AGGREGATE_PREDECESSORS",
    "PAYLOAD_TYPE",
    "PRIVATE_KEY_ENV",
    "PUBLIC_KEY_ENV",
    "RECORD_RELATIVE",
    "RECORD_RELATIVES",
    "SCHEMA_RELATIVE",
    "SCOPE_EXCLUSIONS",
    "build_catalog_completion_aggregate",
    "sign_catalog_completion_aggregate",
    "validate_catalog_completion_aggregate",
    "validate_catalog_completion_aggregate_record",
    "verify_catalog_completion_aggregate",
    "write_catalog_completion_aggregate",
]
