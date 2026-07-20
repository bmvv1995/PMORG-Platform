"""Create and verify development-test BQM/BQA qualification records."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import key_id
from pmorg.application.rbdp import pre_authentication_encoding
from pmorg.application.rbdp import private_key_from_env
from pmorg.application.rbdp import public_key_from_env
from pmorg.contracts.types import BuildQualificationAttestation
from pmorg.contracts.types import BuildQualificationManifest
from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import DsseSignature
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import EvidenceBundleIndex
from pmorg.contracts.types import ExpectedArtifactCatalog

BQA_PAYLOAD_TYPE = "application/vnd.pmorg.build-qualification-attestation.v1+json"
BQM_SCHEMA_VERSION = "pmorg.build-qualification-manifest/v1"
BQA_SCHEMA_VERSION = "pmorg.build-qualification-attestation/v1"
BQA_PRIVATE_KEY_ENV = "PMORG_BQA_TEST_ED25519_PRIVATE_KEY"
BQA_PUBLIC_KEY_ENV = "PMORG_BQA_TEST_ED25519_PUBLIC_KEY"


class QualificationVerificationError(ValueError):
    """Raised when qualification content, evidence, or signatures are invalid."""


@dataclass(frozen=True, slots=True)
class ContentAddressedBqm:
    """Canonical BQM bytes and their stable content identity."""

    manifest: BuildQualificationManifest
    payload: bytes
    digest: str


_BQM_ROLE_HASH_FIELDS = {
    "release-build-definition-dsse": "release_build_definition_envelope_hash",
    "build-recipe": "build_recipe_hash",
    "build-input-set": "build_input_set_hash",
    "runtime-scope-policy-map": "runtime_scope_policy_map_hash",
    "expected-artifact-catalog": "expected_artifact_catalog_hash",
    "image-lock": "image_lock_hash",
    "qualification-policy-map": "qualification_policy_map_hash",
    "sbom-index": "sbom_hash",
    "license-report": "license_report_hash",
    "patch-ledger-report": "patch_ledger_report_hash",
    "provenance-report": "provenance_report_hash",
    "surface-mode-report": "surface_mode_report_hash",
    "provenance-evidence-bundle-index": "provenance_evidence_bundle_index_hash",
    "capability-catalog": "capability_catalog_hash",
    "capability-disposition-report": "capability_disposition_report_hash",
    "capability-evidence-bundle-index": "capability_evidence_bundle_index_hash",
    "vulnerability-report": "vulnerability_report_hash",
    "upstream-test-report": "upstream_test_report_hash",
    "ce-boundary-report": "ce_boundary_report_hash",
    "ee-inventory-report": "ee_inventory_report_hash",
}
_DEADLINE_KEYS = frozenset(
    {
        "expires_at",
        "valid_until",
        "next_revalidation_at",
        "revocation_deadline",
        "verification_deadline",
    }
)


def sha256_digest(payload: bytes) -> str:
    """Return the canonical PMORG SHA-256 digest spelling."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def artifact_set_digest(manifest: BuildQualificationManifest) -> str:
    """Hash the ordered observed artifact descriptor set."""

    descriptors = [
        item.model_dump(mode="json") for item in manifest.artifact_descriptors
    ]
    return sha256_digest(canonical_json_bytes(descriptors))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise QualificationVerificationError(f"JSON repeats key: {key}")
        value[key] = item
    return value


def _decode_base64(value: str, *, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise QualificationVerificationError(
            f"{label} is not canonical base64"
        ) from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise QualificationVerificationError(f"{label} is not canonical base64")
    return decoded


def _load_contract_schema(
    contract_root: Path,
    schema_version: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        manifest = json.loads(
            (contract_root / "manifest.json").read_bytes(),
            object_pairs_hook=_reject_duplicate_keys,
        )
        entry = next(
            item
            for item in manifest["contracts"]
            if item["schema_version"] == schema_version
        )
        schema_bytes = (contract_root / entry["schema_path"]).read_bytes()
        schema = json.loads(schema_bytes, object_pairs_hook=_reject_duplicate_keys)
    except (
        FileNotFoundError,
        KeyError,
        StopIteration,
        TypeError,
        json.JSONDecodeError,
    ) as error:
        raise QualificationVerificationError(
            f"committed contract artifacts are incomplete for {schema_version}"
        ) from error
    if sha256_digest(schema_bytes) != entry.get("schema_sha256"):
        raise QualificationVerificationError(
            f"committed schema digest does not match manifest for {schema_version}"
        )
    if manifest.get("wire_surface") != "pmorg-contracts/1.0":
        raise QualificationVerificationError(
            "contract manifest has the wrong wire surface"
        )
    return manifest, schema


def _validate_schema(value: Any, schema: Mapping[str, Any], *, label: str) -> None:
    try:
        Draft202012Validator(schema).validate(value)
    except Exception as error:
        raise QualificationVerificationError(
            f"{label} does not validate against its committed schema"
        ) from error


def _safe_evidence_path(root: Path, relative_path: str) -> Path:
    root = root.resolve()
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise QualificationVerificationError(
            "evidence path escapes its offline root"
        ) from error
    return path


def _parse_datetime(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationVerificationError(
            f"invalid evidence deadline: {label}"
        ) from error
    utc_offset = parsed.utcoffset()
    if utc_offset is None or utc_offset.total_seconds() != 0:
        raise QualificationVerificationError(f"evidence deadline is not UTC: {label}")
    return parsed


def _walk_evidence_value(
    value: Any,
    *,
    root: Path,
    active_paths: set[Path],
    deadlines: list[datetime],
) -> None:
    if isinstance(value, dict):
        if set(EvidenceArtifactRef.model_fields).issubset(value):
            try:
                reference = EvidenceArtifactRef.model_validate(value)
            except ValidationError as error:
                raise QualificationVerificationError(
                    "invalid nested evidence reference"
                ) from error
            _verify_evidence_ref(
                reference,
                root=root,
                active_paths=active_paths,
                deadlines=deadlines,
            )
            return
        for key, item in value.items():
            if key in _DEADLINE_KEYS and isinstance(item, str):
                deadlines.append(_parse_datetime(item, label=key))
            _walk_evidence_value(
                item,
                root=root,
                active_paths=active_paths,
                deadlines=deadlines,
            )
    elif isinstance(value, list):
        for item in value:
            _walk_evidence_value(
                item,
                root=root,
                active_paths=active_paths,
                deadlines=deadlines,
            )


def _verify_evidence_ref(
    reference: EvidenceArtifactRef,
    *,
    root: Path,
    active_paths: set[Path],
    deadlines: list[datetime],
) -> None:
    path = _safe_evidence_path(root, reference.relative_path)
    try:
        payload = path.read_bytes()
    except FileNotFoundError as error:
        raise QualificationVerificationError(
            f"offline evidence is missing: {reference.relative_path}"
        ) from error
    if len(payload) != reference.size_bytes:
        raise QualificationVerificationError(
            f"offline evidence size mismatch: {reference.logical_name}"
        )
    if sha256_digest(payload) != reference.digest:
        raise QualificationVerificationError(
            f"offline evidence digest mismatch: {reference.logical_name}"
        )
    if path in active_paths:
        raise QualificationVerificationError("offline evidence graph contains a cycle")
    if reference.media_type != "application/json":
        return
    try:
        decoded = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationVerificationError(
            f"JSON evidence is invalid: {reference.logical_name}"
        ) from error
    active_paths.add(path)
    try:
        if isinstance(decoded, dict) and decoded.get("schema_version") == (
            "pmorg.evidence-bundle-index/v1"
        ):
            nested = EvidenceBundleIndex.model_validate(decoded)
            if canonical_json_bytes(nested.model_dump(mode="json")) != payload:
                raise QualificationVerificationError(
                    "evidence bundle index is not canonical"
                )
            _verify_evidence_index(
                nested,
                root=root,
                active_paths=active_paths,
                deadlines=deadlines,
                require_sorted=False,
            )
        else:
            _walk_evidence_value(
                decoded,
                root=root,
                active_paths=active_paths,
                deadlines=deadlines,
            )
    finally:
        active_paths.remove(path)


def _verify_evidence_index(
    index: EvidenceBundleIndex,
    *,
    root: Path,
    active_paths: set[Path],
    deadlines: list[datetime],
    require_sorted: bool,
) -> None:
    if index.entry_count != len(index.entries):
        raise QualificationVerificationError("evidence index entry count is not exact")
    names = [item.logical_name for item in index.entries]
    paths = [item.relative_path for item in index.entries]
    digests = [item.digest for item in index.entries]
    if len(names) != len(set(names)):
        raise QualificationVerificationError("evidence logical names are not unique")
    if len(paths) != len(set(paths)):
        raise QualificationVerificationError("evidence relative paths are not unique")
    if len(digests) != len(set(digests)):
        raise QualificationVerificationError("evidence digests are not unique")
    if require_sorted and names != sorted(names):
        raise QualificationVerificationError(
            "qualification evidence roles are not ordered"
        )
    for reference in index.entries:
        _verify_evidence_ref(
            reference,
            root=root,
            active_paths=active_paths,
            deadlines=deadlines,
        )


def verify_offline_evidence_index(
    index: EvidenceBundleIndex | Mapping[str, Any],
    *,
    root: Path,
    require_sorted: bool = False,
) -> tuple[datetime, ...]:
    """Resolve a byte-closed, acyclic evidence index from local bytes only."""

    validated = EvidenceBundleIndex.model_validate(index)
    deadlines: list[datetime] = []
    _verify_evidence_index(
        validated,
        root=root,
        active_paths=set(),
        deadlines=deadlines,
        require_sorted=require_sorted,
    )
    return tuple(deadlines)


def _required_qualification_roles(
    policy_manifest: Mapping[str, Any],
    *,
    onyx_surface: str,
) -> list[str]:
    try:
        roles = policy_manifest["round_3_contract"]["qualification_bundle_roles"]
        common = list(roles["common"])
        conditional = list(roles[f"{onyx_surface}_only"])
    except (KeyError, TypeError) as error:
        raise QualificationVerificationError(
            "baseline qualification role policy is incomplete"
        ) from error
    return sorted([*common, *conditional])


def _validate_bqm_contract(
    manifest: BuildQualificationManifest,
    *,
    qualification_index: EvidenceBundleIndex,
    contract_root: Path,
    policy_manifest_path: Path,
    evidence_root: Path,
) -> None:
    contract_manifest, schema = _load_contract_schema(contract_root, BQM_SCHEMA_VERSION)
    try:
        policy_bytes = policy_manifest_path.read_bytes()
        policy = json.loads(policy_bytes, object_pairs_hook=_reject_duplicate_keys)
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise QualificationVerificationError(
            "baseline policy manifest is invalid"
        ) from error
    if manifest.baseline_manifest_hash != sha256_digest(policy_bytes):
        raise QualificationVerificationError("BQM baseline manifest hash is not exact")
    if manifest.pmorg_spec_commit != contract_manifest["specification"]["commit"]:
        raise QualificationVerificationError("BQM PMORG specification pin is not exact")
    try:
        expected_onyx_commit = policy["upstream"]["commit"]
        expected_onyx_tag = policy["upstream"]["release_tag"]
    except (KeyError, TypeError) as error:
        raise QualificationVerificationError(
            "baseline Onyx identity is incomplete"
        ) from error
    if (
        manifest.onyx_commit != expected_onyx_commit
        or manifest.onyx_release_tag != expected_onyx_tag
    ):
        raise QualificationVerificationError("BQM Onyx baseline identity is not exact")
    if manifest.onyx_surface != "ce" or manifest.usage_mode != "development_test":
        raise QualificationVerificationError("BQM admits only CE development_test")
    if (
        manifest.ce_boundary_report_hash is None
        or manifest.ee_inventory_report_hash is not None
    ):
        raise QualificationVerificationError(
            "BQM conditional surface report is invalid"
        )
    if any(
        count != 0
        for count in (
            manifest.missing_artifact_count,
            manifest.unexpected_artifact_count,
            manifest.duplicate_artifact_key_count,
        )
    ):
        raise QualificationVerificationError("BQM artifact coverage is not exact")
    if manifest.artifact_count != len(manifest.artifact_descriptors):
        raise QualificationVerificationError("BQM artifact count is not exact")
    descriptor_values = [
        item.model_dump(mode="json") for item in manifest.artifact_descriptors
    ]
    descriptor_keys = [
        (item.artifact_id, item.platform) for item in manifest.artifact_descriptors
    ]
    if descriptor_values != sorted(
        descriptor_values,
        key=lambda item: (item["artifact_id"], item["platform"]),
    ):
        raise QualificationVerificationError("BQM artifact descriptors are not ordered")
    if len(descriptor_keys) != len(set(descriptor_keys)):
        raise QualificationVerificationError(
            "BQM artifact descriptor keys are duplicated"
        )
    if manifest.artifact_set_hash != artifact_set_digest(manifest):
        raise QualificationVerificationError(
            "BQM artifact set hash is not content-derived"
        )

    index_bytes = canonical_json_bytes(qualification_index.model_dump(mode="json"))
    if manifest.qualification_bundle_index_hash != sha256_digest(index_bytes):
        raise QualificationVerificationError(
            "BQM qualification index hash is not exact"
        )
    if qualification_index.subject_binding_hash != manifest.artifact_set_hash:
        raise QualificationVerificationError(
            "BQM qualification index does not bind the artifact set"
        )
    roles = [entry.logical_name for entry in qualification_index.entries]
    if roles != _required_qualification_roles(
        policy, onyx_surface=manifest.onyx_surface
    ):
        raise QualificationVerificationError("BQM qualification role set is not exact")
    verify_offline_evidence_index(
        qualification_index,
        root=evidence_root,
        require_sorted=True,
    )
    refs = {entry.logical_name: entry for entry in qualification_index.entries}
    for role, field_name in _BQM_ROLE_HASH_FIELDS.items():
        expected = getattr(manifest, field_name)
        if role in refs:
            if expected != refs[role].digest:
                raise QualificationVerificationError(f"BQM role hash mismatch: {role}")
        elif expected is not None:
            raise QualificationVerificationError(
                f"BQM has an unindexed role hash: {role}"
            )

    expected_catalog_ref = refs["expected-artifact-catalog"]
    catalog_path = _safe_evidence_path(
        evidence_root, expected_catalog_ref.relative_path
    )
    try:
        catalog = ExpectedArtifactCatalog.model_validate_json(catalog_path.read_bytes())
    except (FileNotFoundError, ValidationError) as error:
        raise QualificationVerificationError(
            "expected artifact catalog is invalid"
        ) from error
    expected_keys = [
        (
            item.artifact_id,
            item.component,
            item.artifact_kind,
            item.media_type,
            item.platform,
        )
        for item in catalog.items
    ]
    observed_keys = [
        (
            item.artifact_id,
            item.component,
            item.artifact_kind,
            item.media_type,
            item.platform,
        )
        for item in manifest.artifact_descriptors
    ]
    if catalog.expected_artifact_count != len(catalog.items):
        raise QualificationVerificationError(
            "expected artifact catalog count is invalid"
        )
    if catalog.build_recipe_hash != manifest.build_recipe_hash:
        raise QualificationVerificationError(
            "expected artifact catalog does not bind the BQM build recipe"
        )
    if (
        manifest.expected_artifact_count != len(expected_keys)
        or observed_keys != expected_keys
    ):
        raise QualificationVerificationError(
            "BQM expected and observed artifact sets differ"
        )
    _validate_schema(manifest.model_dump(mode="json"), schema, label="BQM")


def content_address_build_qualification_manifest(
    manifest: BuildQualificationManifest | Mapping[str, Any],
    *,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    contract_root: Path,
    policy_manifest_path: Path,
    evidence_root: Path,
) -> ContentAddressedBqm:
    """Validate and content-address one exact CE development-test BQM."""

    validated = BuildQualificationManifest.model_validate(manifest)
    validated_index = EvidenceBundleIndex.model_validate(qualification_index)
    _validate_bqm_contract(
        validated,
        qualification_index=validated_index,
        contract_root=contract_root,
        policy_manifest_path=policy_manifest_path,
        evidence_root=evidence_root,
    )
    payload = canonical_json_bytes(validated.model_dump(mode="json"))
    return ContentAddressedBqm(validated, payload, sha256_digest(payload))


def _bqa_evidence_index(
    attestation: BuildQualificationAttestation,
) -> EvidenceBundleIndex:
    entries = sorted(
        [
            attestation.revocation_status,
            attestation.trusted_time_receipt_envelope,
            attestation.verification_material_bundle,
        ],
        key=lambda item: item.logical_name,
    )
    return EvidenceBundleIndex(
        schema_version="pmorg.evidence-bundle-index/v1",
        bundle_kind="build-qualification-attestation-support",
        subject_binding_hash=attestation.build_manifest_hash,
        entries=entries,
        entry_count=len(entries),
    )


def _validate_bqa_contract(
    attestation: BuildQualificationAttestation,
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex,
    contract_root: Path,
    evidence_root: Path,
) -> None:
    _, schema = _load_contract_schema(contract_root, BQA_SCHEMA_VERSION)
    if attestation.build_manifest_hash != bqm.digest:
        raise QualificationVerificationError("BQA does not bind the exact BQM")
    if attestation.artifact_set_hash != bqm.manifest.artifact_set_hash:
        raise QualificationVerificationError("BQA artifact set binding is invalid")
    if attestation.qualification_bundle_index_hash != (
        bqm.manifest.qualification_bundle_index_hash
    ):
        raise QualificationVerificationError(
            "BQA qualification index binding is invalid"
        )
    if not (
        attestation.valid_from
        <= attestation.issued_at
        < attestation.next_revalidation_at
        <= attestation.valid_until
    ):
        raise QualificationVerificationError("BQA validity window is invalid")
    validity_seconds = (
        attestation.valid_until - attestation.valid_from
    ).total_seconds()
    revalidation_seconds = (
        attestation.next_revalidation_at - attestation.issued_at
    ).total_seconds()
    if validity_seconds > attestation.temporal_policy.max_validity_seconds:
        raise QualificationVerificationError("BQA exceeds its maximum validity window")
    if revalidation_seconds > (
        attestation.temporal_policy.max_revalidation_interval_seconds
    ):
        raise QualificationVerificationError("BQA exceeds its revalidation interval")
    deadlines = [
        *verify_offline_evidence_index(qualification_index, root=evidence_root),
        *verify_offline_evidence_index(
            _bqa_evidence_index(attestation),
            root=evidence_root,
            require_sorted=True,
        ),
    ]
    if not deadlines:
        raise QualificationVerificationError("BQA has no offline contributor deadline")
    earliest_deadline = min(deadlines)
    if attestation.valid_until > earliest_deadline:
        raise QualificationVerificationError(
            "BQA validity exceeds a contributor deadline"
        )
    if attestation.next_revalidation_at > earliest_deadline:
        raise QualificationVerificationError(
            "BQA revalidation exceeds a contributor deadline"
        )
    _validate_schema(attestation.model_dump(mode="json"), schema, label="BQA")


def sign_build_qualification_attestation(
    attestation: BuildQualificationAttestation | Mapping[str, Any],
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
    environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    """Emit one detached, single-signature BQA using ephemeral test keys."""

    validated = BuildQualificationAttestation.model_validate(attestation)
    validated_index = EvidenceBundleIndex.model_validate(qualification_index)
    _validate_bqa_contract(
        validated,
        bqm=bqm,
        qualification_index=validated_index,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    payload = canonical_json_bytes(validated.model_dump(mode="json"))
    try:
        private_key = private_key_from_env(name=BQA_PRIVATE_KEY_ENV, environ=environ)
    except ValueError as error:
        raise QualificationVerificationError(
            "BQA ephemeral private key is invalid"
        ) from error
    signature = private_key.sign(pre_authentication_encoding(BQA_PAYLOAD_TYPE, payload))
    return DsseEnvelope(
        payloadType=BQA_PAYLOAD_TYPE,
        payload=base64.b64encode(payload).decode("ascii"),
        signatures=[
            DsseSignature(
                keyid=key_id(private_key.public_key()),
                sig=base64.b64encode(signature).decode("ascii"),
            )
        ],
    )


def verify_build_qualification_attestation(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
    environ: Mapping[str, str] | None = None,
) -> BuildQualificationAttestation:
    """Verify BQA signature, canonical payload, bindings, evidence, and deadlines."""

    validated_envelope = DsseEnvelope.model_validate(envelope)
    if validated_envelope.payloadType != BQA_PAYLOAD_TYPE:
        raise QualificationVerificationError("unexpected BQA DSSE payload type")
    if len(validated_envelope.signatures) != 1:
        raise QualificationVerificationError("BQA requires exactly one DSSE signature")
    payload = _decode_base64(validated_envelope.payload, label="BQA payload")
    signature_record = validated_envelope.signatures[0]
    signature = _decode_base64(signature_record.sig, label="BQA signature")
    try:
        public_key = public_key_from_env(name=BQA_PUBLIC_KEY_ENV, environ=environ)
    except ValueError as error:
        raise QualificationVerificationError(
            "BQA ephemeral public key is invalid"
        ) from error
    if signature_record.keyid != key_id(public_key):
        raise QualificationVerificationError("BQA key identity is invalid")
    try:
        public_key.verify(
            signature,
            pre_authentication_encoding(BQA_PAYLOAD_TYPE, payload),
        )
    except InvalidSignature as error:
        raise QualificationVerificationError("BQA DSSE signature is invalid") from error
    try:
        decoded = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationVerificationError("BQA payload is not valid JSON") from error
    if canonical_json_bytes(decoded) != payload:
        raise QualificationVerificationError("BQA payload is not canonical JSON")
    try:
        attestation = BuildQualificationAttestation.model_validate_json(payload)
    except ValidationError as error:
        raise QualificationVerificationError("BQA payload model is invalid") from error
    validated_index = EvidenceBundleIndex.model_validate(qualification_index)
    _validate_bqa_contract(
        attestation,
        bqm=bqm,
        qualification_index=validated_index,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return attestation


__all__ = [
    "BQA_PAYLOAD_TYPE",
    "BQA_PRIVATE_KEY_ENV",
    "BQA_PUBLIC_KEY_ENV",
    "ContentAddressedBqm",
    "QualificationVerificationError",
    "artifact_set_digest",
    "content_address_build_qualification_manifest",
    "sha256_digest",
    "sign_build_qualification_attestation",
    "verify_build_qualification_attestation",
    "verify_offline_evidence_index",
]
