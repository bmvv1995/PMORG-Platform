"""Create and evaluate fail-closed CE development-test distribution admissions."""

from __future__ import annotations

from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Any
from typing import Literal
from uuid import UUID

from pydantic import ValidationError

from pmorg.application.admission import _envelope_digest
from pmorg.application.admission import _evidence_deadlines
from pmorg.application.admission import _load_contract_schema
from pmorg.application.admission import _sign_envelope
from pmorg.application.admission import _validate_schema
from pmorg.application.admission import _validate_temporal_window
from pmorg.application.admission import _verify_envelope
from pmorg.application.admission import AdmissionVerificationError
from pmorg.application.admission import artifact_id_set_digest
from pmorg.application.qualification import ContentAddressedBqm
from pmorg.application.qualification import QualificationVerificationError
from pmorg.application.qualification import sha256_digest
from pmorg.application.qualification import verify_build_qualification_attestation
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.contracts.types import AdmissionUseReceiptPayload
from pmorg.contracts.types import BuildQualificationAttestation
from pmorg.contracts.types import DistributionAdmissionRecord
from pmorg.contracts.types import DistributionDestinationDescriptor
from pmorg.contracts.types import DistributionDestinationMeasurementAttestation
from pmorg.contracts.types import DistributionPayloadDescriptor
from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import EvidenceBundleIndex
from pmorg.contracts.types import RuntimeScopePolicyMap

DISTRIBUTION_ADMISSION_PAYLOAD_TYPE = (
    "application/vnd.pmorg.distribution-admission.v1+json"
)
DESTINATION_MEASUREMENT_PAYLOAD_TYPE = (
    "application/vnd.pmorg.distribution-destination-measurement.v1+json"
)
DISTRIBUTION_ADMISSION_SCHEMA_VERSION = "pmorg.distribution-admission/v1"
DISTRIBUTION_PAYLOAD_SCHEMA_VERSION = "pmorg.distribution-payload-descriptor/v1"
DISTRIBUTION_DESTINATION_SCHEMA_VERSION = "pmorg.distribution-destination-descriptor/v1"
DESTINATION_MEASUREMENT_SCHEMA_VERSION = "pmorg.distribution-destination-measurement/v1"

DESTINATION_MEASUREMENT_PRIVATE_KEY_ENV = (
    "PMORG_DISTRIBUTION_DESTINATION_TEST_ED25519_PRIVATE_KEY"
)
DESTINATION_MEASUREMENT_PUBLIC_KEY_ENV = (
    "PMORG_DISTRIBUTION_DESTINATION_TEST_ED25519_PUBLIC_KEY"
)
DISTRIBUTION_ADMISSION_PRIVATE_KEY_ENV = (
    "PMORG_DISTRIBUTION_ADMISSION_TEST_ED25519_PRIVATE_KEY"
)
DISTRIBUTION_ADMISSION_PUBLIC_KEY_ENV = (
    "PMORG_DISTRIBUTION_ADMISSION_TEST_ED25519_PUBLIC_KEY"
)

DistributionOperation = Literal["registry_publish", "artifact_export"]
DistributionVerificationEvent = Literal[
    "registry_publish",
    "artifact_export",
    "transfer_revalidation",
]
DistributionReceiptVerdict = Literal["allow", "deny", "abort"]


@dataclass(frozen=True, slots=True)
class ContentAddressedDistributionPayload:
    """Canonical distribution subset and exact identity."""

    descriptor: DistributionPayloadDescriptor
    payload: bytes
    digest: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class ContentAddressedDistributionDestination:
    """Canonical measured distribution destination and exact identity."""

    descriptor: DistributionDestinationDescriptor
    payload: bytes
    digest: str
    fingerprint: str


def _distribution_payload_fingerprint(
    descriptor: DistributionPayloadDescriptor,
) -> str:
    value = descriptor.model_dump(mode="json")
    value.pop("distribution_payload_hash")
    return sha256_digest(canonical_json_bytes(value))


def _runtime_scope_entry(
    *,
    operation: DistributionOperation,
    runtime_scope_policy_map: RuntimeScopePolicyMap,
    qualification_index: EvidenceBundleIndex,
    bqm: ContentAddressedBqm,
    contract_root: Path,
    evidence_root: Path,
):
    refs = {item.logical_name: item for item in qualification_index.entries}
    try:
        runtime_ref = refs["runtime-scope-policy-map"]
    except KeyError as error:
        raise AdmissionVerificationError(
            "qualification evidence has no runtime scope policy map"
        ) from error
    runtime_bytes = canonical_json_bytes(
        runtime_scope_policy_map.model_dump(mode="json")
    )
    if (
        sha256_digest(runtime_bytes) != runtime_ref.digest
        or runtime_ref.digest != bqm.manifest.runtime_scope_policy_map_hash
    ):
        raise AdmissionVerificationError(
            "runtime scope policy map is not bound to the qualified build"
        )
    _evidence_deadlines([runtime_ref], evidence_root=evidence_root)
    if runtime_scope_policy_map.onyx_surface != "ce":
        raise AdmissionVerificationError("distribution admits only the CE surface")
    if (
        runtime_scope_policy_map.baseline_manifest_hash
        != bqm.manifest.baseline_manifest_hash
    ):
        raise AdmissionVerificationError(
            "runtime scope policy map baseline binding is invalid"
        )
    entries = {item.scope_class: item for item in runtime_scope_policy_map.entries}
    if set(entries) != {
        "deployment_runtime",
        "registry_publish",
        "artifact_export",
    } or len(entries) != len(runtime_scope_policy_map.entries):
        raise AdmissionVerificationError("runtime scope policy classes are not exact")
    scope = entries[operation]
    if scope.expected_release_metadata_role_set_hash is None:
        raise AdmissionVerificationError(
            "distribution scope has no release metadata role set"
        )
    _, destination_schema_digest = _load_contract_schema(
        contract_root,
        DISTRIBUTION_DESTINATION_SCHEMA_VERSION,
    )
    if scope.target_destination_policy_schema_hash != destination_schema_digest:
        raise AdmissionVerificationError(
            "distribution destination schema is not bound by the runtime map"
        )
    return scope


def content_address_distribution_payload(
    descriptor: DistributionPayloadDescriptor | Mapping[str, Any],
    *,
    release_metadata_index: EvidenceBundleIndex | Mapping[str, Any],
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
) -> ContentAddressedDistributionPayload:
    """Reconstruct the exact qualified subset and release metadata to distribute."""

    validated = DistributionPayloadDescriptor.model_validate(descriptor)
    metadata_index = EvidenceBundleIndex.model_validate(release_metadata_index)
    validated_index = EvidenceBundleIndex.model_validate(qualification_index)
    runtime_map = RuntimeScopePolicyMap.model_validate(runtime_scope_policy_map)
    scope = _runtime_scope_entry(
        operation=validated.operation,
        runtime_scope_policy_map=runtime_map,
        qualification_index=validated_index,
        bqm=bqm,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    descriptors = [
        item.model_dump(mode="json")
        for item in validated.deployable_artifact_descriptors
    ]
    if descriptors != sorted(
        descriptors,
        key=lambda item: (item["artifact_id"], item["platform"]),
    ):
        raise AdmissionVerificationError("distribution artifacts are not ordered")
    keys = [
        (item.artifact_id, item.platform)
        for item in validated.deployable_artifact_descriptors
    ]
    if len(keys) != len(set(keys)):
        raise AdmissionVerificationError("distribution artifact keys are duplicated")
    if any(
        count != 0
        for count in (
            validated.missing_deployable_artifact_count,
            validated.unexpected_deployable_artifact_count,
            validated.duplicate_deployable_artifact_key_count,
            validated.missing_release_metadata_count,
            validated.unexpected_release_metadata_count,
            validated.duplicate_release_metadata_count,
        )
    ):
        raise AdmissionVerificationError("distribution payload coverage is not exact")
    if validated.deployable_artifact_count != len(
        descriptors
    ) or validated.expected_deployable_artifact_count != len(descriptors):
        raise AdmissionVerificationError("distribution artifact count is not exact")
    qualified = {
        (item.artifact_id, item.platform): item.model_dump(mode="json")
        for item in bqm.manifest.artifact_descriptors
    }
    if any(qualified.get(key) != value for key, value in zip(keys, descriptors)):
        raise AdmissionVerificationError(
            "distribution payload contains an unqualified or drifted artifact"
        )
    artifact_ids = [
        item.artifact_id for item in validated.deployable_artifact_descriptors
    ]
    artifact_set_hash = artifact_id_set_digest(artifact_ids)
    if (
        validated.expected_artifact_id_set_hash != artifact_set_hash
        or scope.expected_artifact_id_set_hash != artifact_set_hash
        or validated.distribution_scope_policy_hash != scope.scope_policy_hash
    ):
        raise AdmissionVerificationError(
            "distribution artifact subset does not match the runtime scope"
        )

    metadata_values = [item.model_dump(mode="json") for item in metadata_index.entries]
    metadata_roles = [item.logical_name for item in metadata_index.entries]
    if metadata_values != sorted(
        metadata_values, key=lambda item: item["logical_name"]
    ):
        raise AdmissionVerificationError("release metadata entries are not ordered")
    if len(metadata_roles) != len(set(metadata_roles)):
        raise AdmissionVerificationError("release metadata roles are duplicated")
    role_set_hash = artifact_id_set_digest(metadata_roles)
    metadata_payload = canonical_json_bytes(metadata_index.model_dump(mode="json"))
    if (
        validated.expected_release_metadata_role_set_hash != role_set_hash
        or scope.expected_release_metadata_role_set_hash != role_set_hash
    ):
        raise AdmissionVerificationError(
            "release metadata roles do not match the runtime scope"
        )
    if (
        validated.release_metadata_bundle_index_hash != sha256_digest(metadata_payload)
        or validated.release_metadata_entry_count != len(metadata_values)
        or validated.expected_release_metadata_entry_count != len(metadata_values)
        or metadata_index.entry_count != len(metadata_values)
    ):
        raise AdmissionVerificationError("release metadata index is not exact")
    _evidence_deadlines(metadata_index.entries, evidence_root=evidence_root)
    if validated.distribution_payload_hash != _distribution_payload_fingerprint(
        validated
    ):
        raise AdmissionVerificationError(
            "distribution payload hash is not content-derived"
        )
    _validate_schema(
        validated.model_dump(mode="json"),
        contract_root=contract_root,
        schema_version=DISTRIBUTION_PAYLOAD_SCHEMA_VERSION,
        label="distribution payload descriptor",
    )
    payload = canonical_json_bytes(validated.model_dump(mode="json"))
    return ContentAddressedDistributionPayload(
        descriptor=validated,
        payload=payload,
        digest=sha256_digest(payload),
        fingerprint=validated.distribution_payload_hash,
    )


def content_address_distribution_destination(
    descriptor: DistributionDestinationDescriptor | Mapping[str, Any],
    *,
    contract_root: Path,
) -> ContentAddressedDistributionDestination:
    """Reconstruct the exact controlled synthetic destination."""

    validated = DistributionDestinationDescriptor.model_validate(descriptor)
    if validated.derived_destination_class != "controlled_synthetic_registry":
        raise AdmissionVerificationError(
            "distribution admits only a controlled synthetic destination"
        )
    if validated.production_destination_count != 0:
        raise AdmissionVerificationError("production destinations are not admitted")
    if validated.unknown_destination_count != 0:
        raise AdmissionVerificationError("unknown destinations are not admitted")
    _validate_schema(
        validated.model_dump(mode="json"),
        contract_root=contract_root,
        schema_version=DISTRIBUTION_DESTINATION_SCHEMA_VERSION,
        label="distribution destination descriptor",
    )
    payload = canonical_json_bytes(validated.model_dump(mode="json"))
    digest = sha256_digest(payload)
    return ContentAddressedDistributionDestination(
        descriptor=validated,
        payload=payload,
        digest=digest,
        fingerprint=digest,
    )


def _validate_destination_measurement(
    measurement: DistributionDestinationMeasurementAttestation,
    *,
    destination: ContentAddressedDistributionDestination,
    contract_root: Path,
    evidence_root: Path,
) -> None:
    if (
        measurement.destination_descriptor_hash != destination.digest
        or measurement.destination_fingerprint != destination.fingerprint
    ):
        raise AdmissionVerificationError(
            "destination measurement does not bind the destination"
        )
    if not measurement.valid_from <= measurement.measured_at <= measurement.issued_at:
        raise AdmissionVerificationError(
            "destination measurement timestamps are invalid"
        )
    _validate_temporal_window(
        valid_from=measurement.valid_from,
        issued_at=measurement.issued_at,
        next_revalidation_at=measurement.next_revalidation_at,
        valid_until=measurement.valid_until,
        max_validity_seconds=measurement.temporal_policy.max_validity_seconds,
        max_revalidation_interval_seconds=(
            measurement.temporal_policy.max_revalidation_interval_seconds
        ),
        label="destination measurement",
    )
    if (
        measurement.issued_at - measurement.measured_at
    ).total_seconds() > measurement.temporal_policy.max_measurement_age_seconds:
        raise AdmissionVerificationError("destination measurement is already stale")
    deadlines = _evidence_deadlines(
        [
            measurement.destination_evidence_bundle,
            measurement.trusted_time_receipt_envelope,
            measurement.verification_material_bundle,
        ],
        evidence_root=evidence_root,
    )
    if not deadlines:
        raise AdmissionVerificationError(
            "destination measurement has no contributor deadline"
        )
    earliest_deadline = min(deadlines)
    if measurement.valid_until > earliest_deadline:
        raise AdmissionVerificationError(
            "destination measurement validity exceeds a contributor deadline"
        )
    if measurement.next_revalidation_at > earliest_deadline:
        raise AdmissionVerificationError(
            "destination measurement revalidation exceeds a contributor deadline"
        )
    _validate_schema(
        measurement.model_dump(mode="json"),
        contract_root=contract_root,
        schema_version=DESTINATION_MEASUREMENT_SCHEMA_VERSION,
        label="distribution destination measurement",
    )


def sign_destination_measurement(
    measurement: DistributionDestinationMeasurementAttestation | Mapping[str, Any],
    *,
    destination: ContentAddressedDistributionDestination,
    contract_root: Path,
    evidence_root: Path,
    environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    """Sign a measured synthetic distribution destination."""

    validated = DistributionDestinationMeasurementAttestation.model_validate(
        measurement
    )
    _validate_destination_measurement(
        validated,
        destination=destination,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return _sign_envelope(
        canonical_json_bytes(validated.model_dump(mode="json")),
        payload_type=DESTINATION_MEASUREMENT_PAYLOAD_TYPE,
        private_key_env=DESTINATION_MEASUREMENT_PRIVATE_KEY_ENV,
        environ=environ,
    )


def verify_destination_measurement(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    destination: ContentAddressedDistributionDestination,
    contract_root: Path,
    evidence_root: Path,
    environ: Mapping[str, str] | None = None,
) -> DistributionDestinationMeasurementAttestation:
    """Verify measurement signature, destination binding, evidence, and time."""

    payload_bytes = _verify_envelope(
        envelope,
        payload_type=DESTINATION_MEASUREMENT_PAYLOAD_TYPE,
        public_key_env=DESTINATION_MEASUREMENT_PUBLIC_KEY_ENV,
        environ=environ,
        label="distribution destination measurement",
    )
    try:
        measurement = DistributionDestinationMeasurementAttestation.model_validate_json(
            payload_bytes
        )
    except ValidationError as error:
        raise AdmissionVerificationError(
            "destination measurement payload model is invalid"
        ) from error
    _validate_destination_measurement(
        measurement,
        destination=destination,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return measurement


def _validate_distribution_admission(
    admission: DistributionAdmissionRecord,
    *,
    bqm: ContentAddressedBqm,
    bqa: BuildQualificationAttestation,
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    payload: ContentAddressedDistributionPayload,
    destination: ContentAddressedDistributionDestination,
    destination_measurement: DistributionDestinationMeasurementAttestation,
    destination_measurement_envelope: DsseEnvelope | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
) -> None:
    if admission.operation != payload.descriptor.operation:
        raise AdmissionVerificationError(
            "distribution operation does not match payload"
        )
    if admission.operation != destination.descriptor.operation:
        raise AdmissionVerificationError(
            "distribution operation does not match destination"
        )
    if admission.onyx_surface != "ce" or admission.usage_mode != "development_test":
        raise AdmissionVerificationError(
            "distribution admission admits only CE development_test"
        )
    if (
        admission.admission_basis != "synthetic_environment"
        or admission.destination_class != "controlled_synthetic_registry"
        or admission.ce_release_authorization is not None
        or admission.enterprise_authorization is not None
    ):
        raise AdmissionVerificationError(
            "distribution admission has a non-synthetic authorization basis"
        )
    if (
        bqm.manifest.onyx_surface != "ce"
        or bqm.manifest.usage_mode != "development_test"
    ):
        raise AdmissionVerificationError("qualified build is outside admission scope")
    if (
        admission.artifact_set_hash != bqm.manifest.artifact_set_hash
        or admission.build_manifest_hash != bqm.digest
        or admission.build_attestation_envelope_hash != _envelope_digest(bqa_envelope)
    ):
        raise AdmissionVerificationError(
            "distribution admission does not bind the qualified build"
        )
    if (
        bqa.build_manifest_hash != bqm.digest
        or bqa.artifact_set_hash != bqm.manifest.artifact_set_hash
    ):
        raise AdmissionVerificationError("build attestation binding is invalid")
    if (
        admission.distribution_payload_descriptor_hash != payload.digest
        or admission.distribution_payload_hash != payload.fingerprint
    ):
        raise AdmissionVerificationError(
            "distribution admission does not bind the reconstructed payload"
        )
    if (
        admission.destination_descriptor_hash != destination.digest
        or admission.destination_fingerprint != destination.fingerprint
    ):
        raise AdmissionVerificationError(
            "distribution admission does not bind the reconstructed destination"
        )
    if (
        admission.destination_measurement_envelope_hash
        != _envelope_digest(destination_measurement_envelope)
        or destination_measurement.destination_descriptor_hash != destination.digest
    ):
        raise AdmissionVerificationError(
            "distribution admission destination measurement binding is invalid"
        )
    if (
        admission.trusted_clock_id != bqa.trusted_clock_id
        or admission.trusted_clock_id != destination_measurement.trusted_clock_id
    ):
        raise AdmissionVerificationError("distribution trusted clock identity drifts")
    if admission.temporal_policy != destination_measurement.temporal_policy:
        raise AdmissionVerificationError("distribution temporal policy drifts")
    _validate_temporal_window(
        valid_from=admission.valid_from,
        issued_at=admission.issued_at,
        next_revalidation_at=admission.next_revalidation_at,
        valid_until=admission.valid_until,
        max_validity_seconds=admission.temporal_policy.max_validity_seconds,
        max_revalidation_interval_seconds=(
            admission.temporal_policy.max_revalidation_interval_seconds
        ),
        label="distribution admission",
    )
    if admission.valid_from < max(bqa.valid_from, destination_measurement.valid_from):
        raise AdmissionVerificationError(
            "distribution admission starts before a contributor is valid"
        )
    if admission.issued_at < max(bqa.issued_at, destination_measurement.issued_at):
        raise AdmissionVerificationError(
            "distribution admission predates contributor verification"
        )
    if admission.valid_until > min(
        bqa.valid_until,
        destination_measurement.valid_until,
    ):
        raise AdmissionVerificationError(
            "distribution admission validity exceeds a contributor"
        )
    if admission.next_revalidation_at > min(
        bqa.next_revalidation_at,
        destination_measurement.next_revalidation_at,
    ):
        raise AdmissionVerificationError(
            "distribution admission revalidation exceeds a contributor"
        )
    if (
        admission.issued_at - destination_measurement.measured_at
    ).total_seconds() > admission.temporal_policy.max_measurement_age_seconds:
        raise AdmissionVerificationError(
            "distribution destination measurement is stale"
        )
    deadlines = _evidence_deadlines(
        [
            admission.trusted_time_receipt_envelope,
            admission.revocation_status,
            admission.verification_material_bundle,
            admission.verifier_receipt,
        ],
        evidence_root=evidence_root,
    )
    if not deadlines:
        raise AdmissionVerificationError(
            "distribution admission has no contributor deadline"
        )
    earliest_deadline = min(deadlines)
    if admission.valid_until > earliest_deadline:
        raise AdmissionVerificationError(
            "distribution admission validity exceeds an evidence deadline"
        )
    if admission.next_revalidation_at > earliest_deadline:
        raise AdmissionVerificationError(
            "distribution admission revalidation exceeds an evidence deadline"
        )
    _validate_schema(
        admission.model_dump(mode="json"),
        contract_root=contract_root,
        schema_version=DISTRIBUTION_ADMISSION_SCHEMA_VERSION,
        label="distribution admission",
    )


def _reconstruct_dependencies(
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    release_metadata_index: EvidenceBundleIndex | Mapping[str, Any],
    payload_descriptor: DistributionPayloadDescriptor | Mapping[str, Any],
    destination_descriptor: DistributionDestinationDescriptor | Mapping[str, Any],
    destination_measurement_envelope: DsseEnvelope | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
    bqa_environ: Mapping[str, str] | None,
    measurement_environ: Mapping[str, str] | None,
) -> tuple[
    BuildQualificationAttestation,
    ContentAddressedDistributionPayload,
    ContentAddressedDistributionDestination,
    DistributionDestinationMeasurementAttestation,
]:
    validated_index = EvidenceBundleIndex.model_validate(qualification_index)
    try:
        bqa = verify_build_qualification_attestation(
            bqa_envelope,
            bqm=bqm,
            qualification_index=validated_index,
            contract_root=contract_root,
            evidence_root=evidence_root,
            environ=bqa_environ,
        )
    except QualificationVerificationError as error:
        raise AdmissionVerificationError(
            "qualified build attestation is invalid"
        ) from error
    payload = content_address_distribution_payload(
        payload_descriptor,
        release_metadata_index=release_metadata_index,
        bqm=bqm,
        qualification_index=validated_index,
        runtime_scope_policy_map=runtime_scope_policy_map,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    destination = content_address_distribution_destination(
        destination_descriptor,
        contract_root=contract_root,
    )
    measurement = verify_destination_measurement(
        destination_measurement_envelope,
        destination=destination,
        contract_root=contract_root,
        evidence_root=evidence_root,
        environ=measurement_environ,
    )
    return bqa, payload, destination, measurement


def sign_distribution_admission(
    admission: DistributionAdmissionRecord | Mapping[str, Any],
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    release_metadata_index: EvidenceBundleIndex | Mapping[str, Any],
    payload_descriptor: DistributionPayloadDescriptor | Mapping[str, Any],
    destination_descriptor: DistributionDestinationDescriptor | Mapping[str, Any],
    destination_measurement_envelope: DsseEnvelope | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
    bqa_environ: Mapping[str, str] | None = None,
    measurement_environ: Mapping[str, str] | None = None,
    admission_environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    """Sign one fully reconstructed synthetic distribution admission."""

    bqa, payload, destination, measurement = _reconstruct_dependencies(
        bqm=bqm,
        qualification_index=qualification_index,
        bqa_envelope=bqa_envelope,
        runtime_scope_policy_map=runtime_scope_policy_map,
        release_metadata_index=release_metadata_index,
        payload_descriptor=payload_descriptor,
        destination_descriptor=destination_descriptor,
        destination_measurement_envelope=destination_measurement_envelope,
        contract_root=contract_root,
        evidence_root=evidence_root,
        bqa_environ=bqa_environ,
        measurement_environ=measurement_environ,
    )
    validated = DistributionAdmissionRecord.model_validate(admission)
    _validate_distribution_admission(
        validated,
        bqm=bqm,
        bqa=bqa,
        bqa_envelope=bqa_envelope,
        payload=payload,
        destination=destination,
        destination_measurement=measurement,
        destination_measurement_envelope=destination_measurement_envelope,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return _sign_envelope(
        canonical_json_bytes(validated.model_dump(mode="json")),
        payload_type=DISTRIBUTION_ADMISSION_PAYLOAD_TYPE,
        private_key_env=DISTRIBUTION_ADMISSION_PRIVATE_KEY_ENV,
        environ=admission_environ,
    )


def verify_distribution_admission(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    release_metadata_index: EvidenceBundleIndex | Mapping[str, Any],
    payload_descriptor: DistributionPayloadDescriptor | Mapping[str, Any],
    destination_descriptor: DistributionDestinationDescriptor | Mapping[str, Any],
    destination_measurement_envelope: DsseEnvelope | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
    bqa_environ: Mapping[str, str] | None = None,
    measurement_environ: Mapping[str, str] | None = None,
    admission_environ: Mapping[str, str] | None = None,
) -> tuple[
    DistributionAdmissionRecord,
    BuildQualificationAttestation,
    DistributionDestinationMeasurementAttestation,
]:
    """Verify an admission and independently reconstruct every governed input."""

    bqa, payload, destination, measurement = _reconstruct_dependencies(
        bqm=bqm,
        qualification_index=qualification_index,
        bqa_envelope=bqa_envelope,
        runtime_scope_policy_map=runtime_scope_policy_map,
        release_metadata_index=release_metadata_index,
        payload_descriptor=payload_descriptor,
        destination_descriptor=destination_descriptor,
        destination_measurement_envelope=destination_measurement_envelope,
        contract_root=contract_root,
        evidence_root=evidence_root,
        bqa_environ=bqa_environ,
        measurement_environ=measurement_environ,
    )
    payload_bytes = _verify_envelope(
        envelope,
        payload_type=DISTRIBUTION_ADMISSION_PAYLOAD_TYPE,
        public_key_env=DISTRIBUTION_ADMISSION_PUBLIC_KEY_ENV,
        environ=admission_environ,
        label="distribution admission",
    )
    try:
        admission = DistributionAdmissionRecord.model_validate_json(payload_bytes)
    except ValidationError as error:
        raise AdmissionVerificationError(
            "distribution admission payload model is invalid"
        ) from error
    _validate_distribution_admission(
        admission,
        bqm=bqm,
        bqa=bqa,
        bqa_envelope=bqa_envelope,
        payload=payload,
        destination=destination,
        destination_measurement=measurement,
        destination_measurement_envelope=destination_measurement_envelope,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return admission, bqa, measurement


def _receipt_verdict(
    *,
    verification_event: DistributionVerificationEvent,
    allow: bool,
) -> DistributionReceiptVerdict:
    if allow:
        return "allow"
    if verification_event == "transfer_revalidation":
        return "abort"
    return "deny"


def evaluate_distribution_use(
    *,
    use_id: UUID,
    verification_event: DistributionVerificationEvent,
    governed_operation: DistributionOperation,
    admission_envelope: DsseEnvelope | Mapping[str, Any] | None,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    release_metadata_index: EvidenceBundleIndex | Mapping[str, Any],
    actual_payload_descriptor: DistributionPayloadDescriptor | Mapping[str, Any],
    actual_destination_descriptor: DistributionDestinationDescriptor
    | Mapping[str, Any],
    post_auth_destination_descriptor: DistributionDestinationDescriptor
    | Mapping[str, Any],
    redirect_destination_descriptors: Sequence[
        DistributionDestinationDescriptor | Mapping[str, Any]
    ],
    destination_measurement_envelope: DsseEnvelope | Mapping[str, Any],
    trusted_time_receipt_envelope: EvidenceArtifactRef,
    revocation_check: EvidenceArtifactRef,
    verification_material_bundle: EvidenceArtifactRef,
    verifier_identity: str,
    verification_policy_hash: str,
    now: datetime,
    contract_root: Path,
    evidence_root: Path,
    bqa_environ: Mapping[str, str] | None = None,
    measurement_environ: Mapping[str, str] | None = None,
    admission_environ: Mapping[str, str] | None = None,
) -> AdmissionUseReceiptPayload:
    """Deny before publish/export and abort transfers before any deadline."""

    if now.utcoffset() is None or now.utcoffset() != timedelta(0):
        raise AdmissionVerificationError("verification time must be UTC")
    reconstruction_error = False
    try:
        payload = content_address_distribution_payload(
            actual_payload_descriptor,
            release_metadata_index=release_metadata_index,
            bqm=bqm,
            qualification_index=qualification_index,
            runtime_scope_policy_map=runtime_scope_policy_map,
            contract_root=contract_root,
            evidence_root=evidence_root,
        )
    except (AdmissionVerificationError, ValidationError):
        reconstructed = DistributionPayloadDescriptor.model_validate(
            actual_payload_descriptor
        )
        raw = canonical_json_bytes(reconstructed.model_dump(mode="json"))
        payload = ContentAddressedDistributionPayload(
            descriptor=reconstructed,
            payload=raw,
            digest=sha256_digest(raw),
            fingerprint=reconstructed.distribution_payload_hash,
        )
        reconstruction_error = True
    try:
        destination = content_address_distribution_destination(
            actual_destination_descriptor,
            contract_root=contract_root,
        )
    except (AdmissionVerificationError, ValidationError):
        reconstructed_destination = DistributionDestinationDescriptor.model_validate(
            actual_destination_descriptor
        )
        raw_destination = canonical_json_bytes(
            reconstructed_destination.model_dump(mode="json")
        )
        destination_digest = sha256_digest(raw_destination)
        destination = ContentAddressedDistributionDestination(
            descriptor=reconstructed_destination,
            payload=raw_destination,
            digest=destination_digest,
            fingerprint=destination_digest,
        )
        reconstruction_error = True

    allow = False
    denial_reason: str | None = None
    admission_hash = sha256_digest(b"")
    if reconstruction_error:
        denial_reason = "actual_state_reconstruction_invalid"
    elif admission_envelope is None:
        denial_reason = "admission_missing"
    else:
        try:
            admission_hash = _envelope_digest(admission_envelope)
            admission, bqa, measurement = verify_distribution_admission(
                admission_envelope,
                bqm=bqm,
                qualification_index=qualification_index,
                bqa_envelope=bqa_envelope,
                runtime_scope_policy_map=runtime_scope_policy_map,
                release_metadata_index=release_metadata_index,
                payload_descriptor=actual_payload_descriptor,
                destination_descriptor=actual_destination_descriptor,
                destination_measurement_envelope=destination_measurement_envelope,
                contract_root=contract_root,
                evidence_root=evidence_root,
                bqa_environ=bqa_environ,
                measurement_environ=measurement_environ,
                admission_environ=admission_environ,
            )
            if admission.operation != governed_operation:
                raise AdmissionVerificationError("admission operation does not match")
            if verification_event not in {
                "registry_publish",
                "artifact_export",
                "transfer_revalidation",
            }:
                raise AdmissionVerificationError("verification event is invalid")
            if verification_event != "transfer_revalidation" and (
                verification_event != governed_operation
            ):
                raise AdmissionVerificationError("verification event does not match")
            for observed in [
                post_auth_destination_descriptor,
                *redirect_destination_descriptors,
            ]:
                observed_destination = content_address_distribution_destination(
                    observed,
                    contract_root=contract_root,
                )
                if (
                    observed_destination.digest != destination.digest
                    or observed_destination.fingerprint != destination.fingerprint
                ):
                    raise AdmissionVerificationError(
                        "destination changed after authorization or redirect"
                    )
            skew = timedelta(seconds=admission.temporal_policy.max_clock_skew_seconds)
            cutoff = (
                min(
                    admission.next_revalidation_at,
                    admission.valid_until,
                    bqa.next_revalidation_at,
                    bqa.valid_until,
                    measurement.next_revalidation_at,
                    measurement.valid_until,
                    measurement.measured_at
                    + timedelta(
                        seconds=admission.temporal_policy.max_measurement_age_seconds
                    ),
                )
                - skew
            )
            if now < admission.valid_from - skew:
                raise AdmissionVerificationError("admission is not yet valid")
            if now >= cutoff:
                raise AdmissionVerificationError(
                    "distribution requires revalidation before its deadline"
                )
            allow = True
        except (AdmissionVerificationError, ValidationError):
            denial_reason = "admission_invalid_or_expired"
    try:
        current_deadlines = _evidence_deadlines(
            [
                trusted_time_receipt_envelope,
                revocation_check,
                verification_material_bundle,
            ],
            evidence_root=evidence_root,
        )
        if not current_deadlines or now >= min(current_deadlines):
            raise AdmissionVerificationError(
                "verification evidence is expired or has no deadline"
            )
    except AdmissionVerificationError:
        allow = False
        denial_reason = "verification_evidence_invalid"
    verdict = _receipt_verdict(
        verification_event=verification_event,
        allow=allow,
    )
    return AdmissionUseReceiptPayload(
        schema_version="pmorg.admission-use-receipt/v1",
        use_id=use_id,
        verification_event=verification_event,
        governed_operation=governed_operation,
        admission_envelope_hash=admission_hash,
        actual_payload_descriptor_hash=payload.digest,
        actual_payload_fingerprint=payload.fingerprint,
        actual_target_or_destination_descriptor_hash=destination.digest,
        actual_target_or_destination_fingerprint=destination.fingerprint,
        trusted_time_receipt_envelope=trusted_time_receipt_envelope,
        revocation_check=revocation_check,
        verification_policy_hash=verification_policy_hash,
        verification_material_bundle=verification_material_bundle,
        verifier_identity=verifier_identity,
        verified_at=now,
        issued_at=now,
        verdict=verdict,
        denial_reason=None if allow else denial_reason,
    )


__all__ = [
    "DESTINATION_MEASUREMENT_PAYLOAD_TYPE",
    "DESTINATION_MEASUREMENT_PRIVATE_KEY_ENV",
    "DESTINATION_MEASUREMENT_PUBLIC_KEY_ENV",
    "DISTRIBUTION_ADMISSION_PAYLOAD_TYPE",
    "DISTRIBUTION_ADMISSION_PRIVATE_KEY_ENV",
    "DISTRIBUTION_ADMISSION_PUBLIC_KEY_ENV",
    "ContentAddressedDistributionDestination",
    "ContentAddressedDistributionPayload",
    "content_address_distribution_destination",
    "content_address_distribution_payload",
    "evaluate_distribution_use",
    "sign_destination_measurement",
    "sign_distribution_admission",
    "verify_destination_measurement",
    "verify_distribution_admission",
]
