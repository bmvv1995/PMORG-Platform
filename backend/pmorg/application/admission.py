"""Create and evaluate fail-closed CE development-test deployment admissions."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Any
from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.application.qualification import ContentAddressedBqm
from pmorg.application.qualification import QualificationVerificationError
from pmorg.application.qualification import sha256_digest
from pmorg.application.qualification import verify_build_qualification_attestation
from pmorg.application.qualification import verify_offline_evidence_index
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import key_id
from pmorg.application.rbdp import pre_authentication_encoding
from pmorg.application.rbdp import private_key_from_env
from pmorg.application.rbdp import public_key_from_env
from pmorg.contracts.types import AdmissionUseReceiptPayload
from pmorg.contracts.types import BuildQualificationAttestation
from pmorg.contracts.types import DeploymentAdmissionRecord
from pmorg.contracts.types import DeploymentPayloadDescriptor
from pmorg.contracts.types import DeploymentTargetDescriptor
from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import DsseSignature
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import EvidenceBundleIndex
from pmorg.contracts.types import RuntimeScopePolicyMap
from pmorg.contracts.types import TargetMeasurementAttestation

TARGET_MEASUREMENT_PAYLOAD_TYPE = (
    "application/vnd.pmorg.target-measurement-attestation.v1+json"
)
DEPLOYMENT_ADMISSION_PAYLOAD_TYPE = "application/vnd.pmorg.deployment-admission.v1+json"
TARGET_MEASUREMENT_SCHEMA_VERSION = "pmorg.target-measurement-attestation/v1"
DEPLOYMENT_ADMISSION_SCHEMA_VERSION = "pmorg.deployment-admission/v1"
DEPLOYMENT_PAYLOAD_SCHEMA_VERSION = "pmorg.deployment-payload-descriptor/v1"
DEPLOYMENT_TARGET_SCHEMA_VERSION = "pmorg.deployment-target-descriptor/v1"

MEASUREMENT_PRIVATE_KEY_ENV = "PMORG_TARGET_MEASUREMENT_TEST_ED25519_PRIVATE_KEY"
MEASUREMENT_PUBLIC_KEY_ENV = "PMORG_TARGET_MEASUREMENT_TEST_ED25519_PUBLIC_KEY"
ADMISSION_PRIVATE_KEY_ENV = "PMORG_DEPLOYMENT_ADMISSION_TEST_ED25519_PRIVATE_KEY"
ADMISSION_PUBLIC_KEY_ENV = "PMORG_DEPLOYMENT_ADMISSION_TEST_ED25519_PUBLIC_KEY"

DeploymentVerificationEvent = Literal[
    "deploy",
    "startup",
    "watchdog_revalidation",
]
DeploymentOperation = Literal["deploy", "startup"]
DeploymentReceiptVerdict = Literal["allow", "deny", "quiesce"]


class AdmissionVerificationError(ValueError):
    """Raised when an admission dependency, envelope, or use is invalid."""


@dataclass(frozen=True, slots=True)
class ContentAddressedDeploymentPayload:
    """Canonical deployment payload descriptor and its exact identity."""

    descriptor: DeploymentPayloadDescriptor
    payload: bytes
    digest: str


@dataclass(frozen=True, slots=True)
class ContentAddressedDeploymentTarget:
    """Canonical deployment target descriptor and its exact identity."""

    descriptor: DeploymentTargetDescriptor
    payload: bytes
    digest: str
    fingerprint: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionVerificationError(f"JSON repeats key: {key}")
        value[key] = item
    return value


def _decode_base64(value: str, *, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AdmissionVerificationError(f"{label} is not canonical base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise AdmissionVerificationError(f"{label} is not canonical base64")
    return decoded


def _load_contract_schema(
    contract_root: Path,
    schema_version: str,
) -> tuple[dict[str, Any], str]:
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
        raise AdmissionVerificationError(
            f"committed contract artifacts are incomplete for {schema_version}"
        ) from error
    digest = sha256_digest(schema_bytes)
    if digest != entry.get("schema_sha256"):
        raise AdmissionVerificationError(
            f"committed schema digest does not match manifest for {schema_version}"
        )
    if manifest.get("wire_surface") != "pmorg-contracts/1.0":
        raise AdmissionVerificationError("contract manifest has the wrong wire surface")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise AdmissionVerificationError(
            f"committed schema is invalid for {schema_version}"
        ) from error
    return schema, digest


def _validate_schema(
    value: Mapping[str, Any],
    *,
    contract_root: Path,
    schema_version: str,
    label: str,
) -> None:
    schema, _ = _load_contract_schema(contract_root, schema_version)
    try:
        Draft202012Validator(schema).validate(value)
    except Exception as error:
        raise AdmissionVerificationError(
            f"{label} does not validate against its committed schema"
        ) from error


def _evidence_deadlines(
    references: list[EvidenceArtifactRef],
    *,
    evidence_root: Path,
) -> tuple[datetime, ...]:
    deadlines: list[datetime] = []
    for index, reference in enumerate(references):
        bundle = EvidenceBundleIndex(
            schema_version="pmorg.evidence-bundle-index/v1",
            bundle_kind=f"deployment-admission-support-{index}",
            subject_binding_hash=None,
            entries=[reference],
            entry_count=1,
        )
        try:
            deadlines.extend(verify_offline_evidence_index(bundle, root=evidence_root))
        except QualificationVerificationError as error:
            raise AdmissionVerificationError(
                f"deployment admission evidence is invalid: {reference.logical_name}"
            ) from error
    return tuple(deadlines)


def _envelope_digest(envelope: DsseEnvelope | Mapping[str, Any]) -> str:
    validated = DsseEnvelope.model_validate(envelope)
    return sha256_digest(canonical_json_bytes(validated.model_dump(mode="json")))


def artifact_id_set_digest(artifact_ids: list[str]) -> str:
    """Hash the sorted, unique artifact ID set admitted by one runtime scope."""

    if not artifact_ids or len(artifact_ids) != len(set(artifact_ids)):
        raise AdmissionVerificationError("artifact ID set is empty or duplicated")
    return sha256_digest(canonical_json_bytes(sorted(artifact_ids)))


def _deployment_payload_fingerprint(
    descriptor: DeploymentPayloadDescriptor,
) -> str:
    value = descriptor.model_dump(mode="json")
    value.pop("deployment_payload_fingerprint")
    return sha256_digest(canonical_json_bytes(value))


def content_address_deployment_payload(
    descriptor: DeploymentPayloadDescriptor | Mapping[str, Any],
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
) -> ContentAddressedDeploymentPayload:
    """Reconstruct and bind an exact deployment payload to the qualified build."""

    validated = DeploymentPayloadDescriptor.model_validate(descriptor)
    validated_index = EvidenceBundleIndex.model_validate(qualification_index)
    runtime_map = RuntimeScopePolicyMap.model_validate(runtime_scope_policy_map)
    descriptor_values = [
        item.model_dump(mode="json") for item in validated.artifact_descriptors
    ]
    descriptor_keys = [
        (item.artifact_id, item.platform) for item in validated.artifact_descriptors
    ]
    if descriptor_values != sorted(
        descriptor_values,
        key=lambda item: (item["artifact_id"], item["platform"]),
    ):
        raise AdmissionVerificationError("deployment artifacts are not ordered")
    if len(descriptor_keys) != len(set(descriptor_keys)):
        raise AdmissionVerificationError("deployment artifact keys are duplicated")
    if any(
        count != 0
        for count in (
            validated.missing_artifact_count,
            validated.unexpected_artifact_count,
            validated.duplicate_artifact_key_count,
        )
    ):
        raise AdmissionVerificationError("deployment artifact coverage is not exact")
    if validated.artifact_count != len(
        descriptor_values
    ) or validated.expected_artifact_count != len(descriptor_values):
        raise AdmissionVerificationError("deployment artifact count is not exact")
    expected_values = [
        item.model_dump(mode="json") for item in bqm.manifest.artifact_descriptors
    ]
    if descriptor_values != expected_values:
        raise AdmissionVerificationError(
            "deployment payload differs from the qualified artifact set"
        )
    if validated.deployment_payload_fingerprint != (
        _deployment_payload_fingerprint(validated)
    ):
        raise AdmissionVerificationError(
            "deployment payload fingerprint is not content-derived"
        )

    refs = {item.logical_name: item for item in validated_index.entries}
    try:
        runtime_ref = refs["runtime-scope-policy-map"]
    except KeyError as error:
        raise AdmissionVerificationError(
            "qualification evidence has no runtime scope policy map"
        ) from error
    runtime_bytes = canonical_json_bytes(runtime_map.model_dump(mode="json"))
    if (
        sha256_digest(runtime_bytes) != runtime_ref.digest
        or runtime_ref.digest != bqm.manifest.runtime_scope_policy_map_hash
    ):
        raise AdmissionVerificationError(
            "runtime scope policy map is not bound to the qualified build"
        )
    _evidence_deadlines([runtime_ref], evidence_root=evidence_root)
    if runtime_map.onyx_surface != "ce":
        raise AdmissionVerificationError("deployment admits only the CE surface")
    if runtime_map.baseline_manifest_hash != bqm.manifest.baseline_manifest_hash:
        raise AdmissionVerificationError(
            "runtime scope policy map baseline binding is invalid"
        )
    scope_classes = [entry.scope_class for entry in runtime_map.entries]
    if sorted(scope_classes) != [
        "artifact_export",
        "deployment_runtime",
        "registry_publish",
    ] or len(scope_classes) != len(set(scope_classes)):
        raise AdmissionVerificationError("runtime scope policy classes are not exact")
    deployment_scope = next(
        entry
        for entry in runtime_map.entries
        if entry.scope_class == "deployment_runtime"
    )
    if validated.deployment_scope_policy_hash != deployment_scope.scope_policy_hash:
        raise AdmissionVerificationError(
            "deployment scope policy does not match the runtime map"
        )
    if deployment_scope.expected_artifact_id_set_hash != artifact_id_set_digest(
        [item.artifact_id for item in validated.artifact_descriptors]
    ):
        raise AdmissionVerificationError(
            "deployment artifact ID set does not match the runtime map"
        )
    _, target_schema_digest = _load_contract_schema(
        contract_root, DEPLOYMENT_TARGET_SCHEMA_VERSION
    )
    if deployment_scope.target_destination_policy_schema_hash != target_schema_digest:
        raise AdmissionVerificationError(
            "deployment target schema is not bound by the runtime map"
        )
    _validate_schema(
        validated.model_dump(mode="json"),
        contract_root=contract_root,
        schema_version=DEPLOYMENT_PAYLOAD_SCHEMA_VERSION,
        label="deployment payload descriptor",
    )
    payload = canonical_json_bytes(validated.model_dump(mode="json"))
    return ContentAddressedDeploymentPayload(
        descriptor=validated,
        payload=payload,
        digest=sha256_digest(payload),
    )


def content_address_deployment_target(
    descriptor: DeploymentTargetDescriptor | Mapping[str, Any],
    *,
    contract_root: Path,
) -> ContentAddressedDeploymentTarget:
    """Reconstruct the exact measured target identity from canonical bytes."""

    validated = DeploymentTargetDescriptor.model_validate(descriptor)
    if validated.derived_target_class != "synthetic_sandbox":
        raise AdmissionVerificationError(
            "deployment admission admits only a synthetic sandbox"
        )
    if validated.production_resource_count != 0:
        raise AdmissionVerificationError("production resources are not admitted")
    if validated.unknown_resource_count != 0:
        raise AdmissionVerificationError("unknown target resources are not admitted")
    _validate_schema(
        validated.model_dump(mode="json"),
        contract_root=contract_root,
        schema_version=DEPLOYMENT_TARGET_SCHEMA_VERSION,
        label="deployment target descriptor",
    )
    payload = canonical_json_bytes(validated.model_dump(mode="json"))
    digest = sha256_digest(payload)
    return ContentAddressedDeploymentTarget(
        descriptor=validated,
        payload=payload,
        digest=digest,
        fingerprint=digest,
    )


def _validate_temporal_window(
    *,
    valid_from: datetime,
    issued_at: datetime,
    next_revalidation_at: datetime,
    valid_until: datetime,
    max_validity_seconds: int,
    max_revalidation_interval_seconds: int,
    label: str,
) -> None:
    if not valid_from <= issued_at < next_revalidation_at <= valid_until:
        raise AdmissionVerificationError(f"{label} validity window is invalid")
    if (valid_until - valid_from).total_seconds() > max_validity_seconds:
        raise AdmissionVerificationError(f"{label} exceeds its maximum validity window")
    if (
        next_revalidation_at - issued_at
    ).total_seconds() > max_revalidation_interval_seconds:
        raise AdmissionVerificationError(f"{label} exceeds its revalidation interval")


def _validate_target_measurement(
    measurement: TargetMeasurementAttestation,
    *,
    payload: ContentAddressedDeploymentPayload,
    target: ContentAddressedDeploymentTarget,
    contract_root: Path,
    evidence_root: Path,
) -> None:
    if (
        measurement.deployment_payload_descriptor_hash != payload.digest
        or measurement.deployment_payload_fingerprint
        != payload.descriptor.deployment_payload_fingerprint
    ):
        raise AdmissionVerificationError(
            "target measurement does not bind the deployment payload"
        )
    if (
        measurement.target_descriptor_hash != target.digest
        or measurement.target_fingerprint != target.fingerprint
    ):
        raise AdmissionVerificationError(
            "target measurement does not bind the deployment target"
        )
    if not measurement.valid_from <= measurement.measured_at <= measurement.issued_at:
        raise AdmissionVerificationError("target measurement timestamps are invalid")
    _validate_temporal_window(
        valid_from=measurement.valid_from,
        issued_at=measurement.issued_at,
        next_revalidation_at=measurement.next_revalidation_at,
        valid_until=measurement.valid_until,
        max_validity_seconds=measurement.temporal_policy.max_validity_seconds,
        max_revalidation_interval_seconds=(
            measurement.temporal_policy.max_revalidation_interval_seconds
        ),
        label="target measurement",
    )
    if (
        measurement.issued_at - measurement.measured_at
    ).total_seconds() > measurement.temporal_policy.max_measurement_age_seconds:
        raise AdmissionVerificationError("target measurement is already stale")
    deadlines = _evidence_deadlines(
        [
            measurement.resource_evidence_bundle,
            measurement.trusted_time_receipt_envelope,
            measurement.verification_material_bundle,
        ],
        evidence_root=evidence_root,
    )
    if not deadlines:
        raise AdmissionVerificationError(
            "target measurement has no contributor deadline"
        )
    earliest_deadline = min(deadlines)
    if measurement.valid_until > earliest_deadline:
        raise AdmissionVerificationError(
            "target measurement validity exceeds a contributor deadline"
        )
    if measurement.next_revalidation_at > earliest_deadline:
        raise AdmissionVerificationError(
            "target measurement revalidation exceeds a contributor deadline"
        )
    _validate_schema(
        measurement.model_dump(mode="json"),
        contract_root=contract_root,
        schema_version=TARGET_MEASUREMENT_SCHEMA_VERSION,
        label="target measurement",
    )


def _sign_envelope(
    payload: bytes,
    *,
    payload_type: str,
    private_key_env: str,
    environ: Mapping[str, str] | None,
) -> DsseEnvelope:
    try:
        private_key = private_key_from_env(
            name=private_key_env,
            environ=environ,
        )
    except ValueError as error:
        raise AdmissionVerificationError("ephemeral private key is invalid") from error
    signature = private_key.sign(pre_authentication_encoding(payload_type, payload))
    return DsseEnvelope(
        payloadType=payload_type,
        payload=base64.b64encode(payload).decode("ascii"),
        signatures=[
            DsseSignature(
                keyid=key_id(private_key.public_key()),
                sig=base64.b64encode(signature).decode("ascii"),
            )
        ],
    )


def _verify_envelope(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    payload_type: str,
    public_key_env: str,
    environ: Mapping[str, str] | None,
    label: str,
) -> bytes:
    try:
        validated = DsseEnvelope.model_validate(envelope)
    except ValidationError as error:
        raise AdmissionVerificationError(f"{label} envelope is invalid") from error
    if validated.payloadType != payload_type:
        raise AdmissionVerificationError(f"unexpected {label} DSSE payload type")
    if len(validated.signatures) != 1:
        raise AdmissionVerificationError(f"{label} requires exactly one DSSE signature")
    payload = _decode_base64(validated.payload, label=f"{label} payload")
    signature_record = validated.signatures[0]
    signature = _decode_base64(signature_record.sig, label=f"{label} signature")
    try:
        public_key = public_key_from_env(
            name=public_key_env,
            environ=environ,
        )
    except ValueError as error:
        raise AdmissionVerificationError("ephemeral public key is invalid") from error
    if signature_record.keyid != key_id(public_key):
        raise AdmissionVerificationError(f"{label} key identity is invalid")
    try:
        public_key.verify(
            signature,
            pre_authentication_encoding(payload_type, payload),
        )
    except InvalidSignature as error:
        raise AdmissionVerificationError(
            f"{label} DSSE signature is invalid"
        ) from error
    try:
        decoded = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionVerificationError(
            f"{label} payload is not valid JSON"
        ) from error
    if canonical_json_bytes(decoded) != payload:
        raise AdmissionVerificationError(f"{label} payload is not canonical JSON")
    return payload


def sign_target_measurement(
    measurement: TargetMeasurementAttestation | Mapping[str, Any],
    *,
    payload: ContentAddressedDeploymentPayload,
    target: ContentAddressedDeploymentTarget,
    contract_root: Path,
    evidence_root: Path,
    environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    """Sign one synthetic target measurement with an ephemeral environment key."""

    validated = TargetMeasurementAttestation.model_validate(measurement)
    _validate_target_measurement(
        validated,
        payload=payload,
        target=target,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return _sign_envelope(
        canonical_json_bytes(validated.model_dump(mode="json")),
        payload_type=TARGET_MEASUREMENT_PAYLOAD_TYPE,
        private_key_env=MEASUREMENT_PRIVATE_KEY_ENV,
        environ=environ,
    )


def verify_target_measurement(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    payload: ContentAddressedDeploymentPayload,
    target: ContentAddressedDeploymentTarget,
    contract_root: Path,
    evidence_root: Path,
    environ: Mapping[str, str] | None = None,
) -> TargetMeasurementAttestation:
    """Verify target measurement signature, exact bindings, evidence, and time."""

    payload_bytes = _verify_envelope(
        envelope,
        payload_type=TARGET_MEASUREMENT_PAYLOAD_TYPE,
        public_key_env=MEASUREMENT_PUBLIC_KEY_ENV,
        environ=environ,
        label="target measurement",
    )
    try:
        measurement = TargetMeasurementAttestation.model_validate_json(payload_bytes)
    except ValidationError as error:
        raise AdmissionVerificationError(
            "target measurement payload model is invalid"
        ) from error
    _validate_target_measurement(
        measurement,
        payload=payload,
        target=target,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return measurement


def _validate_admission(
    admission: DeploymentAdmissionRecord,
    *,
    bqm: ContentAddressedBqm,
    bqa: BuildQualificationAttestation,
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    payload: ContentAddressedDeploymentPayload,
    target: ContentAddressedDeploymentTarget,
    target_measurement: TargetMeasurementAttestation,
    target_measurement_envelope: DsseEnvelope | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
) -> None:
    if admission.governed_operation not in {"deploy", "startup"}:
        raise AdmissionVerificationError("deployment operation is not admitted")
    if admission.onyx_surface != "ce" or admission.usage_mode != "development_test":
        raise AdmissionVerificationError(
            "deployment admission admits only CE development_test"
        )
    if (
        admission.admission_basis != "synthetic_environment"
        or admission.target_class != "synthetic_sandbox"
        or admission.ce_release_authorization is not None
        or admission.enterprise_authorization is not None
    ):
        raise AdmissionVerificationError(
            "deployment admission has a non-synthetic authorization basis"
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
            "deployment admission does not bind the qualified build"
        )
    if (
        bqa.build_manifest_hash != bqm.digest
        or bqa.artifact_set_hash != bqm.manifest.artifact_set_hash
    ):
        raise AdmissionVerificationError("build attestation binding is invalid")
    if (
        admission.deployment_payload_descriptor_hash != payload.digest
        or admission.deployment_payload_fingerprint
        != payload.descriptor.deployment_payload_fingerprint
    ):
        raise AdmissionVerificationError(
            "deployment admission does not bind the reconstructed payload"
        )
    if (
        admission.target_descriptor_hash != target.digest
        or admission.target_fingerprint != target.fingerprint
    ):
        raise AdmissionVerificationError(
            "deployment admission does not bind the reconstructed target"
        )
    if (
        admission.target_measurement_envelope_hash
        != _envelope_digest(target_measurement_envelope)
        or target_measurement.deployment_payload_descriptor_hash != payload.digest
        or target_measurement.target_descriptor_hash != target.digest
    ):
        raise AdmissionVerificationError(
            "deployment admission target measurement binding is invalid"
        )
    if (
        admission.trusted_clock_id != bqa.trusted_clock_id
        or admission.trusted_clock_id != target_measurement.trusted_clock_id
    ):
        raise AdmissionVerificationError("deployment trusted clock identity drifts")
    if admission.temporal_policy != target_measurement.temporal_policy:
        raise AdmissionVerificationError("deployment temporal policy drifts")
    _validate_temporal_window(
        valid_from=admission.valid_from,
        issued_at=admission.issued_at,
        next_revalidation_at=admission.next_revalidation_at,
        valid_until=admission.valid_until,
        max_validity_seconds=admission.temporal_policy.max_validity_seconds,
        max_revalidation_interval_seconds=(
            admission.temporal_policy.max_revalidation_interval_seconds
        ),
        label="deployment admission",
    )
    if admission.valid_from < max(bqa.valid_from, target_measurement.valid_from):
        raise AdmissionVerificationError(
            "deployment admission starts before a contributor is valid"
        )
    if admission.issued_at < max(bqa.issued_at, target_measurement.issued_at):
        raise AdmissionVerificationError(
            "deployment admission predates contributor verification"
        )
    if admission.valid_until > min(bqa.valid_until, target_measurement.valid_until):
        raise AdmissionVerificationError(
            "deployment admission validity exceeds a contributor"
        )
    if admission.next_revalidation_at > min(
        bqa.next_revalidation_at,
        target_measurement.next_revalidation_at,
    ):
        raise AdmissionVerificationError(
            "deployment admission revalidation exceeds a contributor"
        )
    if (
        admission.issued_at - target_measurement.measured_at
    ).total_seconds() > admission.temporal_policy.max_measurement_age_seconds:
        raise AdmissionVerificationError("deployment target measurement is stale")
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
            "deployment admission has no contributor deadline"
        )
    earliest_deadline = min(deadlines)
    if admission.valid_until > earliest_deadline:
        raise AdmissionVerificationError(
            "deployment admission validity exceeds an evidence deadline"
        )
    if admission.next_revalidation_at > earliest_deadline:
        raise AdmissionVerificationError(
            "deployment admission revalidation exceeds an evidence deadline"
        )
    _validate_schema(
        admission.model_dump(mode="json"),
        contract_root=contract_root,
        schema_version=DEPLOYMENT_ADMISSION_SCHEMA_VERSION,
        label="deployment admission",
    )


def sign_deployment_admission(
    admission: DeploymentAdmissionRecord | Mapping[str, Any],
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    payload_descriptor: DeploymentPayloadDescriptor | Mapping[str, Any],
    target_descriptor: DeploymentTargetDescriptor | Mapping[str, Any],
    target_measurement_envelope: DsseEnvelope | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
    bqa_environ: Mapping[str, str] | None = None,
    measurement_environ: Mapping[str, str] | None = None,
    admission_environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    """Sign one fully bound synthetic deployment admission."""

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
    payload = content_address_deployment_payload(
        payload_descriptor,
        bqm=bqm,
        qualification_index=validated_index,
        runtime_scope_policy_map=runtime_scope_policy_map,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    target = content_address_deployment_target(
        target_descriptor,
        contract_root=contract_root,
    )
    measurement = verify_target_measurement(
        target_measurement_envelope,
        payload=payload,
        target=target,
        contract_root=contract_root,
        evidence_root=evidence_root,
        environ=measurement_environ,
    )
    validated = DeploymentAdmissionRecord.model_validate(admission)
    _validate_admission(
        validated,
        bqm=bqm,
        bqa=bqa,
        bqa_envelope=bqa_envelope,
        payload=payload,
        target=target,
        target_measurement=measurement,
        target_measurement_envelope=target_measurement_envelope,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return _sign_envelope(
        canonical_json_bytes(validated.model_dump(mode="json")),
        payload_type=DEPLOYMENT_ADMISSION_PAYLOAD_TYPE,
        private_key_env=ADMISSION_PRIVATE_KEY_ENV,
        environ=admission_environ,
    )


def verify_deployment_admission(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    payload_descriptor: DeploymentPayloadDescriptor | Mapping[str, Any],
    target_descriptor: DeploymentTargetDescriptor | Mapping[str, Any],
    target_measurement_envelope: DsseEnvelope | Mapping[str, Any],
    contract_root: Path,
    evidence_root: Path,
    bqa_environ: Mapping[str, str] | None = None,
    measurement_environ: Mapping[str, str] | None = None,
    admission_environ: Mapping[str, str] | None = None,
) -> tuple[
    DeploymentAdmissionRecord,
    BuildQualificationAttestation,
    TargetMeasurementAttestation,
]:
    """Verify an admission and independently reconstruct all governed inputs."""

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
    payload = content_address_deployment_payload(
        payload_descriptor,
        bqm=bqm,
        qualification_index=validated_index,
        runtime_scope_policy_map=runtime_scope_policy_map,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    target = content_address_deployment_target(
        target_descriptor,
        contract_root=contract_root,
    )
    measurement = verify_target_measurement(
        target_measurement_envelope,
        payload=payload,
        target=target,
        contract_root=contract_root,
        evidence_root=evidence_root,
        environ=measurement_environ,
    )
    payload_bytes = _verify_envelope(
        envelope,
        payload_type=DEPLOYMENT_ADMISSION_PAYLOAD_TYPE,
        public_key_env=ADMISSION_PUBLIC_KEY_ENV,
        environ=admission_environ,
        label="deployment admission",
    )
    try:
        admission = DeploymentAdmissionRecord.model_validate_json(payload_bytes)
    except ValidationError as error:
        raise AdmissionVerificationError(
            "deployment admission payload model is invalid"
        ) from error
    _validate_admission(
        admission,
        bqm=bqm,
        bqa=bqa,
        bqa_envelope=bqa_envelope,
        payload=payload,
        target=target,
        target_measurement=measurement,
        target_measurement_envelope=target_measurement_envelope,
        contract_root=contract_root,
        evidence_root=evidence_root,
    )
    return admission, bqa, measurement


def _receipt_verdict(
    *,
    verification_event: DeploymentVerificationEvent,
    allow: bool,
) -> DeploymentReceiptVerdict:
    if allow:
        return "allow"
    if verification_event == "watchdog_revalidation":
        return "quiesce"
    return "deny"


def evaluate_deployment_use(
    *,
    use_id: UUID,
    verification_event: DeploymentVerificationEvent,
    governed_operation: DeploymentOperation,
    admission_envelope: DsseEnvelope | Mapping[str, Any] | None,
    bqm: ContentAddressedBqm,
    qualification_index: EvidenceBundleIndex | Mapping[str, Any],
    bqa_envelope: DsseEnvelope | Mapping[str, Any],
    runtime_scope_policy_map: RuntimeScopePolicyMap | Mapping[str, Any],
    actual_payload_descriptor: DeploymentPayloadDescriptor | Mapping[str, Any],
    actual_target_descriptor: DeploymentTargetDescriptor | Mapping[str, Any],
    target_measurement_envelope: DsseEnvelope | Mapping[str, Any],
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
    """Fail closed at deploy/startup and quiesce before watchdog deadlines."""

    if now.utcoffset() is None or now.utcoffset() != timedelta(0):
        raise AdmissionVerificationError("verification time must be UTC")
    reconstruction_error = False
    try:
        payload = content_address_deployment_payload(
            actual_payload_descriptor,
            bqm=bqm,
            qualification_index=qualification_index,
            runtime_scope_policy_map=runtime_scope_policy_map,
            contract_root=contract_root,
            evidence_root=evidence_root,
        )
    except (AdmissionVerificationError, ValidationError):
        reconstructed_payload = DeploymentPayloadDescriptor.model_validate(
            actual_payload_descriptor
        )
        raw_payload = canonical_json_bytes(
            reconstructed_payload.model_dump(mode="json")
        )
        payload = ContentAddressedDeploymentPayload(
            descriptor=reconstructed_payload,
            payload=raw_payload,
            digest=sha256_digest(raw_payload),
        )
        reconstruction_error = True
    try:
        target = content_address_deployment_target(
            actual_target_descriptor,
            contract_root=contract_root,
        )
    except (AdmissionVerificationError, ValidationError):
        reconstructed_target = DeploymentTargetDescriptor.model_validate(
            actual_target_descriptor
        )
        raw_target = canonical_json_bytes(reconstructed_target.model_dump(mode="json"))
        target_digest = sha256_digest(raw_target)
        target = ContentAddressedDeploymentTarget(
            descriptor=reconstructed_target,
            payload=raw_target,
            digest=target_digest,
            fingerprint=target_digest,
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
            admission, bqa, measurement = verify_deployment_admission(
                admission_envelope,
                bqm=bqm,
                qualification_index=qualification_index,
                bqa_envelope=bqa_envelope,
                runtime_scope_policy_map=runtime_scope_policy_map,
                payload_descriptor=actual_payload_descriptor,
                target_descriptor=actual_target_descriptor,
                target_measurement_envelope=target_measurement_envelope,
                contract_root=contract_root,
                evidence_root=evidence_root,
                bqa_environ=bqa_environ,
                measurement_environ=measurement_environ,
                admission_environ=admission_environ,
            )
            if governed_operation not in {"deploy", "startup"}:
                raise AdmissionVerificationError("governed operation is invalid")
            if admission.governed_operation != governed_operation:
                raise AdmissionVerificationError("admission operation does not match")
            if verification_event not in {
                "deploy",
                "startup",
                "watchdog_revalidation",
            }:
                raise AdmissionVerificationError("verification event is invalid")
            if verification_event in {"deploy", "startup"} and (
                verification_event != governed_operation
            ):
                raise AdmissionVerificationError("verification event does not match")
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
                    "admission requires revalidation before its deadline"
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
        actual_payload_fingerprint=payload.descriptor.deployment_payload_fingerprint,
        actual_target_or_destination_descriptor_hash=target.digest,
        actual_target_or_destination_fingerprint=target.fingerprint,
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
    "ADMISSION_PRIVATE_KEY_ENV",
    "ADMISSION_PUBLIC_KEY_ENV",
    "DEPLOYMENT_ADMISSION_PAYLOAD_TYPE",
    "MEASUREMENT_PRIVATE_KEY_ENV",
    "MEASUREMENT_PUBLIC_KEY_ENV",
    "TARGET_MEASUREMENT_PAYLOAD_TYPE",
    "AdmissionVerificationError",
    "ContentAddressedDeploymentPayload",
    "ContentAddressedDeploymentTarget",
    "artifact_id_set_digest",
    "content_address_deployment_payload",
    "content_address_deployment_target",
    "evaluate_deployment_use",
    "sign_deployment_admission",
    "sign_target_measurement",
    "verify_deployment_admission",
    "verify_target_measurement",
]
