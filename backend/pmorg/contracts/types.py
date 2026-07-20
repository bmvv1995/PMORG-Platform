"""Strict PMORG V3 qualification, admission, capability, and provenance types."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from typing import Literal

from pydantic import AfterValidator
from pydantic import AwareDatetime
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import NonNegativeInt
from pydantic import PositiveInt
from pydantic import UUID7


def _require_relative_path(value: str) -> str:
    if value.startswith("/") or ".." in value.split("/"):
        raise ValueError("path must remain bundle-relative")
    return value


Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
HmacSha256Digest = Annotated[str, Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")]
GitSha = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
SemVer = Annotated[
    str,
    Field(
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$"
    ),
]
RelativePath = Annotated[
    str,
    Field(min_length=1),
    AfterValidator(_require_relative_path),
]
OnyxSurface = Literal["ce", "ee"]
UsageMode = Literal["development_test", "production"]
ArtifactKind = Literal["oci_image", "worker", "package", "migration", "static_bundle"]
GovernedOperation = Literal["deploy", "startup", "registry_publish", "artifact_export"]
OwnershipClass = Literal[
    "pmorg_owned",
    "upstream_ce_reused",
    "upstream_ce_direct_patch",
    "upstream_ee_reused",
    "upstream_ee_direct_patch",
    "third_party",
]
LicenseClass = Literal["pmorg", "mit-expat", "onyx-enterprise", "third-party"]


def _require_utc(value: datetime) -> datetime:
    utc_offset = value.utcoffset()
    if utc_offset is None or utc_offset.total_seconds() != 0:
        raise ValueError("timestamp must be RFC3339 UTC")
    return value


UtcDatetime = Annotated[AwareDatetime, AfterValidator(_require_utc)]


class StrictContract(BaseModel):
    """Closed, immutable wire object used by every PMORG contract model."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )


class EvidenceArtifactRef(StrictContract):
    logical_name: Annotated[str, Field(min_length=1)]
    media_type: Annotated[str, Field(min_length=1)]
    digest: Sha256Digest
    size_bytes: NonNegativeInt
    relative_path: RelativePath


class EvidenceBundleIndex(StrictContract):
    schema_version: Literal["pmorg.evidence-bundle-index/v1"]
    bundle_kind: Annotated[str, Field(min_length=1)]
    subject_binding_hash: Sha256Digest | None
    entries: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]
    entry_count: PositiveInt


class DsseSignature(StrictContract):
    keyid: Annotated[str, Field(min_length=1)]
    sig: Annotated[str, Field(min_length=1)]


class DsseEnvelope(StrictContract):
    payloadType: Annotated[str, Field(min_length=1)]
    payload: Annotated[str, Field(min_length=1)]
    signatures: Annotated[list[DsseSignature], Field(min_length=1)]


class TemporalPolicyBinding(StrictContract):
    policy_hash: Sha256Digest
    max_clock_skew_seconds: NonNegativeInt
    max_time_receipt_age_seconds: NonNegativeInt
    max_measurement_age_seconds: NonNegativeInt
    max_validity_seconds: NonNegativeInt
    max_revalidation_interval_seconds: NonNegativeInt


class TrustedTimeReceiptPayload(StrictContract):
    schema_version: Literal["pmorg.trusted-time-receipt/v1"]
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    clock_source_id: Annotated[str, Field(min_length=1)]
    sequence: PositiveInt
    previous_receipt_envelope_hash: Sha256Digest | None
    observed_at: UtcDatetime
    uncertainty_seconds: NonNegativeInt
    monotonic_counter: PositiveInt
    source_evidence_bundle: EvidenceArtifactRef
    verification_material_bundle: EvidenceArtifactRef
    verification_policy_hash: Sha256Digest
    verifier_identity: Annotated[str, Field(min_length=1)]
    issued_at: UtcDatetime


class ExpectedArtifactCatalogItem(StrictContract):
    artifact_id: Annotated[str, Field(min_length=1)]
    component: Annotated[str, Field(min_length=1)]
    artifact_kind: ArtifactKind
    media_type: Annotated[str, Field(min_length=1)]
    platform: Annotated[str, Field(min_length=1)]


class ExpectedArtifactCatalog(StrictContract):
    schema_version: Literal["pmorg.expected-artifact-catalog/v1"]
    build_recipe_hash: Sha256Digest
    items: Annotated[list[ExpectedArtifactCatalogItem], Field(min_length=1)]
    expected_artifact_count: PositiveInt


class RuntimeScopePolicyEntry(StrictContract):
    scope_class: Literal["deployment_runtime", "registry_publish", "artifact_export"]
    scope_policy_hash: Sha256Digest
    expected_artifact_id_set_hash: Sha256Digest
    expected_release_metadata_role_set_hash: Sha256Digest | None
    target_destination_policy_schema_hash: Sha256Digest


class RuntimeScopePolicyMap(StrictContract):
    schema_version: Literal["pmorg.runtime-scope-policy-map/v1"]
    baseline_manifest_hash: Sha256Digest
    onyx_surface: OnyxSurface
    entries: Annotated[list[RuntimeScopePolicyEntry], Field(min_length=1)]


class ArtifactDescriptor(ExpectedArtifactCatalogItem):
    digest: Sha256Digest
    size_bytes: NonNegativeInt


class ReleaseBuildDefinitionPayload(StrictContract):
    schema_version: Literal["pmorg.release-build-definition/v1"]
    baseline_manifest_hash: Sha256Digest
    pmorg_spec_commit: GitSha
    pmorg_platform_commit: GitSha
    onyx_commit: GitSha
    onyx_surface: OnyxSurface
    allowed_usage_modes: Annotated[list[UsageMode], Field(min_length=1)]
    build_recipe: EvidenceArtifactRef
    build_input_set: EvidenceArtifactRef
    expected_artifact_catalog_hash: Sha256Digest
    qualification_policy_map_hash: Sha256Digest
    runtime_scope_policy_map: EvidenceArtifactRef
    approval_authority: EvidenceArtifactRef
    verifier_identity: Annotated[str, Field(min_length=1)]
    verification_policy_hash: Sha256Digest
    verification_material_bundle: EvidenceArtifactRef
    issued_at: UtcDatetime


class QualificationPolicyEntry(StrictContract):
    report_role: Annotated[str, Field(min_length=1)]
    policy_digest: Sha256Digest


class QualificationPolicyMap(StrictContract):
    schema_version: Literal["pmorg.qualification-policy-map/v1"]
    baseline_manifest_hash: Sha256Digest
    entries: Annotated[list[QualificationPolicyEntry], Field(min_length=1)]
    entry_count: PositiveInt


class BuildQualificationManifest(StrictContract):
    schema_version: Literal["pmorg.build-qualification-manifest/v1"]
    baseline_manifest_hash: Sha256Digest
    release_build_definition_envelope_hash: Sha256Digest
    build_recipe_hash: Sha256Digest
    build_input_set_hash: Sha256Digest
    runtime_scope_policy_map_hash: Sha256Digest
    expected_artifact_catalog_hash: Sha256Digest
    artifact_descriptors: Annotated[list[ArtifactDescriptor], Field(min_length=1)]
    artifact_count: PositiveInt
    expected_artifact_count: PositiveInt
    missing_artifact_count: NonNegativeInt
    unexpected_artifact_count: NonNegativeInt
    duplicate_artifact_key_count: NonNegativeInt
    artifact_set_hash: Sha256Digest
    image_lock_hash: Sha256Digest
    pmorg_platform_commit: GitSha
    pmorg_spec_commit: GitSha
    onyx_release_tag: Annotated[str, Field(min_length=1)]
    onyx_commit: GitSha
    onyx_surface: OnyxSurface
    usage_mode: UsageMode
    qualification_policy_map_hash: Sha256Digest
    sbom_hash: Sha256Digest
    license_report_hash: Sha256Digest
    patch_ledger_report_hash: Sha256Digest
    provenance_report_hash: Sha256Digest
    provenance_evidence_bundle_index_hash: Sha256Digest
    surface_mode_report_hash: Sha256Digest
    capability_catalog_hash: Sha256Digest
    capability_disposition_report_hash: Sha256Digest
    capability_evidence_bundle_index_hash: Sha256Digest
    vulnerability_report_hash: Sha256Digest
    upstream_test_report_hash: Sha256Digest
    ce_boundary_report_hash: Sha256Digest | None
    ee_inventory_report_hash: Sha256Digest | None
    qualification_bundle_index_hash: Sha256Digest


class QualificationReport(StrictContract):
    schema_version: Annotated[str, Field(pattern=r"^pmorg\.[a-z0-9.-]+/v1$")]
    report_kind: Annotated[str, Field(min_length=1)]
    subject_artifact_set_hash: Sha256Digest
    onyx_commit: GitSha
    onyx_surface: OnyxSurface
    usage_mode: UsageMode
    policy_digest: Sha256Digest
    tool_name: Annotated[str, Field(min_length=1)]
    tool_version: Annotated[str, Field(min_length=1)]
    tool_artifact_digest: Sha256Digest
    tool_config_hash: Sha256Digest
    input_snapshot_set_hash: Sha256Digest
    input_bundle_index_hash: Sha256Digest
    expected_item_count: NonNegativeInt
    observed_item_count: NonNegativeInt
    missing_item_count: NonNegativeInt
    duplicate_item_count: NonNegativeInt
    verdict: Literal["pass", "fail"]
    evidence_bundle_index_hash: Sha256Digest


class BuildQualificationAttestation(StrictContract):
    schema_version: Literal["pmorg.build-qualification-attestation/v1"]
    build_manifest_hash: Sha256Digest
    artifact_set_hash: Sha256Digest
    qualification_bundle_index_hash: Sha256Digest
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    next_revalidation_at: UtcDatetime
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    trusted_time_receipt_envelope: EvidenceArtifactRef
    temporal_policy: TemporalPolicyBinding
    revocation_status: EvidenceArtifactRef
    verification_material_bundle: EvidenceArtifactRef
    verifier_identity: Annotated[str, Field(min_length=1)]
    verification_policy_hash: Sha256Digest
    issued_at: UtcDatetime


class DeploymentPayloadDescriptor(StrictContract):
    schema_version: Literal["pmorg.deployment-payload-descriptor/v1"]
    deployment_scope_policy_hash: Sha256Digest
    artifact_descriptors: Annotated[list[ArtifactDescriptor], Field(min_length=1)]
    artifact_count: PositiveInt
    expected_artifact_count: PositiveInt
    missing_artifact_count: NonNegativeInt
    unexpected_artifact_count: NonNegativeInt
    duplicate_artifact_key_count: NonNegativeInt
    runtime_workload_spec_hash: Sha256Digest
    runtime_binding_set_hash: Sha256Digest
    deployment_payload_fingerprint: Sha256Digest


class DeploymentTargetDescriptor(StrictContract):
    schema_version: Literal["pmorg.deployment-target-descriptor/v1"]
    target_uid_hmac: HmacSha256Digest
    workload_identity_set_hash: Sha256Digest
    organization_binding_set_hash: Sha256Digest
    data_binding_set_hash: Sha256Digest
    identity_provider_set_hash: Sha256Digest
    channel_binding_set_hash: Sha256Digest
    secret_binding_set_hash: Sha256Digest
    network_policy_hash: Sha256Digest
    resource_classification_report_hash: Sha256Digest
    production_resource_count: NonNegativeInt
    unknown_resource_count: NonNegativeInt
    derived_target_class: Literal["synthetic_sandbox", "client"]


class TargetMeasurementAttestation(StrictContract):
    schema_version: Literal["pmorg.target-measurement-attestation/v1"]
    deployment_payload_descriptor_hash: Sha256Digest
    deployment_payload_fingerprint: Sha256Digest
    target_descriptor_hash: Sha256Digest
    target_fingerprint: Sha256Digest
    resource_evidence_bundle: EvidenceArtifactRef
    verification_material_bundle: EvidenceArtifactRef
    measured_at: UtcDatetime
    issued_at: UtcDatetime
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    next_revalidation_at: UtcDatetime
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    trusted_time_receipt_envelope: EvidenceArtifactRef
    temporal_policy: TemporalPolicyBinding
    verifier_identity: Annotated[str, Field(min_length=1)]
    verification_policy_hash: Sha256Digest


class CeReleaseAuthorizationBinding(StrictContract):
    schema_version: Literal["pmorg.ce-release-authorization-binding/v1"]
    release_id: Annotated[str, Field(min_length=1)]
    issuer_identity: Annotated[str, Field(min_length=1)]
    release_evidence: EvidenceArtifactRef
    permitted_onyx_surface: Literal["ce"]
    permitted_usage_mode: Literal["production"]
    permitted_operations: Annotated[list[GovernedOperation], Field(min_length=1)]
    artifact_scope_policy_hash: Sha256Digest
    target_destination_scope_policy_hash: Sha256Digest
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    next_revalidation_at: UtcDatetime
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    trusted_time_receipt_envelope: EvidenceArtifactRef
    temporal_policy: TemporalPolicyBinding
    revocation_status: EvidenceArtifactRef
    verification_policy_hash: Sha256Digest
    verification_material_bundle: EvidenceArtifactRef
    issued_at: UtcDatetime


class EnterpriseAuthorizationBinding(StrictContract):
    schema_version: Literal["pmorg.enterprise-authorization-binding/v1"]
    authorization_id_hmac: HmacSha256Digest
    issuer_identity: Annotated[str, Field(min_length=1)]
    authorization_evidence: EvidenceArtifactRef
    authorized_entity_hmac: HmacSha256Digest
    seat_scope_hash: Sha256Digest
    agreement_hash: Sha256Digest
    permitted_onyx_surface: Literal["ee"]
    permitted_usage_mode: Literal["production"]
    permitted_operations: Annotated[list[GovernedOperation], Field(min_length=1)]
    artifact_scope_policy_hash: Sha256Digest
    target_destination_scope_policy_hash: Sha256Digest
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    next_revalidation_at: UtcDatetime
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    trusted_time_receipt_envelope: EvidenceArtifactRef
    temporal_policy: TemporalPolicyBinding
    revocation_status: EvidenceArtifactRef
    verification_policy_hash: Sha256Digest
    verification_material_bundle: EvidenceArtifactRef
    issued_at: UtcDatetime


class DeploymentAdmissionRecord(StrictContract):
    schema_version: Literal["pmorg.deployment-admission/v1"]
    admission_id: UUID7
    governed_operation: Literal["deploy", "startup"]
    artifact_set_hash: Sha256Digest
    build_manifest_hash: Sha256Digest
    build_attestation_envelope_hash: Sha256Digest
    deployment_payload_descriptor_hash: Sha256Digest
    deployment_payload_fingerprint: Sha256Digest
    onyx_surface: OnyxSurface
    usage_mode: UsageMode
    target_descriptor_hash: Sha256Digest
    target_fingerprint: Sha256Digest
    target_measurement_envelope_hash: Sha256Digest
    target_class: Literal["synthetic_sandbox", "client"]
    admission_basis: Literal[
        "synthetic_environment", "ce_release", "onyx_enterprise_authorization"
    ]
    ce_release_authorization: CeReleaseAuthorizationBinding | None
    enterprise_authorization: EnterpriseAuthorizationBinding | None
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    trusted_time_receipt_envelope: EvidenceArtifactRef
    temporal_policy: TemporalPolicyBinding
    revocation_status: EvidenceArtifactRef
    next_revalidation_at: UtcDatetime
    verifier_identity: Annotated[str, Field(min_length=1)]
    verification_policy_hash: Sha256Digest
    verification_material_bundle: EvidenceArtifactRef
    verifier_receipt: EvidenceArtifactRef
    issued_at: UtcDatetime


class AdmissionUseReceiptPayload(StrictContract):
    schema_version: Literal["pmorg.admission-use-receipt/v1"]
    use_id: UUID7
    verification_event: Literal[
        "deploy",
        "startup",
        "watchdog_revalidation",
        "registry_publish",
        "artifact_export",
        "transfer_revalidation",
    ]
    governed_operation: GovernedOperation
    admission_envelope_hash: Sha256Digest
    actual_payload_descriptor_hash: Sha256Digest
    actual_payload_fingerprint: Sha256Digest
    actual_target_or_destination_descriptor_hash: Sha256Digest
    actual_target_or_destination_fingerprint: Sha256Digest
    trusted_time_receipt_envelope: EvidenceArtifactRef
    revocation_check: EvidenceArtifactRef
    verification_policy_hash: Sha256Digest
    verification_material_bundle: EvidenceArtifactRef
    verifier_identity: Annotated[str, Field(min_length=1)]
    verified_at: UtcDatetime
    issued_at: UtcDatetime
    verdict: Literal["allow", "deny", "quiesce", "abort"]
    denial_reason: str | None


class DistributionPayloadDescriptor(StrictContract):
    schema_version: Literal["pmorg.distribution-payload-descriptor/v1"]
    operation: Literal["registry_publish", "artifact_export"]
    distribution_scope_policy_hash: Sha256Digest
    expected_artifact_id_set_hash: Sha256Digest
    expected_release_metadata_role_set_hash: Sha256Digest
    deployable_artifact_descriptors: Annotated[
        list[ArtifactDescriptor], Field(min_length=1)
    ]
    deployable_artifact_count: PositiveInt
    expected_deployable_artifact_count: PositiveInt
    missing_deployable_artifact_count: NonNegativeInt
    unexpected_deployable_artifact_count: NonNegativeInt
    duplicate_deployable_artifact_key_count: NonNegativeInt
    release_metadata_bundle_index_hash: Sha256Digest
    release_metadata_entry_count: PositiveInt
    expected_release_metadata_entry_count: PositiveInt
    missing_release_metadata_count: NonNegativeInt
    unexpected_release_metadata_count: NonNegativeInt
    duplicate_release_metadata_count: NonNegativeInt
    distribution_payload_hash: Sha256Digest


class DistributionDestinationDescriptor(StrictContract):
    schema_version: Literal["pmorg.distribution-destination-descriptor/v1"]
    destination_uid_hmac: HmacSha256Digest
    operation: Literal["registry_publish", "artifact_export"]
    registry_or_gateway_identity_set_hash: Sha256Digest
    account_binding_set_hash: Sha256Digest
    organization_binding_set_hash: Sha256Digest
    authorized_entity_binding_set_hash: Sha256Digest
    seat_scope_binding_set_hash: Sha256Digest
    agreement_binding_set_hash: Sha256Digest
    endpoint_and_storage_policy_hash: Sha256Digest
    resource_classification_report_hash: Sha256Digest
    production_destination_count: NonNegativeInt
    unknown_destination_count: NonNegativeInt
    derived_destination_class: Literal[
        "controlled_synthetic_registry", "client_destination"
    ]


class DistributionDestinationMeasurementAttestation(StrictContract):
    schema_version: Literal["pmorg.distribution-destination-measurement/v1"]
    destination_descriptor_hash: Sha256Digest
    destination_fingerprint: Sha256Digest
    destination_evidence_bundle: EvidenceArtifactRef
    verification_material_bundle: EvidenceArtifactRef
    measured_at: UtcDatetime
    issued_at: UtcDatetime
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    next_revalidation_at: UtcDatetime
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    trusted_time_receipt_envelope: EvidenceArtifactRef
    temporal_policy: TemporalPolicyBinding
    verifier_identity: Annotated[str, Field(min_length=1)]
    verification_policy_hash: Sha256Digest


class DistributionAdmissionRecord(StrictContract):
    schema_version: Literal["pmorg.distribution-admission/v1"]
    admission_id: UUID7
    operation: Literal["registry_publish", "artifact_export"]
    artifact_set_hash: Sha256Digest
    build_manifest_hash: Sha256Digest
    build_attestation_envelope_hash: Sha256Digest
    distribution_payload_descriptor_hash: Sha256Digest
    distribution_payload_hash: Sha256Digest
    onyx_surface: OnyxSurface
    usage_mode: UsageMode
    destination_descriptor_hash: Sha256Digest
    destination_fingerprint: Sha256Digest
    destination_measurement_envelope_hash: Sha256Digest
    destination_class: Literal["controlled_synthetic_registry", "client_destination"]
    admission_basis: Literal[
        "synthetic_environment", "ce_release", "onyx_enterprise_authorization"
    ]
    ce_release_authorization: CeReleaseAuthorizationBinding | None
    enterprise_authorization: EnterpriseAuthorizationBinding | None
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    next_revalidation_at: UtcDatetime
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    trusted_time_receipt_envelope: EvidenceArtifactRef
    temporal_policy: TemporalPolicyBinding
    revocation_status: EvidenceArtifactRef
    verifier_identity: Annotated[str, Field(min_length=1)]
    verification_policy_hash: Sha256Digest
    verification_material_bundle: EvidenceArtifactRef
    verifier_receipt: EvidenceArtifactRef
    issued_at: UtcDatetime


class ContentAddressedSourceRef(StrictContract):
    repository: Annotated[str, Field(min_length=1)]
    commit: GitSha
    paths: Annotated[list[RelativePath], Field(min_length=1)]
    tree_hash: Sha256Digest
    source_snapshot: EvidenceArtifactRef


class SourceScopeManifest(StrictContract):
    schema_version: Literal["pmorg.source-scope-manifest/v1"]
    repository: Annotated[str, Field(min_length=1)]
    commit: GitSha
    scope_kind: Literal["pmorg", "onyx_ce", "onyx_ee"]
    roots: Annotated[list[RelativePath], Field(min_length=1)]
    tree_hash: Sha256Digest
    path_inventory: EvidenceArtifactRef
    derivation_policy_hash: Sha256Digest
    generator_identity: Annotated[str, Field(min_length=1)]
    generator_artifact_digest: Sha256Digest
    derivation_evidence_bundle: EvidenceArtifactRef
    expected_path_count: NonNegativeInt
    duplicate_path_count: NonNegativeInt
    unreadable_path_count: NonNegativeInt


class TestEvidence(StrictContract):
    test_id: Annotated[str, Field(min_length=1)]
    test_manifest: EvidenceArtifactRef
    result: EvidenceArtifactRef
    verdict: Literal["pass", "fail"]


class CandidateQualificationReport(StrictContract):
    schema_version: Literal["pmorg.candidate-qualification-report/v1"]
    catalog_hash: Sha256Digest
    capability_id: Annotated[str, Field(min_length=1)]
    candidate_id: Annotated[str, Field(min_length=1)]
    source_ref: ContentAddressedSourceRef
    qualification_policy: EvidenceArtifactRef
    required_test_manifest: EvidenceArtifactRef
    expected_test_count: PositiveInt
    executed_test_count: PositiveInt
    missing_test_count: NonNegativeInt
    duplicate_test_count: NonNegativeInt
    failed_test_count: NonNegativeInt
    test_evidence: Annotated[list[TestEvidence], Field(min_length=1)]
    verdict: Literal["pass", "fail"]


class OnyxCapabilityCandidate(StrictContract):
    candidate_id: Annotated[str, Field(min_length=1)]
    source_ref: ContentAddressedSourceRef
    onyx_surface: OnyxSurface
    license_class: Literal["mit-expat", "onyx-enterprise", "third-party"]
    qualification: Literal["pass", "fail"]
    qualification_report: CandidateQualificationReport


class CandidateSearchEvidence(StrictContract):
    schema_version: Literal["pmorg.candidate-search-evidence/v1"]
    search_id: Annotated[str, Field(min_length=1)]
    catalog_hash: Sha256Digest
    capability_id: Annotated[str, Field(min_length=1)]
    searched_surfaces: Annotated[list[OnyxSurface], Field(min_length=1)]
    source_scopes: Annotated[list[SourceScopeManifest], Field(min_length=1)]
    search_spec_version: SemVer
    search_tool_name: Annotated[str, Field(min_length=1)]
    search_tool_version: SemVer
    search_tool_artifact_digest: Sha256Digest
    expected_path_count: NonNegativeInt
    scanned_path_count: NonNegativeInt
    unscanned_path_count: NonNegativeInt
    duplicate_path_count: NonNegativeInt
    unreadable_path_count: NonNegativeInt
    raw_hit_count: NonNegativeInt
    candidate_ids: list[str]
    rejected_hit_count: NonNegativeInt
    classification_record_count: NonNegativeInt
    unclassified_hit_count: NonNegativeInt
    duplicate_hit_id_count: NonNegativeInt
    query_plan: EvidenceArtifactRef
    raw_results: EvidenceArtifactRef
    hit_classification: EvidenceArtifactRef


class PostDispositionQualificationReport(StrictContract):
    schema_version: Literal["pmorg.post-disposition-qualification/v1"]
    catalog_hash: Sha256Digest
    capability_id: Annotated[str, Field(min_length=1)]
    implementation_path_set_hash: Sha256Digest
    patch_ledger_set_hash: Sha256Digest
    required_test_manifest: EvidenceArtifactRef
    expected_test_count: PositiveInt
    executed_test_count: PositiveInt
    missing_test_count: NonNegativeInt
    duplicate_test_count: NonNegativeInt
    failed_test_count: NonNegativeInt
    test_evidence: Annotated[list[TestEvidence], Field(min_length=1)]
    verdict: Literal["pass", "fail"]


class ImplementationPathRef(StrictContract):
    path: RelativePath
    content_hash: Sha256Digest
    source_ref: ContentAddressedSourceRef
    ownership_class: OwnershipClass
    license_class: LicenseClass
    provenance_inventory_item: EvidenceArtifactRef


class PatchLedgerRecordRef(StrictContract):
    ledger_entry_id: Annotated[str, Field(min_length=1)]
    path: RelativePath
    source_ref: ContentAddressedSourceRef
    base_blob_hash: Sha256Digest | None
    patched_blob_hash: Sha256Digest | None
    ownership_class: Literal["upstream_ce_direct_patch", "upstream_ee_direct_patch"]
    license_class: Literal["mit-expat", "onyx-enterprise"]
    ledger_record: EvidenceArtifactRef
    protector_tests: Annotated[list[TestEvidence], Field(min_length=1)]


class DeviationDecisionPayload(StrictContract):
    schema_version: Literal["pmorg.capability-deviation-decision/v1"]
    decision_id: Annotated[str, Field(min_length=1)]
    decision_type: Literal["adr", "waiver"]
    pmorg_spec_commit: GitSha
    pmorg_platform_commit: GitSha
    onyx_commit: GitSha
    onyx_surface: OnyxSurface
    usage_mode: UsageMode
    artifact_set_hash: Sha256Digest
    catalog_version: SemVer
    catalog_hash: Sha256Digest
    capability_id: Annotated[str, Field(min_length=1)]
    affected_candidate_ids: Annotated[list[str], Field(min_length=1)]
    permitted_disposition: Literal["patch", "pmorg_independent"]
    implementation_path_set_hash: Sha256Digest
    patch_ledger_set_hash: Sha256Digest
    post_disposition_test_manifest_hash: Sha256Digest
    rationale: Annotated[str, Field(min_length=1)]
    approver_identity: Annotated[str, Field(min_length=1)]
    authority_grant: EvidenceArtifactRef
    approved_at: UtcDatetime
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    next_revalidation_at: UtcDatetime
    trusted_clock_id: Annotated[str, Field(min_length=1)]
    trusted_time_receipt_envelope: EvidenceArtifactRef
    temporal_policy: TemporalPolicyBinding
    revocation_status: EvidenceArtifactRef
    verifier_identity: Annotated[str, Field(min_length=1)]
    verification_policy_hash: Sha256Digest
    verification_material_bundle: EvidenceArtifactRef
    issued_at: UtcDatetime


class CapabilityCatalogItem(StrictContract):
    capability_id: Annotated[str, Field(min_length=1)]
    pmorg_requirement_ids: Annotated[list[str], Field(min_length=1)]
    contract_tests: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]


class CapabilityCatalog(StrictContract):
    schema_version: Literal["pmorg.capability-catalog/v1"]
    catalog_version: SemVer
    pmorg_spec_commit: GitSha
    disposition_scope_rule: EvidenceArtifactRef
    applicable_requirement_set: EvidenceArtifactRef
    required_search_surfaces: Annotated[list[OnyxSurface], Field(min_length=1)]
    expected_requirement_count: PositiveInt
    mapped_requirement_count: PositiveInt
    unmapped_requirement_count: NonNegativeInt
    unknown_requirement_count: NonNegativeInt
    duplicate_capability_id_count: NonNegativeInt
    items: Annotated[list[CapabilityCatalogItem], Field(min_length=1)]
    item_count: PositiveInt


class CapabilityDispositionRecord(StrictContract):
    schema_version: Literal["pmorg.capability-disposition/v1"]
    catalog_version: SemVer
    catalog_hash: Sha256Digest
    pmorg_spec_commit: GitSha
    pmorg_platform_commit: GitSha
    onyx_commit: GitSha
    artifact_set_hash: Sha256Digest
    onyx_surface: OnyxSurface
    usage_mode: UsageMode
    capability_id: Annotated[str, Field(min_length=1)]
    pmorg_requirement_ids: Annotated[list[str], Field(min_length=1)]
    candidate_search_outcome: Literal["candidates_found", "no_candidate"]
    candidate_search_evidence: CandidateSearchEvidence
    candidates: list[OnyxCapabilityCandidate]
    disposition: Literal["reuse", "patch", "pmorg_independent"]
    selected_candidate_ids: list[str]
    implementation_path_set_hash: Sha256Digest
    implementation_refs: Annotated[list[ImplementationPathRef], Field(min_length=1)]
    patch_ledger_set_hash: Sha256Digest
    patch_ledger_refs: list[PatchLedgerRecordRef]
    post_disposition_qualification: PostDispositionQualificationReport
    rationale: Annotated[str, Field(min_length=1)]
    deviation_decision_envelope: EvidenceArtifactRef | None
    record_evidence_bundle_index: EvidenceArtifactRef


class CapabilityDispositionReport(StrictContract):
    schema_version: Literal["pmorg.capability-disposition-report/v1"]
    catalog_version: SemVer
    pmorg_spec_commit: GitSha
    pmorg_platform_commit: GitSha
    subject_artifact_set_hash: Sha256Digest
    onyx_surface: OnyxSurface
    usage_mode: UsageMode
    catalog_hash: Sha256Digest
    catalog_item_count: PositiveInt
    catalog_requirement_count: PositiveInt
    record_refs: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]
    record_count: PositiveInt
    covered_count: PositiveInt
    missing_count: NonNegativeInt
    duplicate_count: NonNegativeInt
    unmapped_requirement_count: NonNegativeInt
    unknown_requirement_count: NonNegativeInt
    requirement_ref_mismatch_count: NonNegativeInt
    dangling_evidence_count: NonNegativeInt
    records_and_evidence_bundle_index: EvidenceArtifactRef


class ProvenancePathInventoryItem(StrictContract):
    path: RelativePath
    content_hash: Sha256Digest
    ownership_class: OwnershipClass
    patch_ledger_record: EvidenceArtifactRef | None
    license_class: LicenseClass


class ProvenanceMatchRecord(StrictContract):
    match_id: Annotated[str, Field(min_length=1)]
    raw_match_id: Annotated[str, Field(min_length=1)]
    subject_path: RelativePath
    subject_input_content_hash: Sha256Digest
    subject_final_content_hash: Sha256Digest | None
    path_ownership_class: Literal[
        "pmorg_owned", "upstream_ce_direct_patch", "upstream_ee_direct_patch"
    ]
    upstream_ee_path: RelativePath
    upstream_ee_content_hash: Sha256Digest
    match_kind: Literal["exact", "normalized", "similarity"]
    algorithm_id: Annotated[str, Field(min_length=1)]
    similarity_basis_points: Annotated[int, Field(ge=0, le=10000)]
    resolution: Literal["independent_match", "licensed_patch", "removed", "unresolved"]
    patch_ledger_record: PatchLedgerRecordRef | None
    license_class: LicenseClass
    reviewer_identity: Annotated[str, Field(min_length=1)]
    verifier_identity: Annotated[str, Field(min_length=1)]
    resolution_evidence: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]


class ProvenanceScanReport(StrictContract):
    schema_version: Literal["pmorg.provenance-scan-report/v1"]
    pmorg_spec_commit: GitSha
    subject_artifact_set_hash: Sha256Digest
    onyx_surface: OnyxSurface
    usage_mode: UsageMode
    scanner_name: Annotated[str, Field(min_length=1)]
    scanner_version: SemVer
    scanner_artifact_digest: Sha256Digest
    algorithm_id: Annotated[str, Field(min_length=1)]
    normalization_spec_version: SemVer
    similarity_threshold_basis_points: Annotated[int, Field(ge=0, le=10000)]
    pmorg_repository: Annotated[str, Field(min_length=1)]
    pmorg_platform_commit: GitSha
    upstream_repository: Annotated[str, Field(min_length=1)]
    upstream_commit: GitSha
    ee_tree_hash: Sha256Digest
    pmorg_tree_hash: Sha256Digest
    pmorg_source_scope: SourceScopeManifest
    ee_source_scope: SourceScopeManifest
    scan_input_path_inventory: EvidenceArtifactRef
    final_path_inventory: EvidenceArtifactRef
    expected_pmorg_path_count: NonNegativeInt
    scanned_pmorg_path_count: NonNegativeInt
    unscanned_pmorg_path_count: NonNegativeInt
    expected_ee_path_count: NonNegativeInt
    scanned_ee_path_count: NonNegativeInt
    unscanned_ee_path_count: NonNegativeInt
    unreadable_path_count: NonNegativeInt
    duplicate_path_count: NonNegativeInt
    unclassified_path_count: NonNegativeInt
    raw_match_records: EvidenceArtifactRef
    raw_match_count: NonNegativeInt
    classified_match_records: EvidenceArtifactRef
    classification_record_count: NonNegativeInt
    unclassified_match_count: NonNegativeInt
    duplicate_match_id_count: NonNegativeInt
    match_record_count: NonNegativeInt
    exact_match_count: NonNegativeInt
    similarity_match_count: NonNegativeInt
    unreviewed_match_count: NonNegativeInt
    invalid_licensed_patch_count: NonNegativeInt
    forbidden_copy_count: NonNegativeInt
    unresolved_count: NonNegativeInt
    evidence_bundle_index_hash: Sha256Digest
