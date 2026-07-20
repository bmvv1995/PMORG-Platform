"""Single source of truth for generated PMORG contract artifacts."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel

from pmorg.contracts import commands
from pmorg.contracts import types

SPECIFICATION_REPOSITORY = "https://github.com/bmvv1995/PMORG.git"
SPECIFICATION_COMMIT = "05bc4df345d2d65e05b510135a4d99c9edbf886e"
MANIFEST_VERSION = "pmorg.contract-schema-manifest/v1"


@dataclass(frozen=True, order=True)
class ContractDefinition:
    schema_version: str
    model: type[BaseModel]
    write_schema: bool = True

    @property
    def stem(self) -> str:
        return (
            self.schema_version.removeprefix("pmorg.")
            .replace(".", "-")
            .replace("/", "-")
        )


_RELEASE_CONTRACTS = (
    ("pmorg.admission-use-receipt/v1", types.AdmissionUseReceiptPayload),
    (
        "pmorg.build-qualification-attestation/v1",
        types.BuildQualificationAttestation,
    ),
    ("pmorg.build-qualification-manifest/v1", types.BuildQualificationManifest),
    (
        "pmorg.candidate-qualification-report/v1",
        types.CandidateQualificationReport,
    ),
    ("pmorg.candidate-search-evidence/v1", types.CandidateSearchEvidence),
    ("pmorg.capability-catalog/v1", types.CapabilityCatalog),
    (
        "pmorg.capability-deviation-decision/v1",
        types.DeviationDecisionPayload,
    ),
    (
        "pmorg.capability-disposition-report/v1",
        types.CapabilityDispositionReport,
    ),
    ("pmorg.capability-disposition/v1", types.CapabilityDispositionRecord),
    (
        "pmorg.ce-release-authorization-binding/v1",
        types.CeReleaseAuthorizationBinding,
    ),
    ("pmorg.deployment-admission/v1", types.DeploymentAdmissionRecord),
    (
        "pmorg.deployment-payload-descriptor/v1",
        types.DeploymentPayloadDescriptor,
    ),
    (
        "pmorg.deployment-target-descriptor/v1",
        types.DeploymentTargetDescriptor,
    ),
    ("pmorg.distribution-admission/v1", types.DistributionAdmissionRecord),
    (
        "pmorg.distribution-destination-descriptor/v1",
        types.DistributionDestinationDescriptor,
    ),
    (
        "pmorg.distribution-destination-measurement/v1",
        types.DistributionDestinationMeasurementAttestation,
    ),
    (
        "pmorg.distribution-payload-descriptor/v1",
        types.DistributionPayloadDescriptor,
    ),
    (
        "pmorg.enterprise-authorization-binding/v1",
        types.EnterpriseAuthorizationBinding,
    ),
    ("pmorg.evidence-bundle-index/v1", types.EvidenceBundleIndex),
    ("pmorg.expected-artifact-catalog/v1", types.ExpectedArtifactCatalog),
    (
        "pmorg.post-disposition-qualification/v1",
        types.PostDispositionQualificationReport,
    ),
    ("pmorg.provenance-scan-report/v1", types.ProvenanceScanReport),
    ("pmorg.qualification-policy-map/v1", types.QualificationPolicyMap),
    (
        "pmorg.release-build-definition/v1",
        types.ReleaseBuildDefinitionPayload,
    ),
    ("pmorg.runtime-scope-policy-map/v1", types.RuntimeScopePolicyMap),
    ("pmorg.source-scope-manifest/v1", types.SourceScopeManifest),
    (
        "pmorg.target-measurement-attestation/v1",
        types.TargetMeasurementAttestation,
    ),
    ("pmorg.trusted-time-receipt/v1", types.TrustedTimeReceiptPayload),
)

_SHARED_CONTRACTS = (
    ("pmorg.dsse-envelope/v1", types.DsseEnvelope),
    ("pmorg.evidence-artifact-ref/v1", types.EvidenceArtifactRef),
    ("pmorg.qualification-report/v1", types.QualificationReport),
    ("pmorg.temporal-policy-binding/v1", types.TemporalPolicyBinding),
)

_COMMAND_CONTRACTS = (
    ("pmorg.action.execute-authorized/v1", commands.ActionExecuteAuthorizedPayload),
    ("pmorg.approval.request/v1", commands.ApprovalRequestPayload),
    (
        "pmorg.commitment.record-confirmation/v1",
        commands.CommitmentRecordConfirmationPayload,
    ),
    (
        "pmorg.evidence.record-reference/v1",
        commands.EvidenceRecordReferencePayload,
    ),
    (
        "pmorg.outcome.request-verification/v1",
        commands.OutcomeRequestVerificationPayload,
    ),
    ("pmorg.plan.propose-version/v1", commands.PlanProposeVersionPayload),
    (
        "pmorg.provenance-gap.record-detection/v1",
        commands.ProvenanceGapRecordDetectionPayload,
    ),
    ("pmorg.provenance-gap.resolve/v1", commands.ProvenanceGapResolvePayload),
    ("pmorg.run.complete/v1", commands.RunCompletePayload),
    ("pmorg.run.reclaim-expired/v1", commands.RunReclaimExpiredPayload),
    ("pmorg.task.activate-due/v1", commands.TaskActivateDuePayload),
    ("pmorg.task.block/v1", commands.TaskBlockPayload),
    ("pmorg.task.claim/v1", commands.TaskClaimPayload),
    ("pmorg.task.heartbeat/v1", commands.TaskHeartbeatPayload),
    ("pmorg.task.mark-managed/v1", commands.TaskMarkManagedPayload),
    ("pmorg.task.propose/v1", commands.TaskProposePayload),
    ("pmorg.task.record-escalation/v1", commands.TaskRecordEscalationPayload),
    ("pmorg.task.record-followup/v1", commands.TaskRecordFollowupPayload),
    ("pmorg.task.record-progress/v1", commands.TaskRecordProgressPayload),
    ("pmorg.task.release/v1", commands.TaskReleasePayload),
    ("pmorg.task.schedule/v1", commands.TaskSchedulePayload),
    ("pmorg.task.wait-response/v1", commands.TaskWaitResponsePayload),
)

CONTRACT_DEFINITIONS = tuple(
    sorted(
        ContractDefinition(schema_version=schema_version, model=model)
        for schema_version, model in (
            *_RELEASE_CONTRACTS,
            *_SHARED_CONTRACTS,
            *_COMMAND_CONTRACTS,
        )
    )
)

REQUIRED_RELEASE_SCHEMA_VERSIONS = frozenset(
    schema_version for schema_version, _model in _RELEASE_CONTRACTS
)
