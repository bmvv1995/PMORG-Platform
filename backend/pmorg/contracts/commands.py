"""Closed payload schemas for the normative PMORG Odoo command catalog."""

from __future__ import annotations

from typing import Annotated
from typing import Literal
from uuid import UUID

from pydantic import Field
from pydantic import NonNegativeInt
from pydantic import PositiveInt
from pydantic import UUID7

from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import Sha256Digest
from pmorg.contracts.types import StrictContract
from pmorg.contracts.types import UtcDatetime


class OpaqueAnchorRef(StrictContract):
    anchor_type: Annotated[str, Field(min_length=1)]
    anchor_id: Annotated[str, Field(min_length=1)]


class RuntimeCapability(StrictContract):
    capability_id: Annotated[str, Field(min_length=1)]
    capability_version: Annotated[str, Field(min_length=1)]


class TaskClaimPayload(StrictContract):
    schema_version: Literal["pmorg.task.claim/v1"]
    task_id: PositiveInt
    runtime_capabilities: list[RuntimeCapability]
    requested_lease_seconds: PositiveInt


class TaskHeartbeatPayload(StrictContract):
    schema_version: Literal["pmorg.task.heartbeat/v1"]
    task_id: PositiveInt
    run_id: UUID
    lease_token: Annotated[str, Field(min_length=1)]


class TaskReleasePayload(StrictContract):
    schema_version: Literal["pmorg.task.release/v1"]
    task_id: PositiveInt
    run_id: UUID
    reason_code: Annotated[str, Field(min_length=1)]


class TaskRecordProgressPayload(StrictContract):
    schema_version: Literal["pmorg.task.record-progress/v1"]
    task_id: PositiveInt
    run_id: UUID
    progress_code: Annotated[str, Field(min_length=1)]
    summary_ref: EvidenceArtifactRef


class TaskWaitResponsePayload(StrictContract):
    schema_version: Literal["pmorg.task.wait-response/v1"]
    task_id: PositiveInt
    conversation_id: UUID
    expected_from: Annotated[list[UUID], Field(min_length=1)]
    next_check_at: UtcDatetime


class TaskSchedulePayload(StrictContract):
    schema_version: Literal["pmorg.task.schedule/v1"]
    task_id: PositiveInt
    next_check_at: UtcDatetime
    reason_code: Annotated[str, Field(min_length=1)]


class TaskActivateDuePayload(StrictContract):
    schema_version: Literal["pmorg.task.activate-due/v1"]
    task_id: PositiveInt
    trigger_type: Literal["response", "approval", "trusted_time_tick"]
    trigger_ref: Annotated[str, Field(min_length=1)]


class TaskBlockPayload(StrictContract):
    schema_version: Literal["pmorg.task.block/v1"]
    task_id: PositiveInt
    blocker: Annotated[str, Field(min_length=1)]
    owner_identity_id: UUID
    exit_condition: Annotated[str, Field(min_length=1)]


class TaskMarkManagedPayload(StrictContract):
    schema_version: Literal["pmorg.task.mark-managed/v1"]
    task_id: PositiveInt
    monitoring_policy_ref: EvidenceArtifactRef


class TaskRecordFollowupPayload(StrictContract):
    schema_version: Literal["pmorg.task.record-followup/v1"]
    task_id: PositiveInt
    intervention_id: UUID7
    conversation_id: UUID
    outbound_message_id: UUID
    message_receipt_ref: EvidenceArtifactRef
    reason_code: Annotated[str, Field(min_length=1)]
    policy_ref: EvidenceArtifactRef


class TaskRecordEscalationPayload(StrictContract):
    schema_version: Literal["pmorg.task.record-escalation/v1"]
    task_id: PositiveInt
    escalation_id: UUID7
    recipient_identity_ids: Annotated[list[UUID], Field(min_length=1)]
    trigger_ref: EvidenceArtifactRef
    reason_code: Annotated[str, Field(min_length=1)]
    policy_ref: EvidenceArtifactRef
    evidence_refs: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]


class RunReclaimExpiredPayload(StrictContract):
    schema_version: Literal["pmorg.run.reclaim-expired/v1"]
    task_id: PositiveInt
    run_id: UUID


class ObservationWindow(StrictContract):
    starts_at: UtcDatetime
    ends_at: UtcDatetime


class ProvenanceGapRecordDetectionPayload(StrictContract):
    schema_version: Literal["pmorg.provenance-gap.record-detection/v1"]
    detector_class: Annotated[str, Field(min_length=1)]
    effect_ref: OpaqueAnchorRef
    anchor_refs: Annotated[list[OpaqueAnchorRef], Field(min_length=1)]
    window: ObservationWindow
    materiality_policy_ref: EvidenceArtifactRef
    signal_hash: Sha256Digest


class ProvenanceGapResolvePayload(StrictContract):
    schema_version: Literal["pmorg.provenance-gap.resolve/v1"]
    gap_id: UUID
    resolution_code: Literal["explained", "dismissed"]
    evidence_refs: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]
    memory_receipt_refs: list[EvidenceArtifactRef]
    policy_ref: EvidenceArtifactRef


class TaskProposal(StrictContract):
    task_type: Annotated[str, Field(min_length=1)]
    title: Annotated[str, Field(min_length=1)]
    expected_outcome: Annotated[str, Field(min_length=1)]
    assignee: UUID | None
    due_at: UtcDatetime | None
    anchors: list[OpaqueAnchorRef]


class TaskProposePayload(TaskProposal):
    schema_version: Literal["pmorg.task.propose/v1"]
    initiative_id: PositiveInt


class PlanProposeVersionPayload(StrictContract):
    schema_version: Literal["pmorg.plan.propose-version/v1"]
    initiative_id: PositiveInt
    base_version: NonNegativeInt
    tasks: Annotated[list[TaskProposal], Field(min_length=1)]
    rationale: Annotated[str, Field(min_length=1)]
    evidence_refs: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]


class CommitmentRecordConfirmationPayload(StrictContract):
    schema_version: Literal["pmorg.commitment.record-confirmation/v1"]
    commitment_id: UUID
    confirmer: UUID
    confirmation_evidence: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]


class ApprovalRequestPayload(StrictContract):
    schema_version: Literal["pmorg.approval.request/v1"]
    action_hash: Sha256Digest
    action_type: Annotated[str, Field(min_length=1)]
    approver_policy: EvidenceArtifactRef
    expires_at: UtcDatetime


class EvidenceRecordReferencePayload(StrictContract):
    schema_version: Literal["pmorg.evidence.record-reference/v1"]
    target_ref: OpaqueAnchorRef
    evidence_id: UUID
    relation_role: Annotated[str, Field(min_length=1)]


class OutcomeRequestVerificationPayload(StrictContract):
    schema_version: Literal["pmorg.outcome.request-verification/v1"]
    outcome_id: UUID
    criterion_refs: Annotated[list[PositiveInt], Field(min_length=1)]
    evidence_refs: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]


class ActionParameter(StrictContract):
    name: Annotated[str, Field(min_length=1)]
    value_schema_version: Annotated[str, Field(min_length=1)]
    value_hash: Sha256Digest
    value_ref: EvidenceArtifactRef


class AuthorizedActionPayload(StrictContract):
    action_schema_version: Annotated[str, Field(min_length=1)]
    parameters: list[ActionParameter]


class ActionExecuteAuthorizedPayload(StrictContract):
    schema_version: Literal["pmorg.action.execute-authorized/v1"]
    action_type: Annotated[str, Field(min_length=1)]
    action_payload: AuthorizedActionPayload
    approval_ref: EvidenceArtifactRef


class RunCompletePayload(StrictContract):
    schema_version: Literal["pmorg.run.complete/v1"]
    task_id: PositiveInt
    run_id: UUID
    result_code: Annotated[str, Field(min_length=1)]
    receipt_refs: Annotated[list[EvidenceArtifactRef], Field(min_length=1)]
