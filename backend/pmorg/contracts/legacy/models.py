"""Closed data shapes emitted by the isolated V2 compatibility mapper."""

from __future__ import annotations

from typing import Annotated
from typing import Literal
from uuid import UUID

from pydantic import Field
from pydantic import UUID7

from pmorg.contracts.types import GitSha
from pmorg.contracts.types import Sha256Digest
from pmorg.contracts.types import StrictContract
from pmorg.contracts.types import UtcDatetime

LegacyType = Literal[
    "evidence",
    "claim",
    "outcome",
    "task",
    "run",
    "event",
    "inbox_row",
]
LegacyTargetSystem = Literal["odoo", "semantic_core", "migration_reference"]
LegacyRelationRole = Literal[
    "source_artifact",
    "evidence",
    "claim",
    "assessment",
    "validation",
    "contradiction",
    "supersession",
    "commitment",
    "outcome",
    "task",
    "run",
    "event",
    "reference_only",
]
MappingDisposition = Literal["authoritative", "reference_only"]
LegacyRunState = Literal["succeeded", "failed", "cancelled", "expired"]
LegacyTaskState = Literal[
    "ready",
    "completed",
    "failed",
    "review",
    "waiting_response",
    "waiting_approval",
    "scheduled",
    "blocked",
]


class LegacySourceDescriptor(StrictContract):
    """Canonical identity of one frozen V2 source instance."""

    repository: Annotated[str, Field(min_length=1)]
    commit_sha: GitSha
    sandbox_id: Annotated[str, Field(min_length=1)]
    database_uuid: UUID
    legacy_contract_version: Annotated[str, Field(min_length=1)]


class LegacySourceIdentity(StrictContract):
    """V3 identity for one legacy row; serial IDs are never reused as UUIDs."""

    schema_version: Literal["pmorg.legacy-source-identity/v1"]
    legacy_identity_id: UUID7
    organization_id: UUID
    legacy_source_instance_id: Sha256Digest
    legacy_namespace: Annotated[str, Field(min_length=1)]
    legacy_contract_version: Annotated[str, Field(min_length=1)]
    legacy_type: LegacyType
    legacy_id: Annotated[str, Field(min_length=1)]
    import_manifest_hash: Sha256Digest


class LegacyProvenance(StrictContract):
    """One explicit 1:N binding from a legacy identity to a V3 target."""

    schema_version: Literal["pmorg.legacy-provenance-binding/v1"]
    binding_id: UUID7
    legacy_identity_id: UUID
    target_system: LegacyTargetSystem
    target_type: Annotated[str, Field(min_length=1)]
    target_id: Annotated[str, Field(min_length=1)]
    relation_role: LegacyRelationRole
    imported_at: UtcDatetime


class LegacyMappingResult(StrictContract):
    source: LegacySourceIdentity
    provenance: LegacyProvenance
    disposition: MappingDisposition
    reason: Annotated[str, Field(min_length=1)]


class IdempotencyDecision(StrictContract):
    status: Literal["accept", "replay", "conflict", "reference_only"]
    request_hash: Sha256Digest
    emits_effect: bool
    authoritative: bool


class ClaimStateMapping(StrictContract):
    v3_state: Literal[
        "proposed",
        "validated",
        "rejected",
        "disputed",
        "superseded",
        "reference_only",
    ]
    disposition: MappingDisposition
    reason: Annotated[str, Field(min_length=1)]


class TaskRunStateMapping(StrictContract):
    run_state: LegacyRunState | None
    task_state: LegacyTaskState | None
    disposition: MappingDisposition
    emits_event: bool
    reason: Annotated[str, Field(min_length=1)]
