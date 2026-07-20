"""Pure, removable compatibility mapping for frozen PMORG V2 fixtures."""

from pmorg.contracts.legacy.mapper import classify_idempotency
from pmorg.contracts.legacy.mapper import derive_legacy_source_instance_id
from pmorg.contracts.legacy.mapper import derive_memory_idempotency_key
from pmorg.contracts.legacy.mapper import derive_source_system
from pmorg.contracts.legacy.mapper import map_claim_state
from pmorg.contracts.legacy.mapper import map_legacy_provenance
from pmorg.contracts.legacy.mapper import map_memory_error
from pmorg.contracts.legacy.mapper import map_memory_operation
from pmorg.contracts.legacy.mapper import map_task_run_effect
from pmorg.contracts.legacy.mapper import map_v3_operations_to_legacy
from pmorg.contracts.legacy.models import ClaimStateMapping
from pmorg.contracts.legacy.models import IdempotencyDecision
from pmorg.contracts.legacy.models import LegacyProvenance
from pmorg.contracts.legacy.models import LegacySourceDescriptor
from pmorg.contracts.legacy.models import LegacySourceIdentity
from pmorg.contracts.legacy.models import TaskRunStateMapping

__all__ = [
    "ClaimStateMapping",
    "IdempotencyDecision",
    "LegacyProvenance",
    "LegacySourceDescriptor",
    "LegacySourceIdentity",
    "TaskRunStateMapping",
    "classify_idempotency",
    "derive_legacy_source_instance_id",
    "derive_memory_idempotency_key",
    "derive_source_system",
    "map_claim_state",
    "map_legacy_provenance",
    "map_memory_error",
    "map_memory_operation",
    "map_task_run_effect",
    "map_v3_operations_to_legacy",
]
