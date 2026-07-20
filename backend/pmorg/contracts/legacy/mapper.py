"""Deterministic V2-to-V3 mapping without I/O, persistence, or runtime calls."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any
from typing import Literal
from uuid import UUID

from pmorg.contracts.legacy.models import ClaimStateMapping
from pmorg.contracts.legacy.models import IdempotencyDecision
from pmorg.contracts.legacy.models import LegacyMappingResult
from pmorg.contracts.legacy.models import LegacyProvenance
from pmorg.contracts.legacy.models import LegacyRelationRole
from pmorg.contracts.legacy.models import LegacyRunState
from pmorg.contracts.legacy.models import LegacySourceDescriptor
from pmorg.contracts.legacy.models import LegacySourceIdentity
from pmorg.contracts.legacy.models import LegacyTargetSystem
from pmorg.contracts.legacy.models import LegacyTaskState
from pmorg.contracts.legacy.models import LegacyType
from pmorg.contracts.legacy.models import TaskRunStateMapping
from pmorg.contracts.types import UtcDatetime

V2_MEMORY_OPERATIONS = frozenset(
    {
        "memory_negotiate_registry",
        "memory_capture_evidence",
        "memory_propose_claim",
        "memory_validate_claim",
        "memory_supersede",
        "memory_record_outcome",
        "memory_recall",
        "memory_get_timeline",
    }
)
V3_MEMORY_OPERATIONS = frozenset(
    {
        "negotiate_registry",
        "capture_evidence",
        "propose_claim",
        "assess_claim",
        "validate_claim",
        "supersede_claim",
        "record_outcome",
        "recall",
        "get_timeline",
        "record_contradiction",
        "record_commitment",
    }
)

_OPERATION_MAP: dict[str, tuple[str, ...]] = {
    "memory_negotiate_registry": ("negotiate_registry",),
    "memory_capture_evidence": ("capture_evidence",),
    "memory_propose_claim": ("propose_claim",),
    "memory_validate_claim": ("assess_claim", "validate_claim"),
    "memory_supersede": ("supersede_claim",),
    "memory_record_outcome": ("record_outcome",),
    "memory_recall": ("recall",),
    "memory_get_timeline": ("get_timeline",),
}

_ERROR_MAP: dict[str, str] = {
    "MEM_CONTRACT": "UNSUPPORTED_SCHEMA_VERSION",
    "MEM_SCHEMA": "INVALID_ARGUMENT",
    "MEM_STATE": "INVALID_CLAIM_TRANSITION",
    "MEM_REGISTRY_MISMATCH": "REGISTRY_MISMATCH",
    "MEM_ANCHOR_TYPE_UNKNOWN": "ANCHOR_TYPE_NOT_ALLOWED",
    "MEM_NOT_AUTHORIZED": "AUTHORITY_REQUIRED",
    "MEM_SELF_VALIDATION": "INDEPENDENT_VALIDATOR_REQUIRED",
    "MEM_HASH_MISMATCH": "EVIDENCE_HASH_MISMATCH",
    "MEM_INTERNAL": "INTERNAL_ERROR",
}


class LegacyMappingError(ValueError):
    """Raised when a legacy value has no unambiguous V3 mapping."""


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Canonicalize the RFC 8785 subset used by migration fixtures.

    Floats are rejected because their ECMAScript serialization cannot be
    reproduced safely with the Python standard library alone.
    """

    def reject_floats(item: Any) -> None:
        if isinstance(item, float):
            raise LegacyMappingError("floating-point values are not canonical inputs")
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise LegacyMappingError("canonical object keys must be strings")
                reject_floats(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                reject_floats(nested)
        elif isinstance(item, int) and not isinstance(item, bool):
            if not -(2**53 - 1) <= item <= 2**53 - 1:
                raise LegacyMappingError("integer exceeds the interoperable JSON range")
        elif item is not None and not isinstance(item, (str, bool)):
            raise LegacyMappingError(
                f"unsupported canonical value type: {type(item).__name__}"
            )

    reject_floats(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def derive_legacy_source_instance_id(descriptor: LegacySourceDescriptor) -> str:
    """Bind one import to repository, commit, sandbox, database, and version."""

    return _sha256(descriptor.model_dump(mode="json"))


def derive_source_system(legacy_source_instance_id: str) -> str:
    digest = legacy_source_instance_id.removeprefix("sha256:")
    if (
        len(digest) != 64
        or legacy_source_instance_id != f"sha256:{digest}"
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise LegacyMappingError("legacy source instance must be a sha256 digest")
    return f"legacy-import/{legacy_source_instance_id}"


def derive_memory_idempotency_key(
    *, legacy_source_instance_id: str, legacy_namespace: str, external_id: str
) -> str:
    projection = {
        "external_id": external_id,
        "legacy_namespace": legacy_namespace,
        "legacy_source_instance_id": legacy_source_instance_id,
    }
    return "v2e1:" + hashlib.sha256(_canonical_json_bytes(projection)).hexdigest()


def classify_idempotency(
    *,
    validated_request: Mapping[str, Any],
    existing_row: bool,
    existing_request_hash: str | None,
    original_payload_verifiable: bool,
) -> IdempotencyDecision:
    """Apply request-hash semantics before any business precondition."""

    request_hash = _sha256(validated_request)
    if not existing_row:
        return IdempotencyDecision(
            status="accept",
            request_hash=request_hash,
            emits_effect=True,
            authoritative=True,
        )
    if not original_payload_verifiable or existing_request_hash is None:
        return IdempotencyDecision(
            status="reference_only",
            request_hash=request_hash,
            emits_effect=False,
            authoritative=False,
        )
    if existing_request_hash == request_hash:
        return IdempotencyDecision(
            status="replay",
            request_hash=request_hash,
            emits_effect=False,
            authoritative=True,
        )
    return IdempotencyDecision(
        status="conflict",
        request_hash=request_hash,
        emits_effect=False,
        authoritative=True,
    )


def map_memory_operation(operation: str) -> tuple[str, ...]:
    try:
        return _OPERATION_MAP[operation]
    except KeyError as exc:
        raise LegacyMappingError(
            f"unsupported V2 memory operation: {operation}"
        ) from exc


def map_v3_operations_to_legacy(operations: tuple[str, ...]) -> str:
    """Reverse one mapped fixture without inventing V2 aliases for new operations."""

    reverse_map = {mapped: legacy for legacy, mapped in _OPERATION_MAP.items()}
    try:
        return reverse_map[operations]
    except KeyError as exc:
        raise LegacyMappingError(
            f"V3 operation sequence has no V2 fixture mapping: {operations!r}"
        ) from exc


def map_memory_error(
    error_code: str,
    *,
    unknown_resource: Literal["evidence", "claim"] | None = None,
) -> str:
    if error_code == "MEM_UNKNOWN":
        if unknown_resource == "evidence":
            return "EVIDENCE_NOT_FOUND"
        if unknown_resource == "claim":
            return "CLAIM_NOT_FOUND"
        raise LegacyMappingError("MEM_UNKNOWN requires evidence or claim context")
    try:
        return _ERROR_MAP[error_code]
    except KeyError as exc:
        raise LegacyMappingError(f"unsupported V2 memory error: {error_code}") from exc


def map_claim_state(
    state: str,
    *,
    source_verified: bool,
    evidence_reconstructible: bool = False,
    authority_receipt_reconstructible: bool = False,
    assessment_reconstructible: bool = False,
    prior_validation_reconstructible: bool = False,
    contradiction_reconstructible: bool = False,
    supersession_reconstructible: bool = False,
) -> ClaimStateMapping:
    if not source_verified:
        return ClaimStateMapping(
            v3_state="reference_only",
            disposition="reference_only",
            reason="legacy source instance or namespace is not verifiable",
        )
    if state == "candidate":
        return ClaimStateMapping(
            v3_state="proposed",
            disposition="authoritative",
            reason="candidate claims remain proposed without implicit truth promotion",
        )
    if state == "validated":
        if evidence_reconstructible and authority_receipt_reconstructible:
            return ClaimStateMapping(
                v3_state="validated",
                disposition="authoritative",
                reason="evidence and authority receipts are reconstructible",
            )
        return ClaimStateMapping(
            v3_state="proposed",
            disposition="reference_only",
            reason="legacy validated status lacks reconstructible evidence or authority",
        )
    if state == "refuted":
        if prior_validation_reconstructible and contradiction_reconstructible:
            return ClaimStateMapping(
                v3_state="disputed",
                disposition="authoritative",
                reason="prior validation and contradiction receipts are reconstructible",
            )
        if assessment_reconstructible:
            return ClaimStateMapping(
                v3_state="rejected",
                disposition="authoritative",
                reason="rejection assessment evidence is reconstructible",
            )
        return ClaimStateMapping(
            v3_state="reference_only",
            disposition="reference_only",
            reason="legacy refuted status is ambiguous without receipts",
        )
    if state == "superseded":
        if supersession_reconstructible:
            return ClaimStateMapping(
                v3_state="superseded",
                disposition="authoritative",
                reason="old/new identities, scope, and interval are reconstructible",
            )
        return ClaimStateMapping(
            v3_state="reference_only",
            disposition="reference_only",
            reason="supersession relation is incomplete",
        )
    if state == "under_review":
        return ClaimStateMapping(
            v3_state="reference_only",
            disposition="reference_only",
            reason="human interpretation review is not a V3 claim state",
        )
    raise LegacyMappingError(f"unsupported V2 claim state: {state}")


def map_task_run_effect(
    effect: str,
    *,
    evidence_reconstructible: bool,
    effect_class: Literal[
        "read_only", "idempotent_receipted", "external_uncertain"
    ] = "external_uncertain",
) -> TaskRunStateMapping:
    if effect in {"record_followup", "record_escalation"}:
        if evidence_reconstructible:
            return TaskRunStateMapping(
                run_state=None,
                task_state=None,
                disposition="authoritative",
                emits_event=True,
                reason="a single append-only event can be reconstructed",
            )
        return TaskRunStateMapping(
            run_state=None,
            task_state=None,
            disposition="reference_only",
            emits_event=False,
            reason="aggregate counters cannot synthesize missing legacy events",
        )

    if effect in {"reclaim_expired", "live_run"}:
        if not evidence_reconstructible:
            return TaskRunStateMapping(
                run_state=None,
                task_state="review",
                disposition="reference_only",
                emits_event=False,
                reason="legacy lease or effect evidence is incomplete",
            )
        safe_to_retry = effect_class in {"read_only", "idempotent_receipted"}
        return TaskRunStateMapping(
            run_state="expired" if effect == "reclaim_expired" else None,
            task_state="ready" if safe_to_retry else "review",
            disposition="authoritative",
            emits_event=effect == "reclaim_expired",
            reason=(
                "legacy lease is revoked and the effect is safe to retry"
                if safe_to_retry
                else "missing effect receipts make the external effect uncertain"
            ),
        )

    complete_map: dict[str, tuple[LegacyRunState | None, LegacyTaskState]] = {
        "mark_managed": (None, "ready"),
        "complete_done": ("succeeded", "completed"),
        "complete_failed": ("failed", "failed"),
        "complete_needs_review": ("succeeded", "review"),
        "release_task": ("cancelled", "ready"),
        "waiting_response": ("succeeded", "waiting_response"),
        "approval_active": ("succeeded", "waiting_approval"),
        "schedule_next_check": ("succeeded", "scheduled"),
        "block_task": ("succeeded", "blocked"),
    }
    try:
        run_state, task_state = complete_map[effect]
    except KeyError as exc:
        raise LegacyMappingError(f"unsupported V2 task/run effect: {effect}") from exc

    if effect == "release_task" and effect_class == "external_uncertain":
        return TaskRunStateMapping(
            run_state="cancelled",
            task_state="review",
            disposition="reference_only",
            emits_event=False,
            reason="voluntary release cannot hide an uncertain external effect",
        )
    if not evidence_reconstructible:
        return TaskRunStateMapping(
            run_state=None,
            task_state="review",
            disposition="reference_only",
            emits_event=False,
            reason="required legacy effect evidence is incomplete",
        )
    return TaskRunStateMapping(
        run_state=run_state,
        task_state=task_state,
        disposition="authoritative",
        emits_event=True,
        reason="legacy effect and required receipts are reconstructible",
    )


def map_legacy_provenance(
    *,
    legacy_identity_id: UUID,
    binding_id: UUID,
    organization_id: UUID,
    descriptor: LegacySourceDescriptor,
    legacy_namespace: str,
    legacy_type: LegacyType,
    legacy_id: str,
    import_manifest_hash: str,
    target_system: LegacyTargetSystem,
    target_type: str,
    target_id: str,
    relation_role: LegacyRelationRole,
    imported_at: UtcDatetime,
    source_verified: bool,
    namespace_verified: bool,
) -> LegacyMappingResult:
    source = LegacySourceIdentity(
        schema_version="pmorg.legacy-source-identity/v1",
        legacy_identity_id=legacy_identity_id,
        organization_id=organization_id,
        legacy_source_instance_id=derive_legacy_source_instance_id(descriptor),
        legacy_namespace=legacy_namespace,
        legacy_contract_version=descriptor.legacy_contract_version,
        legacy_type=legacy_type,
        legacy_id=legacy_id,
        import_manifest_hash=import_manifest_hash,
    )
    authoritative = source_verified and namespace_verified
    if not authoritative:
        target_system = "migration_reference"
        relation_role = "reference_only"
    provenance = LegacyProvenance(
        schema_version="pmorg.legacy-provenance-binding/v1",
        binding_id=binding_id,
        legacy_identity_id=legacy_identity_id,
        target_system=target_system,
        target_type=target_type,
        target_id=target_id,
        relation_role=relation_role,
        imported_at=imported_at,
    )
    return LegacyMappingResult(
        source=source,
        provenance=provenance,
        disposition="authoritative" if authoritative else "reference_only",
        reason=(
            "source instance and namespace are verified"
            if authoritative
            else "unverified legacy identity is confined to migration_reference"
        ),
    )
