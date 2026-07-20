from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from datetime import UTC
from pathlib import Path
from uuid import UUID

from pmorg.contracts import SUPPORTED_WIRE_SURFACES
from pmorg.contracts import WIRE_SURFACE
from pmorg.contracts.legacy import classify_idempotency
from pmorg.contracts.legacy import derive_legacy_source_instance_id
from pmorg.contracts.legacy import derive_memory_idempotency_key
from pmorg.contracts.legacy import derive_source_system
from pmorg.contracts.legacy import LegacySourceDescriptor
from pmorg.contracts.legacy import map_claim_state
from pmorg.contracts.legacy import map_legacy_provenance
from pmorg.contracts.legacy import map_memory_error
from pmorg.contracts.legacy import map_memory_operation
from pmorg.contracts.legacy import map_task_run_effect
from pmorg.contracts.legacy import map_v3_operations_to_legacy
from pmorg.contracts.legacy.mapper import LegacyMappingError
from pmorg.contracts.legacy.mapper import V2_MEMORY_OPERATIONS
from pmorg.contracts.legacy.mapper import V3_MEMORY_OPERATIONS
from pmorg.legacy_boundaries import assert_legacy_mapper_purity
from pmorg.legacy_boundaries import find_legacy_purity_violations

PMORG_ROOT = Path(__file__).resolve().parents[1]
LEGACY_ROOT = PMORG_ROOT / "contracts" / "legacy"
FIXTURE = Path(__file__).parent / "fixtures" / "legacy" / "v2-memory.json"

LEGACY_IDENTITY_ID = UUID("0190f1a0-7b1c-7abc-8def-0123456789ab")
BINDING_ID = UUID("0190f1a0-7b1c-7def-8abc-0123456789ab")
ORGANIZATION_ID = UUID("0190f1a0-7b1c-7fed-8123-0123456789ab")


def _descriptor() -> LegacySourceDescriptor:
    return LegacySourceDescriptor(
        repository="https://github.com/bmvv1995/PMORG.git",
        commit_sha="0123456789abcdef0123456789abcdef01234567",
        sandbox_id="sb3",
        database_uuid=UUID("12345678-1234-5678-9234-567812345678"),
        legacy_contract_version="pmorg-memory/1.0",
    )


class LegacyMapperTests(unittest.TestCase):
    def test_mapper_package_is_pure_and_guard_fails_closed(self) -> None:
        self.assertEqual(find_legacy_purity_violations(LEGACY_ROOT), ())
        assert_legacy_mapper_purity(LEGACY_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "backend" / "pmorg" / "contracts" / "legacy"
            root.mkdir(parents=True)
            (root / "bad.py").write_text(
                "import requests\nfrom pathlib import Path\nopen('state')\n",
                encoding="utf-8",
            )
            violations = find_legacy_purity_violations(root)
        self.assertEqual(len(violations), 3)

    def test_only_v3_wire_surface_remains_public(self) -> None:
        self.assertEqual(WIRE_SURFACE, "pmorg-contracts/1.0")
        self.assertEqual(SUPPORTED_WIRE_SURFACES, {WIRE_SURFACE})
        self.assertFalse(any("v2" in item.lower() for item in SUPPORTED_WIRE_SURFACES))

    def test_operation_fixture_maps_exactly_eight_to_eleven(self) -> None:
        fixture = json.loads(FIXTURE.read_bytes())
        mapped = {
            operation: map_memory_operation(operation)
            for operation in fixture["operations"]
        }
        flattened = {item for values in mapped.values() for item in values}
        self.assertEqual(set(fixture["operations"]), V2_MEMORY_OPERATIONS)
        self.assertEqual(len(V2_MEMORY_OPERATIONS), 8)
        self.assertEqual(len(V3_MEMORY_OPERATIONS), 11)
        self.assertEqual(
            V3_MEMORY_OPERATIONS - flattened,
            {"record_contradiction", "record_commitment"},
        )
        self.assertEqual(
            mapped["memory_validate_claim"], ("assess_claim", "validate_claim")
        )
        self.assertEqual(
            {
                map_v3_operations_to_legacy(v3_operations)
                for v3_operations in mapped.values()
            },
            set(fixture["operations"]),
        )
        with self.assertRaises(LegacyMappingError):
            map_memory_operation("memory_delete")
        with self.assertRaises(LegacyMappingError):
            map_v3_operations_to_legacy(("record_contradiction",))

    def test_error_mapping_preserves_unknown_resource_context(self) -> None:
        self.assertEqual(map_memory_error("MEM_SCHEMA"), "INVALID_ARGUMENT")
        self.assertEqual(
            map_memory_error("MEM_UNKNOWN", unknown_resource="evidence"),
            "EVIDENCE_NOT_FOUND",
        )
        self.assertEqual(
            map_memory_error("MEM_UNKNOWN", unknown_resource="claim"),
            "CLAIM_NOT_FOUND",
        )
        with self.assertRaises(LegacyMappingError):
            map_memory_error("MEM_UNKNOWN")

    def test_source_identity_and_memory_key_are_stable_and_scoped(self) -> None:
        source_id = derive_legacy_source_instance_id(_descriptor())
        self.assertEqual(source_id, derive_legacy_source_instance_id(_descriptor()))
        self.assertEqual(len(source_id), 71)
        self.assertEqual(derive_source_system(source_id), f"legacy-import/{source_id}")
        key = derive_memory_idempotency_key(
            legacy_source_instance_id=source_id,
            legacy_namespace="org-dist",
            external_id="evidence-17",
        )
        self.assertEqual(len(key), 69)
        self.assertNotEqual(
            key,
            derive_memory_idempotency_key(
                legacy_source_instance_id=source_id,
                legacy_namespace="org-other",
                external_id="evidence-17",
            ),
        )
        with self.assertRaises(LegacyMappingError):
            derive_source_system("sha256:not-a-digest")

    def test_request_hash_replay_conflict_and_unverifiable_row(self) -> None:
        request = json.loads(FIXTURE.read_bytes())["capture_request"]
        accepted = classify_idempotency(
            validated_request=request,
            existing_row=False,
            existing_request_hash=None,
            original_payload_verifiable=True,
        )
        replay = classify_idempotency(
            validated_request=dict(reversed(list(request.items()))),
            existing_row=True,
            existing_request_hash=accepted.request_hash,
            original_payload_verifiable=True,
        )
        conflict = classify_idempotency(
            validated_request={**request, "content": "different"},
            existing_row=True,
            existing_request_hash=accepted.request_hash,
            original_payload_verifiable=True,
        )
        unverifiable = classify_idempotency(
            validated_request=request,
            existing_row=True,
            existing_request_hash=None,
            original_payload_verifiable=False,
        )
        self.assertEqual(accepted.status, "accept")
        self.assertEqual(replay.status, "replay")
        self.assertFalse(replay.emits_effect)
        self.assertEqual(conflict.status, "conflict")
        self.assertFalse(conflict.emits_effect)
        self.assertEqual(unverifiable.status, "reference_only")
        self.assertFalse(unverifiable.authoritative)
        with self.assertRaises(LegacyMappingError):
            classify_idempotency(
                validated_request={"unsafe_integer": 2**60},
                existing_row=False,
                existing_request_hash=None,
                original_payload_verifiable=True,
            )

    def test_unverified_source_is_never_promoted(self) -> None:
        mapped = map_legacy_provenance(
            legacy_identity_id=LEGACY_IDENTITY_ID,
            binding_id=BINDING_ID,
            organization_id=ORGANIZATION_ID,
            descriptor=_descriptor(),
            legacy_namespace="org-dist",
            legacy_type="claim",
            legacy_id="42",
            import_manifest_hash="sha256:" + "a" * 64,
            target_system="semantic_core",
            target_type="Claim",
            target_id="0190f1a0-7b1c-7aaa-8aaa-0123456789ab",
            relation_role="claim",
            imported_at=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
            source_verified=False,
            namespace_verified=True,
        )
        self.assertEqual(mapped.disposition, "reference_only")
        self.assertEqual(mapped.provenance.target_system, "migration_reference")
        self.assertEqual(mapped.provenance.relation_role, "reference_only")
        self.assertEqual(mapped.source.legacy_id, "42")
        self.assertNotEqual(str(mapped.source.legacy_identity_id), "42")

    def test_claim_state_mapping_fails_closed_on_missing_receipts(self) -> None:
        validated = map_claim_state(
            "validated",
            source_verified=True,
            evidence_reconstructible=True,
            authority_receipt_reconstructible=True,
        )
        incomplete = map_claim_state("validated", source_verified=True)
        disputed = map_claim_state(
            "refuted",
            source_verified=True,
            prior_validation_reconstructible=True,
            contradiction_reconstructible=True,
        )
        self.assertEqual(validated.v3_state, "validated")
        self.assertEqual(incomplete.v3_state, "proposed")
        self.assertEqual(incomplete.disposition, "reference_only")
        self.assertEqual(disputed.v3_state, "disputed")

    def test_task_state_mapping_never_invents_lease_or_events(self) -> None:
        done = map_task_run_effect(
            "complete_done",
            evidence_reconstructible=True,
            effect_class="idempotent_receipted",
        )
        uncertain = map_task_run_effect(
            "live_run",
            evidence_reconstructible=True,
            effect_class="external_uncertain",
        )
        incomplete = map_task_run_effect(
            "reclaim_expired",
            evidence_reconstructible=False,
            effect_class="read_only",
        )
        missing_followup = map_task_run_effect(
            "record_followup",
            evidence_reconstructible=False,
        )
        self.assertEqual((done.run_state, done.task_state), ("succeeded", "completed"))
        self.assertEqual(uncertain.run_state, None)
        self.assertEqual(uncertain.task_state, "review")
        self.assertEqual(incomplete.task_state, "review")
        self.assertEqual(incomplete.disposition, "reference_only")
        self.assertFalse(missing_followup.emits_event)
        self.assertEqual(missing_followup.disposition, "reference_only")


if __name__ == "__main__":
    unittest.main()
