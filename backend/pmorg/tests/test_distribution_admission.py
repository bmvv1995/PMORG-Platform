from __future__ import annotations

import base64
import json
import unittest
from datetime import datetime
from datetime import UTC
from pathlib import Path
from types import MethodType
from typing import Any
from typing import Literal
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pmorg.application.admission import AdmissionVerificationError
from pmorg.application.admission import artifact_id_set_digest
from pmorg.application.distribution_admission import (
    content_address_distribution_destination,
)
from pmorg.application.distribution_admission import (
    content_address_distribution_payload,
)
from pmorg.application.distribution_admission import (
    DESTINATION_MEASUREMENT_PRIVATE_KEY_ENV,
)
from pmorg.application.distribution_admission import (
    DESTINATION_MEASUREMENT_PUBLIC_KEY_ENV,
)
from pmorg.application.distribution_admission import (
    DISTRIBUTION_ADMISSION_PRIVATE_KEY_ENV,
)
from pmorg.application.distribution_admission import (
    DISTRIBUTION_ADMISSION_PUBLIC_KEY_ENV,
)
from pmorg.application.distribution_admission import evaluate_distribution_use
from pmorg.application.distribution_admission import sign_destination_measurement
from pmorg.application.distribution_admission import sign_distribution_admission
from pmorg.application.distribution_admission import verify_destination_measurement
from pmorg.application.distribution_admission import verify_distribution_admission
from pmorg.application.qualification import sha256_digest
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import export_ephemeral_key_environment
from pmorg.application.rbdp import PRIVATE_KEY_ENV
from pmorg.application.rbdp import PUBLIC_KEY_ENV
from pmorg.contracts.types import DistributionAdmissionRecord
from pmorg.contracts.types import DistributionDestinationDescriptor
from pmorg.contracts.types import DistributionDestinationMeasurementAttestation
from pmorg.contracts.types import DistributionPayloadDescriptor
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import EvidenceBundleIndex
from pmorg.contracts.types import RuntimeScopePolicyMap

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_ROOT = REPOSITORY_ROOT / "backend" / "pmorg" / "contracts"
POLICY_MANIFEST_PATH = REPOSITORY_ROOT / "pmorg" / "baseline-manifest.json"
_UNSET = object()


def _schema_digest(schema_version: str) -> str:
    manifest = json.loads((CONTRACT_ROOT / "manifest.json").read_bytes())
    entry = next(
        item
        for item in manifest["contracts"]
        if item["schema_version"] == schema_version
    )
    return entry["schema_sha256"]


def _new_qualification_fixture() -> Any:
    from pmorg.tests import test_qualification_signing

    fixture: Any = test_qualification_signing.TestQualificationSigning(
        methodName="test_bqm_is_content_addressed_exact_and_offline_resolvable"
    )
    original_qualification_index = fixture._qualification_index

    def qualification_index(self):
        index = original_qualification_index()
        baseline_hash = sha256_digest(POLICY_MANIFEST_PATH.read_bytes())
        artifact_ids = ["pmorg-ce-source"]
        release_roles = ["release-manifest"]
        deployment_schema = _schema_digest("pmorg.deployment-target-descriptor/v1")
        destination_schema = _schema_digest(
            "pmorg.distribution-destination-descriptor/v1"
        )
        self.runtime_scope_policy_map = RuntimeScopePolicyMap.model_validate(
            {
                "schema_version": "pmorg.runtime-scope-policy-map/v1",
                "baseline_manifest_hash": baseline_hash,
                "onyx_surface": "ce",
                "entries": [
                    {
                        "scope_class": "deployment_runtime",
                        "scope_policy_hash": "sha256:" + "1" * 64,
                        "expected_artifact_id_set_hash": artifact_id_set_digest(
                            artifact_ids
                        ),
                        "expected_release_metadata_role_set_hash": None,
                        "target_destination_policy_schema_hash": deployment_schema,
                    },
                    {
                        "scope_class": "registry_publish",
                        "scope_policy_hash": "sha256:" + "2" * 64,
                        "expected_artifact_id_set_hash": artifact_id_set_digest(
                            artifact_ids
                        ),
                        "expected_release_metadata_role_set_hash": (
                            artifact_id_set_digest(release_roles)
                        ),
                        "target_destination_policy_schema_hash": destination_schema,
                    },
                    {
                        "scope_class": "artifact_export",
                        "scope_policy_hash": "sha256:" + "3" * 64,
                        "expected_artifact_id_set_hash": artifact_id_set_digest(
                            artifact_ids
                        ),
                        "expected_release_metadata_role_set_hash": (
                            artifact_id_set_digest(release_roles)
                        ),
                        "target_destination_policy_schema_hash": destination_schema,
                    },
                ],
            }
        )
        ref = self._write_json(
            "qualification/runtime-scope-policy-map.json",
            self.runtime_scope_policy_map.model_dump(mode="json"),
        ).model_copy(update={"logical_name": "runtime-scope-policy-map"})
        return index.model_copy(
            update={
                "entries": [
                    ref if item.logical_name == "runtime-scope-policy-map" else item
                    for item in index.entries
                ]
            }
        )

    setattr(fixture, "_qualification_index", MethodType(qualification_index, fixture))
    fixture.setUp()
    return fixture


class TestDistributionAdmission(unittest.TestCase):
    def setUp(self) -> None:
        fixture = _new_qualification_fixture()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.bqa_envelope = fixture._envelope()
        self.now = datetime(2026, 7, 20, 0, 12, tzinfo=UTC)

        measurement_keys = export_ephemeral_key_environment(
            Ed25519PrivateKey.generate()
        )
        admission_keys = export_ephemeral_key_environment(Ed25519PrivateKey.generate())
        self.measurement_environment = {
            DESTINATION_MEASUREMENT_PRIVATE_KEY_ENV: measurement_keys[PRIVATE_KEY_ENV],
            DESTINATION_MEASUREMENT_PUBLIC_KEY_ENV: measurement_keys[PUBLIC_KEY_ENV],
        }
        self.admission_environment = {
            DISTRIBUTION_ADMISSION_PRIVATE_KEY_ENV: admission_keys[PRIVATE_KEY_ENV],
            DISTRIBUTION_ADMISSION_PUBLIC_KEY_ENV: admission_keys[PUBLIC_KEY_ENV],
        }
        metadata = self._write_support("release-manifest")
        self.release_metadata_index = EvidenceBundleIndex(
            schema_version="pmorg.evidence-bundle-index/v1",
            bundle_kind="distribution-release-metadata",
            subject_binding_hash=None,
            entries=[metadata],
            entry_count=1,
        )
        self.payload_descriptor = self._payload_descriptor()
        self.payload = content_address_distribution_payload(
            self.payload_descriptor,
            release_metadata_index=self.release_metadata_index,
            bqm=fixture.bqm,
            qualification_index=fixture.qualification_index,
            runtime_scope_policy_map=fixture.runtime_scope_policy_map,
            contract_root=CONTRACT_ROOT,
            evidence_root=fixture.evidence_root,
        )
        self.destination_descriptor = self._destination_descriptor()
        self.destination = content_address_distribution_destination(
            self.destination_descriptor,
            contract_root=CONTRACT_ROOT,
        )
        self.measurement_payload = self._measurement_payload()
        self.measurement_envelope = sign_destination_measurement(
            self.measurement_payload,
            destination=self.destination,
            contract_root=CONTRACT_ROOT,
            evidence_root=fixture.evidence_root,
            environ=self.measurement_environment,
        )
        self.admission_payload = self._admission_payload()
        self.admission_envelope = self._sign_admission(self.admission_payload)

    def _write_support(self, name: str) -> EvidenceArtifactRef:
        return self.fixture._write_json(
            f"distribution-admission/{name}.json",
            {
                "role": name,
                "valid_until": self.fixture.deadline.isoformat().replace("+00:00", "Z"),
            },
        ).model_copy(update={"logical_name": name})

    def _payload_descriptor(self) -> DistributionPayloadDescriptor:
        descriptor = {
            "schema_version": "pmorg.distribution-payload-descriptor/v1",
            "operation": "registry_publish",
            "distribution_scope_policy_hash": "sha256:" + "2" * 64,
            "expected_artifact_id_set_hash": artifact_id_set_digest(
                ["pmorg-ce-source"]
            ),
            "expected_release_metadata_role_set_hash": artifact_id_set_digest(
                ["release-manifest"]
            ),
            "deployable_artifact_descriptors": [
                item.model_dump(mode="json")
                for item in self.fixture.bqm.manifest.artifact_descriptors
            ],
            "deployable_artifact_count": 1,
            "expected_deployable_artifact_count": 1,
            "missing_deployable_artifact_count": 0,
            "unexpected_deployable_artifact_count": 0,
            "duplicate_deployable_artifact_key_count": 0,
            "release_metadata_bundle_index_hash": sha256_digest(
                canonical_json_bytes(
                    self.release_metadata_index.model_dump(mode="json")
                )
            ),
            "release_metadata_entry_count": 1,
            "expected_release_metadata_entry_count": 1,
            "missing_release_metadata_count": 0,
            "unexpected_release_metadata_count": 0,
            "duplicate_release_metadata_count": 0,
            "distribution_payload_hash": "sha256:" + "0" * 64,
        }
        fingerprint_input = dict(descriptor)
        fingerprint_input.pop("distribution_payload_hash")
        descriptor["distribution_payload_hash"] = sha256_digest(
            canonical_json_bytes(fingerprint_input)
        )
        return DistributionPayloadDescriptor.model_validate(descriptor)

    def _destination_descriptor(self) -> DistributionDestinationDescriptor:
        return DistributionDestinationDescriptor.model_validate(
            {
                "schema_version": "pmorg.distribution-destination-descriptor/v1",
                "destination_uid_hmac": "hmac-sha256:" + "a" * 64,
                "operation": "registry_publish",
                "registry_or_gateway_identity_set_hash": "sha256:" + "b" * 64,
                "account_binding_set_hash": "sha256:" + "c" * 64,
                "organization_binding_set_hash": "sha256:" + "d" * 64,
                "authorized_entity_binding_set_hash": "sha256:" + "e" * 64,
                "seat_scope_binding_set_hash": "sha256:" + "f" * 64,
                "agreement_binding_set_hash": "sha256:" + "1" * 64,
                "endpoint_and_storage_policy_hash": "sha256:" + "2" * 64,
                "resource_classification_report_hash": "sha256:" + "3" * 64,
                "production_destination_count": 0,
                "unknown_destination_count": 0,
                "derived_destination_class": "controlled_synthetic_registry",
            }
        )

    def _measurement_payload(
        self,
    ) -> DistributionDestinationMeasurementAttestation:
        return DistributionDestinationMeasurementAttestation.model_validate(
            {
                "schema_version": "pmorg.distribution-destination-measurement/v1",
                "destination_descriptor_hash": self.destination.digest,
                "destination_fingerprint": self.destination.fingerprint,
                "destination_evidence_bundle": self._write_support(
                    "destination-evidence"
                ),
                "verification_material_bundle": self._write_support(
                    "destination-verification-material"
                ),
                "measured_at": datetime(2026, 7, 20, 0, 10, tzinfo=UTC),
                "issued_at": datetime(2026, 7, 20, 0, 11, tzinfo=UTC),
                "valid_from": datetime(2026, 7, 20, 0, 10, tzinfo=UTC),
                "valid_until": datetime(2026, 7, 20, 0, 20, tzinfo=UTC),
                "next_revalidation_at": datetime(2026, 7, 20, 0, 18, tzinfo=UTC),
                "trusted_clock_id": "pmorg-test-clock",
                "trusted_time_receipt_envelope": self._write_support(
                    "destination-trusted-time"
                ),
                "temporal_policy": {
                    "policy_hash": "sha256:" + "4" * 64,
                    "max_clock_skew_seconds": 5,
                    "max_time_receipt_age_seconds": 120,
                    "max_measurement_age_seconds": 600,
                    "max_validity_seconds": 900,
                    "max_revalidation_interval_seconds": 600,
                },
                "verifier_identity": "pmorg-destination-measurer",
                "verification_policy_hash": "sha256:" + "5" * 64,
            }
        )

    def _admission_payload(self) -> DistributionAdmissionRecord:
        return DistributionAdmissionRecord.model_validate(
            {
                "schema_version": "pmorg.distribution-admission/v1",
                "admission_id": UUID("01900000-0000-7000-8000-000000000011"),
                "operation": "registry_publish",
                "artifact_set_hash": self.fixture.bqm.manifest.artifact_set_hash,
                "build_manifest_hash": self.fixture.bqm.digest,
                "build_attestation_envelope_hash": sha256_digest(
                    canonical_json_bytes(self.bqa_envelope.model_dump(mode="json"))
                ),
                "distribution_payload_descriptor_hash": self.payload.digest,
                "distribution_payload_hash": self.payload.fingerprint,
                "onyx_surface": "ce",
                "usage_mode": "development_test",
                "destination_descriptor_hash": self.destination.digest,
                "destination_fingerprint": self.destination.fingerprint,
                "destination_measurement_envelope_hash": sha256_digest(
                    canonical_json_bytes(
                        self.measurement_envelope.model_dump(mode="json")
                    )
                ),
                "destination_class": "controlled_synthetic_registry",
                "admission_basis": "synthetic_environment",
                "ce_release_authorization": None,
                "enterprise_authorization": None,
                "valid_from": datetime(2026, 7, 20, 0, 11, tzinfo=UTC),
                "valid_until": datetime(2026, 7, 20, 0, 20, tzinfo=UTC),
                "next_revalidation_at": datetime(2026, 7, 20, 0, 18, tzinfo=UTC),
                "trusted_clock_id": "pmorg-test-clock",
                "trusted_time_receipt_envelope": self._write_support(
                    "admission-trusted-time"
                ),
                "temporal_policy": self.measurement_payload.temporal_policy,
                "revocation_status": self._write_support("admission-revocation"),
                "verifier_identity": "pmorg-distribution-admission-verifier",
                "verification_policy_hash": "sha256:" + "6" * 64,
                "verification_material_bundle": self._write_support(
                    "admission-verification-material"
                ),
                "verifier_receipt": self._write_support("admission-verifier-receipt"),
                "issued_at": self.now,
            }
        )

    def _sign_admission(self, admission: DistributionAdmissionRecord):
        return sign_distribution_admission(
            admission,
            bqm=self.fixture.bqm,
            qualification_index=self.fixture.qualification_index,
            bqa_envelope=self.bqa_envelope,
            runtime_scope_policy_map=self.fixture.runtime_scope_policy_map,
            release_metadata_index=self.release_metadata_index,
            payload_descriptor=self.payload_descriptor,
            destination_descriptor=self.destination_descriptor,
            destination_measurement_envelope=self.measurement_envelope,
            contract_root=CONTRACT_ROOT,
            evidence_root=self.fixture.evidence_root,
            bqa_environ=self.fixture.environment,
            measurement_environ=self.measurement_environment,
            admission_environ=self.admission_environment,
        )

    def _evaluate(
        self,
        *,
        event: Literal[
            "registry_publish", "artifact_export", "transfer_revalidation"
        ] = "registry_publish",
        envelope: Any = _UNSET,
        now: datetime | None = None,
        destination: DistributionDestinationDescriptor | None = None,
        post_auth: DistributionDestinationDescriptor | None = None,
        redirects: list[DistributionDestinationDescriptor] | None = None,
        payload: DistributionPayloadDescriptor | None = None,
    ):
        actual_destination = destination or self.destination_descriptor
        return evaluate_distribution_use(
            use_id=UUID("01900000-0000-7000-8000-000000000012"),
            verification_event=event,
            governed_operation="registry_publish",
            admission_envelope=(
                self.admission_envelope if envelope is _UNSET else envelope
            ),
            bqm=self.fixture.bqm,
            qualification_index=self.fixture.qualification_index,
            bqa_envelope=self.bqa_envelope,
            runtime_scope_policy_map=self.fixture.runtime_scope_policy_map,
            release_metadata_index=self.release_metadata_index,
            actual_payload_descriptor=payload or self.payload_descriptor,
            actual_destination_descriptor=actual_destination,
            post_auth_destination_descriptor=post_auth or actual_destination,
            redirect_destination_descriptors=redirects or [],
            destination_measurement_envelope=self.measurement_envelope,
            trusted_time_receipt_envelope=self._write_support("use-trusted-time"),
            revocation_check=self._write_support("use-revocation"),
            verification_material_bundle=self._write_support(
                "use-verification-material"
            ),
            verifier_identity="pmorg-distribution-use-verifier",
            verification_policy_hash="sha256:" + "7" * 64,
            now=now or self.now,
            contract_root=CONTRACT_ROOT,
            evidence_root=self.fixture.evidence_root,
            bqa_environ=self.fixture.environment,
            measurement_environ=self.measurement_environment,
            admission_environ=self.admission_environment,
        )

    def test_round_trip_reconstructs_subset_and_allows_publish(self) -> None:
        self.assertEqual(
            self._sign_admission(self.admission_payload), self.admission_envelope
        )
        admission, bqa, measurement = verify_distribution_admission(
            self.admission_envelope,
            bqm=self.fixture.bqm,
            qualification_index=self.fixture.qualification_index,
            bqa_envelope=self.bqa_envelope,
            runtime_scope_policy_map=self.fixture.runtime_scope_policy_map,
            release_metadata_index=self.release_metadata_index,
            payload_descriptor=self.payload_descriptor,
            destination_descriptor=self.destination_descriptor,
            destination_measurement_envelope=self.measurement_envelope,
            contract_root=CONTRACT_ROOT,
            evidence_root=self.fixture.evidence_root,
            bqa_environ=self.fixture.environment,
            measurement_environ=self.measurement_environment,
            admission_environ=self.admission_environment,
        )
        self.assertEqual(admission, self.admission_payload)
        self.assertEqual(bqa, self.fixture.bqa_payload)
        self.assertEqual(measurement, self.measurement_payload)
        receipt = self._evaluate(redirects=[self.destination_descriptor])
        self.assertEqual(receipt.verdict, "allow")
        self.assertIsNone(receipt.denial_reason)

    def test_missing_invalid_and_predeadline_transfer_abort_fail_closed(self) -> None:
        missing = self._evaluate(envelope=None)
        self.assertEqual(missing.verdict, "deny")
        self.assertEqual(missing.denial_reason, "admission_missing")

        tampered = self.admission_envelope.model_dump(mode="json")
        payload = bytearray(base64.b64decode(tampered["payload"]))
        payload[-2] ^= 1
        tampered["payload"] = base64.b64encode(payload).decode("ascii")
        denied = self._evaluate(envelope=tampered)
        self.assertEqual(denied.verdict, "deny")

        aborted = self._evaluate(
            event="transfer_revalidation",
            now=datetime(2026, 7, 20, 0, 17, 55, tzinfo=UTC),
        )
        self.assertEqual(aborted.verdict, "abort")
        self.assertEqual(aborted.denial_reason, "admission_invalid_or_expired")

    def test_auth_and_redirect_destination_drift_is_denied_or_aborted(self) -> None:
        drifted = self.destination_descriptor.model_copy(
            update={"endpoint_and_storage_policy_hash": "sha256:" + "8" * 64}
        )
        post_auth_denied = self._evaluate(post_auth=drifted)
        self.assertEqual(post_auth_denied.verdict, "deny")
        redirect_aborted = self._evaluate(
            event="transfer_revalidation",
            redirects=[drifted],
        )
        self.assertEqual(redirect_aborted.verdict, "abort")

    def test_payload_metadata_destination_and_measurement_drift_are_rejected(
        self,
    ) -> None:
        drifted_payload = self.payload_descriptor.model_copy(
            update={"distribution_scope_policy_hash": "sha256:" + "9" * 64}
        )
        receipt = self._evaluate(payload=drifted_payload)
        self.assertEqual(receipt.verdict, "deny")
        self.assertEqual(
            receipt.denial_reason,
            "actual_state_reconstruction_invalid",
        )

        production = self.destination_descriptor.model_copy(
            update={"production_destination_count": 1}
        )
        production_receipt = self._evaluate(destination=production)
        self.assertEqual(production_receipt.verdict, "deny")

        measurement = self.measurement_envelope.model_dump(mode="json")
        measurement_payload = bytearray(base64.b64decode(measurement["payload"]))
        measurement_payload[-2] ^= 1
        measurement["payload"] = base64.b64encode(measurement_payload).decode("ascii")
        with self.assertRaisesRegex(AdmissionVerificationError, "signature is invalid"):
            verify_destination_measurement(
                measurement,
                destination=self.destination,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.fixture.evidence_root,
                environ=self.measurement_environment,
            )

    def test_ephemeral_keys_evidence_and_deadline_escape_are_rejected(self) -> None:
        with self.assertRaisesRegex(AdmissionVerificationError, "private key"):
            sign_destination_measurement(
                self.measurement_payload,
                destination=self.destination,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.fixture.evidence_root,
                environ={},
            )
        escaped = self.admission_payload.model_copy(
            update={
                "next_revalidation_at": datetime(2026, 7, 20, 0, 19, tzinfo=UTC),
                "valid_until": datetime(2026, 7, 20, 0, 21, tzinfo=UTC),
            }
        )
        with self.assertRaisesRegex(
            AdmissionVerificationError,
            "validity exceeds a contributor",
        ):
            self._sign_admission(escaped)
        evidence_path = (
            self.fixture.evidence_root
            / self.admission_payload.revocation_status.relative_path
        )
        evidence_path.write_bytes(evidence_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(AdmissionVerificationError, "evidence is invalid"):
            self._sign_admission(self.admission_payload)


if __name__ == "__main__":
    unittest.main()
