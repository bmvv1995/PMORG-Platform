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

from pmorg.application.admission import ADMISSION_PRIVATE_KEY_ENV
from pmorg.application.admission import ADMISSION_PUBLIC_KEY_ENV
from pmorg.application.admission import AdmissionVerificationError
from pmorg.application.admission import artifact_id_set_digest
from pmorg.application.admission import content_address_deployment_payload
from pmorg.application.admission import content_address_deployment_target
from pmorg.application.admission import evaluate_deployment_use
from pmorg.application.admission import MEASUREMENT_PRIVATE_KEY_ENV
from pmorg.application.admission import MEASUREMENT_PUBLIC_KEY_ENV
from pmorg.application.admission import sign_deployment_admission
from pmorg.application.admission import sign_target_measurement
from pmorg.application.admission import verify_deployment_admission
from pmorg.application.admission import verify_target_measurement
from pmorg.application.qualification import sha256_digest
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import export_ephemeral_key_environment
from pmorg.application.rbdp import PRIVATE_KEY_ENV
from pmorg.application.rbdp import PUBLIC_KEY_ENV
from pmorg.contracts.types import DeploymentAdmissionRecord
from pmorg.contracts.types import DeploymentPayloadDescriptor
from pmorg.contracts.types import DeploymentTargetDescriptor
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import RuntimeScopePolicyMap
from pmorg.contracts.types import TargetMeasurementAttestation

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
        target_schema = _schema_digest("pmorg.deployment-target-descriptor/v1")
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
                        "target_destination_policy_schema_hash": target_schema,
                    },
                    {
                        "scope_class": "registry_publish",
                        "scope_policy_hash": "sha256:" + "2" * 64,
                        "expected_artifact_id_set_hash": artifact_id_set_digest(
                            artifact_ids
                        ),
                        "expected_release_metadata_role_set_hash": (
                            "sha256:" + "3" * 64
                        ),
                        "target_destination_policy_schema_hash": "sha256:" + "4" * 64,
                    },
                    {
                        "scope_class": "artifact_export",
                        "scope_policy_hash": "sha256:" + "5" * 64,
                        "expected_artifact_id_set_hash": artifact_id_set_digest(
                            artifact_ids
                        ),
                        "expected_release_metadata_role_set_hash": (
                            "sha256:" + "6" * 64
                        ),
                        "target_destination_policy_schema_hash": "sha256:" + "7" * 64,
                    },
                ],
            }
        )
        ref = self._write_json(
            "qualification/runtime-scope-policy-map.json",
            self.runtime_scope_policy_map.model_dump(mode="json"),
        ).model_copy(update={"logical_name": "runtime-scope-policy-map"})
        entries = [
            ref if item.logical_name == "runtime-scope-policy-map" else item
            for item in index.entries
        ]
        return index.model_copy(update={"entries": entries})

    setattr(fixture, "_qualification_index", MethodType(qualification_index, fixture))
    fixture.setUp()
    return fixture


class TestDeploymentAdmission(unittest.TestCase):
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
            MEASUREMENT_PRIVATE_KEY_ENV: measurement_keys[PRIVATE_KEY_ENV],
            MEASUREMENT_PUBLIC_KEY_ENV: measurement_keys[PUBLIC_KEY_ENV],
        }
        self.admission_environment = {
            ADMISSION_PRIVATE_KEY_ENV: admission_keys[PRIVATE_KEY_ENV],
            ADMISSION_PUBLIC_KEY_ENV: admission_keys[PUBLIC_KEY_ENV],
        }
        self.payload_descriptor = self._payload_descriptor()
        self.payload = content_address_deployment_payload(
            self.payload_descriptor,
            bqm=fixture.bqm,
            qualification_index=fixture.qualification_index,
            runtime_scope_policy_map=fixture.runtime_scope_policy_map,
            contract_root=CONTRACT_ROOT,
            evidence_root=fixture.evidence_root,
        )
        self.target_descriptor = self._target_descriptor()
        self.target = content_address_deployment_target(
            self.target_descriptor,
            contract_root=CONTRACT_ROOT,
        )
        self.measurement_payload = self._measurement_payload()
        self.measurement_envelope = sign_target_measurement(
            self.measurement_payload,
            payload=self.payload,
            target=self.target,
            contract_root=CONTRACT_ROOT,
            evidence_root=fixture.evidence_root,
            environ=self.measurement_environment,
        )
        self.admission_payload = self._admission_payload()
        self.admission_envelope = self._sign_admission(self.admission_payload)

    def _write_support(self, name: str) -> EvidenceArtifactRef:
        return self.fixture._write_json(
            f"admission/{name}.json",
            {
                "role": name,
                "valid_until": self.fixture.deadline.isoformat().replace("+00:00", "Z"),
            },
        ).model_copy(update={"logical_name": name})

    def _payload_descriptor(self) -> DeploymentPayloadDescriptor:
        descriptor = {
            "schema_version": "pmorg.deployment-payload-descriptor/v1",
            "deployment_scope_policy_hash": "sha256:" + "1" * 64,
            "artifact_descriptors": [
                item.model_dump(mode="json")
                for item in self.fixture.bqm.manifest.artifact_descriptors
            ],
            "artifact_count": 1,
            "expected_artifact_count": 1,
            "missing_artifact_count": 0,
            "unexpected_artifact_count": 0,
            "duplicate_artifact_key_count": 0,
            "runtime_workload_spec_hash": "sha256:" + "8" * 64,
            "runtime_binding_set_hash": "sha256:" + "9" * 64,
            "deployment_payload_fingerprint": "sha256:" + "0" * 64,
        }
        fingerprint_input = dict(descriptor)
        fingerprint_input.pop("deployment_payload_fingerprint")
        descriptor["deployment_payload_fingerprint"] = sha256_digest(
            canonical_json_bytes(fingerprint_input)
        )
        return DeploymentPayloadDescriptor.model_validate(descriptor)

    def _target_descriptor(self) -> DeploymentTargetDescriptor:
        return DeploymentTargetDescriptor.model_validate(
            {
                "schema_version": "pmorg.deployment-target-descriptor/v1",
                "target_uid_hmac": "hmac-sha256:" + "a" * 64,
                "workload_identity_set_hash": "sha256:" + "b" * 64,
                "organization_binding_set_hash": "sha256:" + "c" * 64,
                "data_binding_set_hash": "sha256:" + "d" * 64,
                "identity_provider_set_hash": "sha256:" + "e" * 64,
                "channel_binding_set_hash": "sha256:" + "f" * 64,
                "secret_binding_set_hash": "sha256:" + "1" * 64,
                "network_policy_hash": "sha256:" + "2" * 64,
                "resource_classification_report_hash": "sha256:" + "3" * 64,
                "production_resource_count": 0,
                "unknown_resource_count": 0,
                "derived_target_class": "synthetic_sandbox",
            }
        )

    def _measurement_payload(self) -> TargetMeasurementAttestation:
        return TargetMeasurementAttestation.model_validate(
            {
                "schema_version": "pmorg.target-measurement-attestation/v1",
                "deployment_payload_descriptor_hash": self.payload.digest,
                "deployment_payload_fingerprint": (
                    self.payload.descriptor.deployment_payload_fingerprint
                ),
                "target_descriptor_hash": self.target.digest,
                "target_fingerprint": self.target.fingerprint,
                "resource_evidence_bundle": self._write_support(
                    "target-resource-evidence"
                ),
                "verification_material_bundle": self._write_support(
                    "target-verification-material"
                ),
                "measured_at": datetime(2026, 7, 20, 0, 10, tzinfo=UTC),
                "issued_at": datetime(2026, 7, 20, 0, 11, tzinfo=UTC),
                "valid_from": datetime(2026, 7, 20, 0, 10, tzinfo=UTC),
                "valid_until": datetime(2026, 7, 20, 0, 20, tzinfo=UTC),
                "next_revalidation_at": datetime(2026, 7, 20, 0, 18, tzinfo=UTC),
                "trusted_clock_id": "pmorg-test-clock",
                "trusted_time_receipt_envelope": self._write_support(
                    "target-trusted-time"
                ),
                "temporal_policy": {
                    "policy_hash": "sha256:" + "4" * 64,
                    "max_clock_skew_seconds": 5,
                    "max_time_receipt_age_seconds": 120,
                    "max_measurement_age_seconds": 600,
                    "max_validity_seconds": 900,
                    "max_revalidation_interval_seconds": 600,
                },
                "verifier_identity": "pmorg-target-measurer",
                "verification_policy_hash": "sha256:" + "5" * 64,
            }
        )

    def _admission_payload(self) -> DeploymentAdmissionRecord:
        return DeploymentAdmissionRecord.model_validate(
            {
                "schema_version": "pmorg.deployment-admission/v1",
                "admission_id": UUID("01900000-0000-7000-8000-000000000001"),
                "governed_operation": "deploy",
                "artifact_set_hash": self.fixture.bqm.manifest.artifact_set_hash,
                "build_manifest_hash": self.fixture.bqm.digest,
                "build_attestation_envelope_hash": sha256_digest(
                    canonical_json_bytes(self.bqa_envelope.model_dump(mode="json"))
                ),
                "deployment_payload_descriptor_hash": self.payload.digest,
                "deployment_payload_fingerprint": (
                    self.payload.descriptor.deployment_payload_fingerprint
                ),
                "onyx_surface": "ce",
                "usage_mode": "development_test",
                "target_descriptor_hash": self.target.digest,
                "target_fingerprint": self.target.fingerprint,
                "target_measurement_envelope_hash": sha256_digest(
                    canonical_json_bytes(
                        self.measurement_envelope.model_dump(mode="json")
                    )
                ),
                "target_class": "synthetic_sandbox",
                "admission_basis": "synthetic_environment",
                "ce_release_authorization": None,
                "enterprise_authorization": None,
                "valid_from": datetime(2026, 7, 20, 0, 11, tzinfo=UTC),
                "valid_until": datetime(2026, 7, 20, 0, 20, tzinfo=UTC),
                "trusted_clock_id": "pmorg-test-clock",
                "trusted_time_receipt_envelope": self._write_support(
                    "admission-trusted-time"
                ),
                "temporal_policy": self.measurement_payload.temporal_policy,
                "revocation_status": self._write_support("admission-revocation"),
                "next_revalidation_at": datetime(2026, 7, 20, 0, 18, tzinfo=UTC),
                "verifier_identity": "pmorg-admission-verifier",
                "verification_policy_hash": "sha256:" + "6" * 64,
                "verification_material_bundle": self._write_support(
                    "admission-verification-material"
                ),
                "verifier_receipt": self._write_support("admission-verifier-receipt"),
                "issued_at": self.now,
            }
        )

    def _sign_admission(self, admission: DeploymentAdmissionRecord):
        return sign_deployment_admission(
            admission,
            bqm=self.fixture.bqm,
            qualification_index=self.fixture.qualification_index,
            bqa_envelope=self.bqa_envelope,
            runtime_scope_policy_map=self.fixture.runtime_scope_policy_map,
            payload_descriptor=self.payload_descriptor,
            target_descriptor=self.target_descriptor,
            target_measurement_envelope=self.measurement_envelope,
            contract_root=CONTRACT_ROOT,
            evidence_root=self.fixture.evidence_root,
            bqa_environ=self.fixture.environment,
            measurement_environ=self.measurement_environment,
            admission_environ=self.admission_environment,
        )

    def _evaluate(
        self,
        *,
        event: Literal["deploy", "startup", "watchdog_revalidation"] = "deploy",
        operation: Literal["deploy", "startup"] = "deploy",
        envelope: Any = _UNSET,
        now: datetime | None = None,
        target: DeploymentTargetDescriptor | None = None,
    ):
        return evaluate_deployment_use(
            use_id=UUID("01900000-0000-7000-8000-000000000002"),
            verification_event=event,
            governed_operation=operation,
            admission_envelope=(
                self.admission_envelope if envelope is _UNSET else envelope
            ),
            bqm=self.fixture.bqm,
            qualification_index=self.fixture.qualification_index,
            bqa_envelope=self.bqa_envelope,
            runtime_scope_policy_map=self.fixture.runtime_scope_policy_map,
            actual_payload_descriptor=self.payload_descriptor,
            actual_target_descriptor=target or self.target_descriptor,
            target_measurement_envelope=self.measurement_envelope,
            trusted_time_receipt_envelope=self._write_support("use-trusted-time"),
            revocation_check=self._write_support("use-revocation"),
            verification_material_bundle=self._write_support(
                "use-verification-material"
            ),
            verifier_identity="pmorg-use-verifier",
            verification_policy_hash="sha256:" + "7" * 64,
            now=now or self.now,
            contract_root=CONTRACT_ROOT,
            evidence_root=self.fixture.evidence_root,
            bqa_environ=self.fixture.environment,
            measurement_environ=self.measurement_environment,
            admission_environ=self.admission_environment,
        )

    def test_round_trip_reconstructs_all_exact_bindings_and_allows_deploy(self) -> None:
        second = self._sign_admission(self.admission_payload)
        self.assertEqual(second, self.admission_envelope)
        admission, bqa, measurement = verify_deployment_admission(
            self.admission_envelope,
            bqm=self.fixture.bqm,
            qualification_index=self.fixture.qualification_index,
            bqa_envelope=self.bqa_envelope,
            runtime_scope_policy_map=self.fixture.runtime_scope_policy_map,
            payload_descriptor=self.payload_descriptor,
            target_descriptor=self.target_descriptor,
            target_measurement_envelope=self.measurement_envelope,
            contract_root=CONTRACT_ROOT,
            evidence_root=self.fixture.evidence_root,
            bqa_environ=self.fixture.environment,
            measurement_environ=self.measurement_environment,
            admission_environ=self.admission_environment,
        )
        self.assertEqual(admission, self.admission_payload)
        self.assertEqual(bqa, self.fixture.bqa_payload)
        self.assertEqual(measurement, self.measurement_payload)
        receipt = self._evaluate()
        self.assertEqual(receipt.verdict, "allow")
        self.assertIsNone(receipt.denial_reason)

        startup_payload = self.admission_payload.model_copy(
            update={"governed_operation": "startup"}
        )
        startup_envelope = self._sign_admission(startup_payload)
        startup_receipt = self._evaluate(
            event="startup",
            operation="startup",
            envelope=startup_envelope,
        )
        self.assertEqual(startup_receipt.verdict, "allow")

    def test_absent_invalid_and_expiring_admissions_fail_closed(self) -> None:
        missing = self._evaluate(envelope=None)
        self.assertEqual(missing.verdict, "deny")
        self.assertEqual(missing.denial_reason, "admission_missing")

        tampered = self.admission_envelope.model_dump(mode="json")
        payload = bytearray(base64.b64decode(tampered["payload"]))
        payload[-2] ^= 1
        tampered["payload"] = base64.b64encode(payload).decode("ascii")
        denied = self._evaluate(envelope=tampered)
        self.assertEqual(denied.verdict, "deny")

        quiesced = self._evaluate(
            event="watchdog_revalidation",
            now=datetime(2026, 7, 20, 0, 17, 55, tzinfo=UTC),
        )
        self.assertEqual(quiesced.verdict, "quiesce")
        self.assertEqual(
            quiesced.denial_reason,
            "admission_invalid_or_expired",
        )

    def test_payload_target_measurement_and_signature_drift_are_rejected(self) -> None:
        changed_target = self.target_descriptor.model_copy(
            update={"network_policy_hash": "sha256:" + "8" * 64}
        )
        drifted = self._evaluate(target=changed_target)
        self.assertEqual(drifted.verdict, "deny")

        measurement = self.measurement_envelope.model_dump(mode="json")
        measurement_payload = bytearray(base64.b64decode(measurement["payload"]))
        measurement_payload[-2] ^= 1
        measurement["payload"] = base64.b64encode(measurement_payload).decode("ascii")
        with self.assertRaisesRegex(AdmissionVerificationError, "signature is invalid"):
            verify_target_measurement(
                measurement,
                payload=self.payload,
                target=self.target,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.fixture.evidence_root,
                environ=self.measurement_environment,
            )

        other_keys = export_ephemeral_key_environment(Ed25519PrivateKey.generate())
        wrong_environment = {
            ADMISSION_PRIVATE_KEY_ENV: other_keys[PRIVATE_KEY_ENV],
            ADMISSION_PUBLIC_KEY_ENV: other_keys[PUBLIC_KEY_ENV],
        }
        with self.assertRaisesRegex(AdmissionVerificationError, "key identity"):
            verify_deployment_admission(
                self.admission_envelope,
                bqm=self.fixture.bqm,
                qualification_index=self.fixture.qualification_index,
                bqa_envelope=self.bqa_envelope,
                runtime_scope_policy_map=self.fixture.runtime_scope_policy_map,
                payload_descriptor=self.payload_descriptor,
                target_descriptor=self.target_descriptor,
                target_measurement_envelope=self.measurement_envelope,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.fixture.evidence_root,
                bqa_environ=self.fixture.environment,
                measurement_environ=self.measurement_environment,
                admission_environ=wrong_environment,
            )

    def test_production_unknown_and_deadline_escape_are_rejected(self) -> None:
        production = self.target_descriptor.model_copy(
            update={"production_resource_count": 1}
        )
        with self.assertRaisesRegex(AdmissionVerificationError, "production resources"):
            content_address_deployment_target(
                production,
                contract_root=CONTRACT_ROOT,
            )
        production_receipt = self._evaluate(target=production)
        self.assertEqual(production_receipt.verdict, "deny")
        self.assertEqual(
            production_receipt.denial_reason,
            "actual_state_reconstruction_invalid",
        )
        unknown = self.target_descriptor.model_copy(
            update={"unknown_resource_count": 1}
        )
        with self.assertRaisesRegex(AdmissionVerificationError, "unknown"):
            content_address_deployment_target(
                unknown,
                contract_root=CONTRACT_ROOT,
            )
        escaped = self.admission_payload.model_copy(
            update={
                "next_revalidation_at": datetime(2026, 7, 20, 0, 19, tzinfo=UTC),
                "valid_until": datetime(2026, 7, 20, 0, 21, tzinfo=UTC),
            }
        )
        with self.assertRaisesRegex(
            AdmissionVerificationError, "validity exceeds a contributor"
        ):
            self._sign_admission(escaped)

    def test_ephemeral_keys_are_mandatory_and_evidence_drift_fails(self) -> None:
        with self.assertRaisesRegex(AdmissionVerificationError, "private key"):
            sign_target_measurement(
                self.measurement_payload,
                payload=self.payload,
                target=self.target,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.fixture.evidence_root,
                environ={},
            )
        evidence_path = (
            self.fixture.evidence_root
            / self.admission_payload.revocation_status.relative_path
        )
        evidence_path.write_bytes(evidence_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(AdmissionVerificationError, "evidence is invalid"):
            self._sign_admission(self.admission_payload)


if __name__ == "__main__":
    unittest.main()
