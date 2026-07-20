from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from datetime import datetime
from datetime import timedelta
from datetime import UTC
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pmorg.application.qualification import artifact_set_digest
from pmorg.application.qualification import BQA_PRIVATE_KEY_ENV
from pmorg.application.qualification import BQA_PUBLIC_KEY_ENV
from pmorg.application.qualification import content_address_build_qualification_manifest
from pmorg.application.qualification import QualificationVerificationError
from pmorg.application.qualification import sha256_digest
from pmorg.application.qualification import sign_build_qualification_attestation
from pmorg.application.qualification import verify_build_qualification_attestation
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import export_ephemeral_key_environment
from pmorg.application.rbdp import PRIVATE_KEY_ENV
from pmorg.application.rbdp import PUBLIC_KEY_ENV
from pmorg.contracts.types import BuildQualificationAttestation
from pmorg.contracts.types import BuildQualificationManifest
from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import EvidenceBundleIndex
from pmorg.contracts.types import ExpectedArtifactCatalog
from pmorg.contracts.types import ExpectedArtifactCatalogItem

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_ROOT = REPOSITORY_ROOT / "backend" / "pmorg" / "contracts"
POLICY_MANIFEST_PATH = REPOSITORY_ROOT / "pmorg" / "baseline-manifest.json"
SPEC_COMMIT = "05bc4df345d2d65e05b510135a4d99c9edbf886e"
PLATFORM_COMMIT = "4dec69113dfe5ebe4b3e07609889e0803d4a6832"
ONYX_COMMIT = "1da679cefc96165c6b9b64c3bc769584b88f88c2"


class TestQualificationSigning(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.evidence_root = Path(temporary.name)
        self.deadline = datetime(2026, 7, 21, tzinfo=UTC)
        self.qualification_index = self._qualification_index()
        self.bqm_payload = self._bqm_payload()
        self.bqm = self._content_addressed_bqm()
        self.private_key = Ed25519PrivateKey.generate()
        rbdp_environment = export_ephemeral_key_environment(self.private_key)
        self.environment = {
            BQA_PRIVATE_KEY_ENV: rbdp_environment[PRIVATE_KEY_ENV],
            BQA_PUBLIC_KEY_ENV: rbdp_environment[PUBLIC_KEY_ENV],
        }
        self.bqa_payload = self._bqa_payload()

    def _write_json(self, relative_path: str, value: object) -> EvidenceArtifactRef:
        payload = canonical_json_bytes(value)
        path = self.evidence_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        logical_name = Path(relative_path).stem
        return EvidenceArtifactRef(
            logical_name=logical_name,
            media_type="application/json",
            digest=sha256_digest(payload),
            size_bytes=len(payload),
            relative_path=relative_path,
        )

    def _qualification_index(self) -> EvidenceBundleIndex:
        policy = json.loads(POLICY_MANIFEST_PATH.read_bytes())
        role_policy = policy["round_3_contract"]["qualification_bundle_roles"]
        roles = sorted([*role_policy["common"], *role_policy["ce_only"]])
        entries: list[EvidenceArtifactRef] = []
        for role in roles:
            relative_path = f"qualification/{role}.json"
            if role == "expected-artifact-catalog":
                build_recipe_hash = next(
                    item.digest
                    for item in entries
                    if item.logical_name == "build-recipe"
                )
                catalog = ExpectedArtifactCatalog(
                    schema_version="pmorg.expected-artifact-catalog/v1",
                    build_recipe_hash=build_recipe_hash,
                    items=[
                        ExpectedArtifactCatalogItem(
                            artifact_id="pmorg-ce-source",
                            component="pmorg-platform",
                            artifact_kind="package",
                            media_type="application/vnd.pmorg.ce-source.v1+tar",
                            platform="source",
                        )
                    ],
                    expected_artifact_count=1,
                )
                ref = self._write_json(relative_path, catalog.model_dump(mode="json"))
            elif role == "provenance-evidence-bundle-index":
                child = self._write_json(
                    "qualification/nested/provenance-resource.json",
                    {
                        "role": "provenance-resource",
                        "valid_until": self.deadline.isoformat().replace("+00:00", "Z"),
                    },
                )
                nested = EvidenceBundleIndex(
                    schema_version="pmorg.evidence-bundle-index/v1",
                    bundle_kind="provenance",
                    subject_binding_hash=None,
                    entries=[child],
                    entry_count=1,
                )
                ref = self._write_json(relative_path, nested.model_dump(mode="json"))
            else:
                ref = self._write_json(
                    relative_path,
                    {
                        "role": role,
                        "valid_until": self.deadline.isoformat().replace("+00:00", "Z"),
                    },
                )
            ref = ref.model_copy(update={"logical_name": role})
            entries.append(ref)
        return EvidenceBundleIndex(
            schema_version="pmorg.evidence-bundle-index/v1",
            bundle_kind="build-qualification",
            subject_binding_hash=None,
            entries=entries,
            entry_count=len(entries),
        )

    def _bqm_payload(self) -> BuildQualificationManifest:
        example = json.loads(
            (
                CONTRACT_ROOT / "examples" / "build-qualification-manifest-v1.json"
            ).read_bytes()
        )
        refs = {item.logical_name: item for item in self.qualification_index.entries}
        role_fields = {
            "release_build_definition_envelope_hash": "release-build-definition-dsse",
            "build_recipe_hash": "build-recipe",
            "build_input_set_hash": "build-input-set",
            "runtime_scope_policy_map_hash": "runtime-scope-policy-map",
            "expected_artifact_catalog_hash": "expected-artifact-catalog",
            "image_lock_hash": "image-lock",
            "qualification_policy_map_hash": "qualification-policy-map",
            "sbom_hash": "sbom-index",
            "license_report_hash": "license-report",
            "patch_ledger_report_hash": "patch-ledger-report",
            "provenance_report_hash": "provenance-report",
            "surface_mode_report_hash": "surface-mode-report",
            "provenance_evidence_bundle_index_hash": (
                "provenance-evidence-bundle-index"
            ),
            "capability_catalog_hash": "capability-catalog",
            "capability_disposition_report_hash": "capability-disposition-report",
            "capability_evidence_bundle_index_hash": "capability-evidence-bundle-index",
            "vulnerability_report_hash": "vulnerability-report",
            "upstream_test_report_hash": "upstream-test-report",
            "ce_boundary_report_hash": "ce-boundary-report",
        }
        example.update(
            {field_name: refs[role].digest for field_name, role in role_fields.items()}
        )
        example.update(
            {
                "baseline_manifest_hash": sha256_digest(
                    POLICY_MANIFEST_PATH.read_bytes()
                ),
                "qualification_bundle_index_hash": "sha256:" + "0" * 64,
                "artifact_descriptors": [
                    {
                        "artifact_id": "pmorg-ce-source",
                        "component": "pmorg-platform",
                        "artifact_kind": "package",
                        "media_type": "application/vnd.pmorg.ce-source.v1+tar",
                        "platform": "source",
                        "digest": "sha256:" + "a" * 64,
                        "size_bytes": 3355,
                    }
                ],
                "artifact_count": 1,
                "expected_artifact_count": 1,
                "missing_artifact_count": 0,
                "unexpected_artifact_count": 0,
                "duplicate_artifact_key_count": 0,
                "pmorg_platform_commit": PLATFORM_COMMIT,
                "pmorg_spec_commit": SPEC_COMMIT,
                "onyx_commit": ONYX_COMMIT,
                "onyx_release_tag": "v4.3.9",
                "onyx_surface": "ce",
                "usage_mode": "development_test",
                "ee_inventory_report_hash": None,
            }
        )
        provisional = BuildQualificationManifest.model_validate(example)
        artifact_digest = artifact_set_digest(provisional)
        self.qualification_index = self.qualification_index.model_copy(
            update={"subject_binding_hash": artifact_digest}
        )
        return provisional.model_copy(
            update={
                "artifact_set_hash": artifact_digest,
                "qualification_bundle_index_hash": sha256_digest(
                    canonical_json_bytes(
                        self.qualification_index.model_dump(mode="json")
                    )
                ),
            }
        )

    def _content_addressed_bqm(self):
        return content_address_build_qualification_manifest(
            self.bqm_payload,
            qualification_index=self.qualification_index,
            contract_root=CONTRACT_ROOT,
            policy_manifest_path=POLICY_MANIFEST_PATH,
            evidence_root=self.evidence_root,
        )

    def _support_ref(self, logical_name: str) -> EvidenceArtifactRef:
        return self._write_json(
            f"bqa/{logical_name}.json",
            {
                "logical_name": logical_name,
                "valid_until": self.deadline.isoformat().replace("+00:00", "Z"),
            },
        ).model_copy(update={"logical_name": logical_name})

    def _bqa_payload(self) -> BuildQualificationAttestation:
        example = json.loads(
            (
                CONTRACT_ROOT / "examples" / "build-qualification-attestation-v1.json"
            ).read_bytes()
        )
        valid_from = datetime(2026, 7, 20, tzinfo=UTC)
        example.update(
            {
                "build_manifest_hash": self.bqm.digest,
                "artifact_set_hash": self.bqm.manifest.artifact_set_hash,
                "qualification_bundle_index_hash": (
                    self.bqm.manifest.qualification_bundle_index_hash
                ),
                "valid_from": valid_from,
                "issued_at": valid_from + timedelta(minutes=5),
                "next_revalidation_at": valid_from + timedelta(minutes=20),
                "valid_until": valid_from + timedelta(minutes=30),
                "trusted_clock_id": "pmorg-test-clock",
                "trusted_time_receipt_envelope": self._support_ref("trusted-time"),
                "revocation_status": self._support_ref("revocation"),
                "verification_material_bundle": self._support_ref(
                    "verification-material"
                ),
                "verifier_identity": "pmorg-test-verifier",
                "temporal_policy": {
                    "policy_hash": "sha256:" + "b" * 64,
                    "max_clock_skew_seconds": 5,
                    "max_time_receipt_age_seconds": 60,
                    "max_measurement_age_seconds": 60,
                    "max_validity_seconds": 3600,
                    "max_revalidation_interval_seconds": 1800,
                },
            }
        )
        return BuildQualificationAttestation.model_validate(example)

    def _envelope(self) -> DsseEnvelope:
        return sign_build_qualification_attestation(
            self.bqa_payload,
            bqm=self.bqm,
            qualification_index=self.qualification_index,
            contract_root=CONTRACT_ROOT,
            evidence_root=self.evidence_root,
            environ=self.environment,
        )

    def test_bqm_is_content_addressed_exact_and_offline_resolvable(self) -> None:
        second = self._content_addressed_bqm()
        self.assertEqual(second, self.bqm)
        self.assertEqual(self.bqm.digest, sha256_digest(self.bqm.payload))

    def test_bqm_rejects_role_and_artifact_coverage_drift(self) -> None:
        missing_role = self.qualification_index.model_copy(
            update={
                "entries": self.qualification_index.entries[1:],
                "entry_count": len(self.qualification_index.entries) - 1,
            }
        )
        with self.assertRaisesRegex(QualificationVerificationError, "index hash"):
            content_address_build_qualification_manifest(
                self.bqm_payload,
                qualification_index=missing_role,
                contract_root=CONTRACT_ROOT,
                policy_manifest_path=POLICY_MANIFEST_PATH,
                evidence_root=self.evidence_root,
            )

        incomplete = self.bqm_payload.model_copy(update={"missing_artifact_count": 1})
        with self.assertRaisesRegex(QualificationVerificationError, "coverage"):
            content_address_build_qualification_manifest(
                incomplete,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                policy_manifest_path=POLICY_MANIFEST_PATH,
                evidence_root=self.evidence_root,
            )

    def test_bqm_rejects_expected_observed_and_evidence_drift(self) -> None:
        changed_descriptor = self.bqm_payload.artifact_descriptors[0].model_copy(
            update={"component": "wrong-component"}
        )
        changed = self.bqm_payload.model_copy(
            update={"artifact_descriptors": [changed_descriptor]}
        )
        changed_artifact_digest = artifact_set_digest(changed)
        changed_index = self.qualification_index.model_copy(
            update={"subject_binding_hash": changed_artifact_digest}
        )
        changed = changed.model_copy(
            update={
                "artifact_set_hash": changed_artifact_digest,
                "qualification_bundle_index_hash": sha256_digest(
                    canonical_json_bytes(changed_index.model_dump(mode="json"))
                ),
            }
        )
        with self.assertRaisesRegex(QualificationVerificationError, "sets differ"):
            content_address_build_qualification_manifest(
                changed,
                qualification_index=changed_index,
                contract_root=CONTRACT_ROOT,
                policy_manifest_path=POLICY_MANIFEST_PATH,
                evidence_root=self.evidence_root,
            )

        evidence_path = (
            self.evidence_root / self.qualification_index.entries[0].relative_path
        )
        evidence_path.write_bytes(evidence_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(QualificationVerificationError, "size mismatch"):
            self._content_addressed_bqm()

    def test_bqa_round_trip_is_deterministic_and_schema_bound(self) -> None:
        first = self._envelope()
        second = self._envelope()
        self.assertEqual(first, second)
        self.assertEqual(
            verify_build_qualification_attestation(
                first,
                bqm=self.bqm,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.evidence_root,
                environ=self.environment,
            ),
            self.bqa_payload,
        )

    def test_bqa_rejects_tampering_wrong_key_and_type(self) -> None:
        envelope = self._envelope().model_dump(mode="json")
        payload = bytearray(base64.b64decode(envelope["payload"]))
        payload[-2] ^= 1
        envelope["payload"] = base64.b64encode(payload).decode("ascii")
        with self.assertRaisesRegex(
            QualificationVerificationError, "signature is invalid"
        ):
            verify_build_qualification_attestation(
                envelope,
                bqm=self.bqm,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.evidence_root,
                environ=self.environment,
            )

        other = export_ephemeral_key_environment(Ed25519PrivateKey.generate())
        wrong_environment = {
            BQA_PRIVATE_KEY_ENV: other[PRIVATE_KEY_ENV],
            BQA_PUBLIC_KEY_ENV: other[PUBLIC_KEY_ENV],
        }
        with self.assertRaisesRegex(QualificationVerificationError, "key identity"):
            verify_build_qualification_attestation(
                self._envelope(),
                bqm=self.bqm,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.evidence_root,
                environ=wrong_environment,
            )
        wrong_type = self._envelope().model_copy(
            update={"payloadType": "application/json"}
        )
        with self.assertRaisesRegex(QualificationVerificationError, "payload type"):
            verify_build_qualification_attestation(
                wrong_type,
                bqm=self.bqm,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.evidence_root,
                environ=self.environment,
            )

    def test_bqa_rejects_binding_and_deadline_escape(self) -> None:
        wrong_binding = self.bqa_payload.model_copy(
            update={"build_manifest_hash": "sha256:" + "f" * 64}
        )
        with self.assertRaisesRegex(QualificationVerificationError, "exact BQM"):
            sign_build_qualification_attestation(
                wrong_binding,
                bqm=self.bqm,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.evidence_root,
                environ=self.environment,
            )

        escaped = self.bqa_payload.model_copy(
            update={
                "valid_until": self.deadline + timedelta(seconds=1),
                "next_revalidation_at": self.deadline,
                "temporal_policy": self.bqa_payload.temporal_policy.model_copy(
                    update={
                        "max_validity_seconds": 200000,
                        "max_revalidation_interval_seconds": 200000,
                    }
                ),
            }
        )
        with self.assertRaisesRegex(
            QualificationVerificationError, "contributor deadline"
        ):
            sign_build_qualification_attestation(
                escaped,
                bqm=self.bqm,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.evidence_root,
                environ=self.environment,
            )

    def test_bqa_rejects_missing_key_multiple_signatures_and_schema_drift(self) -> None:
        with self.assertRaisesRegex(QualificationVerificationError, "private key"):
            sign_build_qualification_attestation(
                self.bqa_payload,
                bqm=self.bqm,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.evidence_root,
                environ={},
            )
        multiple = self._envelope().model_dump(mode="json")
        multiple["signatures"].append(copy.deepcopy(multiple["signatures"][0]))
        with self.assertRaisesRegex(QualificationVerificationError, "exactly one"):
            verify_build_qualification_attestation(
                multiple,
                bqm=self.bqm,
                qualification_index=self.qualification_index,
                contract_root=CONTRACT_ROOT,
                evidence_root=self.evidence_root,
                environ=self.environment,
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            copied_root = Path(temporary_directory)
            (copied_root / "schemas").mkdir()
            (copied_root / "manifest.json").write_bytes(
                (CONTRACT_ROOT / "manifest.json").read_bytes()
            )
            schema_name = "build-qualification-attestation-v1.schema.json"
            schema = json.loads((CONTRACT_ROOT / "schemas" / schema_name).read_bytes())
            schema["title"] = "tampered"
            (copied_root / "schemas" / schema_name).write_bytes(
                canonical_json_bytes(schema)
            )
            with self.assertRaisesRegex(
                QualificationVerificationError, "schema digest"
            ):
                sign_build_qualification_attestation(
                    self.bqa_payload,
                    bqm=self.bqm,
                    qualification_index=self.qualification_index,
                    contract_root=copied_root,
                    evidence_root=self.evidence_root,
                    environ=self.environment,
                )

    def test_no_private_key_material_is_committed(self) -> None:
        owned_paths = [
            REPOSITORY_ROOT / "backend" / "pmorg" / "application" / "qualification.py",
            Path(__file__),
        ]
        for path in owned_paths:
            with self.subTest(path=path):
                source = path.read_text()
                for marker in (
                    "BEGIN " + "PRIVATE KEY",
                    "BEGIN " + "OPENSSH PRIVATE KEY",
                    "BEGIN " + "ED25519 PRIVATE KEY",
                ):
                    self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
