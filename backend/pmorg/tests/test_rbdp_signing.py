from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from datetime import datetime
from datetime import UTC
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import export_ephemeral_key_environment
from pmorg.application.rbdp import pre_authentication_encoding
from pmorg.application.rbdp import RBDP_PAYLOAD_TYPE
from pmorg.application.rbdp import RbdpVerificationError
from pmorg.application.rbdp import sign_release_build_definition
from pmorg.application.rbdp import verify_release_build_definition
from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import DsseSignature
from pmorg.contracts.types import ReleaseBuildDefinitionPayload

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_ROOT = REPOSITORY_ROOT / "backend" / "pmorg" / "contracts"


def _payload() -> ReleaseBuildDefinitionPayload:
    example = json.loads(
        (CONTRACT_ROOT / "examples" / "release-build-definition-v1.json").read_bytes()
    )
    example.update(
        {
            "pmorg_spec_commit": "05bc4df345d2d65e05b510135a4d99c9edbf886e",
            "pmorg_platform_commit": "a9f49afd46b19e391e7e361a9c5e7f9309039d6f",
            "onyx_commit": "1da679cefc96165c6b9b64c3bc769584b88f88c2",
            "onyx_surface": "ce",
            "allowed_usage_modes": ["development_test"],
            "issued_at": datetime(2026, 7, 20, tzinfo=UTC),
        }
    )
    return ReleaseBuildDefinitionPayload.model_validate(example)


class TestRbdpSigning(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.environ = export_ephemeral_key_environment(self.private_key)
        self.payload = _payload()

    def _envelope(self) -> DsseEnvelope:
        return sign_release_build_definition(
            self.payload,
            contract_root=CONTRACT_ROOT,
            environ=self.environ,
        )

    def test_round_trip_is_deterministic_and_schema_bound(self) -> None:
        first = self._envelope()
        second = self._envelope()

        self.assertEqual(first, second)
        self.assertEqual(
            verify_release_build_definition(
                first,
                contract_root=CONTRACT_ROOT,
                environ=self.environ,
            ),
            self.payload,
        )

    def test_payload_byte_flip_is_rejected(self) -> None:
        envelope = self._envelope().model_dump(mode="json")
        payload = bytearray(base64.b64decode(envelope["payload"]))
        payload[-2] ^= 1
        envelope["payload"] = base64.b64encode(payload).decode("ascii")

        with self.assertRaisesRegex(RbdpVerificationError, "signature is invalid"):
            verify_release_build_definition(
                envelope,
                contract_root=CONTRACT_ROOT,
                environ=self.environ,
            )

    def test_wrong_key_and_payload_type_are_rejected(self) -> None:
        envelope = self._envelope()
        other_environment = export_ephemeral_key_environment(
            Ed25519PrivateKey.generate()
        )
        with self.assertRaisesRegex(RbdpVerificationError, "key identity"):
            verify_release_build_definition(
                envelope,
                contract_root=CONTRACT_ROOT,
                environ=other_environment,
            )

        wrong_type = envelope.model_copy(update={"payloadType": "application/json"})
        with self.assertRaisesRegex(RbdpVerificationError, "payload type"):
            verify_release_build_definition(
                wrong_type,
                contract_root=CONTRACT_ROOT,
                environ=self.environ,
            )

    def test_duplicate_and_noncanonical_json_are_rejected_after_valid_signature(
        self,
    ) -> None:
        duplicate_payload = b'{"schema_version":"x","schema_version":"y"}'
        duplicate_envelope = self._signed_raw_envelope(duplicate_payload)
        with self.assertRaisesRegex(RbdpVerificationError, "repeats JSON key"):
            verify_release_build_definition(
                duplicate_envelope,
                contract_root=CONTRACT_ROOT,
                environ=self.environ,
            )

        noncanonical_payload = json.dumps(
            self.payload.model_dump(mode="json"),
            indent=2,
            sort_keys=False,
        ).encode()
        noncanonical_envelope = self._signed_raw_envelope(noncanonical_payload)
        with self.assertRaisesRegex(RbdpVerificationError, "not canonical JSON"):
            verify_release_build_definition(
                noncanonical_envelope,
                contract_root=CONTRACT_ROOT,
                environ=self.environ,
            )

    def _signed_raw_envelope(self, payload: bytes) -> DsseEnvelope:
        signature = self.private_key.sign(
            pre_authentication_encoding(RBDP_PAYLOAD_TYPE, payload)
        )
        valid = self._envelope()
        return DsseEnvelope(
            payloadType=RBDP_PAYLOAD_TYPE,
            payload=base64.b64encode(payload).decode("ascii"),
            signatures=[
                DsseSignature(
                    keyid=valid.signatures[0].keyid,
                    sig=base64.b64encode(signature).decode("ascii"),
                )
            ],
        )

    def test_missing_or_malformed_environment_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(RbdpVerificationError, "environment is absent"):
            sign_release_build_definition(
                self.payload,
                contract_root=CONTRACT_ROOT,
                environ={},
            )
        malformed = dict(self.environ)
        malformed["PMORG_RBDP_TEST_ED25519_PRIVATE_KEY"] = "c2hvcnQ="
        with self.assertRaisesRegex(RbdpVerificationError, "exactly 32"):
            sign_release_build_definition(
                self.payload,
                contract_root=CONTRACT_ROOT,
                environ=malformed,
            )

    def test_production_ee_and_wrong_spec_are_rejected(self) -> None:
        for updates, expected in (
            ({"allowed_usage_modes": ["production"]}, "development_test"),
            ({"onyx_surface": "ee"}, "CE surface"),
            ({"pmorg_spec_commit": "f" * 40}, "committed PMORG specification"),
        ):
            with self.subTest(updates=updates):
                changed = self.payload.model_copy(update=updates)
                with self.assertRaisesRegex(RbdpVerificationError, expected):
                    sign_release_build_definition(
                        changed,
                        contract_root=CONTRACT_ROOT,
                        environ=self.environ,
                    )

    def test_schema_digest_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied_root = Path(temporary_directory)
            (copied_root / "schemas").mkdir()
            manifest = (CONTRACT_ROOT / "manifest.json").read_bytes()
            (copied_root / "manifest.json").write_bytes(manifest)
            schema_name = "release-build-definition-v1.schema.json"
            schema = json.loads((CONTRACT_ROOT / "schemas" / schema_name).read_bytes())
            schema["title"] = "tampered"
            (copied_root / "schemas" / schema_name).write_bytes(
                canonical_json_bytes(schema)
            )

            with self.assertRaisesRegex(RbdpVerificationError, "schema digest"):
                sign_release_build_definition(
                    self.payload,
                    contract_root=copied_root,
                    environ=self.environ,
                )

    def test_signature_list_must_be_singular(self) -> None:
        envelope = self._envelope().model_dump(mode="json")
        envelope["signatures"] = [
            copy.deepcopy(envelope["signatures"][0]),
            copy.deepcopy(envelope["signatures"][0]),
        ]
        with self.assertRaisesRegex(RbdpVerificationError, "exactly one"):
            verify_release_build_definition(
                envelope,
                contract_root=CONTRACT_ROOT,
                environ=self.environ,
            )


if __name__ == "__main__":
    unittest.main()
