from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from shutil import copytree

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat

from pmorg.application.capability_dispositions import build_capability_dispositions
from pmorg.application.capability_dispositions import CAPABILITIES
from pmorg.application.capability_dispositions import CapabilityDispositionError
from pmorg.application.capability_dispositions import PRIVATE_KEY_ENV
from pmorg.application.capability_dispositions import PUBLIC_KEY_ENV
from pmorg.application.capability_dispositions import RECORD_ROOT_RELATIVE
from pmorg.application.capability_dispositions import sign_capability_disposition
from pmorg.application.capability_dispositions import validate_capability_dispositions
from pmorg.application.capability_dispositions import verify_capability_disposition
from pmorg.contracts.types import CapabilityDispositionRecord

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _key_environment() -> dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        PRIVATE_KEY_ENV: base64.b64encode(private_bytes).decode("ascii"),
        PUBLIC_KEY_ENV: base64.b64encode(public_bytes).decode("ascii"),
    }


class TestCapabilityDispositions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = validate_capability_dispositions(REPOSITORY_ROOT)
        cls.environment = _key_environment()

    def _record(self, capability_id: str) -> CapabilityDispositionRecord:
        relative = f"{RECORD_ROOT_RELATIVE}/{capability_id}.json"
        return CapabilityDispositionRecord.model_validate_json(
            (REPOSITORY_ROOT / relative).read_bytes()
        )

    def test_exact_two_bounded_records_are_complete_and_honest(self) -> None:
        self.assertEqual(self.report.record_count, 2)
        self.assertEqual(self.report.covered_count, 2)
        self.assertEqual(self.report.missing_count, 4)
        expected_counts = {
            "deployment-admission": 82,
            "distribution-admission": 104,
        }
        for capability_id, expected_count in expected_counts.items():
            with self.subTest(capability_id=capability_id):
                record = self._record(capability_id)
                self.assertEqual(record.disposition, "pmorg_independent")
                self.assertEqual(record.candidate_search_outcome, "candidates_found")
                self.assertEqual(len(record.candidates), expected_count)
                self.assertTrue(
                    all(item.qualification == "fail" for item in record.candidates)
                )
                self.assertEqual(record.selected_candidate_ids, [])
                self.assertIsNone(record.deviation_decision_envelope)
                self.assertEqual(record.patch_ledger_refs, [])
                self.assertEqual(record.post_disposition_qualification.verdict, "pass")
                self.assertEqual(
                    record.post_disposition_qualification.executed_test_count, 5
                )
                self.assertTrue(
                    all(
                        item.ownership_class == "pmorg_owned"
                        for item in record.implementation_refs
                    )
                )

    def test_dsse_round_trip_is_deterministic_and_exact(self) -> None:
        for capability_id in CAPABILITIES:
            with self.subTest(capability_id=capability_id):
                record = self._record(capability_id)
                first = sign_capability_disposition(
                    record, repository_root=REPOSITORY_ROOT, environ=self.environment
                )
                second = sign_capability_disposition(
                    record, repository_root=REPOSITORY_ROOT, environ=self.environment
                )
                self.assertEqual(first, second)
                self.assertEqual(
                    verify_capability_disposition(
                        first,
                        repository_root=REPOSITORY_ROOT,
                        environ=self.environment,
                    ),
                    record,
                )

    def test_payload_tamper_and_wrong_signer_fail_closed(self) -> None:
        record = self._record("deployment-admission")
        envelope = sign_capability_disposition(
            record, repository_root=REPOSITORY_ROOT, environ=self.environment
        ).model_dump(mode="json")
        payload = bytearray(base64.b64decode(envelope["payload"]))
        payload[-2] ^= 1
        envelope["payload"] = base64.b64encode(payload).decode("ascii")
        with self.assertRaisesRegex(CapabilityDispositionError, "signature is invalid"):
            verify_capability_disposition(
                envelope, repository_root=REPOSITORY_ROOT, environ=self.environment
            )
        valid = sign_capability_disposition(
            record, repository_root=REPOSITORY_ROOT, environ=self.environment
        )
        with self.assertRaisesRegex(CapabilityDispositionError, "key identity"):
            verify_capability_disposition(
                valid, repository_root=REPOSITORY_ROOT, environ=_key_environment()
            )

    def test_semantic_shortcuts_are_rejected_before_signing(self) -> None:
        record = self._record("deployment-admission").model_dump(mode="json")
        mutations = (
            {"candidate_search_outcome": "no_candidate", "candidates": []},
            {"selected_candidate_ids": [record["candidates"][0]["candidate_id"]]},
            {"disposition": "reuse"},
            {"pmorg_platform_commit": "0" * 40},
        )
        for update in mutations:
            with self.subTest(update=update):
                changed = copy.deepcopy(record)
                changed.update(update)
                with self.assertRaises(CapabilityDispositionError):
                    sign_capability_disposition(
                        changed,
                        repository_root=REPOSITORY_ROOT,
                        environ=self.environment,
                    )

    def test_missing_or_tampered_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(REPOSITORY_ROOT, copied, symlinks=True)
            evidence = (
                copied
                / "pmorg/capabilities/post-disposition-qualification-reports/deployment-admission.json"
            )
            value = json.loads(evidence.read_bytes())
            value["verdict"] = "fail"
            evidence.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(CapabilityDispositionError):
                validate_capability_dispositions(copied)

    def test_builder_is_byte_deterministic(self) -> None:
        first = build_capability_dispositions(REPOSITORY_ROOT)
        second = build_capability_dispositions(REPOSITORY_ROOT)
        self.assertEqual(first, second)
        self.assertFalse(
            any(PRIVATE_KEY_ENV.encode() in payload for payload in first.values())
        )


if __name__ == "__main__":
    unittest.main()
