from __future__ import annotations

import base64
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from shutil import copytree
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat

from pmorg.application import capability_dispositions as disposition_module
from pmorg.application.capability_dispositions import build_capability_dispositions
from pmorg.application.capability_dispositions import CAPABILITIES
from pmorg.application.capability_dispositions import CapabilityDispositionError
from pmorg.application.capability_dispositions import PRIVATE_KEY_ENV
from pmorg.application.capability_dispositions import PUBLIC_KEY_ENV
from pmorg.application.capability_dispositions import RECORD_ROOT_RELATIVE
from pmorg.application.capability_dispositions import sign_capability_disposition
from pmorg.application.capability_dispositions import (
    sign_thin_fork_capability_disposition,
)
from pmorg.application.capability_dispositions import THIN_FORK_BASE_PLATFORM_COMMIT
from pmorg.application.capability_dispositions import THIN_FORK_CAPABILITY_ID
from pmorg.application.capability_dispositions import THIN_FORK_CLAIM_BOUNDARY
from pmorg.application.capability_dispositions import THIN_FORK_IMPLEMENTATION_PATHS
from pmorg.application.capability_dispositions import THIN_FORK_RECORD_RELATIVE
from pmorg.application.capability_dispositions import validate_capability_dispositions
from pmorg.application.capability_dispositions import (
    validate_thin_fork_capability_disposition,
)
from pmorg.application.capability_dispositions import verify_capability_disposition
from pmorg.application.capability_dispositions import (
    verify_thin_fork_capability_disposition,
)
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

    def test_thin_fork_record_is_complete_bounded_and_honest(self) -> None:
        record = validate_thin_fork_capability_disposition(REPOSITORY_ROOT)
        self.assertEqual(THIN_FORK_CAPABILITY_ID, record.capability_id)
        self.assertEqual(THIN_FORK_BASE_PLATFORM_COMMIT, record.pmorg_platform_commit)
        self.assertEqual("candidates_found", record.candidate_search_outcome)
        self.assertEqual(55, len(record.candidates))
        self.assertTrue(all(item.qualification == "fail" for item in record.candidates))
        self.assertEqual([], record.selected_candidate_ids)
        self.assertEqual("pmorg_independent", record.disposition)
        self.assertIsNone(record.deviation_decision_envelope)
        self.assertEqual([], record.patch_ledger_refs)
        self.assertEqual(
            list(THIN_FORK_IMPLEMENTATION_PATHS),
            [item.path for item in record.implementation_refs],
        )
        self.assertEqual("pass", record.post_disposition_qualification.verdict)
        self.assertEqual(87, record.post_disposition_qualification.executed_test_count)
        evidence_path = (
            REPOSITORY_ROOT / record.record_evidence_bundle_index.relative_path
        )
        evidence = json.loads(evidence_path.read_bytes())
        self.assertEqual(THIN_FORK_CLAIM_BOUNDARY, evidence["bundle_kind"])

    def test_thin_fork_dsse_round_trip_and_tamper_rejection(self) -> None:
        record = CapabilityDispositionRecord.model_validate_json(
            (REPOSITORY_ROOT / THIN_FORK_RECORD_RELATIVE).read_bytes()
        )
        first = sign_thin_fork_capability_disposition(
            record, repository_root=REPOSITORY_ROOT, environ=self.environment
        )
        second = sign_thin_fork_capability_disposition(
            record, repository_root=REPOSITORY_ROOT, environ=self.environment
        )
        self.assertEqual(first, second)
        self.assertEqual(
            record,
            verify_thin_fork_capability_disposition(
                first, repository_root=REPOSITORY_ROOT, environ=self.environment
            ),
        )
        envelope = first.model_dump(mode="json")
        payload = bytearray(base64.b64decode(envelope["payload"]))
        payload[-2] ^= 1
        envelope["payload"] = base64.b64encode(payload).decode("ascii")
        with self.assertRaisesRegex(CapabilityDispositionError, "signature is invalid"):
            verify_thin_fork_capability_disposition(
                envelope, repository_root=REPOSITORY_ROOT, environ=self.environment
            )
        with self.assertRaisesRegex(CapabilityDispositionError, "key identity"):
            verify_thin_fork_capability_disposition(
                first, repository_root=REPOSITORY_ROOT, environ=_key_environment()
            )

    def test_thin_fork_ledger_signed_entry_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(REPOSITORY_ROOT, copied, symlinks=True)
            ledger_path = copied / "pmorg/patch-ledger.json"
            ledger = json.loads(ledger_path.read_bytes())
            original = ledger["entries"][0]["reason"]
            ledger["entries"][0]["reason"] = f"{original} mutated"
            self.assertNotEqual(original, ledger["entries"][0]["reason"])
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            with self.assertRaisesRegex(
                CapabilityDispositionError, "entries history is not an exact prefix"
            ):
                validate_thin_fork_capability_disposition(copied)

    def test_thin_fork_ledger_signed_entry_deletion_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(REPOSITORY_ROOT, copied, symlinks=True)
            ledger_path = copied / "pmorg/patch-ledger.json"
            ledger = json.loads(ledger_path.read_bytes())
            before = len(ledger["entries"])
            ledger["entries"].pop(0)
            self.assertEqual(before - 1, len(ledger["entries"]))
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            with self.assertRaisesRegex(
                CapabilityDispositionError, "entries history is not an exact prefix"
            ):
                validate_thin_fork_capability_disposition(copied)

    def test_thin_fork_ledger_signed_entry_reorder_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(REPOSITORY_ROOT, copied, symlinks=True)
            ledger_path = copied / "pmorg/patch-ledger.json"
            ledger = json.loads(ledger_path.read_bytes())
            first_id = ledger["entries"][0]["id"]
            ledger["entries"][0], ledger["entries"][1] = (
                ledger["entries"][1],
                ledger["entries"][0],
            )
            self.assertNotEqual(first_id, ledger["entries"][0]["id"])
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            with self.assertRaisesRegex(
                CapabilityDispositionError, "entries history is not an exact prefix"
            ):
                validate_thin_fork_capability_disposition(copied)

    def test_thin_fork_ledger_top_level_pin_change_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(REPOSITORY_ROOT, copied, symlinks=True)
            ledger_path = copied / "pmorg/patch-ledger.json"
            ledger = json.loads(ledger_path.read_bytes())
            original = ledger["specification_commit"]
            ledger["specification_commit"] = "0" * 40
            self.assertNotEqual(original, ledger["specification_commit"])
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            with self.assertRaisesRegex(
                CapabilityDispositionError,
                "top-level pin drifted: specification_commit",
            ):
                validate_thin_fork_capability_disposition(copied)

    def test_thin_fork_ledger_pure_unique_append_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(REPOSITORY_ROOT, copied, symlinks=True)
            ledger_path = copied / "pmorg/patch-ledger.json"
            ledger = json.loads(ledger_path.read_bytes())
            appended = copy.deepcopy(ledger["entries"][-1])
            appended["id"] = "PL-035"
            appended["paths"] = ["pmorg/capabilities/future-q5-artifact.json"]
            appended["reason"] = "Simulated Q5 append-only ledger entry."
            ledger["entries"].append(appended)
            self.assertEqual("PL-035", ledger["entries"][-1]["id"])
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            validate_thin_fork_capability_disposition(copied)

    def test_thin_fork_ledger_duplicate_append_id_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(REPOSITORY_ROOT, copied, symlinks=True)
            ledger_path = copied / "pmorg/patch-ledger.json"
            ledger = json.loads(ledger_path.read_bytes())
            ledger["entries"].append(copy.deepcopy(ledger["entries"][-1]))
            self.assertEqual(ledger["entries"][-2]["id"], ledger["entries"][-1]["id"])
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            with self.assertRaisesRegex(
                CapabilityDispositionError, "entries IDs are not unique"
            ):
                validate_thin_fork_capability_disposition(copied)

    def test_thin_fork_ledger_base_resolution_and_digest_fail_closed(self) -> None:
        real_git = disposition_module._git

        def fail_ledger_resolution(*args: str, repository_root: Path) -> str:
            if args == (
                "rev-parse",
                f"{THIN_FORK_BASE_PLATFORM_COMMIT}:pmorg/patch-ledger.json",
            ):
                raise subprocess.CalledProcessError(128, args)
            return real_git(*args, repository_root=repository_root)

        with patch.object(
            disposition_module, "_git", side_effect=fail_ledger_resolution
        ):
            with self.assertRaisesRegex(
                CapabilityDispositionError, "implementation path is absent from base"
            ):
                validate_thin_fork_capability_disposition(REPOSITORY_ROOT)

        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(REPOSITORY_ROOT, copied, symlinks=True)
            record_path = copied / THIN_FORK_RECORD_RELATIVE
            record = json.loads(record_path.read_bytes())
            ledger_ref = next(
                item
                for item in record["implementation_refs"]
                if item["path"] == "pmorg/patch-ledger.json"
            )
            ledger_ref["content_hash"] = f"sha256:{'0' * 64}"
            record_path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(
                CapabilityDispositionError,
                "base ledger blob does not match recorded implementation digest",
            ):
                validate_thin_fork_capability_disposition(copied)

    def test_thin_fork_semantic_shortcuts_are_rejected_before_signing(self) -> None:
        record = json.loads((REPOSITORY_ROOT / THIN_FORK_RECORD_RELATIVE).read_bytes())
        mutations = (
            {"candidate_search_outcome": "no_candidate", "candidates": []},
            {"selected_candidate_ids": [record["candidates"][0]["candidate_id"]]},
            {"disposition": "reuse"},
            {"pmorg_platform_commit": "0" * 40},
            {"implementation_refs": record["implementation_refs"][:-1]},
            {
                "post_disposition_qualification": {
                    **record["post_disposition_qualification"],
                    "verdict": "fail",
                    "failed_test_count": 1,
                }
            },
        )
        for update in mutations:
            with self.subTest(update=tuple(update)):
                changed = copy.deepcopy(record)
                changed.update(update)
                with self.assertRaises(CapabilityDispositionError):
                    sign_thin_fork_capability_disposition(
                        changed,
                        repository_root=REPOSITORY_ROOT,
                        environ=self.environment,
                    )

    def test_admission_disposition_artifacts_remain_byte_identical(self) -> None:
        completed = subprocess.run(
            [
                "git",
                "diff",
                "--exit-code",
                THIN_FORK_BASE_PLATFORM_COMMIT,
                "--",
                "pmorg/capabilities/capability-disposition-report-v1.json",
                "pmorg/capabilities/dispositions/subject-ce-source-artifact-v1.json",
                "pmorg/capabilities/dispositions/evidence-bundle-v1.json",
                "pmorg/capabilities/dispositions/records/deployment-admission.json",
                "pmorg/capabilities/dispositions/records/distribution-admission.json",
                "pmorg/capabilities/dispositions/evidence/deployment-admission.json",
                "pmorg/capabilities/dispositions/evidence/distribution-admission.json",
                "pmorg/capabilities/dispositions/implementation-snapshots/deployment-admission",
                "pmorg/capabilities/dispositions/implementation-snapshots/distribution-admission",
            ],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
        )
        self.assertEqual(0, completed.returncode, completed.stdout.decode())


if __name__ == "__main__":
    unittest.main()
