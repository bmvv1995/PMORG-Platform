from __future__ import annotations

import base64
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from shutil import copytree
from shutil import ignore_patterns

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat

from pmorg.application import capability_dispositions as shared
from pmorg.application.capability_disposition_qualification_disposition import (
    BASE_PLATFORM_COMMIT,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    build_capability_disposition_qualification_disposition,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    CAPABILITY_ID,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    CapabilityDispositionQualificationDispositionError,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    CLAIM_BOUNDARY,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    EVIDENCE_RELATIVE,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    EXPECTED_IMPLEMENTATION_SET_HASH,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    IMPLEMENTATION_PATHS,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    PAYLOAD_TYPE,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    PRIVATE_KEY_ENV,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    PUBLIC_KEY_ENV,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    RECORD_RELATIVE,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    REQUIREMENT_IDS,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    sign_capability_disposition_qualification_disposition,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    SNAPSHOT_ROOT_RELATIVE,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    validate_capability_disposition_qualification_disposition,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    verify_capability_disposition_qualification_disposition,
)
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import key_id
from pmorg.application.rbdp import pre_authentication_encoding
from pmorg.application.rbdp import private_key_from_env
from pmorg.application.rbdp import RbdpVerificationError

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SEARCH_RELATIVE = (
    "pmorg/capabilities/candidate-search/"
    "capability-disposition-qualification-search-evidence-v1.json"
)
CQR_INDEX_RELATIVE = (
    "pmorg/capabilities/"
    "capability-disposition-qualification-candidate-qualification-reports-v1.json"
)
PDQ_REPORT_RELATIVE = (
    "pmorg/capabilities/"
    "capability-disposition-post-disposition-qualification-report-v1.json"
)
AGGREGATE_PREDECESSORS = (
    "pmorg/capabilities/capability-disposition-report-v1.json",
    "pmorg/capabilities/dispositions/evidence-bundle-v1.json",
    "pmorg/capabilities/dispositions/subject-ce-source-artifact-v1.json",
)


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


def _signed_envelope(value: dict[str, object], environment: dict[str, str]) -> dict:
    private_key = private_key_from_env(name=PRIVATE_KEY_ENV, environ=environment)
    payload = canonical_json_bytes(value)
    signature = private_key.sign(pre_authentication_encoding(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": key_id(private_key.public_key()),
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }


class TestCapabilityDispositionQualificationDisposition(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = validate_capability_disposition_qualification_disposition(
            REPOSITORY_ROOT
        )
        cls.environment = _key_environment()

    def test_exact_48_candidate_denominator_and_honest_cqr_bindings(self) -> None:
        search = json.loads((REPOSITORY_ROOT / SEARCH_RELATIVE).read_bytes())
        index = json.loads((REPOSITORY_ROOT / CQR_INDEX_RELATIVE).read_bytes())
        record_ids = [item.candidate_id for item in self.record.candidates]
        index_by_id = {item["candidate_id"]: item for item in index["entries"]}
        self.assertEqual(48, len(record_ids))
        self.assertEqual(48, len(set(record_ids)))
        self.assertEqual(search["candidate_ids"], record_ids)
        self.assertEqual(set(index_by_id), set(record_ids))
        self.assertEqual(
            {"ce": 42, "ee": 6},
            {
                surface: sum(
                    item.onyx_surface == surface for item in self.record.candidates
                )
                for surface in ("ce", "ee")
            },
        )
        observed_results = 0
        for candidate in self.record.candidates:
            entry = index_by_id[candidate.candidate_id]
            report = candidate.qualification_report
            with self.subTest(candidate_id=candidate.candidate_id):
                self.assertEqual("fail", entry["verdict"])
                self.assertEqual("fail", candidate.qualification)
                self.assertEqual("fail", report.verdict)
                self.assertEqual(5, report.expected_test_count)
                self.assertEqual(5, report.executed_test_count)
                self.assertEqual(5, report.failed_test_count)
                self.assertEqual(0, report.missing_test_count)
                self.assertEqual(0, report.duplicate_test_count)
                self.assertEqual(
                    [
                        "A-PATCH-002",
                        "A-PATCH-003",
                        "A-PATCH-004",
                        "A-PATCH-005",
                        "A-PATCH-006",
                    ],
                    [item.test_id for item in report.test_evidence],
                )
                self.assertTrue(
                    all(item.verdict == "fail" for item in report.test_evidence)
                )
                self.assertEqual(
                    "mit-expat"
                    if candidate.onyx_surface == "ce"
                    else "onyx-enterprise",
                    candidate.license_class,
                )
            observed_results += len(report.test_evidence)
        self.assertEqual(240, observed_results)
        self.assertEqual(5015, index["projected_blob_membership_count"])

    def test_disposition_pdq_and_claim_are_exactly_bounded(self) -> None:
        self.assertEqual(CAPABILITY_ID, self.record.capability_id)
        self.assertEqual(BASE_PLATFORM_COMMIT, self.record.pmorg_platform_commit)
        self.assertEqual(REQUIREMENT_IDS, self.record.pmorg_requirement_ids)
        self.assertEqual("candidates_found", self.record.candidate_search_outcome)
        self.assertEqual("pmorg_independent", self.record.disposition)
        self.assertEqual([], self.record.selected_candidate_ids)
        self.assertEqual([], self.record.patch_ledger_refs)
        self.assertEqual(
            "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            self.record.patch_ledger_set_hash,
        )
        self.assertIsNone(self.record.deviation_decision_envelope)
        self.assertEqual(
            list(IMPLEMENTATION_PATHS),
            [item.path for item in self.record.implementation_refs],
        )
        self.assertEqual(
            EXPECTED_IMPLEMENTATION_SET_HASH,
            self.record.implementation_path_set_hash,
        )
        pdq = self.record.post_disposition_qualification
        self.assertEqual(
            (12, 12, 0, 0, 0, "pass"),
            (
                pdq.expected_test_count,
                pdq.executed_test_count,
                pdq.missing_test_count,
                pdq.duplicate_test_count,
                pdq.failed_test_count,
                pdq.verdict,
            ),
        )
        evidence = json.loads((REPOSITORY_ROOT / EVIDENCE_RELATIVE).read_bytes())
        self.assertEqual(CLAIM_BOUNDARY, evidence["bundle_kind"])
        self.assertEqual(57, evidence["entry_count"])
        self.assertEqual(57, len(evidence["entries"]))
        self.assertEqual(
            48,
            sum(
                "candidate-qualification-reports/candidate-" in item["relative_path"]
                for item in evidence["entries"]
            ),
        )

    def test_public_outputs_are_deterministic_canonical_closed_and_secret_free(
        self,
    ) -> None:
        first = build_capability_disposition_qualification_disposition(REPOSITORY_ROOT)
        second = build_capability_disposition_qualification_disposition(REPOSITORY_ROOT)
        self.assertEqual(first, second)
        expected_paths = {RECORD_RELATIVE, EVIDENCE_RELATIVE} | {
            f"{SNAPSHOT_ROOT_RELATIVE}/{path.replace('/', '__')}.json"
            for path in IMPLEMENTATION_PATHS
        }
        self.assertEqual(expected_paths, set(first))
        for relative_path, payload in first.items():
            with self.subTest(relative_path=relative_path):
                self.assertEqual(canonical_document_bytes(json.loads(payload)), payload)
        envelope = sign_capability_disposition_qualification_disposition(
            self.record,
            repository_root=REPOSITORY_ROOT,
            environ=self.environment,
        )
        forbidden = (
            self.environment[PRIVATE_KEY_ENV].encode(),
            base64.b64decode(self.environment[PRIVATE_KEY_ENV]),
            envelope.signatures[0].sig.encode(),
            base64.b64decode(envelope.signatures[0].sig),
            b'"signatures"',
        )
        self.assertTrue(
            all(
                token not in payload
                for payload in first.values()
                for token in forbidden
            )
        )

    def test_dsse_round_trip_and_envelope_failures(self) -> None:
        envelope = sign_capability_disposition_qualification_disposition(
            self.record,
            repository_root=REPOSITORY_ROOT,
            environ=self.environment,
        )
        self.assertEqual(
            envelope,
            sign_capability_disposition_qualification_disposition(
                self.record,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            ),
        )
        self.assertEqual(
            self.record,
            verify_capability_disposition_qualification_disposition(
                envelope,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            ),
        )
        tampered_payload = envelope.model_dump(mode="json")
        payload = bytearray(base64.b64decode(tampered_payload["payload"]))
        payload[-2] ^= 1
        tampered_payload["payload"] = base64.b64encode(payload).decode("ascii")
        with self.assertRaisesRegex(
            CapabilityDispositionQualificationDispositionError,
            "signature is invalid",
        ):
            verify_capability_disposition_qualification_disposition(
                tampered_payload,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            )
        wrong_type = envelope.model_dump(mode="json")
        wrong_type["payloadType"] = "application/not-pmorg"
        with self.assertRaisesRegex(
            CapabilityDispositionQualificationDispositionError, "payload type"
        ):
            verify_capability_disposition_qualification_disposition(
                wrong_type,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            )
        multiple = envelope.model_dump(mode="json")
        multiple["signatures"].append(copy.deepcopy(multiple["signatures"][0]))
        with self.assertRaisesRegex(
            CapabilityDispositionQualificationDispositionError,
            "exactly one signature",
        ):
            verify_capability_disposition_qualification_disposition(
                multiple,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            )
        with self.assertRaisesRegex(
            CapabilityDispositionQualificationDispositionError, "key identity"
        ):
            verify_capability_disposition_qualification_disposition(
                envelope,
                repository_root=REPOSITORY_ROOT,
                environ=_key_environment(),
            )

    def test_validly_resigned_semantic_forgery_fails(self) -> None:
        forged = self.record.model_dump(mode="json")
        forged["candidates"][0]["qualification"] = "pass"
        forged["candidates"][0]["qualification_report"]["verdict"] = "pass"
        envelope = _signed_envelope(forged, self.environment)
        with self.assertRaisesRegex(
            CapabilityDispositionQualificationDispositionError,
            "derivation drifted",
        ):
            verify_capability_disposition_qualification_disposition(
                envelope,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            )

    def test_keys_are_environment_only_and_signing_is_non_persistent(self) -> None:
        with self.assertRaises(RbdpVerificationError):
            sign_capability_disposition_qualification_disposition(
                self.record, repository_root=REPOSITORY_ROOT, environ={}
            )
        with self.assertRaises(RbdpVerificationError):
            sign_capability_disposition_qualification_disposition(
                self.record,
                repository_root=REPOSITORY_ROOT,
                environ={PRIVATE_KEY_ENV: base64.b64encode(b"short").decode()},
            )
        before = subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        sign_capability_disposition_qualification_disposition(
            self.record,
            repository_root=REPOSITORY_ROOT,
            environ=self.environment,
        )
        after = subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(before, after)

    def test_predecessor_tamper_fails_and_future_append_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(
                REPOSITORY_ROOT,
                copied,
                symlinks=True,
                ignore=ignore_patterns(
                    ".venv", ".pytest_cache", ".mypy_cache", "__pycache__"
                ),
            )
            q7c_path = copied / next(
                item.qualification_report.test_evidence[0].result.relative_path
                for item in self.record.candidates
            )
            q7c_original = q7c_path.read_bytes()
            q7c_path.write_bytes(q7c_original + b" ")
            with self.assertRaises(Exception):
                validate_capability_disposition_qualification_disposition(copied)
            q7c_path.write_bytes(q7c_original)

            q7d_path = copied / PDQ_REPORT_RELATIVE
            q7d_original = q7d_path.read_bytes()
            q7d_path.write_bytes(q7d_original + b" ")
            with self.assertRaises(Exception):
                validate_capability_disposition_qualification_disposition(copied)
            q7d_path.write_bytes(q7d_original)

            sidecar = copied / SNAPSHOT_ROOT_RELATIVE / "unexpected-sidecar.txt"
            sidecar.write_text("not content-addressed evidence", encoding="utf-8")
            with self.assertRaisesRegex(
                CapabilityDispositionQualificationDispositionError,
                "snapshot directory is not byte-closed",
            ):
                validate_capability_disposition_qualification_disposition(copied)
            sidecar.unlink()

            ledger_path = copied / "pmorg/patch-ledger.json"
            ledger = json.loads(ledger_path.read_bytes())
            successor = copy.deepcopy(ledger["entries"][-1])
            successor["id"] = "PL-048"
            successor["paths"] = ["pmorg/capabilities/future-terminal.json"]
            successor["reason"] = "Simulated reversible successor append."
            ledger["entries"].append(successor)
            ledger_path.write_bytes(canonical_document_bytes(ledger))
            future = copied / "pmorg/capabilities/future-terminal.json"
            future.write_bytes(canonical_document_bytes({"future": True}))
            observed = validate_capability_disposition_qualification_disposition(copied)
            self.assertEqual(self.record, observed)

    def test_prior_disposition_guards_and_aggregate_predecessors_remain_exact(
        self,
    ) -> None:
        shared.validate_capability_dispositions(REPOSITORY_ROOT)
        shared.validate_thin_fork_capability_disposition(REPOSITORY_ROOT)
        shared.validate_governed_fork_capability_disposition(REPOSITORY_ROOT)
        shared.validate_qualified_build_capability_disposition(REPOSITORY_ROOT)
        for relative_path in AGGREGATE_PREDECESSORS:
            with self.subTest(relative_path=relative_path):
                historical = subprocess.run(
                    ["git", "show", f"{BASE_PLATFORM_COMMIT}:{relative_path}"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual(
                    historical, (REPOSITORY_ROOT / relative_path).read_bytes()
                )


if __name__ == "__main__":
    unittest.main()
