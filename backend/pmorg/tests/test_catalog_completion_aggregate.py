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

from pmorg.application.catalog_completion_aggregate import BASE_PLATFORM_COMMIT
from pmorg.application.catalog_completion_aggregate import (
    build_catalog_completion_aggregate,
)
from pmorg.application.catalog_completion_aggregate import CAPABILITY_ORDER
from pmorg.application.catalog_completion_aggregate import CATALOG_RELATIVE
from pmorg.application.catalog_completion_aggregate import (
    CatalogCompletionAggregateError,
)
from pmorg.application.catalog_completion_aggregate import CLAIM_BOUNDARY
from pmorg.application.catalog_completion_aggregate import COMPLETION_CLAIM
from pmorg.application.catalog_completion_aggregate import EVIDENCE_RELATIVES
from pmorg.application.catalog_completion_aggregate import EXPECTED_REQUIREMENT_IDS
from pmorg.application.catalog_completion_aggregate import GATE_CLASS
from pmorg.application.catalog_completion_aggregate import LEGACY_AGGREGATE_PREDECESSORS
from pmorg.application.catalog_completion_aggregate import PAYLOAD_TYPE
from pmorg.application.catalog_completion_aggregate import PRIVATE_KEY_ENV
from pmorg.application.catalog_completion_aggregate import PUBLIC_KEY_ENV
from pmorg.application.catalog_completion_aggregate import RECORD_RELATIVE
from pmorg.application.catalog_completion_aggregate import RECORD_RELATIVES
from pmorg.application.catalog_completion_aggregate import SCHEMA_RELATIVE
from pmorg.application.catalog_completion_aggregate import SCOPE_EXCLUSIONS
from pmorg.application.catalog_completion_aggregate import (
    sign_catalog_completion_aggregate,
)
from pmorg.application.catalog_completion_aggregate import (
    validate_catalog_completion_aggregate,
)
from pmorg.application.catalog_completion_aggregate import (
    verify_catalog_completion_aggregate,
)
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import sha256_digest
from pmorg.application.rbdp import canonical_json_bytes
from pmorg.application.rbdp import key_id
from pmorg.application.rbdp import pre_authentication_encoding
from pmorg.application.rbdp import private_key_from_env
from pmorg.application.rbdp import RbdpVerificationError

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


class TestCatalogCompletionAggregate(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = validate_catalog_completion_aggregate(REPOSITORY_ROOT)
        cls.environment = _key_environment()

    def test_exact_six_bindings_and_21_of_21_coverage(self) -> None:
        catalog = json.loads((REPOSITORY_ROOT / CATALOG_RELATIVE).read_bytes())
        requirement_map = {
            item["capability_id"]: item["pmorg_requirement_ids"]
            for item in catalog["items"]
        }
        self.assertEqual(BASE_PLATFORM_COMMIT, self.record.pmorg_platform_commit)
        self.assertEqual(list(CAPABILITY_ORDER), list(requirement_map))
        self.assertEqual(6, self.record.disposition_count)
        self.assertEqual(6, len(self.record.disposition_bindings))
        self.assertEqual(
            list(CAPABILITY_ORDER),
            [binding.capability_id for binding in self.record.disposition_bindings],
        )
        self.assertEqual(21, self.record.expected_requirement_count)
        self.assertEqual(21, self.record.covered_requirement_count)
        self.assertEqual(
            list(EXPECTED_REQUIREMENT_IDS), self.record.covered_requirement_ids
        )
        self.assertEqual(21, len(set(self.record.covered_requirement_ids)))
        self.assertEqual([], self.record.missing_requirement_ids)
        self.assertEqual([], self.record.duplicate_requirement_ids)
        self.assertEqual([], self.record.unknown_requirement_ids)
        for binding in self.record.disposition_bindings:
            with self.subTest(capability_id=binding.capability_id):
                self.assertEqual(
                    requirement_map[binding.capability_id],
                    binding.pmorg_requirement_ids,
                )
                record_path = REPOSITORY_ROOT / binding.record.relative_path
                evidence_path = REPOSITORY_ROOT / binding.evidence_bundle.relative_path
                record_value = json.loads(record_path.read_bytes())
                evidence_value = json.loads(evidence_path.read_bytes())
                self.assertEqual(
                    RECORD_RELATIVES[binding.capability_id],
                    binding.record.relative_path,
                )
                self.assertEqual(
                    EVIDENCE_RELATIVES[binding.capability_id],
                    binding.evidence_bundle.relative_path,
                )
                self.assertEqual(
                    sha256_digest(record_path.read_bytes()), binding.record.digest
                )
                self.assertEqual(
                    sha256_digest(evidence_path.read_bytes()),
                    binding.evidence_bundle.digest,
                )
                self.assertEqual(
                    record_value["record_evidence_bundle_index"]["digest"],
                    binding.evidence_bundle.digest,
                )
                self.assertEqual(
                    evidence_value["subject_binding_hash"],
                    binding.platform_anchor.artifact_set_hash,
                )

    def test_claim_is_completion_only_and_downstream_scopes_stay_excluded(self) -> None:
        self.assertEqual(GATE_CLASS, self.record.gate_class)
        self.assertEqual(CLAIM_BOUNDARY, self.record.claim_boundary)
        self.assertEqual(COMPLETION_CLAIM, self.record.completion_claim)
        self.assertEqual("complete", self.record.completion_status)
        self.assertEqual(list(SCOPE_EXCLUSIONS), self.record.scope_exclusions)
        keys = set(self.record.model_dump(mode="json"))
        self.assertFalse(
            keys
            & {
                "admission_verdict",
                "release_verdict",
                "build_qualification_verdict",
                "production_verdict",
                "g3a_verdict",
            }
        )

    def test_public_outputs_are_deterministic_canonical_closed_and_secret_free(
        self,
    ) -> None:
        first = build_catalog_completion_aggregate(REPOSITORY_ROOT)
        second = build_catalog_completion_aggregate(REPOSITORY_ROOT)
        self.assertEqual(first, second)
        self.assertEqual({SCHEMA_RELATIVE, RECORD_RELATIVE}, set(first))
        for relative_path, payload in first.items():
            with self.subTest(relative_path=relative_path):
                self.assertEqual(canonical_document_bytes(json.loads(payload)), payload)
        envelope = sign_catalog_completion_aggregate(
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
            b'"payload"',
        )
        self.assertTrue(
            all(
                token not in payload
                for payload in first.values()
                for token in forbidden
            )
        )

    def test_dsse_round_trip_and_envelope_failures(self) -> None:
        envelope = sign_catalog_completion_aggregate(
            self.record,
            repository_root=REPOSITORY_ROOT,
            environ=self.environment,
        )
        self.assertEqual(
            envelope,
            sign_catalog_completion_aggregate(
                self.record,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            ),
        )
        self.assertEqual(
            self.record,
            verify_catalog_completion_aggregate(
                envelope,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            ),
        )
        tampered = envelope.model_dump(mode="json")
        payload = bytearray(base64.b64decode(tampered["payload"]))
        payload[-2] ^= 1
        tampered["payload"] = base64.b64encode(payload).decode("ascii")
        with self.assertRaisesRegex(
            CatalogCompletionAggregateError, "signature is invalid"
        ):
            verify_catalog_completion_aggregate(
                tampered,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            )
        wrong_type = envelope.model_dump(mode="json")
        wrong_type["payloadType"] = "application/not-pmorg"
        with self.assertRaisesRegex(CatalogCompletionAggregateError, "payload type"):
            verify_catalog_completion_aggregate(
                wrong_type,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            )
        multiple = envelope.model_dump(mode="json")
        multiple["signatures"].append(copy.deepcopy(multiple["signatures"][0]))
        with self.assertRaisesRegex(
            CatalogCompletionAggregateError, "exactly one signature"
        ):
            verify_catalog_completion_aggregate(
                multiple,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            )
        with self.assertRaisesRegex(CatalogCompletionAggregateError, "key identity"):
            verify_catalog_completion_aggregate(
                envelope,
                repository_root=REPOSITORY_ROOT,
                environ=_key_environment(),
            )

    def test_validly_resigned_semantic_forgery_fails_closed(self) -> None:
        forged = self.record.model_dump(mode="json")
        forged["covered_requirement_count"] = 20
        envelope = _signed_envelope(forged, self.environment)
        with self.assertRaisesRegex(
            CatalogCompletionAggregateError, "derivation drifted"
        ):
            verify_catalog_completion_aggregate(
                envelope,
                repository_root=REPOSITORY_ROOT,
                environ=self.environment,
            )

    def test_keys_are_environment_only_and_signing_is_non_persistent(self) -> None:
        with self.assertRaises(RbdpVerificationError):
            sign_catalog_completion_aggregate(
                self.record, repository_root=REPOSITORY_ROOT, environ={}
            )
        before = subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        sign_catalog_completion_aggregate(
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

    def test_bound_record_evidence_and_catalog_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(
                REPOSITORY_ROOT,
                copied,
                symlinks=True,
                ignore=ignore_patterns(
                    ".venv",
                    ".pytest_cache",
                    ".mypy_cache",
                    "__pycache__",
                    "node_modules",
                ),
            )
            paths = (
                RECORD_RELATIVES[CAPABILITY_ORDER[0]],
                EVIDENCE_RELATIVES[CAPABILITY_ORDER[1]],
                CATALOG_RELATIVE,
            )
            for relative_path in paths:
                path = copied / relative_path
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.subTest(relative_path=relative_path):
                    with self.assertRaisesRegex(
                        CatalogCompletionAggregateError, "bound path drifted"
                    ):
                        validate_catalog_completion_aggregate(copied)
                path.write_bytes(original)
            self.assertEqual(self.record, validate_catalog_completion_aggregate(copied))

    def test_ledger_successor_is_safe_but_pl048_tamper_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = Path(temporary_directory) / "repository"
            copytree(
                REPOSITORY_ROOT,
                copied,
                symlinks=True,
                ignore=ignore_patterns(
                    ".venv",
                    ".pytest_cache",
                    ".mypy_cache",
                    "__pycache__",
                    "node_modules",
                ),
            )
            ledger_path = copied / "pmorg/patch-ledger.json"
            ledger = json.loads(ledger_path.read_bytes())
            successor = copy.deepcopy(ledger["entries"][-1])
            successor["id"] = "PL-049"
            successor["paths"] = ["pmorg/capabilities/future-slice.json"]
            successor["reason"] = "Simulated reversible successor append."
            ledger["entries"].append(successor)
            ledger_path.write_bytes(canonical_document_bytes(ledger))
            future = copied / "pmorg/capabilities/future-slice.json"
            future.write_bytes(canonical_document_bytes({"future": True}))
            self.assertEqual(self.record, validate_catalog_completion_aggregate(copied))
            ledger["entries"][-2]["reason"] += " drift"
            ledger_path.write_bytes(canonical_document_bytes(ledger))
            with self.assertRaisesRegex(
                CatalogCompletionAggregateError, "PL-048 ownership entry"
            ):
                validate_catalog_completion_aggregate(copied)

    def test_predecessors_are_exactly_base_bound(self) -> None:
        bound_paths = (
            CATALOG_RELATIVE,
            *RECORD_RELATIVES.values(),
            *EVIDENCE_RELATIVES.values(),
            *LEGACY_AGGREGATE_PREDECESSORS,
        )
        for relative_path in bound_paths:
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
