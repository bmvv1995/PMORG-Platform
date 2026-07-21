from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from pmorg.application.qualified_build_interface_fit_executor import _read_blobs
from pmorg.application.qualified_build_interface_fit_executor import (
    build_qualified_build_oracle_extension,
)
from pmorg.application.qualified_build_interface_fit_executor import (
    check_qualified_build_oracle_extension,
)
from pmorg.application.qualified_build_interface_fit_executor import (
    execute_qualified_build_interface_fit,
)
from pmorg.application.qualified_build_interface_fit_executor import extension_schema
from pmorg.application.qualified_build_interface_fit_executor import (
    QualifiedBuildInterfaceFitExecutorError,
)
from pmorg.application.qualified_build_interface_fit_executor import TEST_IDS

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class QualifiedBuildInterfaceFitExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        bundle = json.loads(
            (
                REPOSITORY_ROOT / "pmorg/capabilities/candidate-inputs-v1.json"
            ).read_bytes()
        )
        cls.candidate_id = next(
            item["candidate_id"]
            for item in bundle["candidates"]
            if item["capability_id"] == "qualified-reproducible-build"
        )

    def test_extension_is_deterministic_schema_valid_and_predecessor_safe(self) -> None:
        first = build_qualified_build_oracle_extension(REPOSITORY_ROOT)
        second = build_qualified_build_oracle_extension(REPOSITORY_ROOT)
        self.assertEqual(first, second)
        document = json.loads(
            first[
                "pmorg/capabilities/qualification-oracle-extension-qualified-build-v1.json"
            ]
        )
        Draft202012Validator(extension_schema()).validate(document)
        self.assertEqual(
            list(TEST_IDS), [item["test_id"] for item in document["oracles"]]
        )
        self.assertEqual(
            ["unexecutable"] * 4,
            [
                item["oracle_status"]
                for item in document["immutable_predecessor_states"]
            ],
        )
        self.assertEqual(
            ["executable"] * 4,
            [item["oracle_status"] for item in document["oracles"]],
        )
        self.assertEqual(
            "executor_activation_only_no_candidate_reports_or_aggregate_verdict",
            document["claim_boundary"],
        )

    def test_all_four_executors_consume_candidate_bytes_and_live_mutation(
        self,
    ) -> None:
        for test_id in TEST_IDS:
            with self.subTest(test_id=test_id):
                result = execute_qualified_build_interface_fit(
                    self.candidate_id, test_id, repository_root=REPOSITORY_ROOT
                )
                self.assertEqual("executable", result["oracle_status"])
                self.assertEqual("fail", result["verdict"])
                self.assertFalse(result["baseline_fit"])
                self.assertTrue(result["positive_injection_fit"])
                self.assertEqual(
                    result["projected_blob_count"], result["observed_blob_count"]
                )
                self.assertEqual(0, result["unobserved_blob_count"])
                self.assertNotEqual(
                    result["baseline_observation_digest"],
                    result["mutation_observation_digest"],
                )
                self.assertNotEqual(
                    result["baseline_observation_digest"],
                    result["positive_injection_observation_digest"],
                )

    def test_runtime_identity_measures_binary_and_exact_locks(self) -> None:
        result = execute_qualified_build_interface_fit(
            self.candidate_id, TEST_IDS[0], repository_root=REPOSITORY_ROOT
        )
        measurement = result["runtime_measurement"]
        interpreter = Path(sys.executable).resolve().read_bytes()
        self.assertEqual(
            "sha256:" + hashlib.sha256(interpreter).hexdigest(),
            measurement["interpreter_binary"]["digest"],
        )
        self.assertEqual(
            [".python-version", "pyproject.toml", "uv.lock"],
            [item["relative_path"] for item in measurement["declared_artifacts"]],
        )

    def test_candidate_blob_policy_and_unknown_test_tamper_fail_closed(self) -> None:
        original = _read_blobs

        def mutated(root: Path, object_ids: list[str]) -> dict[str, bytes]:
            payloads = original(root, object_ids)
            first = object_ids[0]
            changed = copy.copy(payloads)
            changed[first] = payloads[first] + b"mutation"
            return changed

        with patch(
            "pmorg.application.qualified_build_interface_fit_executor._read_blobs",
            side_effect=mutated,
        ):
            with self.assertRaisesRegex(
                QualifiedBuildInterfaceFitExecutorError,
                "blob (digest|size) drifted",
            ):
                execute_qualified_build_interface_fit(
                    self.candidate_id, TEST_IDS[0], repository_root=REPOSITORY_ROOT
                )

        vector_path = (
            REPOSITORY_ROOT
            / "pmorg/capabilities/qualification-test-vector-extension-qualified-build-v1.json"
        )
        vector_extension = json.loads(vector_path.read_bytes())
        vector_extension["immutable_predecessors"]["oracle_policy"]["digest"] = (
            "sha256:" + "0" * 64
        )
        original_read = __import__(
            "pmorg.application.qualified_build_interface_fit_executor",
            fromlist=["_read_object"],
        )._read_object

        def drifted_read(root: Path, relative_path: str) -> dict[str, object]:
            if relative_path.endswith(
                "qualification-test-vector-extension-qualified-build-v1.json"
            ):
                return vector_extension
            return original_read(root, relative_path)

        with patch(
            "pmorg.application.qualified_build_interface_fit_executor._read_object",
            side_effect=drifted_read,
        ):
            with self.assertRaisesRegex(
                QualifiedBuildInterfaceFitExecutorError, "immutable base policy drifted"
            ):
                build_qualified_build_oracle_extension(REPOSITORY_ROOT)

        reference_drift = json.loads(vector_path.read_bytes())
        reference_drift["interface_reference_implementations"][0]["digest"] = (
            "sha256:" + "0" * 64
        )

        def drifted_reference_read(root: Path, relative_path: str) -> dict[str, object]:
            if relative_path.endswith(
                "qualification-test-vector-extension-qualified-build-v1.json"
            ):
                return reference_drift
            return original_read(root, relative_path)

        with patch(
            "pmorg.application.qualified_build_interface_fit_executor._read_object",
            side_effect=drifted_reference_read,
        ):
            with self.assertRaisesRegex(
                QualifiedBuildInterfaceFitExecutorError,
                "reference implementation set drifted",
            ):
                build_qualified_build_oracle_extension(REPOSITORY_ROOT)

        with self.assertRaisesRegex(
            QualifiedBuildInterfaceFitExecutorError, "unknown test id"
        ):
            execute_qualified_build_interface_fit(
                self.candidate_id, "UNKNOWN", repository_root=REPOSITORY_ROOT
            )

    def test_no_op_mutation_is_rejected(self) -> None:
        with patch(
            "pmorg.application.qualified_build_interface_fit_executor._mutated_blobs",
            side_effect=lambda blobs: [dict(item) for item in blobs],
        ):
            with self.assertRaisesRegex(
                QualifiedBuildInterfaceFitExecutorError,
                "mutation did not change an observation",
            ):
                execute_qualified_build_interface_fit(
                    self.candidate_id, TEST_IDS[0], repository_root=REPOSITORY_ROOT
                )

    def test_committed_extension_matches_generation(self) -> None:
        check_qualified_build_oracle_extension(REPOSITORY_ROOT)


if __name__ == "__main__":
    unittest.main()
