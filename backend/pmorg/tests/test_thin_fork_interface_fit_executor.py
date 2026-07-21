from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from pmorg.application.thin_fork_interface_fit_executor import _read_blobs
from pmorg.application.thin_fork_interface_fit_executor import (
    build_thin_fork_oracle_extension,
)
from pmorg.application.thin_fork_interface_fit_executor import (
    check_thin_fork_oracle_extension,
)
from pmorg.application.thin_fork_interface_fit_executor import (
    execute_thin_fork_interface_fit,
)
from pmorg.application.thin_fork_interface_fit_executor import extension_schema
from pmorg.application.thin_fork_interface_fit_executor import (
    ThinForkInterfaceFitExecutorError,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class ThinForkInterfaceFitExecutorTests(unittest.TestCase):
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
            if item["capability_id"] == "thin-fork-boundary"
        )

    def test_extension_is_deterministic_schema_valid_and_predecessor_safe(self) -> None:
        first = build_thin_fork_oracle_extension(REPOSITORY_ROOT)
        second = build_thin_fork_oracle_extension(REPOSITORY_ROOT)
        self.assertEqual(first, second)
        document = json.loads(
            first["pmorg/capabilities/qualification-oracle-extension-thin-fork-v1.json"]
        )
        Draft202012Validator(extension_schema()).validate(document)
        self.assertEqual(
            {
                "adapter": None,
                "candidate_test_vector": None,
                "oracle_status": "unexecutable",
            },
            document["immutable_predecessor_state"],
        )
        self.assertEqual("executable", document["oracle"]["oracle_status"])
        self.assertEqual(
            "executor_activation_only_no_candidate_reports_or_aggregate_verdict",
            document["claim_boundary"],
        )

    def test_executor_consumes_candidate_bytes_and_live_mutation(self) -> None:
        result = execute_thin_fork_interface_fit(
            self.candidate_id, repository_root=REPOSITORY_ROOT
        )
        self.assertEqual("executable", result["oracle_status"])
        self.assertEqual("fail", result["verdict"])
        self.assertFalse(result["baseline_fit"])
        self.assertTrue(result["positive_injection_fit"])
        self.assertEqual(result["projected_blob_count"], result["observed_blob_count"])
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
        result = execute_thin_fork_interface_fit(
            self.candidate_id, repository_root=REPOSITORY_ROOT
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

    def test_candidate_blob_and_predecessor_policy_tamper_fail_closed(self) -> None:
        original = _read_blobs

        def mutated(root: Path, object_ids: list[str]) -> dict[str, bytes]:
            payloads = original(root, object_ids)
            first = object_ids[0]
            changed = copy.copy(payloads)
            changed[first] = payloads[first] + b"mutation"
            return changed

        with patch(
            "pmorg.application.thin_fork_interface_fit_executor._read_blobs",
            side_effect=mutated,
        ):
            with self.assertRaisesRegex(
                ThinForkInterfaceFitExecutorError,
                "blob (digest|size) drifted",
            ):
                execute_thin_fork_interface_fit(
                    self.candidate_id, repository_root=REPOSITORY_ROOT
                )

        q4a_path = (
            REPOSITORY_ROOT
            / "pmorg/capabilities/qualification-test-vector-extension-thin-fork-v1.json"
        )
        q4a = json.loads(q4a_path.read_bytes())
        q4a["immutable_predecessors"]["oracle_policy"]["digest"] = "sha256:" + "0" * 64
        with patch(
            "pmorg.application.thin_fork_interface_fit_executor._read_object",
            return_value=q4a,
        ):
            with self.assertRaisesRegex(
                ThinForkInterfaceFitExecutorError, "immutable base policy drifted"
            ):
                build_thin_fork_oracle_extension(REPOSITORY_ROOT)

    def test_committed_extension_matches_generation(self) -> None:
        check_thin_fork_oracle_extension(REPOSITORY_ROOT)


if __name__ == "__main__":
    unittest.main()
