from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from pmorg.application.governed_fork_qualification_setup import _read_blobs
from pmorg.application.governed_fork_qualification_setup import (
    build_governed_fork_qualification_setup,
)
from pmorg.application.governed_fork_qualification_setup import (
    check_governed_fork_qualification_setup,
)
from pmorg.application.governed_fork_qualification_setup import evidence_schema
from pmorg.application.governed_fork_qualification_setup import (
    GovernedForkQualificationSetupError,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_PATH = "pmorg/capabilities/governed-fork-interface-fit-evidence-v1.json"
MANIFEST_PATH = (
    "pmorg/capabilities/qualification-test-vector-extension-governed-fork-v1.json"
)
TEST_IDS = ("A-FORK-001", "A-SURFACE-001", "A-UPSTREAM-001")


class GovernedForkQualificationSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.outputs = build_governed_fork_qualification_setup(REPOSITORY_ROOT)
        cls.evidence = json.loads(cls.outputs[EVIDENCE_PATH])
        cls.manifest = json.loads(cls.outputs[MANIFEST_PATH])

    def test_generation_is_deterministic_and_schema_valid(self) -> None:
        self.assertEqual(
            self.outputs,
            build_governed_fork_qualification_setup(REPOSITORY_ROOT),
        )
        Draft202012Validator(evidence_schema()).validate(self.evidence)
        for item in self.manifest["vectors"]:
            vector = json.loads(self.outputs[item["relative_path"]])
            schema = json.loads(
                (
                    REPOSITORY_ROOT / self.manifest["vector_schema"]["relative_path"]
                ).read_bytes()
            )
            Draft202012Validator(schema).validate(vector)

    def test_exact_three_vectors_are_unactivated_and_falsifiable(self) -> None:
        self.assertEqual(
            TEST_IDS,
            tuple(item["test_id"] for item in self.manifest["vectors"]),
        )
        self.assertEqual(
            "definition_only_unactivated", self.manifest["activation_status"]
        )
        self.assertEqual(
            {
                "candidate_influence_both_directions": True,
                "mutation_can_flip_verdict": True,
                "no_op_rejected": True,
                "positive_injection_can_fit": True,
                "runtime_identity_required_at_execution": True,
            },
            self.manifest["falsifiability_contract"],
        )
        for item in self.manifest["vectors"]:
            vector = json.loads(self.outputs[item["relative_path"]])
            case_ids = {case["case_id"] for case in vector["test_cases"]}
            self.assertIn("conforming-positive-injection", case_ids)
            self.assertEqual(
                1,
                sum(case["mutation_required"] for case in vector["test_cases"]),
            )
            self.assertTrue(vector["mutation_probe"]["no_op_rejected"])
            self.assertEqual(
                "binary_measurement_required_at_execution",
                vector["runtime_identity"]["status"],
            )

    def test_exact_committed_denominator_is_screened_byte_closed(self) -> None:
        self.assertEqual(67, self.evidence["candidate_count"])
        self.assertEqual(67, self.evidence["blob_set_scan_count"])
        self.assertEqual(5364, self.evidence["candidate_blob_membership_count"])
        self.assertEqual(5364, self.evidence["blob_set_membership_count"])
        self.assertEqual(
            {"expected": 5364, "scanned": 5364, "unreadable": 0, "unverified": 0},
            self.evidence["coverage"],
        )
        identities = [
            (item["candidate_group"], item["candidate_id"])
            for item in self.evidence["candidates"]
        ]
        self.assertEqual(identities, sorted(set(identities)))
        for candidate in self.evidence["candidates"]:
            self.assertIn("no_fit_inference", candidate["plausibility_state"])

    def test_screening_preserves_all_oracles_and_claim_boundary(self) -> None:
        self.assertEqual(
            TEST_IDS,
            tuple(item["test_id"] for item in self.evidence["active_oracle_states"]),
        )
        for state in self.evidence["active_oracle_states"]:
            self.assertEqual("unexecutable", state["oracle_status"])
            self.assertIsNone(state["adapter"])
            self.assertIsNone(state["candidate_test_vector"])
        self.assertFalse(self.evidence["oracle_activation"])
        self.assertEqual(
            "exhaustive_plausibility_screen_only_no_qualification_or_disposition",
            self.evidence["claim_boundary"],
        )

    def test_blob_mutation_fails_closed_before_evidence(self) -> None:
        original = _read_blobs

        def mutated(root: Path, object_ids: list[str]) -> dict[str, bytes]:
            payloads = original(root, object_ids)
            changed = copy.copy(payloads)
            changed[object_ids[0]] = payloads[object_ids[0]] + b"mutation"
            return changed

        with patch(
            "pmorg.application.governed_fork_qualification_setup._read_blobs",
            side_effect=mutated,
        ):
            with self.assertRaisesRegex(
                GovernedForkQualificationSetupError,
                "blob (digest|size) drifted",
            ):
                build_governed_fork_qualification_setup(REPOSITORY_ROOT)

    def test_committed_outputs_match_and_predecessors_are_not_outputs(self) -> None:
        check_governed_fork_qualification_setup(REPOSITORY_ROOT)
        self.assertNotIn(
            "pmorg/capabilities/qualification-oracle-policy-v1.json", self.outputs
        )
        self.assertNotIn("pmorg/scripts/verify_fork.py", self.outputs)


if __name__ == "__main__":
    unittest.main()
