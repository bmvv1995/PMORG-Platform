from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from pmorg.application.candidate_interface_fit import _read_blobs
from pmorg.application.candidate_interface_fit import _SELECTION
from pmorg.application.candidate_interface_fit import (
    build_candidate_interface_fit_evidence,
)
from pmorg.application.candidate_interface_fit import CandidateInterfaceFitError
from pmorg.application.candidate_interface_fit import (
    check_candidate_interface_fit_evidence,
)
from pmorg.application.candidate_interface_fit import evidence_schema

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class CandidateInterfaceFitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        outputs = build_candidate_interface_fit_evidence(REPOSITORY_ROOT)
        cls.payload = outputs[
            "pmorg/capabilities/candidate-interface-fit-evidence-v1.json"
        ]
        cls.document = json.loads(cls.payload)

    def test_evidence_is_deterministic_and_schema_valid(self) -> None:
        second = build_candidate_interface_fit_evidence(REPOSITORY_ROOT)
        self.assertEqual(
            self.payload,
            second["pmorg/capabilities/candidate-interface-fit-evidence-v1.json"],
        )
        Draft202012Validator(evidence_schema()).validate(self.document)

    def test_exact_high_signal_candidates_are_covered(self) -> None:
        expected = {
            (capability_id, candidate_group)
            for capability_id, groups in _SELECTION.items()
            for candidate_group in groups
        }
        actual = {
            (candidate["capability_id"], candidate["candidate_group"])
            for candidate in self.document["candidates"]
        }
        self.assertEqual(expected, actual)
        self.assertEqual(12, self.document["candidate_count"])

    def test_every_projected_blob_is_verified_and_scanned(self) -> None:
        expected = 0
        for candidate in self.document["candidates"]:
            coverage = candidate["coverage"]
            self.assertEqual(coverage["expected"], coverage["scanned"])
            self.assertEqual(0, coverage["unreadable"])
            self.assertEqual(0, coverage["unverified"])
            self.assertEqual(candidate["blob_count"], len(candidate["inspected_blobs"]))
            expected += candidate["blob_count"]
        self.assertEqual(expected, self.document["coverage"]["expected"])
        self.assertEqual(expected, self.document["coverage"]["scanned"])

    def test_screen_does_not_emit_qualification_or_activate_oracles(self) -> None:
        self.assertFalse(self.document["oracle_activation"])
        self.assertEqual(
            "plausibility_screen_only_no_qualification_or_disposition",
            self.document["claim_boundary"],
        )
        for candidate in self.document["candidates"]:
            self.assertEqual(
                "no_direct_candidate_level_admission_surface_observed",
                candidate["plausibility_state"],
            )
            self.assertTrue(candidate["missing_probe_ids"])

    def test_blob_mutation_is_rejected_before_evidence(self) -> None:
        original = _read_blobs

        def mutated(root: Path, object_ids: list[str]) -> dict[str, bytes]:
            payloads = original(root, object_ids)
            first = object_ids[0]
            changed = copy.copy(payloads)
            changed[first] = payloads[first] + b"mutation"
            return changed

        with patch(
            "pmorg.application.candidate_interface_fit._read_blobs",
            side_effect=mutated,
        ):
            with self.assertRaisesRegex(
                CandidateInterfaceFitError, "blob (digest|size) drifted"
            ):
                build_candidate_interface_fit_evidence(REPOSITORY_ROOT)

    def test_committed_artifacts_match_generation(self) -> None:
        check_candidate_interface_fit_evidence(REPOSITORY_ROOT)


if __name__ == "__main__":
    unittest.main()
