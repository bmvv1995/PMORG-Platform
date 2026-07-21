from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from pmorg.application.candidate_interface_fit_denominator import _read_blobs
from pmorg.application.candidate_interface_fit_denominator import (
    build_candidate_interface_fit_denominator_evidence,
)
from pmorg.application.candidate_interface_fit_denominator import (
    CandidateInterfaceFitDenominatorError,
)
from pmorg.application.candidate_interface_fit_denominator import (
    check_candidate_interface_fit_denominator_evidence,
)
from pmorg.application.candidate_interface_fit_denominator import evidence_schema

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class CandidateInterfaceFitDenominatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        outputs = build_candidate_interface_fit_denominator_evidence(REPOSITORY_ROOT)
        cls.payload = outputs[
            "pmorg/capabilities/candidate-interface-fit-denominator-evidence-v1.json"
        ]
        cls.document = json.loads(cls.payload)

    def test_evidence_is_deterministic_and_schema_valid(self) -> None:
        second = build_candidate_interface_fit_denominator_evidence(REPOSITORY_ROOT)
        self.assertEqual(
            self.payload,
            second[
                "pmorg/capabilities/"
                "candidate-interface-fit-denominator-evidence-v1.json"
            ],
        )
        Draft202012Validator(evidence_schema()).validate(self.document)

    def test_every_discovered_admission_candidate_is_screened(self) -> None:
        self.assertEqual(
            {"deployment-admission": 82, "distribution-admission": 104},
            self.document["capability_candidate_counts"],
        )
        self.assertEqual(186, self.document["candidate_count"])
        identities = [
            (candidate["capability_id"], candidate["candidate_group"])
            for candidate in self.document["candidates"]
        ]
        self.assertEqual(identities, sorted(set(identities)))

    def test_blob_sets_are_scanned_once_and_expand_exactly(self) -> None:
        scans = {
            scan["blob_set_digest"]: scan for scan in self.document["blob_set_scans"]
        }
        self.assertEqual(115, len(scans))
        self.assertEqual(5802, self.document["blob_set_membership_count"])
        self.assertEqual(10351, self.document["candidate_blob_membership_count"])
        for scan in scans.values():
            self.assertEqual(scan["coverage"]["expected"], scan["blob_count"])
            self.assertEqual(scan["coverage"]["scanned"], scan["blob_count"])
        for candidate in self.document["candidates"]:
            scan = scans[candidate["blob_set_digest"]]
            self.assertEqual(candidate["scan_digest"], scan["scan_digest"])

    def test_screen_never_becomes_qualification_or_disposition(self) -> None:
        self.assertFalse(self.document["oracle_activation"])
        self.assertEqual(
            "exhaustive_plausibility_screen_only_no_qualification_or_disposition",
            self.document["claim_boundary"],
        )
        for candidate in self.document["candidates"]:
            self.assertTrue(candidate["missing_probe_ids"])
            self.assertEqual(
                "no_direct_candidate_level_admission_surface_observed",
                candidate["plausibility_state"],
            )

    def test_blob_mutation_is_rejected_before_evidence(self) -> None:
        original = _read_blobs

        def mutated(root: Path, object_ids: list[str]) -> dict[str, bytes]:
            payloads = original(root, object_ids)
            first = object_ids[0]
            changed = copy.copy(payloads)
            changed[first] = payloads[first] + b"mutation"
            return changed

        with patch(
            "pmorg.application.candidate_interface_fit_denominator._read_blobs",
            side_effect=mutated,
        ):
            with self.assertRaisesRegex(
                CandidateInterfaceFitDenominatorError,
                "blob (digest|size) drifted",
            ):
                build_candidate_interface_fit_denominator_evidence(REPOSITORY_ROOT)

    def test_committed_artifacts_match_generation(self) -> None:
        check_candidate_interface_fit_denominator_evidence(REPOSITORY_ROOT)


if __name__ == "__main__":
    unittest.main()
