from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from pmorg.application.thin_fork_interface_fit import _read_blobs
from pmorg.application.thin_fork_interface_fit import (
    build_thin_fork_interface_fit_evidence,
)
from pmorg.application.thin_fork_interface_fit import (
    check_thin_fork_interface_fit_evidence,
)
from pmorg.application.thin_fork_interface_fit import evidence_schema
from pmorg.application.thin_fork_interface_fit import ThinForkInterfaceFitError

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class ThinForkInterfaceFitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        outputs = build_thin_fork_interface_fit_evidence(REPOSITORY_ROOT)
        cls.payload = outputs[
            "pmorg/capabilities/thin-fork-interface-fit-evidence-v1.json"
        ]
        cls.document = json.loads(cls.payload)

    def test_evidence_is_deterministic_and_schema_valid(self) -> None:
        second = build_thin_fork_interface_fit_evidence(REPOSITORY_ROOT)
        self.assertEqual(
            self.payload,
            second["pmorg/capabilities/thin-fork-interface-fit-evidence-v1.json"],
        )
        Draft202012Validator(evidence_schema()).validate(self.document)

    def test_every_discovered_thin_fork_candidate_is_screened(self) -> None:
        self.assertEqual(55, self.document["candidate_count"])
        identities = [
            (candidate["candidate_group"], candidate["candidate_id"])
            for candidate in self.document["candidates"]
        ]
        self.assertEqual(identities, sorted(set(identities)))

    def test_every_projected_blob_membership_is_verified(self) -> None:
        self.assertEqual(55, self.document["blob_set_scan_count"])
        self.assertEqual(5155, self.document["blob_set_membership_count"])
        self.assertEqual(
            {"expected": 5155, "scanned": 5155, "unreadable": 0, "unverified": 0},
            self.document["coverage"],
        )
        scans = {
            scan["blob_set_digest"]: scan for scan in self.document["blob_set_scans"]
        }
        self.assertEqual(55, len(scans))
        for candidate in self.document["candidates"]:
            scan = scans[candidate["blob_set_digest"]]
            self.assertEqual(candidate["scan_digest"], scan["scan_digest"])
            self.assertEqual(candidate["blob_count"], scan["blob_count"])

    def test_screen_preserves_unexecutable_oracle_and_claim_boundary(self) -> None:
        self.assertEqual(
            {
                "adapter": None,
                "candidate_test_vector": None,
                "oracle_status": "unexecutable",
            },
            self.document["active_oracle_state"],
        )
        self.assertFalse(self.document["oracle_activation"])
        self.assertEqual(
            "exhaustive_plausibility_screen_only_no_qualification_or_disposition",
            self.document["claim_boundary"],
        )
        for candidate in self.document["candidates"]:
            self.assertIn("no_fit_inference", candidate["plausibility_state"])

    def test_blob_mutation_is_rejected_before_evidence(self) -> None:
        original = _read_blobs

        def mutated(root: Path, object_ids: list[str]) -> dict[str, bytes]:
            payloads = original(root, object_ids)
            first = object_ids[0]
            changed = copy.copy(payloads)
            changed[first] = payloads[first] + b"mutation"
            return changed

        with patch(
            "pmorg.application.thin_fork_interface_fit._read_blobs",
            side_effect=mutated,
        ):
            with self.assertRaisesRegex(
                ThinForkInterfaceFitError,
                "blob (digest|size) drifted",
            ):
                build_thin_fork_interface_fit_evidence(REPOSITORY_ROOT)

    def test_committed_artifacts_match_generation(self) -> None:
        check_thin_fork_interface_fit_evidence(REPOSITORY_ROOT)


if __name__ == "__main__":
    unittest.main()
