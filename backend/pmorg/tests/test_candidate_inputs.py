from __future__ import annotations

import copy
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pmorg.application.candidate_inputs import build_candidate_input_bundle
from pmorg.application.candidate_inputs import CandidateInputError
from pmorg.application.candidate_inputs import check_candidate_inputs
from pmorg.application.candidate_inputs import OUTPUT_RELATIVE
from pmorg.application.candidate_inputs import SCHEMA_RELATIVE
from pmorg.application.candidate_inputs import validate_candidate_input_bundle
from pmorg.application.qualification_oracles import canonical_document_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TestCandidateInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = build_candidate_input_bundle(REPOSITORY_ROOT)

    def test_exact_candidate_and_blob_coverage(self) -> None:
        self.assertEqual(self.bundle["candidate_count"], 402)
        self.assertEqual(self.bundle["candidate_blob_membership_count"], 30407)
        self.assertEqual(self.bundle["blob_set_count"], 119)
        self.assertEqual(self.bundle["blob_set_membership_count"], 5808)
        self.assertEqual(self.bundle["unique_blob_count"], 5573)
        blob_sets = {item["blob_set_digest"]: item for item in self.bundle["blob_sets"]}
        counts: dict[str, int] = {}
        for manifest in self.bundle["candidates"]:
            capability_id = manifest["capability_id"]
            counts[capability_id] = counts.get(capability_id, 0) + 1
            self.assertGreater(manifest["blob_count"], 0)
            self.assertGreater(len(manifest["matched_hit_ids"]), 0)
            blob_set = blob_sets[manifest["blob_set_digest"]]
            self.assertEqual(manifest["blob_count"], blob_set["blob_count"])
            self.assertTrue(
                all(
                    blob["path"] == manifest["candidate_group"]
                    or blob["path"].startswith(manifest["candidate_group"] + "/")
                    for blob in blob_set["blobs"]
                )
            )
        self.assertEqual(
            counts,
            {
                "capability-disposition-qualification": 48,
                "deployment-admission": 82,
                "distribution-admission": 104,
                "governed-onyx-fork": 67,
                "qualified-reproducible-build": 46,
                "thin-fork-boundary": 55,
            },
        )

    def test_every_candidate_manifest_is_independently_content_addressed(self) -> None:
        identities: set[tuple[str, str]] = set()
        for manifest in self.bundle["candidates"]:
            payload = {
                key: value
                for key, value in manifest.items()
                if key != "manifest_digest"
            }
            expected = (
                "sha256:"
                + hashlib.sha256(canonical_document_bytes(payload)).hexdigest()
            )
            self.assertEqual(manifest["manifest_digest"], expected)
            identity = (manifest["capability_id"], manifest["candidate_id"])
            self.assertNotIn(identity, identities)
            identities.add(identity)

    def test_validator_rejects_manifest_and_count_tampering(self) -> None:
        tampered = copy.deepcopy(self.bundle)
        tampered["candidates"][0]["blob_set_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(CandidateInputError, "manifest digest drifted"):
            validate_candidate_input_bundle(tampered)
        tampered = copy.deepcopy(self.bundle)
        tampered["unique_blob_count"] += 1
        with self.assertRaisesRegex(CandidateInputError, "unique blob count drifted"):
            validate_candidate_input_bundle(tampered)

    def test_generation_is_byte_identical(self) -> None:
        first = canonical_document_bytes(self.bundle)
        second = canonical_document_bytes(build_candidate_input_bundle(REPOSITORY_ROOT))
        self.assertEqual(first, second)

    def test_fresh_clone_checker_and_upstream_evidence_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "clone"
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--shared",
                    "--quiet",
                    str(REPOSITORY_ROOT),
                    str(clone),
                ],
                check=True,
            )
            for relative_path in (
                "backend/pmorg/application/candidate_inputs.py",
                "pmorg/scripts/build_candidate_inputs.py",
                OUTPUT_RELATIVE,
                SCHEMA_RELATIVE,
            ):
                target = clone / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPOSITORY_ROOT / relative_path, target)
            check_candidate_inputs(clone)

            output = clone / OUTPUT_RELATIVE
            original_output = output.read_bytes()
            output.write_bytes(original_output + b"\n")
            with self.assertRaisesRegex(
                CandidateInputError, "committed candidate input"
            ):
                check_candidate_inputs(clone)
            output.write_bytes(original_output)

            classification = next(
                (clone / "pmorg/capabilities/candidate-search").glob(
                    "*-hit-classification-v1.json"
                )
            )
            classification.write_bytes(classification.read_bytes() + b"\n")
            with self.assertRaisesRegex(CandidateInputError, "digest drifted"):
                check_candidate_inputs(clone)


if __name__ == "__main__":
    unittest.main()
