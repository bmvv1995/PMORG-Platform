from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pmorg.application.capability_disposition_interface_fit_executor import (
    execute_capability_disposition_interface_fit,
)
from pmorg.application.capability_disposition_interface_fit_executor import TEST_IDS
from pmorg.application.capability_disposition_qualification_candidate_qualification_reports import (
    build_capability_disposition_qualification_candidate_qualification_outputs,
)
from pmorg.application.capability_disposition_qualification_candidate_qualification_reports import (
    CapabilityDispositionQualificationCandidateQualificationReportError,
)
from pmorg.application.capability_disposition_qualification_candidate_qualification_reports import (
    check_capability_disposition_qualification_candidate_qualification_reports,
)
from pmorg.application.capability_disposition_qualification_candidate_qualification_reports import (
    INDEX_RELATIVE,
)
from pmorg.application.capability_disposition_qualification_candidate_qualification_reports import (
    index_schema,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class CapabilityDispositionQualificationCandidateQualificationReportTests(
    unittest.TestCase
):
    def test_committed_index_is_closed_complete_and_schema_valid(self) -> None:
        check_capability_disposition_qualification_candidate_qualification_reports(
            REPOSITORY_ROOT
        )
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        Draft202012Validator(index_schema()).validate(index)
        self.assertEqual(48, index["report_count"])
        self.assertEqual(5015, index["projected_blob_membership_count"])
        self.assertEqual(240, index["executed_test_count"])
        self.assertEqual(240, index["failed_test_count"])
        self.assertEqual(0, index["passed_test_count"])
        self.assertEqual(0, index["missing_test_count"])
        self.assertEqual(0, index["duplicate_test_count"])
        self.assertEqual(
            [
                "backend/pmorg/application/qualification.py",
                "backend/pmorg/application/qualification_oracles.py",
            ],
            [
                reference["relative_path"]
                for reference in index["reference_implementations"]
            ],
        )
        self.assertEqual(
            "pmorg/capabilities/"
            "capability-disposition-qualification-interface-fit-evidence-v1.json",
            index["q7a_screening_evidence"]["relative_path"],
        )
        self.assertEqual(
            "candidate_qualification_only_no_disposition_or_aggregate_verdict",
            index["claim_boundary"],
        )

    def test_every_candidate_has_five_bound_results_and_one_report(self) -> None:
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        identities = [entry["candidate_id"] for entry in index["entries"]]
        self.assertEqual(identities, sorted(set(identities)))
        self.assertEqual(48, len(identities))
        for entry in index["entries"]:
            report = json.loads(
                (REPOSITORY_ROOT / entry["report"]["relative_path"]).read_bytes()
            )
            self.assertEqual(5, report["executed_test_count"])
            self.assertEqual(5, len(entry["results"]))
            self.assertEqual(
                list(TEST_IDS), [item["test_id"] for item in report["test_evidence"]]
            )
            self.assertEqual(
                entry["results"],
                [item["result"] for item in report["test_evidence"]],
            )
            verdicts = [item["verdict"] for item in report["test_evidence"]]
            self.assertEqual(
                "pass" if all(verdict == "pass" for verdict in verdicts) else "fail",
                entry["verdict"],
            )

    def test_live_executor_remains_candidate_sensitive(self) -> None:
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        for test_id in TEST_IDS:
            result = execute_capability_disposition_interface_fit(
                index["entries"][0]["candidate_id"],
                test_id,
                repository_root=REPOSITORY_ROOT,
            )
            self.assertEqual(
                result["projected_blob_count"], result["observed_blob_count"]
            )
            self.assertEqual(0, result["unobserved_blob_count"])
            self.assertNotEqual(
                result["baseline_observation_digest"],
                result["mutation_observation_digest"],
            )
            self.assertTrue(result["positive_injection_fit"])

    def test_complete_execution_is_deterministic_within_one_runtime(self) -> None:
        first = (
            build_capability_disposition_qualification_candidate_qualification_outputs(
                REPOSITORY_ROOT
            )
        )
        second = (
            build_capability_disposition_qualification_candidate_qualification_outputs(
                REPOSITORY_ROOT
            )
        )
        self.assertEqual(first, second)
        self.assertEqual(290, len(first))

    def test_tampered_result_is_rejected(self) -> None:
        import shutil

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            root.mkdir()
            for relative in (
                "backend/pmorg",
                "pmorg/capabilities",
                "pmorg/scripts",
            ):
                shutil.copytree(REPOSITORY_ROOT / relative, root / relative)
            for relative in (".python-version", "pyproject.toml", "uv.lock"):
                shutil.copy2(REPOSITORY_ROOT / relative, root / relative)
            index = json.loads((root / INDEX_RELATIVE).read_bytes())
            result_path = root / index["entries"][0]["results"][0]["relative_path"]
            result = json.loads(result_path.read_bytes())
            result["candidate_manifest_digest"] = "sha256:" + "0" * 64
            result_path.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CapabilityDispositionQualificationCandidateQualificationReportError,
                "candidate result A-PATCH-002 digest drifted",
            ):
                check_capability_disposition_qualification_candidate_qualification_reports(
                    root
                )


if __name__ == "__main__":
    unittest.main()
