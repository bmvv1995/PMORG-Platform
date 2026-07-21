from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from pmorg.application.admission_interface_fit_executor import (
    execute_admission_interface_fit,
)
from pmorg.application.candidate_qualification_reports import (
    build_candidate_qualification_report_outputs,
)
from pmorg.application.candidate_qualification_reports import (
    CandidateQualificationReportError,
)
from pmorg.application.candidate_qualification_reports import (
    check_candidate_qualification_reports,
)
from pmorg.application.candidate_qualification_reports import INDEX_RELATIVE
from pmorg.application.candidate_qualification_reports import index_schema
from pmorg.application.candidate_qualification_reports import REPORT_ROOT_RELATIVE
from pmorg.application.candidate_qualification_reports import RESULT_ROOT_RELATIVE

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class CandidateQualificationReportTests(unittest.TestCase):
    def test_committed_index_is_closed_and_schema_valid(self) -> None:
        check_candidate_qualification_reports(REPOSITORY_ROOT)
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        Draft202012Validator(index_schema()).validate(index)
        self.assertEqual(186, index["report_count"])
        self.assertEqual(186, index["executed_test_count"])
        self.assertEqual(0, index["missing_test_count"])
        self.assertEqual(0, index["duplicate_test_count"])
        self.assertEqual(
            {"deployment-admission": 82, "distribution-admission": 104},
            index["capability_report_counts"],
        )
        self.assertEqual(
            "candidate_qualification_only_no_disposition_or_admission",
            index["claim_boundary"],
        )

    def test_every_entry_has_one_result_and_one_contract_report(self) -> None:
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        identities = [
            (entry["capability_id"], entry["candidate_id"])
            for entry in index["entries"]
        ]
        self.assertEqual(identities, sorted(set(identities)))
        self.assertEqual(186, len(identities))
        for entry in index["entries"]:
            self.assertTrue(
                entry["result"]["relative_path"].startswith(RESULT_ROOT_RELATIVE + "/")
            )
            self.assertTrue(
                entry["report"]["relative_path"].startswith(REPORT_ROOT_RELATIVE + "/")
            )
            report = json.loads(
                (REPOSITORY_ROOT / entry["report"]["relative_path"]).read_bytes()
            )
            self.assertEqual(1, report["expected_test_count"])
            self.assertEqual(1, report["executed_test_count"])
            self.assertEqual(0, report["missing_test_count"])
            self.assertEqual(0, report["duplicate_test_count"])
            self.assertEqual(1, len(report["test_evidence"]))
            self.assertEqual(entry["result"], report["test_evidence"][0]["result"])

    def test_live_executor_remains_candidate_sensitive_for_both_capabilities(
        self,
    ) -> None:
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        for capability_id in (
            "deployment-admission",
            "distribution-admission",
        ):
            candidate_id = next(
                entry["candidate_id"]
                for entry in index["entries"]
                if entry["capability_id"] == capability_id
            )
            result = execute_admission_interface_fit(
                capability_id,
                candidate_id,
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
        first = build_candidate_qualification_report_outputs(REPOSITORY_ROOT)
        second = build_candidate_qualification_report_outputs(REPOSITORY_ROOT)
        self.assertEqual(first, second)
        self.assertEqual(374, len(first))

    def test_missing_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            with patch(
                "pmorg.application.candidate_qualification_reports.REPOSITORY_ROOT",
                REPOSITORY_ROOT,
            ):
                self._copy_evidence_tree(root)
            index = json.loads((root / INDEX_RELATIVE).read_bytes())
            (root / index["entries"][0]["result"]["relative_path"]).unlink()
            with self.assertRaisesRegex(
                CandidateQualificationReportError, "result is missing"
            ):
                check_candidate_qualification_reports(root)

    def test_tampered_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            self._copy_evidence_tree(root)
            index = json.loads((root / INDEX_RELATIVE).read_bytes())
            result_path = root / index["entries"][0]["result"]["relative_path"]
            result = json.loads(result_path.read_bytes())
            result["candidate_manifest_digest"] = "sha256:" + "0" * 64
            result_path.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                CandidateQualificationReportError, "result digest drifted"
            ):
                check_candidate_qualification_reports(root)

    @staticmethod
    def _copy_evidence_tree(target: Path) -> None:
        import shutil

        target.mkdir(parents=True)
        for relative in (
            "backend/pmorg/application",
            "backend/pmorg/contracts/schemas",
            "pmorg/capabilities",
            "pmorg/scripts",
        ):
            source = REPOSITORY_ROOT / relative
            destination = target / relative
            shutil.copytree(source, destination)
        for relative in (".python-version", "pyproject.toml", "uv.lock"):
            shutil.copy2(REPOSITORY_ROOT / relative, target / relative)


if __name__ == "__main__":
    unittest.main()
