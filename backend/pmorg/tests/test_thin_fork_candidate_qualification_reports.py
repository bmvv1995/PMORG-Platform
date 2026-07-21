from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pmorg.application.thin_fork_candidate_qualification_reports import (
    build_thin_fork_candidate_qualification_outputs,
)
from pmorg.application.thin_fork_candidate_qualification_reports import (
    check_thin_fork_candidate_qualification_reports,
)
from pmorg.application.thin_fork_candidate_qualification_reports import INDEX_RELATIVE
from pmorg.application.thin_fork_candidate_qualification_reports import index_schema
from pmorg.application.thin_fork_candidate_qualification_reports import (
    ThinForkCandidateQualificationReportError,
)
from pmorg.application.thin_fork_interface_fit_executor import (
    execute_thin_fork_interface_fit,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class ThinForkCandidateQualificationReportTests(unittest.TestCase):
    def test_committed_index_is_closed_complete_and_schema_valid(self) -> None:
        check_thin_fork_candidate_qualification_reports(REPOSITORY_ROOT)
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        Draft202012Validator(index_schema()).validate(index)
        self.assertEqual(55, index["report_count"])
        self.assertEqual(55, index["executed_test_count"])
        self.assertEqual(0, index["missing_test_count"])
        self.assertEqual(0, index["duplicate_test_count"])
        self.assertEqual(
            "thin_fork_candidate_qualification_only_no_disposition",
            index["claim_boundary"],
        )

    def test_every_candidate_has_one_bound_result_and_report(self) -> None:
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        identities = [entry["candidate_id"] for entry in index["entries"]]
        self.assertEqual(identities, sorted(set(identities)))
        for entry in index["entries"]:
            result = json.loads(
                (REPOSITORY_ROOT / entry["result"]["relative_path"]).read_bytes()
            )
            report = json.loads(
                (REPOSITORY_ROOT / entry["report"]["relative_path"]).read_bytes()
            )
            self.assertEqual(1, report["executed_test_count"])
            self.assertEqual(entry["result"], report["test_evidence"][0]["result"])
            self.assertEqual(entry["verdict"], result["verdict"])

    def test_live_executor_remains_candidate_sensitive(self) -> None:
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        result = execute_thin_fork_interface_fit(
            index["entries"][0]["candidate_id"], repository_root=REPOSITORY_ROOT
        )
        self.assertEqual(result["projected_blob_count"], result["observed_blob_count"])
        self.assertEqual(0, result["unobserved_blob_count"])
        self.assertNotEqual(
            result["baseline_observation_digest"],
            result["mutation_observation_digest"],
        )
        self.assertTrue(result["positive_injection_fit"])

    def test_complete_execution_is_deterministic_within_one_runtime(self) -> None:
        first = build_thin_fork_candidate_qualification_outputs(REPOSITORY_ROOT)
        second = build_thin_fork_candidate_qualification_outputs(REPOSITORY_ROOT)
        self.assertEqual(first, second)
        self.assertEqual(112, len(first))

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
            result_path = root / index["entries"][0]["result"]["relative_path"]
            result = json.loads(result_path.read_bytes())
            result["candidate_manifest_digest"] = "sha256:" + "0" * 64
            result_path.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ThinForkCandidateQualificationReportError, "result digest drifted"
            ):
                check_thin_fork_candidate_qualification_reports(root)


if __name__ == "__main__":
    unittest.main()
