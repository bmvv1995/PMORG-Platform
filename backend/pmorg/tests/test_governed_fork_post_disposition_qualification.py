from __future__ import annotations

import json
import subprocess
import sys
import unittest

from jsonschema import Draft202012Validator

from pmorg.application.governed_fork_post_disposition_qualification import (
    BASE_PLATFORM_COMMIT,
)
from pmorg.application.governed_fork_post_disposition_qualification import (
    check_governed_fork_post_disposition_qualification,
)
from pmorg.application.governed_fork_post_disposition_qualification import (
    INDEX_RELATIVE,
)
from pmorg.application.governed_fork_post_disposition_qualification import index_schema
from pmorg.application.governed_fork_post_disposition_qualification import (
    MANIFEST_RELATIVE,
)
from pmorg.application.governed_fork_post_disposition_qualification import (
    REPORT_RELATIVE,
)
from pmorg.application.governed_fork_post_disposition_qualification import (
    REPOSITORY_ROOT,
)
from pmorg.application.governed_fork_post_disposition_qualification import (
    RUNNER_RELATIVE,
)
from pmorg.application.governed_fork_post_disposition_qualification import TEST_COUNT
from pmorg.application.governed_fork_post_disposition_qualification import (
    VERIFY_FORK_RELATIVE,
)
from pmorg.application.governed_fork_post_disposition_qualification import (
    VERIFY_FORK_TEST_RELATIVE,
)
from pmorg.contracts.types import PostDispositionQualificationReport


class GovernedForkPostDispositionQualificationTests(unittest.TestCase):
    def test_committed_evidence_graph_is_closed_and_valid(self) -> None:
        check_governed_fork_post_disposition_qualification(REPOSITORY_ROOT)
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        Draft202012Validator(index_schema()).validate(index)
        self.assertEqual(TEST_COUNT, index["expected_test_count"])
        self.assertEqual(TEST_COUNT, index["executed_test_count"])
        self.assertEqual(0, index["failed_test_count"])
        self.assertEqual(0, index["missing_test_count"])
        self.assertEqual(0, index["duplicate_test_count"])
        self.assertEqual(
            "governed_fork_post_disposition_qualification_only_no_disposition",
            index["claim_boundary"],
        )
        report = json.loads((REPOSITORY_ROOT / REPORT_RELATIVE).read_bytes())
        self.assertEqual("governed-onyx-fork", report["capability_id"])

    def test_manifest_projects_exact_bounded_suite_and_trust_paths(self) -> None:
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        manifest = json.loads((REPOSITORY_ROOT / MANIFEST_RELATIVE).read_bytes())
        completed = subprocess.run(
            [sys.executable, "-B", RUNNER_RELATIVE, "--list"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        identities = json.loads(completed.stdout)
        self.assertEqual(TEST_COUNT, len(identities))
        self.assertEqual(
            identities,
            [item["fully_qualified_name"] for item in manifest["test_cases"]],
        )
        self.assertEqual(
            [VERIFY_FORK_RELATIVE],
            [item["relative_path"] for item in manifest["implementation_bindings"]],
        )
        self.assertEqual(BASE_PLATFORM_COMMIT, index["pmorg_platform_commit"])

    def test_trust_boundary_files_are_byte_identical_to_base(self) -> None:
        for relative_path in (VERIFY_FORK_RELATIVE, VERIFY_FORK_TEST_RELATIVE):
            base_payload = subprocess.run(
                ["git", "show", f"{BASE_PLATFORM_COMMIT}:{relative_path}"],
                cwd=REPOSITORY_ROOT,
                check=True,
                capture_output=True,
            ).stdout
            self.assertEqual(
                base_payload,
                (REPOSITORY_ROOT / relative_path).read_bytes(),
                relative_path,
            )

    def test_report_contains_exactly_87_executed_pass_results(self) -> None:
        report = json.loads((REPOSITORY_ROOT / REPORT_RELATIVE).read_bytes())
        validated = PostDispositionQualificationReport.model_validate(report)
        self.assertEqual(TEST_COUNT, validated.expected_test_count)
        self.assertEqual(TEST_COUNT, validated.executed_test_count)
        self.assertEqual(0, validated.failed_test_count)
        self.assertEqual(TEST_COUNT, len(validated.test_evidence))
        self.assertTrue(all(item.verdict == "pass" for item in validated.test_evidence))

    def test_suite_receipt_binds_the_exact_pr_base(self) -> None:
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        receipt_path = index["suite_receipt"]["relative_path"]
        receipt = json.loads((REPOSITORY_ROOT / receipt_path).read_bytes())
        self.assertEqual(BASE_PLATFORM_COMMIT, receipt["pmorg_platform_commit"])


if __name__ == "__main__":
    unittest.main()
