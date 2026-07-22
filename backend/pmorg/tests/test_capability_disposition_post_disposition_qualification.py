from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from shutil import copytree

from jsonschema import Draft202012Validator

from pmorg.application.capability_disposition_post_disposition_qualification import (
    BASE_PLATFORM_COMMIT,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    CapabilityDispositionPostDispositionQualificationError,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    check_capability_disposition_post_disposition_qualification,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    INDEX_RELATIVE,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    index_schema,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    MANIFEST_RELATIVE,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    PATCH_LEDGER_RELATIVE,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    Q7D_EVIDENCE_COMMIT,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    QUALIFICATION_ORACLES_RELATIVE,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    QUALIFICATION_RELATIVE,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    REPORT_RELATIVE,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    REPOSITORY_ROOT,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    RUNNER_RELATIVE,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    TEST_COUNT,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (
    TEST_MODULE_RELATIVES,
)
from pmorg.contracts.types import PostDispositionQualificationReport


def _copy_repository(temporary_directory: str) -> Path:
    destination = Path(temporary_directory) / "repository"
    copytree(REPOSITORY_ROOT, destination, symlinks=True)
    return destination


class CapabilityDispositionPostDispositionQualificationTests(unittest.TestCase):
    def _require_evidence_commit(self) -> None:
        if Q7D_EVIDENCE_COMMIT is None:
            self.skipTest("bootstrap evidence commit has not been anchored yet")

    def test_committed_evidence_graph_is_closed_and_valid(self) -> None:
        check_capability_disposition_post_disposition_qualification(REPOSITORY_ROOT)
        index = json.loads((REPOSITORY_ROOT / INDEX_RELATIVE).read_bytes())
        Draft202012Validator(index_schema()).validate(index)
        self.assertEqual(TEST_COUNT, index["expected_test_count"])
        self.assertEqual(TEST_COUNT, index["executed_test_count"])
        self.assertEqual(0, index["failed_test_count"])
        self.assertEqual(0, index["missing_test_count"])
        self.assertEqual(0, index["duplicate_test_count"])
        self.assertEqual(
            (
                "capability_disposition_post_disposition_qualification_only_"
                "no_disposition_or_aggregate_verdict"
            ),
            index["claim_boundary"],
        )
        report = json.loads((REPOSITORY_ROOT / REPORT_RELATIVE).read_bytes())
        self.assertEqual(
            "capability-disposition-qualification", report["capability_id"]
        )

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
            [QUALIFICATION_RELATIVE, QUALIFICATION_ORACLES_RELATIVE],
            [item["relative_path"] for item in manifest["implementation_bindings"]],
        )
        self.assertEqual(
            list(TEST_MODULE_RELATIVES),
            [item["relative_path"] for item in manifest["test_module_bindings"]],
        )
        self.assertEqual(BASE_PLATFORM_COMMIT, index["pmorg_platform_commit"])

    def test_trust_boundary_files_are_byte_identical_to_base(self) -> None:
        for relative_path in (
            QUALIFICATION_RELATIVE,
            QUALIFICATION_ORACLES_RELATIVE,
            *TEST_MODULE_RELATIVES,
        ):
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

    def test_report_contains_exactly_12_executed_pass_results(self) -> None:
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

    def test_benign_successor_and_unique_ledger_append_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = _copy_repository(temporary_directory)
            unrelated = copied / "backend/pmorg/domain/__init__.py"
            unrelated.write_bytes(unrelated.read_bytes() + b"\n# benign successor\n")
            ledger_path = copied / PATCH_LEDGER_RELATIVE
            ledger = json.loads(ledger_path.read_bytes())
            next_number = (
                max(int(item["id"].removeprefix("PL-")) for item in ledger["entries"])
                + 1
            )
            appended = copy.deepcopy(ledger["entries"][-1])
            appended["id"] = f"PL-{next_number:03d}"
            appended["paths"] = ["backend/pmorg/application/future_q7_slice.py"]
            appended["reason"] = "Benign successor-safety simulation."
            ledger["entries"].append(appended)
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            check_capability_disposition_post_disposition_qualification(copied)

    def test_archival_evidence_tamper_fails_closed(self) -> None:
        self._require_evidence_commit()
        cases = (
            "pmorg/capabilities/capability-disposition-post-disposition-suite-receipt-v1.json",
            REPORT_RELATIVE,
            "pmorg/scripts/build_capability_disposition_post_disposition_qualification.py",
        )
        for relative_path in cases:
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    copied = _copy_repository(temporary_directory)
                    path = copied / relative_path
                    path.write_bytes(path.read_bytes() + b"\n")
                    with self.assertRaisesRegex(
                        CapabilityDispositionPostDispositionQualificationError,
                        "archival evidence drifted",
                    ):
                        check_capability_disposition_post_disposition_qualification(
                            copied
                        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = _copy_repository(temporary_directory)
            index = json.loads((copied / INDEX_RELATIVE).read_bytes())
            result_path = copied / index["results"][0]["relative_path"]
            result_path.write_bytes(result_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                CapabilityDispositionPostDispositionQualificationError,
                "archival evidence drifted",
            ):
                check_capability_disposition_post_disposition_qualification(copied)

    def test_static_trust_file_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = _copy_repository(temporary_directory)
            path = copied / QUALIFICATION_RELATIVE
            path.write_bytes(path.read_bytes() + b"\n# tamper\n")
            with self.assertRaisesRegex(
                CapabilityDispositionPostDispositionQualificationError,
                "trusted Capability Disposition path changed",
            ):
                check_capability_disposition_post_disposition_qualification(copied)

    def test_q7_predecessor_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied = _copy_repository(temporary_directory)
            path = (
                copied / "pmorg/capabilities/"
                "capability-disposition-qualification-candidate-qualification-reports-v1.json"
            )
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                CapabilityDispositionPostDispositionQualificationError,
                "Q7d predecessor drifted",
            ):
                check_capability_disposition_post_disposition_qualification(copied)

    def test_patch_ledger_history_and_pins_fail_closed(self) -> None:
        mutations = ("entry", "delete", "reorder", "pin", "duplicate")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    copied = _copy_repository(temporary_directory)
                    ledger_path = copied / PATCH_LEDGER_RELATIVE
                    ledger = json.loads(ledger_path.read_bytes())
                    if mutation == "entry":
                        ledger["entries"][0]["reason"] += " tampered"
                    elif mutation == "delete":
                        ledger["entries"].pop(0)
                    elif mutation == "reorder":
                        ledger["entries"][0], ledger["entries"][1] = (
                            ledger["entries"][1],
                            ledger["entries"][0],
                        )
                    elif mutation == "pin":
                        ledger["specification_commit"] = "0" * 40
                    else:
                        ledger["entries"].append(copy.deepcopy(ledger["entries"][-1]))
                    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
                    with self.assertRaisesRegex(
                        CapabilityDispositionPostDispositionQualificationError,
                        "patch ledger",
                    ):
                        check_capability_disposition_post_disposition_qualification(
                            copied
                        )


if __name__ == "__main__":
    unittest.main()
