from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pmorg.application.post_disposition_qualification import CAPABILITY_SPECS
from pmorg.application.post_disposition_qualification import CATALOG_RELATIVE
from pmorg.application.post_disposition_qualification import DERIVATION_RELATIVES
from pmorg.application.post_disposition_qualification import execute_live_suites
from pmorg.application.post_disposition_qualification import INDEX_RELATIVE
from pmorg.application.post_disposition_qualification import INDEX_SCHEMA_RELATIVE
from pmorg.application.post_disposition_qualification import MANIFEST_ROOT_RELATIVE
from pmorg.application.post_disposition_qualification import MANIFEST_SCHEMA_RELATIVE
from pmorg.application.post_disposition_qualification import PATCH_LEDGER_RELATIVE
from pmorg.application.post_disposition_qualification import (
    PostDispositionQualificationError,
)
from pmorg.application.post_disposition_qualification import REPORT_ROOT_RELATIVE
from pmorg.application.post_disposition_qualification import REPORT_SCHEMA_RELATIVE
from pmorg.application.post_disposition_qualification import REPOSITORY_ROOT
from pmorg.application.post_disposition_qualification import RESULT_ROOT_RELATIVE
from pmorg.application.post_disposition_qualification import RESULT_SCHEMA_RELATIVE
from pmorg.application.post_disposition_qualification import (
    validate_post_disposition_qualification,
)


class TestPostDispositionQualification(unittest.TestCase):
    def test_committed_evidence_graph_is_closed_and_valid(self) -> None:
        index = validate_post_disposition_qualification(REPOSITORY_ROOT)
        self.assertEqual(index["capability_count"], 2)
        self.assertEqual(index["expected_test_count"], 10)
        self.assertEqual(index["executed_test_count"], 10)
        self.assertEqual(index["failed_test_count"], 0)
        self.assertEqual(
            index["claim_boundary"],
            "post_disposition_qualification_only_no_disposition_record",
        )

    def test_both_admission_suites_pass_live_as_ten_isolated_tests(self) -> None:
        results = execute_live_suites()
        self.assertEqual(
            {capability: len(items) for capability, items in results.items()},
            {"deployment-admission": 5, "distribution-admission": 5},
        )
        for items in results.values():
            self.assertTrue(all(item["tests_run"] == 1 for item in items))
            self.assertTrue(all(item["verdict"] == "pass" for item in items))

    def test_missing_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            self._copy_evidence(root)
            index = json.loads((root / INDEX_RELATIVE).read_bytes())
            result_path = index["entries"][0]["results"][0]["relative_path"]
            (root / result_path).unlink()
            with self.assertRaises(PostDispositionQualificationError):
                validate_post_disposition_qualification(root)

    def test_tampered_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            self._copy_evidence(root)
            index = json.loads((root / INDEX_RELATIVE).read_bytes())
            result_path = root / index["entries"][0]["results"][0]["relative_path"]
            value = json.loads(result_path.read_bytes())
            value["verdict"] = "fail"
            result_path.write_text(json.dumps(value, sort_keys=True) + "\n")
            with self.assertRaises(PostDispositionQualificationError):
                validate_post_disposition_qualification(root)

    @staticmethod
    def _copy_evidence(root: Path) -> None:
        import shutil

        files = {
            CATALOG_RELATIVE,
            PATCH_LEDGER_RELATIVE,
            REPORT_SCHEMA_RELATIVE,
            INDEX_RELATIVE,
            INDEX_SCHEMA_RELATIVE,
            MANIFEST_SCHEMA_RELATIVE,
            RESULT_SCHEMA_RELATIVE,
            *DERIVATION_RELATIVES,
        }
        for spec in CAPABILITY_SPECS.values():
            files.update(spec["implementation_paths"])
            files.add(spec["test_file"])
        for relative_path in files:
            destination = root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPOSITORY_ROOT / relative_path, destination)
        for relative_root in (
            MANIFEST_ROOT_RELATIVE,
            RESULT_ROOT_RELATIVE,
            REPORT_ROOT_RELATIVE,
        ):
            shutil.copytree(REPOSITORY_ROOT / relative_root, root / relative_root)
        for relative_path in (".python-version", "pyproject.toml", "uv.lock"):
            shutil.copy2(REPOSITORY_ROOT / relative_path, root / relative_path)


if __name__ == "__main__":
    unittest.main()
