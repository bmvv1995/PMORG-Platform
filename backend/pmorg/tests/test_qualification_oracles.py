from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pmorg.application.qualification_oracles import build_qualification_oracle_policy
from pmorg.application.qualification_oracles import check_qualification_oracles
from pmorg.application.qualification_oracles import QualificationOracleError
from pmorg.application.qualification_oracles import validate_qualification_oracle_result

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TestQualificationOracles(unittest.TestCase):
    def test_policy_is_closed_content_addressed_and_deterministic(self) -> None:
        check_qualification_oracles(REPOSITORY_ROOT)
        first = build_qualification_oracle_policy(REPOSITORY_ROOT)
        second = build_qualification_oracle_policy(REPOSITORY_ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first["oracle_count"], 15)
        self.assertEqual(first["candidate_projection"]["candidate_count"], 402)
        self.assertEqual(
            [item["oracle_status"] for item in first["oracles"]].count("unexecutable"),
            2,
        )
        for oracle in first["oracles"]:
            if oracle["oracle_status"] == "executable":
                self.assertTrue(oracle["bindings"])
                self.assertIsNone(oracle["unexecutable_reason"])
            else:
                self.assertFalse(oracle["bindings"])
                self.assertTrue(oracle["unexecutable_reason"])

    def test_admission_oracles_are_explicitly_unexecutable(self) -> None:
        policy = build_qualification_oracle_policy(REPOSITORY_ROOT)
        unexecutable = {
            (item["capability_id"], item["test_id"])
            for item in policy["oracles"]
            if item["oracle_status"] == "unexecutable"
        }
        self.assertEqual(
            unexecutable,
            {
                ("deployment-admission", "A-LIC-002"),
                ("distribution-admission", "A-LIC-003"),
            },
        )

    def test_unexecutable_or_incompletely_observed_result_cannot_pass(self) -> None:
        policy = build_qualification_oracle_policy(REPOSITORY_ROOT)
        oracle = next(
            item
            for item in policy["oracles"]
            if item["oracle_status"] == "unexecutable"
        )
        result = {
            "schema_version": "pmorg.qualification-oracle-result/v1",
            "capability_id": oracle["capability_id"],
            "test_id": oracle["test_id"],
            "candidate_id": "candidate-" + "0" * 64,
            "oracle_id": oracle["oracle_id"],
            "oracle_status": "unexecutable",
            "projected_blob_count": 1,
            "observed_blob_count": 1,
            "unobserved_blob_count": 0,
            "execution_exit_codes": [],
            "bindings": [],
            "failure_reasons": [],
            "verdict": "pass",
        }
        with self.assertRaisesRegex(
            QualificationOracleError, "unexecutable oracle cannot pass"
        ):
            validate_qualification_oracle_result(
                result, repository_root=REPOSITORY_ROOT
            )

        executable = next(
            item for item in policy["oracles"] if item["oracle_status"] == "executable"
        )
        incomplete = copy.deepcopy(result)
        incomplete.update(
            {
                "capability_id": executable["capability_id"],
                "test_id": executable["test_id"],
                "oracle_id": executable["oracle_id"],
                "oracle_status": "executable",
                "projected_blob_count": 2,
                "observed_blob_count": 1,
                "unobserved_blob_count": 1,
                "execution_exit_codes": [0],
                "bindings": [
                    {
                        "digest": executable["bindings"][0]["digest"],
                        "relative_path": executable["bindings"][0]["relative_path"],
                    }
                ],
            }
        )
        with self.assertRaisesRegex(
            QualificationOracleError, "PASS is not evidence-complete"
        ):
            validate_qualification_oracle_result(
                incomplete, repository_root=REPOSITORY_ROOT
            )

    def test_binding_and_committed_output_drift_fail_closed(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pmorg-oracles-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "repo"
        subprocess.run(
            ["git", "clone", "-q", "--shared", str(REPOSITORY_ROOT), str(root)],
            check=True,
        )
        for relative_path in (
            "backend/pmorg/application/qualification_oracles.py",
            "pmorg/capabilities/qualification-oracle-policy-v1.json",
            "pmorg/capabilities/qualification-oracle-result-v1.schema.json",
        ):
            source = REPOSITORY_ROOT / relative_path
            target = root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        check_qualification_oracles(root)

        policy_path = root / "pmorg/capabilities/qualification-oracle-policy-v1.json"
        policy = json.loads(policy_path.read_bytes())
        policy["oracles"][0]["bindings"][0]["digest"] = "sha256:" + "0" * 64
        policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(QualificationOracleError, "artifact drifted"):
            check_qualification_oracles(root)

        shutil.copy2(
            REPOSITORY_ROOT / "pmorg/capabilities/qualification-oracle-policy-v1.json",
            policy_path,
        )
        binding_path = root / "pmorg/scripts/build_capability_catalog.py"
        binding_path.write_text("# binding drift\n", encoding="utf-8")
        with self.assertRaisesRegex(QualificationOracleError, "artifact drifted"):
            check_qualification_oracles(root)


if __name__ == "__main__":
    unittest.main()
