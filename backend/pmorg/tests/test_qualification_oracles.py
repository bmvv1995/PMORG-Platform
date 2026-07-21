from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pmorg.application.qualification_oracles import build_qualification_oracle_policy
from pmorg.application.qualification_oracles import canonical_document_bytes
from pmorg.application.qualification_oracles import check_qualification_oracles
from pmorg.application.qualification_oracles import QualificationOracleError
from pmorg.application.qualification_oracles import sha256_digest
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
            15,
        )
        for oracle in first["oracles"]:
            self.assertFalse(oracle["bindings"])
            self.assertIsNone(oracle["adapter"])
            self.assertEqual(oracle["candidate_influence_status"], "not_demonstrated")
            self.assertTrue(oracle["unexecutable_reason"])
        self.assertEqual(
            [item["relative_path"] for item in first["runtime_identity"]["artifacts"]],
            [".python-version", "pyproject.toml", "uv.lock"],
        )
        self.assertEqual(
            first["runtime_identity"]["status"],
            "declaration_bound_binary_unattested",
        )
        runtime_identity = dict(first["runtime_identity"])
        runtime_digest = runtime_identity.pop("digest")
        self.assertEqual(
            runtime_digest,
            sha256_digest(canonical_document_bytes(runtime_identity)),
        )
        self.assertEqual(
            [item["relative_path"] for item in first["derivation_artifacts"]],
            [
                "backend/pmorg/application/qualification_oracles.py",
                "pmorg/scripts/build_qualification_oracles.py",
            ],
        )
        self.assertEqual(
            first["candidate_projection"]["candidate_inputs"]["relative_path"],
            "pmorg/capabilities/candidate-inputs-v1.json",
        )
        self.assertEqual(
            first["candidate_influence_contract"][
                "global_gate_or_sidecar_only_evidence"
            ],
            "forbidden",
        )
        self.assertEqual(
            sum(
                oracle["candidate_test_vector"] is not None
                for oracle in first["oracles"]
            ),
            2,
        )

    def test_global_gates_are_preserved_but_never_candidate_executable(self) -> None:
        policy = build_qualification_oracle_policy(REPOSITORY_ROOT)
        legacy = {
            (item["capability_id"], item["test_id"]): item[
                "legacy_global_gate_bindings"
            ]
            for item in policy["oracles"]
        }
        self.assertEqual(sum(bool(bindings) for bindings in legacy.values()), 13)
        self.assertFalse(legacy[("deployment-admission", "A-LIC-002")])
        self.assertFalse(legacy[("distribution-admission", "A-LIC-003")])

    def test_unexecutable_or_status_forged_result_cannot_pass(self) -> None:
        policy = build_qualification_oracle_policy(REPOSITORY_ROOT)
        oracle = policy["oracles"][0]
        candidate_inputs = json.loads(
            (
                REPOSITORY_ROOT / "pmorg/capabilities/candidate-inputs-v1.json"
            ).read_bytes()
        )
        candidate = next(
            item
            for item in candidate_inputs["candidates"]
            if item["capability_id"] == oracle["capability_id"]
        )
        result = {
            "schema_version": "pmorg.qualification-oracle-result/v1",
            "capability_id": oracle["capability_id"],
            "test_id": oracle["test_id"],
            "candidate_id": candidate["candidate_id"],
            "oracle_id": oracle["oracle_id"],
            "oracle_status": "unexecutable",
            "candidate_manifest_digest": candidate["manifest_digest"],
            "adapter_digest": None,
            "runtime_identity_digest": None,
            "mutation_baseline_digest": None,
            "mutation_result_digest": None,
            "projected_blob_count": 1,
            "observed_blob_count": 1,
            "unobserved_blob_count": 0,
            "execution_exit_codes": [],
            "bindings": [],
            "failure_reasons": [],
            "verdict": "fail",
        }
        validate_qualification_oracle_result(result, repository_root=REPOSITORY_ROOT)

        manifest_drift = dict(result)
        manifest_drift["candidate_manifest_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            QualificationOracleError, "candidate manifest drifted"
        ):
            validate_qualification_oracle_result(
                manifest_drift, repository_root=REPOSITORY_ROOT
            )

        unknown_candidate = dict(result)
        unknown_candidate["candidate_id"] = "candidate-" + "0" * 64
        with self.assertRaisesRegex(QualificationOracleError, "unknown candidate"):
            validate_qualification_oracle_result(
                unknown_candidate, repository_root=REPOSITORY_ROOT
            )

        fabricated_pass = dict(result)
        fabricated_pass["verdict"] = "pass"
        with self.assertRaisesRegex(
            QualificationOracleError, "unexecutable oracle cannot pass"
        ):
            validate_qualification_oracle_result(
                fabricated_pass, repository_root=REPOSITORY_ROOT
            )

        forged = dict(result)
        forged["oracle_status"] = "executable"
        forged["verdict"] = "fail"
        with self.assertRaisesRegex(
            QualificationOracleError, "status drifted from policy"
        ):
            validate_qualification_oracle_result(
                forged, repository_root=REPOSITORY_ROOT
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
            "pmorg/capabilities/qualification-interface-v1.schema.json",
            "pmorg/capabilities/qualification-interfaces-v1.json",
            "pmorg/capabilities/qualification-interfaces/capability-disposition-qualification-v1.json",
            "pmorg/capabilities/qualification-interfaces/deployment-admission-v1.json",
            "pmorg/capabilities/qualification-interfaces/distribution-admission-v1.json",
            "pmorg/capabilities/qualification-interfaces/governed-onyx-fork-v1.json",
            "pmorg/capabilities/qualification-interfaces/qualified-reproducible-build-v1.json",
            "pmorg/capabilities/qualification-interfaces/thin-fork-boundary-v1.json",
            "pmorg/capabilities/qualification-test-vector-v1.schema.json",
            "pmorg/capabilities/qualification-test-vectors-v1.json",
            "pmorg/capabilities/qualification-test-vectors/deployment-admission-A-LIC-002-v1.json",
            "pmorg/capabilities/qualification-test-vectors/distribution-admission-A-LIC-003-v1.json",
        ):
            source = REPOSITORY_ROOT / relative_path
            target = root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        check_qualification_oracles(root)

        policy_path = root / "pmorg/capabilities/qualification-oracle-policy-v1.json"
        policy = json.loads(policy_path.read_bytes())
        policy["oracles"][0]["legacy_global_gate_bindings"][0]["digest"] = (
            "sha256:" + "0" * 64
        )
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

        shutil.copy2(
            REPOSITORY_ROOT / "pmorg/scripts/build_capability_catalog.py",
            binding_path,
        )
        lock_path = root / "uv.lock"
        lock_path.write_bytes(lock_path.read_bytes() + b"# drift\n")
        with self.assertRaisesRegex(QualificationOracleError, "artifact drifted"):
            check_qualification_oracles(root)

        shutil.copy2(REPOSITORY_ROOT / "uv.lock", lock_path)
        candidate_inputs_path = root / "pmorg/capabilities/candidate-inputs-v1.json"
        candidate_inputs_path.write_bytes(candidate_inputs_path.read_bytes() + b" \n")
        with self.assertRaisesRegex(QualificationOracleError, "artifact drifted"):
            check_qualification_oracles(root)


if __name__ == "__main__":
    unittest.main()
