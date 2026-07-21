from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pmorg.application.qualification_oracles import build_qualification_oracle_policy
from pmorg.application.qualification_test_vectors import (
    build_qualification_test_vectors,
)
from pmorg.application.qualification_test_vectors import canonical_document_bytes
from pmorg.application.qualification_test_vectors import (
    check_qualification_test_vectors,
)
from pmorg.application.qualification_test_vectors import QualificationTestVectorError
from pmorg.application.qualification_test_vectors import sha256_digest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TestQualificationTestVectors(unittest.TestCase):
    def test_vectors_are_complete_schema_valid_and_candidate_aware(self) -> None:
        check_qualification_test_vectors(REPOSITORY_ROOT)
        first = build_qualification_test_vectors(REPOSITORY_ROOT)
        second = build_qualification_test_vectors(REPOSITORY_ROOT)
        self.assertEqual(first, second)

        manifest = json.loads(
            first["pmorg/capabilities/qualification-test-vectors-v1.json"]
        )
        schema = json.loads(
            first["pmorg/capabilities/qualification-test-vector-v1.schema.json"]
        )
        self.assertEqual(manifest["vector_count"], 2)
        self.assertEqual(
            [(item["capability_id"], item["test_id"]) for item in manifest["vectors"]],
            [
                ("deployment-admission", "A-LIC-002"),
                ("distribution-admission", "A-LIC-003"),
            ],
        )
        self.assertEqual(
            manifest["runtime_identity_contract_digest"],
            sha256_digest(
                canonical_document_bytes(manifest["runtime_identity_contract"])
            ),
        )
        self.assertEqual(
            [
                item["relative_path"]
                for item in manifest["runtime_identity_contract"]["artifacts"]
            ],
            [".python-version", "pyproject.toml", "uv.lock"],
        )

        for reference in manifest["vectors"]:
            payload = first[reference["relative_path"]]
            self.assertEqual(reference["digest"], sha256_digest(payload))
            self.assertEqual(reference["size_bytes"], len(payload))
            document = json.loads(payload)
            Draft202012Validator(schema).validate(document)
            self.assertEqual(
                document["runtime_identity"]["contract_digest"],
                manifest["runtime_identity_contract_digest"],
            )
            self.assertTrue(
                all(case["candidate_bytes_required"] for case in document["test_cases"])
            )
            self.assertEqual(
                sum(case["mutation_required"] for case in document["test_cases"]),
                1,
            )
            self.assertEqual(
                document["mutation_probe"]["expectation"],
                "at_least_one_observation_or_verdict_changes",
            )
            interface_path = (
                REPOSITORY_ROOT / document["qualification_interface"]["relative_path"]
            )
            self.assertEqual(
                document["qualification_interface"]["digest"],
                sha256_digest(interface_path.read_bytes()),
            )

    def test_policy_binds_only_admission_vectors_and_exact_executors(self) -> None:
        policy = build_qualification_oracle_policy(REPOSITORY_ROOT)
        vector_manifest_path = (
            REPOSITORY_ROOT
            / policy["qualification_test_vector_manifest"]["relative_path"]
        )
        self.assertEqual(
            policy["qualification_test_vector_manifest"]["digest"],
            sha256_digest(vector_manifest_path.read_bytes()),
        )
        vector_pairs = {
            (item["capability_id"], item["test_id"]): item
            for item in json.loads(vector_manifest_path.read_bytes())["vectors"]
        }
        bound = {
            (oracle["capability_id"], oracle["test_id"]): oracle[
                "candidate_test_vector"
            ]
            for oracle in policy["oracles"]
            if oracle["candidate_test_vector"] is not None
        }
        self.assertEqual(set(bound), set(vector_pairs))
        for pair, reference in bound.items():
            self.assertEqual(reference["digest"], vector_pairs[pair]["digest"])
        executable = [
            oracle
            for oracle in policy["oracles"]
            if oracle["oracle_status"] == "executable"
        ]
        self.assertEqual(
            {(item["capability_id"], item["test_id"]) for item in executable},
            set(vector_pairs),
        )
        self.assertTrue(all(item["adapter"] is not None for item in executable))
        self.assertTrue(
            all(
                item["adapter"] is None
                for item in policy["oracles"]
                if item["oracle_status"] == "unexecutable"
            )
        )

    def test_vector_and_runtime_artifact_drift_fail_closed(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pmorg-vectors-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "repo"
        subprocess.run(
            ["git", "clone", "-q", "--shared", str(REPOSITORY_ROOT), str(root)],
            check=True,
        )
        generated = build_qualification_test_vectors(REPOSITORY_ROOT)
        paths = [
            "backend/pmorg/application/qualification_test_vectors.py",
            "pmorg/scripts/build_qualification_test_vectors.py",
            *generated,
        ]
        for relative_path in paths:
            source = REPOSITORY_ROOT / relative_path
            target = root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        check_qualification_test_vectors(root)

        vector_path = (
            root
            / "pmorg/capabilities/qualification-test-vectors/deployment-admission-A-LIC-002-v1.json"
        )
        vector_path.write_bytes(vector_path.read_bytes() + b" \n")
        with self.assertRaisesRegex(
            QualificationTestVectorError,
            "test-vector artifact drifted",
        ):
            check_qualification_test_vectors(root)

        shutil.copy2(
            REPOSITORY_ROOT
            / "pmorg/capabilities/qualification-test-vectors/deployment-admission-A-LIC-002-v1.json",
            vector_path,
        )
        lock_path = root / "uv.lock"
        lock_path.write_bytes(lock_path.read_bytes() + b"# runtime drift\n")
        with self.assertRaisesRegex(
            QualificationTestVectorError,
            "test-vector artifact drifted",
        ):
            check_qualification_test_vectors(root)


if __name__ == "__main__":
    unittest.main()
