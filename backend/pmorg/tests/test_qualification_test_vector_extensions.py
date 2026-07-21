from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pmorg.application.qualification_test_vector_extensions import (
    build_qualification_test_vector_extension,
)
from pmorg.application.qualification_test_vector_extensions import (
    check_qualification_test_vector_extension,
)
from pmorg.application.qualification_test_vector_extensions import (
    QualificationTestVectorExtensionError,
)
from pmorg.application.qualification_test_vector_extensions import sha256_digest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TestQualificationTestVectorExtensions(unittest.TestCase):
    def test_extension_is_deterministic_schema_valid_and_unactivated(self) -> None:
        check_qualification_test_vector_extension(REPOSITORY_ROOT)
        first = build_qualification_test_vector_extension(REPOSITORY_ROOT)
        second = build_qualification_test_vector_extension(REPOSITORY_ROOT)
        self.assertEqual(first, second)

        vector_path = (
            "pmorg/capabilities/qualification-test-vector-extensions/"
            "thin-fork-boundary-A-PATCH-001-v1.json"
        )
        manifest_path = (
            "pmorg/capabilities/qualification-test-vector-extension-thin-fork-v1.json"
        )
        vector = json.loads(first[vector_path])
        manifest = json.loads(first[manifest_path])
        schema = json.loads(
            (REPOSITORY_ROOT / manifest["vector_schema"]["relative_path"]).read_bytes()
        )
        Draft202012Validator(schema).validate(vector)
        self.assertEqual(vector["capability_id"], "thin-fork-boundary")
        self.assertEqual(vector["test_id"], "A-PATCH-001")
        self.assertEqual(
            sum(case["mutation_required"] for case in vector["test_cases"]), 1
        )
        self.assertEqual(manifest["activation_status"], "definition_only_unactivated")
        self.assertEqual(
            manifest["immutable_predecessors"]["oracle_state"],
            {
                "adapter": None,
                "candidate_test_vector": None,
                "oracle_id": "qualification-oracle:thin-fork-boundary:A-PATCH-001:v1",
                "oracle_status": "unexecutable",
            },
        )
        self.assertEqual(
            manifest["vector"]["digest"], sha256_digest(first[vector_path])
        )

    def test_existing_policy_and_vector_manifest_remain_byte_immutable(self) -> None:
        outputs = build_qualification_test_vector_extension(REPOSITORY_ROOT)
        self.assertNotIn(
            "pmorg/capabilities/qualification-oracle-policy-v1.json", outputs
        )
        self.assertNotIn(
            "pmorg/capabilities/qualification-test-vectors-v1.json", outputs
        )
        policy = json.loads(
            (
                REPOSITORY_ROOT
                / "pmorg/capabilities/qualification-oracle-policy-v1.json"
            ).read_bytes()
        )
        oracle = next(
            item
            for item in policy["oracles"]
            if (item["capability_id"], item["test_id"])
            == ("thin-fork-boundary", "A-PATCH-001")
        )
        self.assertEqual(oracle["oracle_status"], "unexecutable")
        self.assertIsNone(oracle["candidate_test_vector"])
        self.assertIsNone(oracle["adapter"])

    def test_extension_and_predecessor_drift_fail_closed(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pmorg-vector-extension-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "repo"
        dependencies = [
            ".python-version",
            "pyproject.toml",
            "uv.lock",
            "backend/pmorg/application/qualification_test_vector_extensions.py",
            "pmorg/scripts/build_qualification_test_vector_extensions.py",
            "pmorg/scripts/verify_fork.py",
            "pmorg/capabilities/qualification-test-vector-v1.schema.json",
            "pmorg/capabilities/qualification-test-vectors-v1.json",
            "pmorg/capabilities/qualification-oracle-policy-v1.json",
            "pmorg/capabilities/qualification-interfaces/thin-fork-boundary-v1.json",
            "pmorg/capabilities/qualification-test-vector-extension-thin-fork-v1.json",
            "pmorg/capabilities/qualification-test-vector-extensions/thin-fork-boundary-A-PATCH-001-v1.json",
        ]
        for relative_path in dependencies:
            source = REPOSITORY_ROOT / relative_path
            target = root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        check_qualification_test_vector_extension(root)

        vector_path = (
            root
            / "pmorg/capabilities/qualification-test-vector-extensions/thin-fork-boundary-A-PATCH-001-v1.json"
        )
        vector_path.write_bytes(vector_path.read_bytes() + b" \n")
        with self.assertRaisesRegex(
            QualificationTestVectorExtensionError, "extension artifact drifted"
        ):
            check_qualification_test_vector_extension(root)

        shutil.copy2(
            REPOSITORY_ROOT
            / "pmorg/capabilities/qualification-test-vector-extensions/thin-fork-boundary-A-PATCH-001-v1.json",
            vector_path,
        )
        policy_path = root / "pmorg/capabilities/qualification-oracle-policy-v1.json"
        policy = json.loads(policy_path.read_bytes())
        oracle = next(
            item
            for item in policy["oracles"]
            if (item["capability_id"], item["test_id"])
            == ("thin-fork-boundary", "A-PATCH-001")
        )
        oracle["oracle_status"] = "executable"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaisesRegex(
            QualificationTestVectorExtensionError, "already activated"
        ):
            check_qualification_test_vector_extension(root)


if __name__ == "__main__":
    unittest.main()
