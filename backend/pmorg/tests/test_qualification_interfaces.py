from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pmorg.application.qualification_interfaces import build_qualification_interfaces
from pmorg.application.qualification_interfaces import check_qualification_interfaces
from pmorg.application.qualification_interfaces import QualificationInterfaceError
from pmorg.application.qualification_interfaces import sha256_digest
from pmorg.application.qualification_oracles import build_qualification_oracle_policy

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TestQualificationInterfaces(unittest.TestCase):
    def test_interfaces_are_complete_schema_valid_and_content_addressed(self) -> None:
        check_qualification_interfaces(REPOSITORY_ROOT)
        first = build_qualification_interfaces(REPOSITORY_ROOT)
        second = build_qualification_interfaces(REPOSITORY_ROOT)
        self.assertEqual(first, second)

        manifest = json.loads(
            first["pmorg/capabilities/qualification-interfaces-v1.json"]
        )
        schema = json.loads(
            first["pmorg/capabilities/qualification-interface-v1.schema.json"]
        )
        self.assertEqual(manifest["interface_count"], 6)
        self.assertEqual(
            [item["capability_id"] for item in manifest["interfaces"]],
            [
                "capability-disposition-qualification",
                "deployment-admission",
                "distribution-admission",
                "governed-onyx-fork",
                "qualified-reproducible-build",
                "thin-fork-boundary",
            ],
        )
        for reference in manifest["interfaces"]:
            payload = first[reference["relative_path"]]
            self.assertEqual(reference["digest"], sha256_digest(payload))
            self.assertEqual(reference["size_bytes"], len(payload))
            document = json.loads(payload)
            Draft202012Validator(schema).validate(document)
            self.assertEqual(
                document["capability_id"],
                reference["capability_id"],
            )
            self.assertIn(
                "candidate byte mutation is observable through the adapter",
                document["invariants"],
            )
            contract = json.loads(
                (
                    REPOSITORY_ROOT
                    / document["contract_test_manifest"]["relative_path"]
                ).read_bytes()
            )
            self.assertEqual(
                [item["test_id"] for item in document["test_properties"]],
                contract["test_ids"],
            )

    def test_oracle_policy_binds_exact_interface_per_capability(self) -> None:
        policy = build_qualification_oracle_policy(REPOSITORY_ROOT)
        manifest_path = (
            REPOSITORY_ROOT
            / policy["qualification_interface_manifest"]["relative_path"]
        )
        self.assertEqual(
            policy["qualification_interface_manifest"]["digest"],
            sha256_digest(manifest_path.read_bytes()),
        )
        interfaces_by_capability = {
            item["capability_id"]: item
            for item in json.loads(manifest_path.read_bytes())["interfaces"]
        }
        executable_pairs = {
            ("deployment-admission", "A-LIC-002"),
            ("distribution-admission", "A-LIC-003"),
        }
        for oracle in policy["oracles"]:
            expected = interfaces_by_capability[oracle["capability_id"]]
            self.assertEqual(
                oracle["qualification_interface"]["digest"],
                expected["digest"],
            )
            pair = (oracle["capability_id"], oracle["test_id"])
            expected_status = (
                "executable" if pair in executable_pairs else "unexecutable"
            )
            self.assertEqual(oracle["oracle_status"], expected_status)
            if pair in executable_pairs:
                self.assertIsNotNone(oracle["adapter"])
            else:
                self.assertIsNone(oracle["adapter"])

    def test_interface_artifact_and_reference_drift_fail_closed(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pmorg-interfaces-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "repo"
        subprocess.run(
            ["git", "clone", "-q", "--shared", str(REPOSITORY_ROOT), str(root)],
            check=True,
        )
        generated = build_qualification_interfaces(REPOSITORY_ROOT)
        paths = [
            "backend/pmorg/application/qualification_interfaces.py",
            "backend/pmorg/application/qualification_oracles.py",
            "pmorg/scripts/build_qualification_interfaces.py",
            *generated,
        ]
        for relative_path in paths:
            source = REPOSITORY_ROOT / relative_path
            target = root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        check_qualification_interfaces(root)

        interface_path = (
            root
            / "pmorg/capabilities/qualification-interfaces/deployment-admission-v1.json"
        )
        interface_path.write_bytes(interface_path.read_bytes() + b" \n")
        with self.assertRaisesRegex(
            QualificationInterfaceError,
            "interface artifact drifted",
        ):
            check_qualification_interfaces(root)

        shutil.copy2(
            REPOSITORY_ROOT
            / "pmorg/capabilities/qualification-interfaces/deployment-admission-v1.json",
            interface_path,
        )
        implementation_path = root / "backend/pmorg/application/admission.py"
        implementation_path.write_bytes(implementation_path.read_bytes() + b"# drift\n")
        with self.assertRaisesRegex(
            QualificationInterfaceError,
            "interface artifact drifted",
        ):
            check_qualification_interfaces(root)


if __name__ == "__main__":
    unittest.main()
