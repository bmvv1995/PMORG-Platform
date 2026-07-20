from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from typing import cast

from pmorg.application.source_scopes import canonical_document_bytes
from pmorg.application.source_scopes import check_source_scopes
from pmorg.application.source_scopes import derive_source_scope_outputs
from pmorg.application.source_scopes import SourceScopeError
from pmorg.application.source_scopes import write_source_scopes

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TestSourceScopes(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pmorg-source-scopes-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "pmorg@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "PMORG Test"],
            cwd=self.root,
            check=True,
        )
        fixtures = {
            "README.md": b"community\n",
            "backend/onyx/app.py": b"VALUE = 'ce'\n",
            "backend/ee/LICENSE": b"enterprise\n",
            "web/src/app/ee/page.tsx": b"export const ee = true;\n",
            "web/src/ee/tool.ts": b"export const tool = 'ee';\n",
        }
        for relative_path, payload in fixtures.items():
            path = self.root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "pinned Onyx fixture"],
            cwd=self.root,
            check=True,
        )
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self._copy_contract_inputs()
        self._write_baseline_and_policy()

    def _copy_contract_inputs(self) -> None:
        for relative_path in (
            "backend/pmorg/application/source_scopes.py",
            "backend/pmorg/contracts/manifest.json",
            "backend/pmorg/contracts/schemas/source-scope-manifest-v1.schema.json",
        ):
            source = REPOSITORY_ROOT / relative_path
            target = self.root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def _write_baseline_and_policy(self) -> None:
        enterprise_paths = [
            "backend/ee/**",
            "web/src/app/ee/**",
            "web/src/ee/**",
        ]
        baseline = {
            "upstream": {
                "repository": "https://github.com/onyx-dot-app/onyx.git",
                "commit": self.commit,
            },
            "licensing": {"enterprise_license_paths": enterprise_paths},
        }
        policy = {
            "schema_version": "pmorg.source-scope-derivation-policy/v1",
            "repository": "https://github.com/onyx-dot-app/onyx.git",
            "onyx_commit": self.commit,
            "enterprise_license_paths": enterprise_paths,
            "inventory_fields": [
                "path",
                "mode",
                "git_object_id",
                "sha256",
                "size_bytes",
            ],
            "scopes": {
                "onyx_ce": {
                    "roots": ["."],
                    "selection": "all_git_blobs_except_enterprise_license_paths",
                },
                "onyx_ee": {
                    "roots": ["backend/ee", "web/src/app/ee", "web/src/ee"],
                    "selection": "enterprise_license_paths_only",
                },
            },
        }
        for relative_path, value in (
            ("pmorg/baseline-manifest.json", baseline),
            ("pmorg/capabilities/source-scope-policy.json", policy),
        ):
            path = self.root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(canonical_document_bytes(value))

    def _read_policy(self) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            json.loads(
                (self.root / "pmorg/capabilities/source-scope-policy.json").read_bytes()
            ),
        )

    def _write_policy(self, policy: dict[str, Any]) -> None:
        (self.root / "pmorg/capabilities/source-scope-policy.json").write_bytes(
            canonical_document_bytes(policy)
        )

    def test_derivation_is_complete_disjoint_and_deterministic(self) -> None:
        first = derive_source_scope_outputs(self.root)
        second = derive_source_scope_outputs(self.root)

        self.assertEqual(first, second)
        ce = json.loads(first.inventories["onyx_ce"])
        ee = json.loads(first.inventories["onyx_ee"])
        evidence = json.loads(first.evidence)
        self.assertEqual(ce["path_count"], 2)
        self.assertEqual(ee["path_count"], 3)
        self.assertEqual(evidence["expected_path_count"], 5)
        self.assertEqual(evidence["scanned_path_count"], 5)
        self.assertEqual(evidence["classified_path_count"], 5)
        self.assertEqual(evidence["unclassified_path_count"], 0)
        self.assertEqual(evidence["overlap_path_count"], 0)
        self.assertEqual(
            [entry["path"] for entry in ee["entries"]],
            [
                "backend/ee/LICENSE",
                "web/src/app/ee/page.tsx",
                "web/src/ee/tool.ts",
            ],
        )

    def test_write_and_check_bind_every_committed_byte(self) -> None:
        write_source_scopes(self.root)
        check_source_scopes(self.root)

        inventory_path = (
            self.root
            / "pmorg/capabilities/source-scopes/onyx-ce-path-inventory-v1.json"
        )
        value = json.loads(inventory_path.read_bytes())
        value["entries"][0]["size_bytes"] += 1
        inventory_path.write_bytes(canonical_document_bytes(value))
        with self.assertRaisesRegex(SourceScopeError, "artifact drifted"):
            check_source_scopes(self.root)

    def test_policy_must_match_exact_baseline_pins_and_license_roots(self) -> None:
        policy = self._read_policy()
        policy["onyx_commit"] = "0" * 40
        self._write_policy(policy)
        with self.assertRaisesRegex(SourceScopeError, "commit pin drifted"):
            derive_source_scope_outputs(self.root)

        self._write_baseline_and_policy()
        policy = self._read_policy()
        policy["enterprise_license_paths"] = ["backend/ee/**"]
        self._write_policy(policy)
        with self.assertRaisesRegex(SourceScopeError, "license paths drifted"):
            derive_source_scope_outputs(self.root)

    def test_policy_rejects_unknown_keys_and_partial_scope_rules(self) -> None:
        policy = self._read_policy()
        policy["unexpected"] = True
        self._write_policy(policy)
        with self.assertRaisesRegex(SourceScopeError, "keys are not exact"):
            derive_source_scope_outputs(self.root)

        self._write_baseline_and_policy()
        policy = self._read_policy()
        del cast(dict[str, Any], policy["scopes"])["onyx_ee"]
        self._write_policy(policy)
        with self.assertRaisesRegex(SourceScopeError, "exact CE and EE"):
            derive_source_scope_outputs(self.root)

    def test_contract_schema_drift_fails_closed(self) -> None:
        write_source_scopes(self.root)
        schema_path = (
            self.root
            / "backend/pmorg/contracts/schemas/source-scope-manifest-v1.schema.json"
        )
        schema = json.loads(schema_path.read_bytes())
        schema["title"] = "TamperedSourceScope"
        schema_path.write_bytes(canonical_document_bytes(schema))
        with self.assertRaisesRegex(SourceScopeError, "schema digest drifted"):
            check_source_scopes(self.root)


if __name__ == "__main__":
    unittest.main()
