from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any
from typing import cast

from pmorg.application.capabilities import build_capability_catalog
from pmorg.application.capabilities import canonical_document_bytes
from pmorg.application.capabilities import CapabilityCatalogError
from pmorg.application.capabilities import check_capability_catalog
from pmorg.application.capabilities import expected_catalog_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TestCapabilityCatalog(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pmorg-capability-catalog-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative_path in (
            "pmorg/baseline-manifest.json",
            "backend/pmorg/contracts/manifest.json",
            "backend/pmorg/contracts/schemas/capability-catalog-v1.schema.json",
        ):
            source = REPOSITORY_ROOT / relative_path
            target = self.root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        shutil.copytree(
            REPOSITORY_ROOT / "pmorg" / "capabilities",
            self.root / "pmorg" / "capabilities",
        )

    def _read_policy(self) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            json.loads(
                (self.root / "pmorg/capabilities/catalog-policy.json").read_bytes()
            ),
        )

    def _write_policy(self, policy: dict[str, Any]) -> None:
        (self.root / "pmorg/capabilities/catalog-policy.json").write_bytes(
            canonical_document_bytes(policy)
        )

    def test_committed_catalog_is_deterministic_and_closed(self) -> None:
        check_capability_catalog(REPOSITORY_ROOT)
        first = expected_catalog_bytes(REPOSITORY_ROOT)
        second = expected_catalog_bytes(REPOSITORY_ROOT)
        catalog = build_capability_catalog(REPOSITORY_ROOT)

        self.assertEqual(first, second)
        self.assertEqual(catalog.catalog_version, "1.0.0")
        self.assertEqual(catalog.expected_requirement_count, 21)
        self.assertEqual(catalog.mapped_requirement_count, 21)
        self.assertEqual(catalog.item_count, 6)
        self.assertEqual(catalog.unmapped_requirement_count, 0)
        self.assertEqual(catalog.unknown_requirement_count, 0)
        self.assertEqual(catalog.duplicate_capability_id_count, 0)
        self.assertEqual(catalog.required_search_surfaces, ["ce", "ee"])

    def test_new_baseline_requirement_fails_as_unmapped(self) -> None:
        baseline_path = self.root / "pmorg/baseline-manifest.json"
        baseline = json.loads(baseline_path.read_bytes())
        baseline["round_3_contract"]["platform_requirements"].append("PLT-999")
        baseline_path.write_bytes(canonical_document_bytes(baseline))

        with self.assertRaisesRegex(CapabilityCatalogError, "unmapped=\\['PLT-999'\\]"):
            build_capability_catalog(self.root)

    def test_unknown_and_duplicate_mappings_fail_closed(self) -> None:
        original = self._read_policy()
        policy = copy.deepcopy(original)
        capabilities = cast(list[dict[str, Any]], policy["capabilities"])
        first = capabilities[0]
        requirements = cast(list[str], first["requirement_ids"])
        requirements[-1] = "A-UNKNOWN-999"
        self._write_policy(policy)
        manifest_path = self.root / str(first["test_manifest"])
        manifest = json.loads(manifest_path.read_bytes())
        manifest["requirement_ids"] = requirements
        manifest_path.write_bytes(canonical_document_bytes(manifest))

        with self.assertRaisesRegex(CapabilityCatalogError, "A-UNKNOWN-999"):
            build_capability_catalog(self.root)

        policy = copy.deepcopy(original)
        capabilities = cast(list[dict[str, Any]], policy["capabilities"])
        first = capabilities[0]
        requirements = cast(list[str], first["requirement_ids"])
        requirements.insert(0, "A-PATCH-001")
        self._write_policy(policy)
        manifest_path = self.root / str(first["test_manifest"])
        manifest = json.loads(manifest_path.read_bytes())
        manifest["requirement_ids"] = requirements
        manifest_path.write_bytes(canonical_document_bytes(manifest))

        with self.assertRaisesRegex(CapabilityCatalogError, "A-PATCH-001"):
            build_capability_catalog(self.root)

    def test_test_manifest_identity_and_path_escape_fail_closed(self) -> None:
        policy = self._read_policy()
        capabilities = cast(list[dict[str, Any]], policy["capabilities"])
        first = capabilities[0]
        manifest_path = self.root / str(first["test_manifest"])
        manifest = json.loads(manifest_path.read_bytes())
        manifest["capability_id"] = "wrong-capability"
        manifest_path.write_bytes(canonical_document_bytes(manifest))

        with self.assertRaisesRegex(CapabilityCatalogError, "does not bind"):
            build_capability_catalog(self.root)

        first["test_manifest"] = "../outside.json"
        self._write_policy(policy)
        with self.assertRaisesRegex(CapabilityCatalogError, "escapes repository root"):
            build_capability_catalog(self.root)

    def test_committed_catalog_drift_fails_closed(self) -> None:
        catalog_path = self.root / "pmorg/capabilities/capability-catalog-v1.json"
        catalog = json.loads(catalog_path.read_bytes())
        catalog["mapped_requirement_count"] = 20
        catalog_path.write_bytes(canonical_document_bytes(catalog))

        with self.assertRaisesRegex(CapabilityCatalogError, "catalog drifted"):
            check_capability_catalog(self.root)

    def test_contract_schema_digest_drift_fails_closed(self) -> None:
        schema_path = (
            self.root
            / "backend/pmorg/contracts/schemas/capability-catalog-v1.schema.json"
        )
        schema = json.loads(schema_path.read_bytes())
        schema["title"] = "TamperedCatalog"
        schema_path.write_bytes(canonical_document_bytes(schema))

        with self.assertRaisesRegex(CapabilityCatalogError, "schema digest drifted"):
            check_capability_catalog(self.root)


if __name__ == "__main__":
    unittest.main()
