"""Drift, closure, and reproducibility guards for pmorg-contracts/1.0."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from pmorg.contracts import WIRE_SURFACE
from pmorg.contracts.artifacts import assert_closed_write_schema
from pmorg.contracts.artifacts import check_artifacts
from pmorg.contracts.artifacts import ContractDriftError
from pmorg.contracts.artifacts import write_artifacts
from pmorg.contracts.registry import CONTRACT_DEFINITIONS
from pmorg.contracts.registry import REQUIRED_RELEASE_SCHEMA_VERSIONS
from pmorg.contracts.registry import SPECIFICATION_COMMIT

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_ROOT = REPOSITORY_ROOT / "backend" / "pmorg" / "contracts"
BASELINE_MANIFEST = REPOSITORY_ROOT / "pmorg" / "baseline-manifest.json"


def _artifact_snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*.json"))
    }


class ContractArtifactTests(unittest.TestCase):
    def test_registry_covers_every_normative_release_schema(self) -> None:
        baseline = json.loads(BASELINE_MANIFEST.read_text(encoding="utf-8"))
        required = frozenset(baseline["round_3_contract"]["required_schema_versions"])
        self.assertEqual(required, REQUIRED_RELEASE_SCHEMA_VERSIONS)
        registered = {item.schema_version for item in CONTRACT_DEFINITIONS}
        self.assertTrue(required <= registered)

    def test_committed_projection_matches_models(self) -> None:
        check_artifacts(CONTRACT_ROOT)

    def test_generation_is_byte_identical_across_independent_runs(self) -> None:
        with (
            tempfile.TemporaryDirectory() as first_dir,
            tempfile.TemporaryDirectory() as second_dir,
        ):
            first = Path(first_dir)
            second = Path(second_dir)
            write_artifacts(first)
            write_artifacts(second)
            self.assertEqual(_artifact_snapshot(first), _artifact_snapshot(second))

    def test_every_write_schema_is_closed_recursively(self) -> None:
        for definition in CONTRACT_DEFINITIONS:
            with self.subTest(schema_version=definition.schema_version):
                schema_path = (
                    CONTRACT_ROOT / "schemas" / f"{definition.stem}.schema.json"
                )
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                assert_closed_write_schema(schema)

    def test_every_example_validates_against_model_and_schema(self) -> None:
        for definition in CONTRACT_DEFINITIONS:
            with self.subTest(schema_version=definition.schema_version):
                example_path = CONTRACT_ROOT / "examples" / f"{definition.stem}.json"
                schema_path = (
                    CONTRACT_ROOT / "schemas" / f"{definition.stem}.schema.json"
                )
                example_bytes = example_path.read_bytes()
                example = json.loads(example_bytes)
                definition.model.model_validate_json(example_bytes)
                Draft202012Validator(json.loads(schema_path.read_bytes())).validate(
                    example
                )

    def test_unknown_write_fields_fail_closed_in_models_and_schemas(self) -> None:
        for definition in CONTRACT_DEFINITIONS:
            with self.subTest(schema_version=definition.schema_version):
                example_path = CONTRACT_ROOT / "examples" / f"{definition.stem}.json"
                schema_path = (
                    CONTRACT_ROOT / "schemas" / f"{definition.stem}.schema.json"
                )
                example = json.loads(example_path.read_bytes())
                example["unexpected_field"] = "forbidden"
                with self.assertRaises(PydanticValidationError):
                    definition.model.model_validate(example)
                with self.assertRaises(JsonSchemaValidationError):
                    Draft202012Validator(json.loads(schema_path.read_bytes())).validate(
                        example
                    )

    def test_deliberate_schema_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            write_artifacts(root)
            target = root / "schemas" / f"{CONTRACT_DEFINITIONS[0].stem}.schema.json"
            schema = json.loads(target.read_bytes())
            schema["properties"].pop(next(iter(schema["properties"])))
            target.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaisesRegex(ContractDriftError, "generated artifact drift"):
                check_artifacts(root)

    def test_manifest_digests_bind_exact_schema_bytes(self) -> None:
        manifest = json.loads((CONTRACT_ROOT / "manifest.json").read_bytes())
        self.assertEqual(manifest["wire_surface"], WIRE_SURFACE)
        self.assertEqual(manifest["specification"]["commit"], SPECIFICATION_COMMIT)
        self.assertEqual(manifest["contract_count"], len(CONTRACT_DEFINITIONS))
        for entry in manifest["contracts"]:
            with self.subTest(schema_version=entry["schema_version"]):
                schema_bytes = (CONTRACT_ROOT / entry["schema_path"]).read_bytes()
                self.assertEqual(
                    entry["schema_sha256"],
                    "sha256:" + hashlib.sha256(schema_bytes).hexdigest(),
                )

    def test_stale_generated_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            write_artifacts(root)
            stale = root / "schemas" / "stale.schema.json"
            shutil.copyfile(next((root / "schemas").glob("*.json")), stale)
            with self.assertRaisesRegex(ContractDriftError, "stale generated artifact"):
                check_artifacts(root)


if __name__ == "__main__":
    unittest.main()
