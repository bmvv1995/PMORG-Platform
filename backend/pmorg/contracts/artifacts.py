"""Generate and verify committed PMORG JSON Schemas, examples, and manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from pmorg.contracts import WIRE_SURFACE
from pmorg.contracts.examples import example_for_model
from pmorg.contracts.registry import CONTRACT_DEFINITIONS
from pmorg.contracts.registry import MANIFEST_VERSION
from pmorg.contracts.registry import REQUIRED_RELEASE_SCHEMA_VERSIONS
from pmorg.contracts.registry import SPECIFICATION_COMMIT
from pmorg.contracts.registry import SPECIFICATION_REPOSITORY

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"


class ContractDriftError(ValueError):
    """Raised when committed contract artifacts differ from generated truth."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes with a single trailing newline."""

    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _walk_schema(value: Any, path: str = "$") -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from _walk_schema(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_schema(child, f"{path}[{index}]")


def assert_closed_write_schema(schema: dict[str, Any]) -> None:
    """Require every object-shaped portion of a write schema to be closed."""

    violations = [
        path
        for path, node in _walk_schema(schema)
        if (node.get("type") == "object" or "properties" in node)
        and node.get("additionalProperties") is not False
    ]
    if violations:
        raise ContractDriftError(
            "write schema contains open object(s): " + ", ".join(violations)
        )


def _schema_for(definition: Any) -> dict[str, Any]:
    schema = definition.model.model_json_schema(
        mode="validation",
        ref_template="#/$defs/{model}",
    )
    schema["$id"] = f"urn:pmorg:contract:{definition.schema_version}"
    schema["$schema"] = JSON_SCHEMA_DIALECT
    schema["x-pmorg-schema-version"] = definition.schema_version
    schema["x-pmorg-wire-surface"] = WIRE_SURFACE
    if definition.write_schema:
        assert_closed_write_schema(schema)
    Draft202012Validator.check_schema(schema)
    return schema


def expected_artifacts() -> dict[str, bytes]:
    """Materialize the complete deterministic artifact set in memory."""

    artifacts: dict[str, bytes] = {}
    manifest_entries: list[dict[str, Any]] = []
    schema_versions = {item.schema_version for item in CONTRACT_DEFINITIONS}
    missing_release_types = REQUIRED_RELEASE_SCHEMA_VERSIONS - schema_versions
    if missing_release_types:
        raise ContractDriftError(
            "registry misses required release schemas: "
            + ", ".join(sorted(missing_release_types))
        )

    for definition in CONTRACT_DEFINITIONS:
        schema = _schema_for(definition)
        example = example_for_model(definition.model)
        schema_bytes = canonical_json_bytes(schema)
        example_bytes = canonical_json_bytes(example)
        definition.model.model_validate_json(example_bytes)
        Draft202012Validator(schema).validate(example)

        schema_path = f"schemas/{definition.stem}.schema.json"
        example_path = f"examples/{definition.stem}.json"
        artifacts[schema_path] = schema_bytes
        artifacts[example_path] = example_bytes
        manifest_entries.append(
            {
                "example_path": example_path,
                "model": definition.model.__name__,
                "schema_path": schema_path,
                "schema_sha256": _sha256(schema_bytes),
                "schema_version": definition.schema_version,
                "write_schema": definition.write_schema,
            }
        )

    manifest = {
        "contracts": manifest_entries,
        "contract_count": len(manifest_entries),
        "manifest_version": MANIFEST_VERSION,
        "specification": {
            "commit": SPECIFICATION_COMMIT,
            "repository": SPECIFICATION_REPOSITORY,
        },
        "wire_surface": WIRE_SURFACE,
    }
    artifacts["manifest.json"] = canonical_json_bytes(manifest)
    return artifacts


def write_artifacts(contract_root: Path) -> None:
    """Replace generated files with the deterministic registry projection."""

    expected = expected_artifacts()
    for directory in (contract_root / "schemas", contract_root / "examples"):
        directory.mkdir(parents=True, exist_ok=True)
        expected_names = {
            Path(relative_path).name
            for relative_path in expected
            if Path(relative_path).parent.name == directory.name
        }
        for path in directory.glob("*.json"):
            if path.name not in expected_names:
                path.unlink()
    for relative_path, contents in expected.items():
        path = contract_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)


def check_artifacts(contract_root: Path) -> None:
    """Fail closed for missing, changed, stale, or semantically invalid artifacts."""

    expected = expected_artifacts()
    actual_paths = {
        path.relative_to(contract_root).as_posix()
        for directory in (contract_root / "schemas", contract_root / "examples")
        if directory.is_dir()
        for path in directory.glob("*.json")
    }
    if (contract_root / "manifest.json").is_file():
        actual_paths.add("manifest.json")
    expected_paths = set(expected)
    problems: list[str] = []
    for missing_path in sorted(expected_paths - actual_paths):
        problems.append(f"missing generated artifact: {missing_path}")
    for stale_path in sorted(actual_paths - expected_paths):
        problems.append(f"stale generated artifact: {stale_path}")
    for relative_path in sorted(expected_paths & actual_paths):
        if (contract_root / relative_path).read_bytes() != expected[relative_path]:
            problems.append(f"generated artifact drift: {relative_path}")
    if problems:
        raise ContractDriftError("\n".join(problems))


def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="contract artifact root",
    )
    arguments = parser.parse_args()
    if arguments.write:
        write_artifacts(arguments.root)
    else:
        check_artifacts(arguments.root)


if __name__ == "__main__":
    _main()
