"""Build and verify the closed PMORG release capability catalog."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from pmorg.contracts.types import CapabilityCatalog
from pmorg.contracts.types import CapabilityCatalogItem
from pmorg.contracts.types import EvidenceArtifactRef
from pmorg.contracts.types import OnyxSurface

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
POLICY_PATH = REPOSITORY_ROOT / "pmorg" / "capabilities" / "catalog-policy.json"
CATALOG_PATH = REPOSITORY_ROOT / "pmorg" / "capabilities" / "capability-catalog-v1.json"
CONTRACT_ROOT = REPOSITORY_ROOT / "backend" / "pmorg" / "contracts"
CATALOG_SCHEMA_VERSION = "pmorg.capability-catalog/v1"

_POLICY_KEYS = {
    "schema_version",
    "catalog_version",
    "pmorg_spec_commit",
    "applicable_requirement_selectors",
    "required_search_surfaces",
    "capabilities",
}
_CAPABILITY_KEYS = {"capability_id", "requirement_ids", "test_manifest"}
_TEST_MANIFEST_KEYS = {
    "schema_version",
    "capability_id",
    "requirement_ids",
    "test_ids",
}
_REQUIREMENT_SELECTORS = (
    "round_3_contract.platform_requirements",
    "round_3_contract.acceptance_controls",
)


class CapabilityCatalogError(ValueError):
    """Raised when catalog inputs or committed output are not closed and exact."""


def canonical_document_bytes(value: Any) -> bytes:
    """Encode a stable, human-reviewable JSON document."""

    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_digest(payload: bytes) -> str:
    """Return the canonical PMORG SHA-256 spelling."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CapabilityCatalogError(f"JSON repeats key: {key}")
        value[key] = item
    return value


def _read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CapabilityCatalogError(
            f"{label} is not readable canonical JSON"
        ) from error
    if not isinstance(value, dict):
        raise CapabilityCatalogError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], *, label: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise CapabilityCatalogError(
            f"{label} keys are not exact; missing={missing}, unknown={unknown}"
        )


def _require_string_list(value: Any, *, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise CapabilityCatalogError(f"{label} must be a non-empty string array")
    return cast(list[str], value)


def _safe_path(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise CapabilityCatalogError(
            f"evidence path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _evidence_ref(
    repository_root: Path, relative_path: str, *, logical_name: str
) -> EvidenceArtifactRef:
    path = _safe_path(repository_root, relative_path)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise CapabilityCatalogError(
            f"catalog evidence is missing: {relative_path}"
        ) from error
    return EvidenceArtifactRef(
        logical_name=logical_name,
        media_type="application/json",
        digest=sha256_digest(payload),
        size_bytes=len(payload),
        relative_path=relative_path,
    )


def _baseline_requirement_ids(baseline: Mapping[str, Any]) -> list[str]:
    try:
        contract = baseline["round_3_contract"]
        platform = _require_string_list(
            contract["platform_requirements"],
            label="baseline platform requirements",
        )
        controls = _require_string_list(
            contract["acceptance_controls"],
            label="baseline acceptance controls",
        )
    except (KeyError, TypeError) as error:
        raise CapabilityCatalogError(
            "baseline does not expose the fixed release requirement set"
        ) from error
    requirement_ids = [*platform, *controls]
    if len(requirement_ids) != len(set(requirement_ids)):
        raise CapabilityCatalogError("baseline requirement set contains duplicates")
    return sorted(requirement_ids)


def _validate_test_manifest(
    repository_root: Path,
    relative_path: str,
    *,
    capability_id: str,
    requirement_ids: list[str],
) -> EvidenceArtifactRef:
    manifest = _read_object(
        _safe_path(repository_root, relative_path),
        label=f"contract test manifest for {capability_id}",
    )
    _require_exact_keys(
        manifest,
        _TEST_MANIFEST_KEYS,
        label=f"contract test manifest for {capability_id}",
    )
    if manifest["schema_version"] != "pmorg.capability-contract-tests/v1":
        raise CapabilityCatalogError(
            f"contract test manifest for {capability_id} has the wrong schema"
        )
    if manifest["capability_id"] != capability_id:
        raise CapabilityCatalogError(
            f"contract test manifest does not bind {capability_id}"
        )
    manifest_requirements = _require_string_list(
        manifest["requirement_ids"],
        label=f"requirement IDs for {capability_id}",
    )
    test_ids = _require_string_list(
        manifest["test_ids"], label=f"test IDs for {capability_id}"
    )
    if manifest_requirements != requirement_ids:
        raise CapabilityCatalogError(
            f"contract test requirements drifted for {capability_id}"
        )
    if manifest_requirements != sorted(set(manifest_requirements)):
        raise CapabilityCatalogError(
            f"contract test requirements are not unique and ordered for {capability_id}"
        )
    if test_ids != sorted(set(test_ids)):
        raise CapabilityCatalogError(
            f"contract test IDs are not unique and ordered for {capability_id}"
        )
    return _evidence_ref(
        repository_root,
        relative_path,
        logical_name=f"{capability_id}-contract-tests",
    )


def build_capability_catalog(
    repository_root: Path = REPOSITORY_ROOT,
) -> CapabilityCatalog:
    """Derive a closed catalog from the fixed baseline and reviewable policy."""

    repository_root = repository_root.resolve()
    policy_relative = "pmorg/capabilities/catalog-policy.json"
    baseline_relative = "pmorg/baseline-manifest.json"
    policy = _read_object(
        _safe_path(repository_root, policy_relative), label="capability catalog policy"
    )
    baseline = _read_object(
        _safe_path(repository_root, baseline_relative), label="PMORG baseline manifest"
    )
    _require_exact_keys(policy, _POLICY_KEYS, label="capability catalog policy")
    if policy["schema_version"] != "pmorg.capability-catalog-policy/v1":
        raise CapabilityCatalogError("capability catalog policy has the wrong schema")
    selectors = _require_string_list(
        policy["applicable_requirement_selectors"],
        label="applicable requirement selectors",
    )
    if tuple(selectors) != _REQUIREMENT_SELECTORS:
        raise CapabilityCatalogError(
            "capability catalog policy must select the exact baseline requirement sets"
        )
    try:
        baseline_spec_commit = baseline["specification"]["commit"]
    except (KeyError, TypeError) as error:
        raise CapabilityCatalogError("baseline specification pin is absent") from error
    if policy["pmorg_spec_commit"] != baseline_spec_commit:
        raise CapabilityCatalogError("catalog policy specification pin drifted")
    required_surfaces = _require_string_list(
        policy["required_search_surfaces"], label="required search surfaces"
    )
    if required_surfaces != ["ce", "ee"]:
        raise CapabilityCatalogError(
            "catalog must require both CE and EE source searches"
        )

    capabilities = policy["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        raise CapabilityCatalogError("catalog policy capabilities must be non-empty")
    expected_requirements = _baseline_requirement_ids(baseline)
    expected_set = set(expected_requirements)
    mapped_requirements: list[str] = []
    items: list[CapabilityCatalogItem] = []
    capability_ids: list[str] = []
    for index, raw_capability in enumerate(capabilities):
        if not isinstance(raw_capability, dict):
            raise CapabilityCatalogError(f"capability {index} must be an object")
        raw_capability = cast(dict[str, Any], raw_capability)
        _require_exact_keys(
            raw_capability, _CAPABILITY_KEYS, label=f"capability {index}"
        )
        capability_id = raw_capability["capability_id"]
        test_manifest = raw_capability["test_manifest"]
        if not isinstance(capability_id, str) or not capability_id:
            raise CapabilityCatalogError(f"capability {index} has no identity")
        if not isinstance(test_manifest, str) or not test_manifest:
            raise CapabilityCatalogError(
                f"capability {capability_id} has no test manifest"
            )
        requirement_ids = _require_string_list(
            raw_capability["requirement_ids"],
            label=f"requirement IDs for {capability_id}",
        )
        if requirement_ids != sorted(set(requirement_ids)):
            raise CapabilityCatalogError(
                f"requirement IDs are not unique and ordered for {capability_id}"
            )
        contract_test_ref = _validate_test_manifest(
            repository_root,
            test_manifest,
            capability_id=capability_id,
            requirement_ids=requirement_ids,
        )
        capability_ids.append(capability_id)
        mapped_requirements.extend(requirement_ids)
        items.append(
            CapabilityCatalogItem(
                capability_id=capability_id,
                pmorg_requirement_ids=requirement_ids,
                contract_tests=[contract_test_ref],
            )
        )

    if capability_ids != sorted(capability_ids):
        raise CapabilityCatalogError("capability IDs must be ordered")
    if len(capability_ids) != len(set(capability_ids)):
        raise CapabilityCatalogError("capability IDs must be unique")
    duplicate_requirements = sorted(
        requirement
        for requirement in set(mapped_requirements)
        if mapped_requirements.count(requirement) != 1
    )
    unknown_requirements = sorted(set(mapped_requirements) - expected_set)
    unmapped_requirements = sorted(expected_set - set(mapped_requirements))
    if duplicate_requirements or unknown_requirements or unmapped_requirements:
        raise CapabilityCatalogError(
            "catalog requirement mapping is not closed; "
            f"duplicates={duplicate_requirements}, unknown={unknown_requirements}, "
            f"unmapped={unmapped_requirements}"
        )

    try:
        return CapabilityCatalog(
            schema_version=CATALOG_SCHEMA_VERSION,
            catalog_version=policy["catalog_version"],
            pmorg_spec_commit=baseline_spec_commit,
            disposition_scope_rule=_evidence_ref(
                repository_root,
                policy_relative,
                logical_name="capability-disposition-scope-rule",
            ),
            applicable_requirement_set=_evidence_ref(
                repository_root,
                baseline_relative,
                logical_name="applicable-release-requirement-set",
            ),
            required_search_surfaces=cast(list[OnyxSurface], required_surfaces),
            expected_requirement_count=len(expected_requirements),
            mapped_requirement_count=len(mapped_requirements),
            unmapped_requirement_count=0,
            unknown_requirement_count=0,
            duplicate_capability_id_count=0,
            items=items,
            item_count=len(items),
        )
    except ValidationError as error:
        raise CapabilityCatalogError("derived capability catalog is invalid") from error


def expected_catalog_bytes(repository_root: Path = REPOSITORY_ROOT) -> bytes:
    """Return the deterministic committed catalog projection."""

    catalog = build_capability_catalog(repository_root)
    return canonical_document_bytes(catalog.model_dump(mode="json"))


def _validate_committed_schema(repository_root: Path, value: Any) -> None:
    contract_root = repository_root / "backend" / "pmorg" / "contracts"
    manifest = _read_object(contract_root / "manifest.json", label="contract manifest")
    try:
        entry = next(
            item
            for item in manifest["contracts"]
            if item["schema_version"] == CATALOG_SCHEMA_VERSION
        )
        schema_path = contract_root / entry["schema_path"]
        schema_bytes = schema_path.read_bytes()
        schema = json.loads(schema_bytes, object_pairs_hook=_reject_duplicate_keys)
    except (KeyError, StopIteration, TypeError, OSError, json.JSONDecodeError) as error:
        raise CapabilityCatalogError(
            "committed capability schema is incomplete"
        ) from error
    if sha256_digest(schema_bytes) != entry.get("schema_sha256"):
        raise CapabilityCatalogError("committed capability schema digest drifted")
    try:
        Draft202012Validator(schema).validate(value)
    except Exception as error:
        raise CapabilityCatalogError(
            "capability catalog does not validate against the committed schema"
        ) from error


def write_capability_catalog(repository_root: Path = REPOSITORY_ROOT) -> None:
    """Write the deterministic catalog artifact."""

    output = repository_root / "pmorg" / "capabilities" / "capability-catalog-v1.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(expected_catalog_bytes(repository_root))


def check_capability_catalog(repository_root: Path = REPOSITORY_ROOT) -> None:
    """Fail closed for catalog drift or contract-schema mismatch."""

    expected = expected_catalog_bytes(repository_root)
    output = repository_root / "pmorg" / "capabilities" / "capability-catalog-v1.json"
    try:
        actual = output.read_bytes()
    except OSError as error:
        raise CapabilityCatalogError(
            "committed capability catalog is missing"
        ) from error
    if actual != expected:
        raise CapabilityCatalogError("committed capability catalog drifted")
    try:
        value = json.loads(actual, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise CapabilityCatalogError(
            "committed capability catalog is invalid JSON"
        ) from error
    _validate_committed_schema(repository_root, value)
