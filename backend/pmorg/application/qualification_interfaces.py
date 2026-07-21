"""Build and verify content-addressed candidate qualification interfaces."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from typing import cast

from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CATALOG_RELATIVE = "pmorg/capabilities/capability-catalog-v1.json"
INTERFACE_ROOT = "pmorg/capabilities/qualification-interfaces"
INTERFACE_SCHEMA_RELATIVE = "pmorg/capabilities/qualification-interface-v1.schema.json"
INTERFACE_MANIFEST_RELATIVE = "pmorg/capabilities/qualification-interfaces-v1.json"
DERIVATION_RELATIVES = (
    "backend/pmorg/application/qualification_interfaces.py",
    "pmorg/scripts/build_qualification_interfaces.py",
)

INTERFACE_SCHEMA_VERSION = "pmorg.qualification-interface/v1"
MANIFEST_SCHEMA_VERSION = "pmorg.qualification-interface-manifest/v1"
INTERFACE_VERSION = "1.0.0"


class QualificationInterfaceError(ValueError):
    """Raised when an interface definition or content binding is not exact."""


def canonical_document_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _safe_path(repository_root: Path, relative_path: str) -> Path:
    candidate = (repository_root / relative_path).resolve()
    try:
        candidate.relative_to(repository_root.resolve())
    except ValueError as error:
        raise QualificationInterfaceError(
            f"path escapes repository root: {relative_path}"
        ) from error
    return candidate


def _read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationInterfaceError(f"{label} is not readable JSON") from error
    if not isinstance(value, dict):
        raise QualificationInterfaceError(f"{label} must be an object")
    return value


def _artifact_ref(
    repository_root: Path,
    relative_path: str,
    *,
    media_type: str,
    logical_name: str | None = None,
) -> dict[str, Any]:
    path = _safe_path(repository_root, relative_path)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise QualificationInterfaceError(
            f"bound artifact is missing: {relative_path}"
        ) from error
    result = {
        "digest": sha256_digest(payload),
        "media_type": media_type,
        "relative_path": relative_path,
        "size_bytes": len(payload),
    }
    if logical_name is not None:
        result["logical_name"] = logical_name
    return result


def interface_schema() -> dict[str, Any]:
    string = {"type": "string", "minLength": 1}
    string_array = {
        "type": "array",
        "minItems": 1,
        "items": string,
        "uniqueItems": True,
    }
    artifact = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "media_type", "relative_path", "size_bytes"],
        "properties": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "media_type": string,
            "relative_path": string,
            "size_bytes": {"type": "integer", "minimum": 1},
        },
    }
    test_property = {
        "type": "object",
        "additionalProperties": False,
        "required": ["observable_property", "test_id"],
        "properties": {
            "observable_property": string,
            "test_id": string,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pmorg:qualification-interface:v1",
        "title": "PMORG candidate qualification interface",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "interface_version",
            "capability_id",
            "candidate_projection",
            "implementation_question",
            "input_contract",
            "output_contract",
            "invariants",
            "test_properties",
            "fit_outcomes",
            "contract_test_manifest",
            "reference_implementations",
        ],
        "properties": {
            "schema_version": {"const": INTERFACE_SCHEMA_VERSION},
            "interface_version": {"const": INTERFACE_VERSION},
            "capability_id": string,
            "candidate_projection": {"const": "module_group_blob_set/v1"},
            "implementation_question": string,
            "input_contract": string_array,
            "output_contract": string_array,
            "invariants": string_array,
            "test_properties": {
                "type": "array",
                "minItems": 1,
                "items": test_property,
            },
            "fit_outcomes": {
                "type": "object",
                "additionalProperties": False,
                "required": ["fail", "patch", "reuse"],
                "properties": {
                    "fail": string,
                    "patch": string,
                    "reuse": string,
                },
            },
            "contract_test_manifest": artifact,
            "reference_implementations": {
                "type": "array",
                "minItems": 1,
                "items": artifact,
            },
        },
    }


_BLUEPRINTS: dict[str, dict[str, Any]] = {
    "capability-disposition-qualification": {
        "question": (
            "Can the candidate emit and validate exact PMORG capability, "
            "qualification and disposition records without weakening closed schemas?"
        ),
        "inputs": [
            "content-addressed candidate manifest and projected candidate bytes",
            "PMORG contract manifest, closed schemas and capability catalog",
            "qualification evidence and temporal bindings",
        ],
        "outputs": [
            "schema-valid content-addressed qualification or disposition record",
            "fail-closed validation errors tied to exact candidate bytes",
        ],
        "invariants": [
            "unknown fields and unknown wire surfaces are rejected",
            "no PASS or disposition exists without complete evidence bindings",
            "candidate byte mutation is observable through the adapter",
        ],
        "implementations": [
            "backend/pmorg/application/qualification.py",
            "backend/pmorg/application/qualification_oracles.py",
        ],
    },
    "deployment-admission": {
        "question": (
            "Can the candidate enforce exact fail-closed deployment admission for "
            "the reconstructed payload and measured target?"
        ),
        "inputs": [
            "qualified BQM/BQA and exact deployment payload descriptor",
            "measured target descriptor, evidence and trusted temporal state",
            "content-addressed candidate manifest and projected candidate bytes",
        ],
        "outputs": [
            "signed deployment admission bound to exact payload and target",
            "allow, deny or pre-deadline quiesce receipt",
        ],
        "invariants": [
            "missing, invalid, drifted or expired admission never allows deployment",
            "production and unknown targets are rejected in development_test scope",
            "candidate byte mutation is observable through the adapter",
        ],
        "implementations": ["backend/pmorg/application/admission.py"],
    },
    "distribution-admission": {
        "question": (
            "Can the candidate enforce exact fail-closed distribution admission for "
            "the qualified subset and measured destination?"
        ),
        "inputs": [
            "qualified BQM/BQA, distribution subset and release metadata roles",
            "measured destination before publish and after auth or redirect",
            "content-addressed candidate manifest and projected candidate bytes",
        ],
        "outputs": [
            "signed distribution admission bound to exact subset and destination",
            "allow, deny or pre-deadline active-transfer abort receipt",
        ],
        "invariants": [
            "destination identity drift after auth or redirect is rejected",
            "production and unknown destinations are rejected in development_test scope",
            "candidate byte mutation is observable through the adapter",
        ],
        "implementations": ["backend/pmorg/application/distribution_admission.py"],
    },
    "governed-onyx-fork": {
        "question": (
            "Can the candidate enforce the pinned thin-fork ownership, seam and "
            "surface policy over an exact candidate tree?"
        ),
        "inputs": [
            "pinned trusted base, candidate tree and protected base identity",
            "ownership roots, seam allowlist and immutable historical evidence",
            "content-addressed candidate manifest and projected candidate bytes",
        ],
        "outputs": [
            "ordered policy violations with exact source paths",
            "success only for an exact admissible fork state",
        ],
        "invariants": [
            "trust-boundary and upstream changes fail closed unless explicitly governed",
            "unknown seams and hybrid governance states are rejected",
            "candidate byte mutation is observable through the adapter",
        ],
        "implementations": ["pmorg/scripts/verify_fork.py"],
    },
    "qualified-reproducible-build": {
        "question": (
            "Can the candidate build the pinned CE source into byte-stable artifacts "
            "with exact evidence and zero EE contamination?"
        ),
        "inputs": [
            "pinned source tree, deterministic build specification and offline inputs",
            "CE boundary, runtime scope policy and evidence bundle",
            "content-addressed candidate manifest and projected candidate bytes",
        ],
        "outputs": [
            "byte-stable artifact set and content-addressed build manifest",
            "signed BQA with reproducibility, license and evidence bindings",
        ],
        "invariants": [
            "independent rebuilds have identical artifact bytes and digests",
            "EE paths, imports, copies and unknown egress fail closed",
            "candidate byte mutation is observable through the adapter",
        ],
        "implementations": [
            "pmorg/scripts/build_ce_artifact.py",
            "pmorg/scripts/verify_ce_build.py",
        ],
    },
    "thin-fork-boundary": {
        "question": (
            "Can the candidate detect every change outside the PMORG-owned boundary "
            "and every ungoverned upstream or seam mutation?"
        ),
        "inputs": [
            "pinned base tree, candidate tree and ownership allowlists",
            "patch ledger, upstream patch records and protector evidence",
            "content-addressed candidate manifest and projected candidate bytes",
        ],
        "outputs": [
            "complete ordered set of boundary violations",
            "success only when every changed path has one valid owner and policy route",
        ],
        "invariants": [
            "unknown ownership and trust-boundary changes fail closed",
            "historical evidence remains byte-immutable and successor-bound",
            "candidate byte mutation is observable through the adapter",
        ],
        "implementations": ["pmorg/scripts/verify_fork.py"],
    },
}


def _catalog_items(repository_root: Path) -> list[dict[str, Any]]:
    catalog = _read_object(
        _safe_path(repository_root, CATALOG_RELATIVE),
        label="capability catalog",
    )
    if catalog.get("catalog_version") != "1.0.0":
        raise QualificationInterfaceError("capability catalog version drifted")
    items = catalog.get("items")
    if not isinstance(items, list) or not items:
        raise QualificationInterfaceError("capability catalog items are missing")
    typed = cast(list[dict[str, Any]], items)
    ids = [item.get("capability_id") for item in typed]
    if ids != sorted(_BLUEPRINTS) or set(ids) != set(_BLUEPRINTS):
        raise QualificationInterfaceError(
            "qualification-interface capability coverage is not exact"
        )
    return typed


def build_qualification_interfaces(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, bytes]:
    repository_root = repository_root.resolve()
    schema = interface_schema()
    validator = Draft202012Validator(schema)
    outputs: dict[str, bytes] = {
        INTERFACE_SCHEMA_RELATIVE: canonical_document_bytes(schema)
    }
    interface_refs: list[dict[str, Any]] = []
    for item in _catalog_items(repository_root):
        capability_id = cast(str, item["capability_id"])
        blueprint = _BLUEPRINTS[capability_id]
        contract_refs = item.get("contract_tests")
        if not isinstance(contract_refs, list) or len(contract_refs) != 1:
            raise QualificationInterfaceError(
                f"{capability_id} does not bind one contract-test manifest"
            )
        contract_ref = cast(dict[str, Any], contract_refs[0])
        relative_path = cast(str, contract_ref.get("relative_path"))
        actual_contract_ref = _artifact_ref(
            repository_root,
            relative_path,
            media_type="application/json",
        )
        expected_contract_ref = {
            key: contract_ref[key]
            for key in ("digest", "media_type", "relative_path", "size_bytes")
        }
        if actual_contract_ref != expected_contract_ref:
            raise QualificationInterfaceError(
                f"{capability_id} contract-test manifest binding drifted"
            )
        contract_manifest = _read_object(
            _safe_path(repository_root, relative_path),
            label=f"{capability_id} contract-test manifest",
        )
        test_ids = contract_manifest.get("test_ids")
        if not isinstance(test_ids, list) or test_ids != sorted(set(test_ids)):
            raise QualificationInterfaceError(
                f"{capability_id} test IDs are not exact and ordered"
            )
        document = {
            "schema_version": INTERFACE_SCHEMA_VERSION,
            "interface_version": INTERFACE_VERSION,
            "capability_id": capability_id,
            "candidate_projection": "module_group_blob_set/v1",
            "implementation_question": blueprint["question"],
            "input_contract": blueprint["inputs"],
            "output_contract": blueprint["outputs"],
            "invariants": blueprint["invariants"],
            "test_properties": [
                {
                    "test_id": test_id,
                    "observable_property": (
                        f"the {capability_id} interface invariant set remains true "
                        f"under the exact {test_id} contract-test requirement"
                    ),
                }
                for test_id in test_ids
            ],
            "fit_outcomes": {
                "reuse": (
                    "all interface inputs and outputs bind without candidate mutation "
                    "and the full observable property vector passes"
                ),
                "patch": (
                    "a byte-bounded candidate patch supplies the interface and the full "
                    "observable property vector passes with mutation influence evidence"
                ),
                "fail": (
                    "the candidate cannot bind the interface or any observable property "
                    "fails; the reason must cite exact projected candidate bytes"
                ),
            },
            "contract_test_manifest": actual_contract_ref,
            "reference_implementations": [
                _artifact_ref(
                    repository_root,
                    path,
                    media_type="text/x-python",
                )
                for path in cast(list[str], blueprint["implementations"])
            ],
        }
        errors = sorted(validator.iter_errors(document), key=str)
        if errors:
            raise QualificationInterfaceError(
                f"{capability_id} interface schema violation: {errors[0]}"
            )
        interface_relative = f"{INTERFACE_ROOT}/{capability_id}-v1.json"
        payload = canonical_document_bytes(document)
        outputs[interface_relative] = payload
        interface_refs.append(
            {
                "capability_id": capability_id,
                "digest": sha256_digest(payload),
                "media_type": "application/json",
                "relative_path": interface_relative,
                "size_bytes": len(payload),
            }
        )
    schema_payload = outputs[INTERFACE_SCHEMA_RELATIVE]
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "interface_version": INTERFACE_VERSION,
        "catalog_version": "1.0.0",
        "candidate_projection": "module_group_blob_set/v1",
        "interface_schema": {
            "digest": sha256_digest(schema_payload),
            "media_type": "application/schema+json",
            "relative_path": INTERFACE_SCHEMA_RELATIVE,
            "size_bytes": len(schema_payload),
        },
        "interfaces": interface_refs,
        "interface_count": len(interface_refs),
        "derivation_artifacts": [
            _artifact_ref(repository_root, path, media_type="text/x-python")
            for path in DERIVATION_RELATIVES
        ],
    }
    outputs[INTERFACE_MANIFEST_RELATIVE] = canonical_document_bytes(manifest)
    return outputs


def write_qualification_interfaces(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, payload in build_qualification_interfaces(
        repository_root
    ).items():
        path = _safe_path(repository_root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def check_qualification_interfaces(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    repository_root = repository_root.resolve()
    for relative_path, expected in build_qualification_interfaces(
        repository_root
    ).items():
        try:
            actual = _safe_path(repository_root, relative_path).read_bytes()
        except OSError as error:
            raise QualificationInterfaceError(
                f"committed interface artifact is missing: {relative_path}"
            ) from error
        if actual != expected:
            raise QualificationInterfaceError(
                f"committed interface artifact drifted: {relative_path}"
            )


__all__ = [
    "INTERFACE_MANIFEST_RELATIVE",
    "QualificationInterfaceError",
    "build_qualification_interfaces",
    "canonical_document_bytes",
    "check_qualification_interfaces",
    "interface_schema",
    "sha256_digest",
    "write_qualification_interfaces",
]
