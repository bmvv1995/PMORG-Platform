#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import cast
from typing import TypedDict

TRUSTED_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class UpstreamManifest(TypedDict):
    repository: str
    release_tag: str
    commit: str
    checkout_remote: str


class SpecificationManifest(TypedDict):
    repository: str
    baseline: str
    commit: str


class LicensingManifest(TypedDict):
    artifact_policy: str
    qualification_status: str
    allowed_onyx_surfaces: list[str]
    allowed_usage_modes: list[str]
    ce_surface_policy: str
    ee_surface_policy: str
    development_test_policy: str
    ce_production_policy: str
    ee_production_policy: str
    production_synthetic_policy: str
    capability_disposition_policy: str
    distribution_policy: str


class BuildManifest(TypedDict):
    mode: str
    onyx_surface: str | None
    usage_mode: str | None
    qualification_refs: dict[str, str | None]
    operation_refs: dict[str, list[str]]


class BaselineManifest(TypedDict):
    schema_version: str
    upstream: UpstreamManifest
    specification: SpecificationManifest
    licensing: LicensingManifest
    round_3_contract: dict[str, object]
    build: BuildManifest


class PatchEntry(TypedDict, total=False):
    id: str
    classification: str
    paths: list[str]
    requirements: list[str]
    reason: str
    verification: list[str]


class PatchLedger(TypedDict):
    schema_version: str
    upstream_commit: str
    specification_commit: str
    ownership_roots_ref: str
    seam_allowlist_ref: str
    upstream_patch_record_schema_version: str
    upstream_patch_records: list[object]
    entries: list[object]


ALLOWED_CLASSIFICATIONS = {
    "PMORG-owned",
    "integration",
    "upstream-candidate",
    "temporary",
}
EXPECTED_ONYX_SURFACES = ["ce", "ee"]
EXPECTED_USAGE_MODES = ["development_test", "production"]
EXPECTED_ENTERPRISE_LICENSE_PATHS = [
    "backend/ee/**",
    "web/src/app/ee/**",
    "web/src/ee/**",
]
EXPECTED_PMORG_SPEC_COMMIT = "05bc4df345d2d65e05b510135a4d99c9edbf886e"
EXPECTED_LICENSING_POLICIES = {
    "artifact_policy": "declared_onyx_surface_and_usage_mode",
    "ce_surface_policy": "exclude_onyx_ee_code",
    "ee_surface_policy": "complete_inventory_required_all_usage_modes",
    "development_test_policy": "synthetic_only_all_surfaces",
    "ce_production_policy": "client_only_ce_release_authorization",
    "ee_production_policy": "client_only_enterprise_authorization",
    "production_synthetic_policy": "deny_all_surfaces",
    "capability_disposition_policy": (
        "complete_catalog_reuse_default_patch_or_pmorg_independent_by_evidence"
    ),
    "distribution_policy": (
        "separate_payload_destination_measurement_and_admission_fail_closed"
    ),
}

EXPECTED_PLATFORM_REQUIREMENTS = [
    "PLT-001",
    "PLT-004",
    "PLT-005",
    "PLT-006",
    "PLT-007",
    "PLT-008",
]
EXPECTED_ACCEPTANCE_CONTROLS = [
    "A-FORK-001",
    "A-UPSTREAM-001",
    "A-LIC-001",
    "A-SURFACE-001",
    "A-REPRO-001",
    "A-EVIDENCE-001",
    "A-REPORT-001",
    "A-LIC-002",
    "A-LIC-003",
    "A-PATCH-001",
    "A-PATCH-002",
    "A-PATCH-003",
    "A-PATCH-004",
    "A-PATCH-005",
    "A-PATCH-006",
]
EXPECTED_SCHEMA_VERSIONS = [
    "pmorg.admission-use-receipt/v1",
    "pmorg.build-qualification-attestation/v1",
    "pmorg.build-qualification-manifest/v1",
    "pmorg.candidate-qualification-report/v1",
    "pmorg.candidate-search-evidence/v1",
    "pmorg.capability-catalog/v1",
    "pmorg.capability-deviation-decision/v1",
    "pmorg.capability-disposition-report/v1",
    "pmorg.capability-disposition/v1",
    "pmorg.ce-release-authorization-binding/v1",
    "pmorg.deployment-admission/v1",
    "pmorg.deployment-payload-descriptor/v1",
    "pmorg.deployment-target-descriptor/v1",
    "pmorg.distribution-admission/v1",
    "pmorg.distribution-destination-descriptor/v1",
    "pmorg.distribution-destination-measurement/v1",
    "pmorg.distribution-payload-descriptor/v1",
    "pmorg.enterprise-authorization-binding/v1",
    "pmorg.evidence-bundle-index/v1",
    "pmorg.expected-artifact-catalog/v1",
    "pmorg.post-disposition-qualification/v1",
    "pmorg.provenance-scan-report/v1",
    "pmorg.qualification-policy-map/v1",
    "pmorg.release-build-definition/v1",
    "pmorg.runtime-scope-policy-map/v1",
    "pmorg.source-scope-manifest/v1",
    "pmorg.target-measurement-attestation/v1",
    "pmorg.trusted-time-receipt/v1",
]
EXPECTED_SCOPE_POLICY_CLASSES = [
    {
        "scope_class": "deployment_runtime",
        "expected_release_metadata_role_set": "forbidden",
    },
    {
        "scope_class": "registry_publish",
        "expected_release_metadata_role_set": "required",
    },
    {
        "scope_class": "artifact_export",
        "expected_release_metadata_role_set": "required",
    },
]
EXPECTED_QUALIFICATION_BUNDLE_ROLES = {
    "common": [
        "release-build-definition-dsse",
        "build-recipe",
        "build-input-set",
        "runtime-scope-policy-map",
        "expected-artifact-catalog",
        "image-lock",
        "qualification-policy-map",
        "sbom-index",
        "license-report",
        "patch-ledger-report",
        "provenance-report",
        "surface-mode-report",
        "provenance-evidence-bundle-index",
        "capability-catalog",
        "capability-disposition-report",
        "capability-evidence-bundle-index",
        "vulnerability-report",
        "upstream-test-report",
    ],
    "ce_only": ["ce-boundary-report"],
    "ee_only": ["ee-inventory-report"],
    "unknown_duplicate_or_wrong_surface_role": "invalid",
}

EXPECTED_DEPLOYMENT_PASS_MATRIX = [
    {
        "onyx_surface": "ce",
        "usage_mode": "development_test",
        "target_class": "synthetic_sandbox",
        "admission_basis": "synthetic_environment",
        "authorization": "none",
    },
    {
        "onyx_surface": "ee",
        "usage_mode": "development_test",
        "target_class": "synthetic_sandbox",
        "admission_basis": "synthetic_environment",
        "authorization": "none",
    },
    {
        "onyx_surface": "ce",
        "usage_mode": "production",
        "target_class": "client",
        "admission_basis": "ce_release",
        "authorization": "ce_release_authorization",
    },
    {
        "onyx_surface": "ee",
        "usage_mode": "production",
        "target_class": "client",
        "admission_basis": "onyx_enterprise_authorization",
        "authorization": "enterprise_authorization",
    },
]
EXPECTED_DEPLOYMENT_DENY_MATRIX = [
    {
        "onyx_surface": "ce",
        "usage_mode": "development_test",
        "target_class": "client",
    },
    {
        "onyx_surface": "ee",
        "usage_mode": "development_test",
        "target_class": "client",
    },
    {
        "onyx_surface": "ce",
        "usage_mode": "production",
        "target_class": "synthetic_sandbox",
    },
    {
        "onyx_surface": "ee",
        "usage_mode": "production",
        "target_class": "synthetic_sandbox",
    },
]
EXPECTED_DISTRIBUTION_PASS_MATRIX = [
    {
        "onyx_surface": "ce",
        "usage_mode": "development_test",
        "destination_class": "controlled_synthetic_registry",
        "admission_basis": "synthetic_environment",
        "authorization": "none",
    },
    {
        "onyx_surface": "ee",
        "usage_mode": "development_test",
        "destination_class": "controlled_synthetic_registry",
        "admission_basis": "synthetic_environment",
        "authorization": "none",
    },
    {
        "onyx_surface": "ce",
        "usage_mode": "production",
        "destination_class": "client_destination",
        "admission_basis": "ce_release",
        "authorization": "ce_release_authorization",
    },
    {
        "onyx_surface": "ee",
        "usage_mode": "production",
        "destination_class": "client_destination",
        "admission_basis": "onyx_enterprise_authorization",
        "authorization": "enterprise_authorization",
    },
]
EXPECTED_DISTRIBUTION_DENY_MATRIX = [
    {
        "onyx_surface": "ce",
        "usage_mode": "development_test",
        "destination_class": "client_destination",
    },
    {
        "onyx_surface": "ee",
        "usage_mode": "development_test",
        "destination_class": "client_destination",
    },
    {
        "onyx_surface": "ce",
        "usage_mode": "production",
        "destination_class": "controlled_synthetic_registry",
    },
    {
        "onyx_surface": "ee",
        "usage_mode": "production",
        "destination_class": "controlled_synthetic_registry",
    },
]

COMMON_QUALIFICATION_REF_KEYS = {
    "release_build_definition_envelope_hash",
    "build_recipe_hash",
    "build_input_set_hash",
    "expected_artifact_catalog_hash",
    "runtime_scope_policy_map_hash",
    "build_qualification_manifest_hash",
    "build_qualification_attestation_envelope_hash",
    "qualification_bundle_index_hash",
    "qualification_policy_map_hash",
    "artifact_set_hash",
    "image_lock_hash",
    "surface_mode_report_hash",
    "sbom_index_hash",
    "license_report_hash",
    "patch_ledger_report_hash",
    "provenance_report_hash",
    "provenance_evidence_bundle_index_hash",
    "capability_catalog_hash",
    "capability_disposition_report_hash",
    "capability_evidence_bundle_index_hash",
    "vulnerability_report_hash",
    "upstream_test_report_hash",
    "trusted_time_receipt_envelope_hash",
}
SURFACE_QUALIFICATION_REF_KEYS = {
    "ce_boundary_report_hash",
    "ee_inventory_report_hash",
}
EXPECTED_QUALIFICATION_REF_KEYS = (
    COMMON_QUALIFICATION_REF_KEYS | SURFACE_QUALIFICATION_REF_KEYS
)
EXPECTED_OPERATION_REF_KEYS = {
    "deployment_admission_envelope_hashes",
    "deployment_admission_use_receipt_envelope_hashes",
    "distribution_admission_envelope_hashes",
    "distribution_admission_use_receipt_envelope_hashes",
}

REQUIRED_TRUE_FLAGS = {
    "build_qualification": [
        "release_definition_signed_before_build",
        "expected_catalog_fixed_before_build",
        "runtime_scope_map_fixed_before_build",
        "build_manifest_detached",
        "build_attestation_detached_dsse",
        "artifact_counts_require_zero_missing_unexpected_duplicate",
        "ce_requires_zero_ee_content",
        "ee_requires_complete_inventory",
        "capability_catalog_requires_complete_applicable_requirement_mapping",
        "adequate_onyx_candidate_reuse_is_default",
        "patch_or_pmorg_independent_requires_valid_deviation_decision",
    ],
    "evidence_policy": [
        "content_addressed_bytes_resolve_offline",
        "dsse_payload_and_envelope_are_detached",
        "dsse_pae_payload_type_is_verified",
        "nonempty_trusted_signatures_required",
        "verification_policy_pinned_outside_verified_artifact",
        "self_authorizing_trust_forbidden",
        "evidence_graph_must_be_acyclic",
        "logical_name_digest_and_relative_path_unique",
        "digest_size_and_path_must_match_bytes",
    ],
    "trusted_time_policy": [
        "signed_receipt_required",
        "receipt_bytes_available_offline",
        "strict_sequence_and_monotonic_counter",
        "previous_receipt_chain_no_gap_fork_or_rollback",
        "freshness_skew_uncertainty_and_measurement_age_bounded",
        "future_dated_signed_times_forbidden",
        "validity_and_revalidation_windows_fail_closed",
        "watchdog_quiesces_active_workload_before_deadline",
        "transfer_revalidation_aborts_active_transfer_before_deadline",
    ],
    "deployment_admission": [
        "reconstruct_payload_from_runtime_bytes",
        "reconstruct_target_from_trusted_apis",
        "reconstruct_at_each_deploy_startup_and_watchdog",
        "revalidation_inherits_parent_operation_and_scope",
        "unknown_or_unmeasurable_is_client_and_denied_without_exact_pass",
    ],
    "distribution_admission": [
        "reconstruct_payload_and_metadata_from_bytes",
        "reconstruct_destination_from_trusted_apis",
        "reconstruct_after_authentication_and_redirect_before_first_byte",
        "revalidation_inherits_parent_operation_and_scope",
        ("unknown_or_unmeasurable_is_client_destination_and_denied_without_exact_pass"),
    ],
}

EXPECTED_OWNERSHIP_ROOTS_REF = "pmorg/policies/ownership-roots.json"
EXPECTED_SEAM_ALLOWLIST_REF = "pmorg/policies/seam-allowlist.json"
EXPECTED_OWNERSHIP_POLICY_SCHEMA = "pmorg.platform.ownership-roots/v2"
EXPECTED_SEAM_POLICY_SCHEMA = "pmorg.platform.seam-allowlist/v3"
EXPECTED_POLICY_PHASE = "governed_integration"
EXPECTED_PATCH_RECORD_SCHEMA = "pmorg.platform.upstream-patch-record/v2"
EXPECTED_SEAM_AUTHORIZATION_SCHEMA = "pmorg.platform.seam-authorization/v1"
EXPECTED_SEAM_SUCCESSOR_AUTHORIZATION_SCHEMA = (
    "pmorg.platform.seam-successor-authorization/v1"
)
RFC3339_UTC_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)
REQUIRED_PATCH_LEDGER_KEYS = {
    "schema_version",
    "upstream_commit",
    "specification_commit",
    "ownership_roots_ref",
    "seam_allowlist_ref",
    "upstream_patch_record_schema_version",
    "upstream_patch_records",
    "entries",
}
REQUIRED_OWNERSHIP_POLICY_KEYS = {
    "schema_version",
    "policy_phase",
    "specification_commit",
    "default_ownership",
    "roots",
    "invariants",
}
REQUIRED_SEAM_POLICY_KEYS = {
    "schema_version",
    "admission_mode",
    "specification_commit",
    "default_decision",
    "seams",
    "invariants",
}
EXPECTED_OWNERSHIP_ROOTS = [
    {
        "root_id": "pmorg-agents",
        "path_pattern": ".codex/**",
        "ownership": "pmorg_owned",
    },
    {
        "root_id": "pmorg-root-document",
        "path_pattern": "PMORG.md",
        "ownership": "pmorg_owned",
    },
    {
        "root_id": "pmorg-governance-workflow",
        "path_pattern": ".github/workflows/pmorg-governance.yml",
        "ownership": "pmorg_owned",
    },
    {
        "root_id": "pmorg-plans",
        "path_pattern": "plans/**",
        "ownership": "pmorg_owned",
    },
    {
        "root_id": "pmorg-governance-and-product",
        "path_pattern": "pmorg/**",
        "ownership": "pmorg_owned",
    },
    {
        "root_id": "pmorg-backend-product",
        "path_pattern": "backend/pmorg/**",
        "ownership": "pmorg_owned",
    },
    {
        "root_id": "pmorg-web-product",
        "path_pattern": "web/src/pmorg/**",
        "ownership": "pmorg_owned",
    },
]
EXPECTED_OWNERSHIP_INVARIANTS = {
    "overlapping_roots_forbidden": True,
    "pmorg_domain_allowed_only_in_pmorg_owned_roots": True,
}
EXPECTED_SEAM_INVARIANTS = {
    "governed_integration_admission_required": True,
    "upstream_owned_change_requires_exactly_one_allowlisted_seam": True,
    "upstream_owned_change_requires_exactly_one_patch_record": True,
    "authorization_adr_must_be_safe_existing_and_accepted": True,
    "concrete_seam_authorization_must_preexist_on_protected_base": True,
    "admitted_seams_are_immutable": True,
    "atomic_seam_commit_must_bind_record_owner_and_path": True,
    "retired_seam_evidence_must_remain_immutable": True,
    "seam_successor_must_replace_exact_protected_base_predecessor": True,
    "seam_successor_must_preserve_canonical_upstream_identity": True,
    "seam_successor_activation_must_be_atomic": True,
    "protector_test_references_must_be_safe_and_existing": True,
    "protector_tests_must_be_python_and_byte_bound": True,
    "protector_tests_must_execute_exactly_once_without_skip": True,
    "upstream_patch_paths_must_remain_regular_files": True,
    "pmorg_domain_in_upstream_owned_roots_forbidden": True,
}
REQUIRED_UPSTREAM_PATCH_RECORD_KEYS = {
    "id",
    "path",
    "seam_id",
    "classification",
    "base_blob_hash",
    "patched_blob_hash",
    "base_git_mode",
    "patched_git_mode",
    "upstream_source_ref",
    "reason",
    "owner",
    "upstream_issue_url",
    "upstream_pr_url",
    "requirement_refs",
    "capability_refs",
    "ownership_class",
    "license_class",
    "onyx_surfaces",
    "protector_tests",
    "last_revalidated_at",
    "conflict_notes",
    "removal_condition",
}
REQUIRED_UPSTREAM_SOURCE_REF_KEYS = {
    "repository",
    "commit",
    "path",
    "tree_hash",
}
REQUIRED_SEAM_KEYS = {
    "seam_id",
    "path_pattern",
    "authorization_adr_ref",
    "authorization_commit",
    "authorization_base_commit",
    "authorization_blob_hash",
    "allowed_classifications",
    "required_protector_tests",
    "reason",
}
REQUIRED_SEAM_AUTHORIZATION_KEYS = {
    "schema_version",
    "decision_id",
    "status",
    "specification_commit",
    "seam_id",
    "path",
    "allowed_classifications",
    "required_protector_tests",
    "protector_test_hashes",
    "authorized_at",
    "rationale",
}
REQUIRED_SEAM_SUCCESSOR_AUTHORIZATION_KEYS = REQUIRED_SEAM_AUTHORIZATION_KEYS | {
    "transition_id",
    "supersedes",
    "successor_patch_record_id",
    "successor_ledger_entry_id",
    "target_blob_hash",
    "target_git_mode",
}
REQUIRED_SEAM_SUCCESSOR_PREDECESSOR_KEYS = {
    "seam_id",
    "patch_record_id",
    "ledger_entry_id",
    "patched_blob_hash",
    "patched_git_mode",
    "authorization_adr_ref",
    "authorization_blob_hash",
}


def run_git(repository_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def changed_paths_from_revision(repository_root: Path, revision: str) -> list[str]:
    # Treat a rename as a deletion plus an addition so neither side can escape
    # ownership, seam, record, and no-deletion checks.
    output = run_git(
        repository_root,
        "diff",
        "--no-ext-diff",
        "--no-renames",
        "--name-only",
        f"{revision}..HEAD",
    )
    return output.splitlines() if output else []


def read_json(path: Path) -> object:
    with path.open(encoding="utf-8") as source_file:
        return json.load(source_file)


def read_json_object(path: Path, label: str) -> dict[str, object]:
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return cast(dict[str, object], value)


def load_manifest(repository_root: Path) -> BaselineManifest:
    value = read_json_object(
        repository_root / "pmorg" / "baseline-manifest.json",
        "baseline manifest",
    )
    for key in ("upstream", "specification", "licensing", "round_3_contract", "build"):
        if not isinstance(value.get(key), dict):
            raise ValueError(f"baseline manifest has no {key} object")
    return cast(BaselineManifest, value)


def load_patch_ledger(repository_root: Path) -> PatchLedger:
    value = read_json_object(
        repository_root / "pmorg" / "patch-ledger.json",
        "patch ledger",
    )
    if not isinstance(value.get("entries"), list):
        raise ValueError("patch ledger has no entries array")
    if not isinstance(value.get("upstream_patch_records"), list):
        raise ValueError("patch ledger has no upstream_patch_records array")
    return cast(PatchLedger, value)


def resolve_policy_path(repository_root: Path, relative_path: object) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError("policy reference is not a non-empty relative path")
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"unsafe policy reference: {relative_path}")
    resolved_root = repository_root.resolve()
    resolved_candidate = (repository_root / candidate).resolve()
    if (
        resolved_candidate != resolved_root
        and resolved_root not in resolved_candidate.parents
    ):
        raise ValueError(f"policy reference escapes repository: {relative_path}")
    return resolved_candidate


def load_ownership_roots(
    repository_root: Path, patch_ledger: PatchLedger
) -> dict[str, object]:
    path = resolve_policy_path(repository_root, patch_ledger.get("ownership_roots_ref"))
    return read_json_object(path, "ownership roots policy")


def load_seam_allowlist(
    repository_root: Path, patch_ledger: PatchLedger
) -> dict[str, object]:
    path = resolve_policy_path(repository_root, patch_ledger.get("seam_allowlist_ref"))
    return read_json_object(path, "seam allowlist policy")


def path_matches_pattern(path: str, pattern: str) -> bool:
    """Match ledger globs while treating brackets as literal path characters."""

    literal_bracket_pattern = pattern.replace("[", "[[]")
    return fnmatch.fnmatchcase(path, literal_bracket_pattern)


def find_path_owners(
    changed_paths: list[str], patch_entries: list[object]
) -> dict[str, list[str]]:
    return {
        changed_path: [
            cast(str, patch_entry.get("id"))
            for patch_entry in patch_entries
            if isinstance(patch_entry, dict)
            and isinstance(patch_entry.get("id"), str)
            and isinstance(patch_entry.get("paths"), list)
            and any(
                isinstance(pattern, str) and path_matches_pattern(changed_path, pattern)
                for pattern in cast(list[object], patch_entry["paths"])
            )
        ]
        for changed_path in changed_paths
    }


def find_uncovered_paths(
    changed_paths: list[str], patch_entries: list[object]
) -> list[str]:
    return [
        path
        for path, owners in find_path_owners(changed_paths, patch_entries).items()
        if not owners
    ]


def is_sha256(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest
    )


def validate_surface_mode(manifest: BaselineManifest) -> list[str]:
    errors: list[str] = []
    licensing = manifest["licensing"]
    build = manifest["build"]

    if licensing.get("source_repository_mode") != "mixed_source":
        errors.append("source repository mode must remain mixed_source")
    if licensing.get("community_license") != "MIT Expat":
        errors.append("community license must remain MIT Expat")
    if licensing.get("enterprise_license_paths") != EXPECTED_ENTERPRISE_LICENSE_PATHS:
        errors.append("Enterprise license path boundary is incomplete or reordered")

    if licensing.get("allowed_onyx_surfaces") != EXPECTED_ONYX_SURFACES:
        errors.append("allowed Onyx surfaces must be exactly ce and ee")
    if licensing.get("allowed_usage_modes") != EXPECTED_USAGE_MODES:
        errors.append(
            "allowed usage modes must be exactly development_test and production"
        )

    for key, expected in EXPECTED_LICENSING_POLICIES.items():
        if licensing.get(key) != expected:
            errors.append(f"unexpected licensing policy {key}")

    onyx_surface = build.get("onyx_surface")
    usage_mode = build.get("usage_mode")
    if (onyx_surface is None) != (usage_mode is None):
        errors.append("onyx_surface and usage_mode must be declared together")
    if onyx_surface is not None and onyx_surface not in EXPECTED_ONYX_SURFACES:
        errors.append(f"invalid onyx_surface: {onyx_surface}")
    if usage_mode is not None and usage_mode not in EXPECTED_USAGE_MODES:
        errors.append(f"invalid usage_mode: {usage_mode}")

    serialized = json.dumps(manifest, sort_keys=True)
    if "licensed-ee" in serialized or "delivery_profile" in serialized:
        errors.append("legacy delivery-profile terminology is forbidden")

    return errors


def validate_round_3_contract(manifest: BaselineManifest) -> list[str]:
    errors: list[str] = []
    contract = manifest["round_3_contract"]
    specification_commit = manifest["specification"].get("commit")

    if manifest.get("schema_version") != "pmorg.platform.baseline/v3":
        errors.append("baseline manifest must use round-3 schema v3")
    if manifest.get("status") != "bootstrap_candidate":
        errors.append("Slice 0 baseline status must remain bootstrap_candidate")
    if contract.get("source_specification_commit") != specification_commit:
        errors.append("round-3 contract and specification pin disagree")
    if specification_commit != EXPECTED_PMORG_SPEC_COMMIT:
        errors.append(
            "baseline is not pinned to the accepted PMORG specification commit"
        )
    if contract.get("authority") != (
        "declarative_snapshot_only_pmorg_commit_is_normative"
    ):
        errors.append(
            "round-3 manifest contract must declare the PMORG commit normative"
        )
    if contract.get("platform_requirements") != EXPECTED_PLATFORM_REQUIREMENTS:
        errors.append(
            "round-3 platform requirements must include PLT-001 and PLT-004..008"
        )
    if contract.get("acceptance_controls") != EXPECTED_ACCEPTANCE_CONTROLS:
        errors.append("round-3 acceptance control set is incomplete or reordered")
    if contract.get("required_schema_versions") != EXPECTED_SCHEMA_VERSIONS:
        errors.append("round-3 schema-version catalog is incomplete or reordered")
    if contract.get("runtime_scope_policy_classes") != EXPECTED_SCOPE_POLICY_CLASSES:
        errors.append(
            "runtime scope policy classes must be deployment_runtime, "
            "registry_publish and artifact_export"
        )
    if (
        contract.get("qualification_bundle_roles")
        != EXPECTED_QUALIFICATION_BUNDLE_ROLES
    ):
        errors.append("qualification bundle logical-role set is incomplete")

    for section_name, flags in REQUIRED_TRUE_FLAGS.items():
        section = contract.get(section_name)
        if not isinstance(section, dict):
            errors.append(f"round-3 contract has no {section_name} object")
            continue
        for flag in flags:
            if section.get(flag) is not True:
                errors.append(f"round-3 policy {section_name}.{flag} must be true")

    build_qualification = contract.get("build_qualification")
    if isinstance(build_qualification, dict):
        if build_qualification.get("required_independent_clean_builds") != 2:
            errors.append(
                "reproducibility requires exactly two independent clean builds"
            )
        if build_qualification.get("reproducible_payloads") != [
            "artifact_descriptors",
            "artifact_set_hash",
            "image_lock_hash",
            "qualification_bundle_index_hash",
            "qualification_report_payload_hashes",
            "build_manifest_payload_hash",
        ]:
            errors.append("reproducible payload set is incomplete")
        if build_qualification.get("allowed_reproducibility_differences") != [
            "qualification_attestation_payload",
            "execution_envelopes",
            "dsse_signatures",
            "trusted_time_receipts",
            "temporal_windows",
        ]:
            errors.append("allowed reproducibility difference set is invalid")

    evidence_policy = contract.get("evidence_policy")
    if isinstance(evidence_policy, dict) and evidence_policy.get(
        "required_offline_evidence_classes"
    ) != [
        "trust-policy",
        "certificates",
        "revocation",
        "trusted-time",
        "verifier-receipts",
        "resources",
        "authorizations",
        "provenance",
    ]:
        errors.append("offline evidence class set is incomplete")

    deployment = contract.get("deployment_admission")
    if isinstance(deployment, dict):
        if deployment.get("direct_operations") != ["deploy", "startup"]:
            errors.append("deployment direct operation set is invalid")
        if deployment.get("revalidation_event") != "watchdog_revalidation":
            errors.append("deployment revalidation event must be watchdog_revalidation")
        if deployment.get("runtime_scope_policy_class") != "deployment_runtime":
            errors.append("deployment must use the deployment_runtime policy class")
        if deployment.get("pass_matrix") != EXPECTED_DEPLOYMENT_PASS_MATRIX:
            errors.append("deployment admission must declare exactly four PASS cells")
        if deployment.get("deny_matrix") != EXPECTED_DEPLOYMENT_DENY_MATRIX:
            errors.append(
                "deployment admission must declare exactly four opposite-class denials"
            )
        if deployment.get("watchdog_failure_action") != "quiesce_before_deadline":
            errors.append("deployment watchdog must quiesce before the deadline")
        if deployment.get("required_contracts") != [
            "deployment-payload-descriptor",
            "deployment-target-descriptor",
            "target-measurement-attestation-dsse",
            "deployment-admission-dsse",
            "admission-use-receipt-dsse",
        ]:
            errors.append("deployment evidence/admission contract set is incomplete")

    distribution = contract.get("distribution_admission")
    if isinstance(distribution, dict):
        if distribution.get("direct_operations") != [
            "registry_publish",
            "artifact_export",
        ]:
            errors.append("distribution direct operation set is invalid")
        if distribution.get("revalidation_event") != "transfer_revalidation":
            errors.append(
                "distribution revalidation event must be transfer_revalidation"
            )
        if distribution.get("runtime_scope_policy_classes") != [
            "registry_publish",
            "artifact_export",
        ]:
            errors.append("distribution runtime scope policy classes are invalid")
        if distribution.get("pass_matrix") != EXPECTED_DISTRIBUTION_PASS_MATRIX:
            errors.append("distribution admission must declare exactly four PASS cells")
        if distribution.get("deny_matrix") != EXPECTED_DISTRIBUTION_DENY_MATRIX:
            errors.append(
                "distribution admission must declare exactly four opposite-class denials"
            )
        if distribution.get("active_transfer_failure_action") != (
            "abort_and_hide_partial_bytes_before_deadline"
        ):
            errors.append(
                "distribution must abort and hide partial bytes before deadline"
            )
        if distribution.get("required_contracts") != [
            "distribution-payload-descriptor",
            "evidence-bundle-index:release_metadata",
            "distribution-destination-descriptor",
            "destination-measurement-attestation-dsse",
            "distribution-admission-dsse",
            "admission-use-receipt-dsse",
        ]:
            errors.append("distribution evidence/admission contract set is incomplete")

    return errors


def validate_build_qualification_state(manifest: BaselineManifest) -> list[str]:
    errors: list[str] = []
    build = manifest["build"]
    mode = build.get("mode")
    onyx_surface = build.get("onyx_surface")
    usage_mode = build.get("usage_mode")
    qualification_refs = build.get("qualification_refs")
    operation_refs = build.get("operation_refs")

    if not isinstance(qualification_refs, dict):
        return ["build has no qualification_refs object"]
    if set(qualification_refs) != EXPECTED_QUALIFICATION_REF_KEYS:
        errors.append(
            "qualification_refs key set is incomplete or contains unknown keys"
        )
    if not isinstance(operation_refs, dict):
        return errors + ["build has no operation_refs object"]
    if set(operation_refs) != EXPECTED_OPERATION_REF_KEYS:
        errors.append("operation_refs key set is incomplete or contains unknown keys")
    invalid_operation_arrays = [
        key
        for key, value in operation_refs.items()
        if not isinstance(value, list) or value
    ]
    if invalid_operation_arrays:
        errors.append(
            "Slice 0 operation ref arrays must remain empty until canonical "
            "admission verification exists: "
            + ", ".join(sorted(invalid_operation_arrays))
        )

    if mode == "not_yet_qualified":
        if onyx_surface is not None or usage_mode is not None:
            errors.append(
                "not_yet_qualified build cannot declare surface or usage mode"
            )
        non_null_refs = [
            key for key, value in qualification_refs.items() if value is not None
        ]
        if non_null_refs:
            errors.append(
                "not_yet_qualified build must keep every dynamic ref null: "
                + ", ".join(sorted(non_null_refs))
            )
    elif mode == "qualified":
        if (
            onyx_surface not in EXPECTED_ONYX_SURFACES
            or usage_mode not in EXPECTED_USAGE_MODES
        ):
            errors.append("qualified build must declare valid surface and usage mode")
        missing_or_invalid = [
            key
            for key in sorted(COMMON_QUALIFICATION_REF_KEYS)
            if not is_sha256(qualification_refs.get(key))
        ]
        if missing_or_invalid:
            errors.append(
                "qualified build has missing or invalid qualification refs: "
                + ", ".join(missing_or_invalid)
            )
        ce_ref = qualification_refs.get("ce_boundary_report_hash")
        ee_ref = qualification_refs.get("ee_inventory_report_hash")
        if onyx_surface == "ce" and (not is_sha256(ce_ref) or ee_ref is not None):
            errors.append("qualified CE build requires only ce_boundary_report_hash")
        if onyx_surface == "ee" and (not is_sha256(ee_ref) or ce_ref is not None):
            errors.append("qualified EE build requires only ee_inventory_report_hash")
        errors.append(
            "Slice 0 verifier cannot admit a qualified build without canonical "
            "offline evidence and DSSE verification"
        )
    else:
        errors.append(f"unknown build qualification mode: {mode}")

    if manifest["licensing"].get("qualification_status") != mode:
        errors.append("licensing qualification_status and build mode disagree")

    return errors


def validate_patch_entries(patch_entries: list[object]) -> list[str]:
    errors: list[str] = []
    for index, patch_entry in enumerate(patch_entries):
        if not isinstance(patch_entry, dict):
            errors.append(f"entry[{index}] is not an object")
            continue
        entry_id = patch_entry.get("id")
        label = (
            entry_id if isinstance(entry_id, str) and entry_id else f"entry[{index}]"
        )

        if not isinstance(entry_id, str) or not entry_id:
            errors.append(f"{label} has no non-empty id")
        classification = patch_entry.get("classification")
        if not isinstance(classification, str) or not classification:
            errors.append(f"{label} has no non-empty classification")

        for key in ("paths", "requirements", "verification"):
            value = patch_entry.get(key)
            if (
                not isinstance(value, list)
                or not value
                or any(not isinstance(item, str) or not item.strip() for item in value)
            ):
                errors.append(f"{label} has no non-empty {key} list")
            elif len(value) != len(set(value)):
                errors.append(f"{label} has duplicate {key}")

        paths = patch_entry.get("paths")
        if isinstance(paths, list):
            for path in paths:
                if not isinstance(path, str):
                    continue
                if Path(path).is_absolute() or ".." in Path(path).parts:
                    errors.append(f"{label} has unsafe path")
                if classification != "PMORG-owned" and ("*" in path or "?" in path):
                    errors.append(f"{label} non-PMORG ledger paths must be exact")

        reason = patch_entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"{label} has no non-empty reason")

    return errors


def validate_patch_ledger_contract(patch_ledger: PatchLedger) -> list[str]:
    errors: list[str] = []
    if set(patch_ledger) != REQUIRED_PATCH_LEDGER_KEYS:
        errors.append("patch ledger has incomplete or unknown top-level fields")
    if patch_ledger.get("schema_version") != "pmorg.platform.patch-ledger/v2":
        errors.append("patch ledger must use thin-fork schema v2")
    if patch_ledger.get("ownership_roots_ref") != EXPECTED_OWNERSHIP_ROOTS_REF:
        errors.append("patch ledger ownership_roots_ref is invalid")
    if patch_ledger.get("seam_allowlist_ref") != EXPECTED_SEAM_ALLOWLIST_REF:
        errors.append("patch ledger seam_allowlist_ref is invalid")
    if (
        patch_ledger.get("upstream_patch_record_schema_version")
        != EXPECTED_PATCH_RECORD_SCHEMA
    ):
        errors.append("patch ledger upstream patch record schema is invalid")
    records = patch_ledger.get("upstream_patch_records")
    if not isinstance(records, list):
        errors.append("patch ledger upstream_patch_records must be an array")
    elif any(not isinstance(record, dict) for record in records):
        errors.append("patch ledger upstream_patch_records must contain only objects")
    entries = patch_ledger.get("entries", [])
    requirement_union = {
        requirement
        for entry in entries
        if isinstance(entry, dict)
        for requirement in entry.get("requirements", [])
        if isinstance(requirement, str)
    }
    missing_requirements = sorted(
        set(EXPECTED_PLATFORM_REQUIREMENTS) - requirement_union
    )
    if missing_requirements:
        errors.append(
            "patch ledger does not trace required platform requirements: "
            + ", ".join(missing_requirements)
        )
    return errors


def validate_ownership_roots(policy: dict[str, object]) -> list[str]:
    errors: list[str] = []
    if set(policy) != REQUIRED_OWNERSHIP_POLICY_KEYS:
        errors.append("ownership roots policy has incomplete or unknown fields")
    if policy.get("schema_version") != EXPECTED_OWNERSHIP_POLICY_SCHEMA:
        errors.append("ownership roots policy has unexpected schema version")
    if policy.get("policy_phase") != EXPECTED_POLICY_PHASE:
        errors.append("ownership roots policy has unexpected phase")
    if policy.get("specification_commit") != EXPECTED_PMORG_SPEC_COMMIT:
        errors.append("ownership roots policy has unexpected specification pin")
    if policy.get("default_ownership") != "upstream_owned":
        errors.append("ownership roots must default to upstream_owned")
    if policy.get("invariants") != EXPECTED_OWNERSHIP_INVARIANTS:
        errors.append("ownership roots invariants are incomplete")
    roots = policy.get("roots")
    if not isinstance(roots, list) or not roots:
        return errors + ["ownership roots policy has no roots"]
    if roots != EXPECTED_OWNERSHIP_ROOTS:
        errors.append(
            "ownership root set must remain the exact reviewed governed boundary"
        )
    root_ids: list[str] = []
    patterns: list[str] = []
    for index, root in enumerate(roots):
        if not isinstance(root, dict):
            errors.append(f"ownership root[{index}] is not an object")
            continue
        root_id = root.get("root_id")
        pattern = root.get("path_pattern")
        ownership = root.get("ownership")
        if not isinstance(root_id, str) or not root_id:
            errors.append(f"ownership root[{index}] has no root_id")
        else:
            root_ids.append(root_id)
        if (
            not isinstance(pattern, str)
            or not pattern
            or Path(pattern).is_absolute()
            or ".." in Path(pattern).parts
        ):
            errors.append(f"ownership root[{index}] has unsafe path_pattern")
        else:
            patterns.append(pattern)
        if ownership not in {"pmorg_owned", "upstream_owned"}:
            errors.append(f"ownership root[{index}] has invalid ownership")
    if len(root_ids) != len(set(root_ids)):
        errors.append("ownership roots have duplicate root_id values")
    if len(patterns) != len(set(patterns)):
        errors.append("ownership roots have duplicate path patterns")
    return errors


def is_full_git_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def is_rfc3339_utc(value: object) -> bool:
    if not isinstance(value, str) or RFC3339_UTC_PATTERN.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return True


def protector_selector_exists_in_text(
    file_suffix: str, source_text: str, selector: str
) -> bool:
    # Slice 0.1 admits only statically collectible Python test nodes. Supporting
    # another runner requires a versioned parser rather than a comment-prone
    # source-text regex.
    if file_suffix != ".py":
        return False
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return False
    imports_unittest = any(
        isinstance(node, ast.Import)
        and any(alias.name == "unittest" for alias in node.names)
        for node in tree.body
    )
    imports_test_case = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "unittest"
        and any(alias.name == "TestCase" for alias in node.names)
        for node in tree.body
    )

    def is_unittest_case(node: ast.ClassDef) -> bool:
        return any(
            (
                imports_unittest
                and isinstance(base, ast.Attribute)
                and isinstance(base.value, ast.Name)
                and base.value.id == "unittest"
                and base.attr == "TestCase"
            )
            or (
                imports_test_case
                and isinstance(base, ast.Name)
                and base.id == "TestCase"
            )
            for base in node.bases
        )

    def can_run_without_skip(node: ast.FunctionDef) -> bool:
        forbidden_names = {
            "expectedFailure",
            "skip",
            "skipIf",
            "skipUnless",
            "skipTest",
            "SkipTest",
        }
        return not any(
            (
                isinstance(child, ast.Name)
                and child.id in forbidden_names
                or isinstance(child, ast.Attribute)
                and child.attr in forbidden_names
            )
            for child in ast.walk(node)
        )

    nodes: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            if not is_unittest_case(node):
                continue
            for child in node.body:
                if (
                    isinstance(child, ast.FunctionDef)
                    and child.name.startswith("test_")
                    and can_run_without_skip(child)
                ):
                    nodes.add(f"{node.name}.{child.name}")
    return selector in nodes


def protector_selector_exists(path: Path, selector: str) -> bool:
    try:
        source_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    return protector_selector_exists_in_text(path.suffix, source_text, selector)


def is_governance_protector_path(relative_path: str) -> bool:
    path = Path(relative_path)
    return (
        path.parent == Path("pmorg/tests")
        and path.name.startswith("test_")
        and path.suffix == ".py"
    )


def protector_test_executes_exactly_once(
    repository_root: Path,
    trusted_repository_root: Path,
    relative_path: str,
    selector: str,
) -> bool:
    """Run only the trusted protector source against candidate repository data."""

    try:
        trusted_test_path = resolve_policy_path(trusted_repository_root, relative_path)
    except ValueError:
        return False
    if worktree_regular_file_mode(trusted_test_path) is None:
        return False
    runner = """
import importlib.util
from pathlib import Path
import sys
import unittest

trusted_test_path = Path(sys.argv[1])
candidate_root = Path(sys.argv[2])
selector = sys.argv[3]
spec = importlib.util.spec_from_file_location("pmorg_trusted_protector", trusted_test_path)
if spec is None or spec.loader is None:
    raise SystemExit(1)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.REPOSITORY_ROOT = candidate_root
suite = unittest.defaultTestLoader.loadTestsFromName(selector, module)
result = unittest.TestResult()
suite.run(result)
valid = (
    result.testsRun == 1
    and not result.failures
    and not result.errors
    and not result.skipped
    and not result.expectedFailures
    and not result.unexpectedSuccesses
)
print("PMORG_PROTECTOR_PASS" if valid else "PMORG_PROTECTOR_FAIL")
raise SystemExit(0 if valid else 1)
"""
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                runner,
                str(trusted_test_path),
                str(repository_root.resolve()),
                selector,
            ],
            cwd=trusted_repository_root,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False
    return completed.returncode == 0 and completed.stdout.splitlines()[-1:] == [
        "PMORG_PROTECTOR_PASS"
    ]


def worktree_regular_file_mode(path: Path) -> str | None:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return None
    if not stat.S_ISREG(mode):
        return None
    executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    return "100755" if executable else "100644"


def git_file_bytes_at_revision(
    repository_root: Path, revision: str, relative_path: str
) -> bytes | None:
    completed = subprocess.run(
        ["git", "show", f"{revision}:{relative_path}"],
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    return completed.stdout if completed.returncode == 0 else None


def git_tree_sha256_at_revision(repository_root: Path, revision: str) -> str | None:
    completed = subprocess.run(
        ["git", "ls-tree", "-r", "-z", revision],
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        return None
    return "sha256:" + hashlib.sha256(completed.stdout).hexdigest()


def git_tree_entry_at_revision(
    repository_root: Path, revision: str, relative_path: str
) -> tuple[str, str] | None:
    completed = subprocess.run(
        [
            "git",
            "ls-tree",
            "-z",
            revision,
            "--",
            f":(literal){relative_path}",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0 or not completed.stdout:
        return None
    metadata, separator, _ = completed.stdout.partition(b"\t")
    parts = metadata.decode("ascii", errors="strict").split()
    if not separator or len(parts) != 3:
        return None
    mode, object_type, _object_id = parts
    return mode, object_type


def json_object_at_revision(
    repository_root: Path, revision: str, relative_path: str
) -> dict[str, object] | None:
    raw_bytes = git_file_bytes_at_revision(repository_root, revision, relative_path)
    if raw_bytes is None:
        return None
    try:
        value = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def seam_at_revision(
    repository_root: Path, revision: str, seam_id: str
) -> dict[str, object] | None:
    policy = json_object_at_revision(
        repository_root, revision, EXPECTED_SEAM_ALLOWLIST_REF
    )
    seams = policy.get("seams") if policy is not None else None
    if not isinstance(seams, list):
        return None
    matches = [
        cast(dict[str, object], seam)
        for seam in seams
        if isinstance(seam, dict) and seam.get("seam_id") == seam_id
    ]
    return matches[0] if len(matches) == 1 else None


def seams_at_revision(
    repository_root: Path, revision: str
) -> list[dict[str, object]] | None:
    policy = json_object_at_revision(
        repository_root, revision, EXPECTED_SEAM_ALLOWLIST_REF
    )
    seams = policy.get("seams") if policy is not None else None
    if not isinstance(seams, list) or any(not isinstance(seam, dict) for seam in seams):
        return None
    return [cast(dict[str, object], seam) for seam in seams]


def seam_for_path_at_revision(
    repository_root: Path, revision: str, path: str
) -> dict[str, object] | None:
    seams = seams_at_revision(repository_root, revision)
    if seams is None:
        return None
    matches = [seam for seam in seams if seam.get("path_pattern") == path]
    return matches[0] if len(matches) == 1 else None


def records_at_revision(
    repository_root: Path, revision: str
) -> list[dict[str, object]] | None:
    ledger = json_object_at_revision(
        repository_root, revision, "pmorg/patch-ledger.json"
    )
    records = ledger.get("upstream_patch_records") if ledger is not None else None
    if not isinstance(records, list) or any(
        not isinstance(record, dict) for record in records
    ):
        return None
    return [cast(dict[str, object], record) for record in records]


def record_for_path_at_revision(
    repository_root: Path, revision: str, path: str
) -> dict[str, object] | None:
    records = records_at_revision(repository_root, revision)
    if records is None:
        return None
    matches = [record for record in records if record.get("path") == path]
    return matches[0] if len(matches) == 1 else None


def patch_entries_at_revision(
    repository_root: Path, revision: str
) -> list[dict[str, object]] | None:
    ledger = json_object_at_revision(
        repository_root, revision, "pmorg/patch-ledger.json"
    )
    entries = ledger.get("entries") if ledger is not None else None
    if not isinstance(entries, list) or any(
        not isinstance(entry, dict) for entry in entries
    ):
        return None
    return [cast(dict[str, object], entry) for entry in entries]


def exact_patch_owner_for_path_at_revision(
    repository_root: Path, revision: str, path: str
) -> dict[str, object] | None:
    entries = patch_entries_at_revision(repository_root, revision)
    if entries is None:
        return None
    matches = [
        entry
        for entry in entries
        if isinstance(entry.get("paths"), list)
        and path in cast(list[object], entry["paths"])
    ]
    return matches[0] if len(matches) == 1 else None


def ledger_identifier_seen_at_or_before(
    repository_root: Path,
    revision: str,
    collection: str,
    identifier: str,
) -> bool:
    history = subprocess.run(
        [
            "git",
            "log",
            "--format=%H",
            revision,
            "--",
            "pmorg/patch-ledger.json",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if history.returncode != 0:
        return True
    for commit in history.stdout.splitlines():
        ledger = json_object_at_revision(
            repository_root, commit, "pmorg/patch-ledger.json"
        )
        values = ledger.get(collection) if ledger is not None else None
        if isinstance(values, list) and any(
            isinstance(value, dict) and value.get("id") == identifier
            for value in values
        ):
            return True
    return False


def seam_authorization_document(
    repository_root: Path, seam: dict[str, object]
) -> dict[str, object] | None:
    authorization_ref = seam.get("authorization_adr_ref")
    if not isinstance(authorization_ref, str):
        return None
    try:
        authorization_path = resolve_policy_path(repository_root, authorization_ref)
        return read_json_object(authorization_path, "seam authorization")
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def seam_authorization_at_authorized_commit(
    repository_root: Path, seam: dict[str, object]
) -> dict[str, object] | None:
    authorization_ref = seam.get("authorization_adr_ref")
    authorization_commit = seam.get("authorization_commit")
    if not isinstance(authorization_ref, str) or not is_full_git_sha(
        authorization_commit
    ):
        return None
    return json_object_at_revision(
        repository_root,
        cast(str, authorization_commit),
        authorization_ref,
    )


def seam_successor_authorization(
    repository_root: Path, seam: dict[str, object]
) -> dict[str, object] | None:
    authorization = seam_authorization_document(repository_root, seam)
    if (
        authorization is not None
        and authorization.get("schema_version")
        == EXPECTED_SEAM_SUCCESSOR_AUTHORIZATION_SCHEMA
    ):
        return authorization
    return None


def seam_successor_authorization_at_authorized_commit(
    repository_root: Path, seam: dict[str, object]
) -> dict[str, object] | None:
    authorization = seam_authorization_at_authorized_commit(repository_root, seam)
    if (
        authorization is not None
        and authorization.get("schema_version")
        == EXPECTED_SEAM_SUCCESSOR_AUTHORIZATION_SCHEMA
    ):
        return authorization
    return None


def git_commit_parents(repository_root: Path, commit: str) -> list[str] | None:
    completed = subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", commit],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    parts = completed.stdout.split()
    if not parts or parts[0] != commit:
        return None
    return parts[1:]


def git_is_ancestor(repository_root: Path, ancestor: str, descendant: str) -> bool:
    return (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=repository_root,
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )


def validate_committed_file_immutability(
    repository_root: Path,
    authorization_commit: str,
    relative_path: str,
    label: str,
) -> list[str]:
    """Reject every committed byte, mode, deletion, and restoration transition."""

    authorized_bytes = git_file_bytes_at_revision(
        repository_root, authorization_commit, relative_path
    )
    authorized_entry = git_tree_entry_at_revision(
        repository_root, authorization_commit, relative_path
    )
    if authorized_bytes is None or authorized_entry is None:
        return [f"{label} cannot establish authorized evidence"]
    history = subprocess.run(
        [
            "git",
            "rev-list",
            "--ancestry-path",
            "--full-history",
            f"{authorization_commit}..HEAD",
            "--",
            f":(literal){relative_path}",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if history.returncode != 0:
        return [f"{label} committed history cannot be reconstructed"]
    errors: list[str] = []
    for commit in history.stdout.splitlines():
        if (
            git_file_bytes_at_revision(repository_root, commit, relative_path)
            != authorized_bytes
            or git_tree_entry_at_revision(repository_root, commit, relative_path)
            != authorized_entry
        ):
            errors.append(f"{label} changed in committed history at {commit}")
    return errors


def validate_seam_evidence_history(
    seam: dict[str, object], repository_root: Path
) -> list[str]:
    authorization_commit = seam.get("authorization_commit")
    authorization_ref = seam.get("authorization_adr_ref")
    tests = seam.get("required_protector_tests")
    if not is_full_git_sha(authorization_commit):
        return []
    evidence_refs: list[tuple[str, str]] = []
    if isinstance(authorization_ref, str):
        evidence_refs.append((authorization_ref, "authorization ADR"))
    if isinstance(tests, list):
        for test_ref in tests:
            if not isinstance(test_ref, str):
                continue
            test_path, separator, _selector = test_ref.partition("::")
            if separator:
                evidence_refs.append((test_path, "protector test"))
    errors: list[str] = []
    for evidence_ref, evidence_kind in evidence_refs:
        errors.extend(
            validate_committed_file_immutability(
                repository_root,
                cast(str, authorization_commit),
                evidence_ref,
                f"{evidence_kind} {evidence_ref}",
            )
        )
    return errors


def validate_historical_seam_activation(
    seam: dict[str, object],
    index: int,
    repository_root: Path,
    ownership_policy: dict[str, object] | None,
    trusted_repository_root: Path,
    introduction_commit: str,
) -> list[str]:
    """Revalidate every generation's exact parent, ledger binding, and path state."""

    label = f"historical seam[{index}]"
    seam_id = seam.get("seam_id")
    path = seam.get("path_pattern")
    if not isinstance(seam_id, str) or not isinstance(path, str):
        return [f"{label} activation identity cannot be established"]
    parents = git_commit_parents(repository_root, introduction_commit)
    if parents is None or not parents:
        return [f"{label} introduction parent cannot be established"]
    introduction_parent = parents[0]
    errors: list[str] = []
    if seam.get("authorization_base_commit") != introduction_parent:
        errors.append(f"{label} authorization base is not its introduction parent")

    successor_authorization = seam_successor_authorization_at_authorized_commit(
        repository_root, seam
    )
    if successor_authorization is not None:
        successor_errors = validate_successor_seam_binding(
            seam,
            index,
            repository_root,
            ownership_policy,
            trusted_repository_root,
            introduction_parent,
        )
        errors.extend(
            f"{label} successor binding invalid: {error}" for error in successor_errors
        )

    record = record_for_path_at_revision(repository_root, introduction_commit, path)
    if record is None:
        errors.append(f"{label} exact patch record is absent at introduction")
        return errors
    errors.extend(validate_upstream_patch_record(record, seam, f"{label} patch record"))
    owner = exact_patch_owner_for_path_at_revision(
        repository_root, introduction_commit, path
    )
    if owner is None:
        errors.append(f"{label} exact ledger owner is absent at introduction")
    else:
        errors.extend(
            f"{label} ledger owner invalid: {error}"
            for error in validate_patch_entries([owner])
        )
        if owner.get("classification") != record.get("classification"):
            errors.append(
                f"{label} ledger owner classification differs from patch record"
            )
        if owner.get("paths") != [path]:
            errors.append(f"{label} ledger owner path set is not exact")
        requirements = owner.get("requirements")
        if not isinstance(requirements, list) or "PLT-004" not in requirements:
            errors.append(f"{label} ledger owner does not trace PLT-004")
    errors.extend(
        validate_atomic_seam_patch_introduction(
            repository_root,
            seam,
            record,
            owner,
            f"{label} patch record",
        )
    )
    return errors


def git_commits_touching_generation_since(
    repository_root: Path,
    start_commit: str,
    governed_path: str,
) -> list[str] | None:
    if not git_is_ancestor(repository_root, start_commit, "HEAD"):
        return None
    history = subprocess.run(
        [
            "git",
            "rev-list",
            "--ancestry-path",
            "--full-history",
            f"{start_commit}..HEAD",
            "--",
            f":(literal){EXPECTED_SEAM_ALLOWLIST_REF}",
            ":(literal)pmorg/patch-ledger.json",
            f":(literal){governed_path}",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return history.stdout.splitlines() if history.returncode == 0 else None


def validate_seam_generation_continuity(
    seam: dict[str, object],
    repository_root: Path,
    introduction_commit: str,
) -> list[str]:
    """Keep each generation exact everywhere it remains active in merged history."""

    seam_id = seam.get("seam_id")
    path = seam.get("path_pattern")
    label = f"historical seam {seam_id}"
    if not isinstance(seam_id, str) or not isinstance(path, str):
        return [f"{label} generation continuity identity cannot be established"]
    introduction_record = record_for_path_at_revision(
        repository_root, introduction_commit, path
    )
    introduction_owner = exact_patch_owner_for_path_at_revision(
        repository_root, introduction_commit, path
    )
    introduction_bytes = git_file_bytes_at_revision(
        repository_root, introduction_commit, path
    )
    introduction_entry = git_tree_entry_at_revision(
        repository_root, introduction_commit, path
    )
    if (
        introduction_record is None
        or introduction_owner is None
        or introduction_bytes is None
        or introduction_entry is None
    ):
        return [f"{label} generation baseline cannot be established"]

    generation_history = git_commits_touching_generation_since(
        repository_root, introduction_commit, path
    )
    errors: list[str] = []
    if generation_history is None:
        return [f"{label} generation history cannot be reconstructed"]
    for commit in generation_history:
        if seam_at_revision(repository_root, commit, seam_id) != seam:
            continue
        if (
            git_file_bytes_at_revision(repository_root, commit, path)
            != introduction_bytes
            or git_tree_entry_at_revision(repository_root, commit, path)
            != introduction_entry
        ):
            errors.append(
                f"{label} path bytes or mode changed before retirement at {commit}"
            )
        if (
            record_for_path_at_revision(repository_root, commit, path)
            != introduction_record
        ):
            errors.append(f"{label} patch record changed before retirement at {commit}")
        if (
            exact_patch_owner_for_path_at_revision(repository_root, commit, path)
            != introduction_owner
        ):
            errors.append(f"{label} ledger owner changed before retirement at {commit}")
    return errors


def first_seam_introduction_commit(repository_root: Path, seam_id: str) -> str | None:
    policy_history = subprocess.run(
        [
            "git",
            "rev-list",
            "--reverse",
            "--topo-order",
            "--full-history",
            "HEAD",
            "--",
            f":(literal){EXPECTED_SEAM_ALLOWLIST_REF}",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if policy_history.returncode != 0:
        return None
    return next(
        (
            commit
            for commit in policy_history.stdout.splitlines()
            if seam_at_revision(repository_root, commit, seam_id) is not None
        ),
        None,
    )


def validate_seam_authorization(
    seam: dict[str, object],
    index: int,
    repository_root: Path | None,
    ownership_policy: dict[str, object] | None,
    trusted_repository_root: Path | None = None,
    protected_base_sha: str | None = None,
) -> list[str]:
    errors: list[str] = []
    label = f"seam[{index}]"
    seam_id = seam.get("seam_id")
    pattern = seam.get("path_pattern")
    authorization_ref = seam.get("authorization_adr_ref")
    authorization_commit = seam.get("authorization_commit")
    authorization_base_commit = seam.get("authorization_base_commit")
    authorization_blob_hash = seam.get("authorization_blob_hash")
    classifications = seam.get("allowed_classifications")
    tests = seam.get("required_protector_tests")

    if not isinstance(authorization_ref, str) or not authorization_ref.strip():
        errors.append(f"{label} has no authorization_adr_ref")
    if not is_full_git_sha(authorization_commit):
        errors.append(f"{label} authorization_commit is not a full Git SHA")
    if not is_full_git_sha(authorization_base_commit):
        errors.append(f"{label} authorization_base_commit is not a full Git SHA")
    if not is_sha256(authorization_blob_hash):
        errors.append(f"{label} authorization_blob_hash is invalid")
    if repository_root is None or not isinstance(authorization_ref, str):
        return errors

    try:
        authorization_path = resolve_policy_path(repository_root, authorization_ref)
    except ValueError:
        return errors + [f"{label} authorization ADR reference is unsafe"]

    if not authorization_ref.startswith("pmorg/adr/"):
        errors.append(f"{label} authorization ADR must live under pmorg/adr")
    if authorization_path.suffix != ".json":
        errors.append(f"{label} authorization ADR must be machine-readable JSON")
    if not authorization_path.is_file():
        errors.append(f"{label} authorization ADR does not exist")
        return errors
    if ownership_policy is not None:
        authorization_owners = ownership_matches(authorization_ref, ownership_policy)
        if (
            len(authorization_owners) != 1
            or authorization_owners[0].get("ownership") != "pmorg_owned"
        ):
            errors.append(f"{label} authorization ADR is not PMORG-owned")

    authorization: dict[str, object] | None = None
    try:
        authorization = read_json_object(authorization_path, f"{label} authorization")
    except (OSError, ValueError, json.JSONDecodeError):
        errors.append(f"{label} authorization ADR is not a valid JSON object")
    else:
        authorization_schema = authorization.get("schema_version")
        expected_authorization_keys = (
            REQUIRED_SEAM_SUCCESSOR_AUTHORIZATION_KEYS
            if authorization_schema == EXPECTED_SEAM_SUCCESSOR_AUTHORIZATION_SCHEMA
            else REQUIRED_SEAM_AUTHORIZATION_KEYS
        )
        if set(authorization) != expected_authorization_keys:
            errors.append(f"{label} authorization ADR has incomplete or unknown fields")
        if authorization_schema not in {
            EXPECTED_SEAM_AUTHORIZATION_SCHEMA,
            EXPECTED_SEAM_SUCCESSOR_AUTHORIZATION_SCHEMA,
        }:
            errors.append(f"{label} authorization ADR has unexpected schema version")
        if authorization.get("status") != "accepted":
            errors.append(f"{label} authorization ADR is not accepted")
        if authorization.get("specification_commit") != EXPECTED_PMORG_SPEC_COMMIT:
            errors.append(f"{label} authorization ADR has wrong specification pin")
        if authorization.get("seam_id") != seam_id:
            errors.append(f"{label} authorization ADR binds another seam_id")
        if authorization.get("path") != pattern:
            errors.append(f"{label} authorization ADR binds another path")
        if authorization.get("allowed_classifications") != classifications:
            errors.append(f"{label} authorization ADR binds other classifications")
        if authorization.get("required_protector_tests") != tests:
            errors.append(f"{label} authorization ADR binds other protector tests")
        for field in ("decision_id", "authorized_at", "rationale"):
            if (
                not isinstance(authorization.get(field), str)
                or not cast(str, authorization[field]).strip()
            ):
                errors.append(f"{label} authorization ADR has no {field}")
        authorized_at = authorization.get("authorized_at")
        if isinstance(authorized_at, str) and not is_rfc3339_utc(authorized_at):
            errors.append(f"{label} authorization ADR authorized_at is not UTC")
        if authorization_schema == EXPECTED_SEAM_SUCCESSOR_AUTHORIZATION_SCHEMA:
            for field in (
                "transition_id",
                "successor_patch_record_id",
                "successor_ledger_entry_id",
            ):
                if (
                    not isinstance(authorization.get(field), str)
                    or not cast(str, authorization[field]).strip()
                ):
                    errors.append(f"{label} successor authorization has no {field}")
            target_blob_hash = authorization.get("target_blob_hash")
            target_git_mode = authorization.get("target_git_mode")
            if not is_sha256(target_blob_hash):
                errors.append(f"{label} successor target_blob_hash is invalid")
            if target_git_mode not in {"100644", "100755"}:
                errors.append(f"{label} successor target_git_mode is invalid")
            supersedes = authorization.get("supersedes")
            if not isinstance(supersedes, dict):
                errors.append(
                    f"{label} successor authorization has no supersedes object"
                )
            else:
                if set(supersedes) != REQUIRED_SEAM_SUCCESSOR_PREDECESSOR_KEYS:
                    errors.append(
                        f"{label} successor predecessor binding has incomplete or unknown fields"
                    )
                for field in (
                    "seam_id",
                    "patch_record_id",
                    "ledger_entry_id",
                    "authorization_adr_ref",
                ):
                    if (
                        not isinstance(supersedes.get(field), str)
                        or not cast(str, supersedes[field]).strip()
                    ):
                        errors.append(f"{label} successor predecessor has no {field}")
                if supersedes.get("seam_id") == seam_id:
                    errors.append(f"{label} successor cannot supersede itself")
                if supersedes.get("patched_blob_hash") == target_blob_hash:
                    errors.append(
                        f"{label} successor target must change predecessor bytes"
                    )
                if not is_sha256(supersedes.get("patched_blob_hash")):
                    errors.append(
                        f"{label} successor predecessor patched_blob_hash is invalid"
                    )
                if supersedes.get("patched_git_mode") not in {"100644", "100755"}:
                    errors.append(
                        f"{label} successor predecessor patched_git_mode is invalid"
                    )
                predecessor_authorization_ref = supersedes.get("authorization_adr_ref")
                if (
                    not isinstance(predecessor_authorization_ref, str)
                    or not predecessor_authorization_ref.startswith("pmorg/adr/")
                    or Path(predecessor_authorization_ref).suffix != ".json"
                    or Path(predecessor_authorization_ref).is_absolute()
                    or ".." in Path(predecessor_authorization_ref).parts
                ):
                    errors.append(
                        f"{label} successor predecessor authorization reference is unsafe"
                    )
                if not is_sha256(supersedes.get("authorization_blob_hash")):
                    errors.append(
                        f"{label} successor predecessor authorization hash is invalid"
                    )

    if (
        not is_full_git_sha(authorization_commit)
        or not is_full_git_sha(authorization_base_commit)
        or not is_sha256(authorization_blob_hash)
    ):
        return errors
    authorization_commit_text = cast(str, authorization_commit)
    authorization_base_commit_text = cast(str, authorization_base_commit)

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    authorization_precedes_base = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            authorization_commit_text,
            authorization_base_commit_text,
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    base_precedes_head = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            authorization_base_commit_text,
            "HEAD",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    if head.returncode != 0 or authorization_precedes_base.returncode != 0:
        errors.append(
            f"{label} authorization_commit is not on the authorized base history"
        )
        return errors
    if base_precedes_head.returncode != 0:
        errors.append(f"{label} authorization_base_commit is not an ancestor of HEAD")
        return errors
    if head.stdout.strip() == authorization_base_commit_text:
        errors.append(f"{label} authorization base must precede the seam change")
    trusted_seam_base_commit: str | None = None
    effective_protected_base_sha = (
        protected_base_sha
        if protected_base_sha is not None
        else os.environ.get("PMORG_PROTECTED_BASE_SHA")
    )
    if effective_protected_base_sha:
        if not is_full_git_sha(effective_protected_base_sha):
            errors.append(f"{label} PMORG_PROTECTED_BASE_SHA is not a full Git SHA")
        else:
            protected_base_commit = cast(str, effective_protected_base_sha)
            trusted_seam_base_commit = protected_base_commit
            protected_base_precedes_head = subprocess.run(
                [
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    protected_base_commit,
                    "HEAD",
                ],
                cwd=repository_root,
                check=False,
                capture_output=True,
            )
            authorization_base_precedes_protected_base = subprocess.run(
                [
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    authorization_base_commit_text,
                    protected_base_commit,
                ],
                cwd=repository_root,
                check=False,
                capture_output=True,
            )
            if protected_base_precedes_head.returncode != 0:
                errors.append(f"{label} protected PR base is not an ancestor of HEAD")
            if authorization_base_precedes_protected_base.returncode != 0:
                errors.append(
                    f"{label} authorization base is not on protected PR base history"
                )
            if isinstance(seam_id, str):
                protected_base_seam = seam_at_revision(
                    repository_root, protected_base_commit, seam_id
                )
                if protected_base_seam is None:
                    if protected_base_commit != authorization_base_commit_text:
                        errors.append(
                            f"{label} new seam authorization base differs from protected PR base"
                        )
                    introduction_commit = first_seam_introduction_commit(
                        repository_root, seam_id
                    )
                    introduction_parent = (
                        subprocess.run(
                            ["git", "rev-parse", f"{introduction_commit}^"],
                            cwd=repository_root,
                            check=False,
                            capture_output=True,
                            text=True,
                        )
                        if introduction_commit is not None
                        else None
                    )
                    if (
                        introduction_commit is None
                        or introduction_parent is None
                        or introduction_parent.returncode != 0
                        or introduction_parent.stdout.strip() != protected_base_commit
                    ):
                        errors.append(
                            f"{label} new seam must be introduced atomically on protected PR base"
                        )
                    elif (
                        seam_at_revision(repository_root, introduction_commit, seam_id)
                        != seam
                    ):
                        errors.append(
                            f"{label} new seam changed after its atomic introduction"
                        )
                elif protected_base_seam != seam:
                    errors.append(
                        f"{label} existing seam is immutable; authorize a new seam_id"
                    )
    else:
        origin_main = subprocess.run(
            ["git", "rev-parse", "refs/remotes/origin/main"],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if (
            origin_main.returncode != 0
            or origin_main.stdout.strip() != head.stdout.strip()
        ):
            errors.append(
                f"{label} PMORG_PROTECTED_BASE_SHA is required off origin/main"
            )
        elif isinstance(seam_id, str):
            trusted_seam_base_commit = authorization_base_commit_text
            introduction_commit = first_seam_introduction_commit(
                repository_root, seam_id
            )
            if introduction_commit is None:
                errors.append(f"{label} seam introduction commit cannot be established")
            else:
                introduction_parent = subprocess.run(
                    ["git", "rev-parse", f"{introduction_commit}^"],
                    cwd=repository_root,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if (
                    introduction_parent.returncode != 0
                    or introduction_parent.stdout.strip()
                    != authorization_base_commit_text
                ):
                    errors.append(
                        f"{label} authorization base is not the protected seam-introduction parent"
                    )
                introduction_seam = seam_at_revision(
                    repository_root, introduction_commit, seam_id
                )
                if introduction_seam != seam:
                    errors.append(
                        f"{label} existing seam changed after introduction; authorize a new seam_id"
                    )

    authorized_bytes = git_file_bytes_at_revision(
        repository_root, authorization_commit_text, authorization_ref
    )
    if authorized_bytes is None:
        errors.append(f"{label} authorization ADR is absent at authorization_commit")
        return errors
    actual_hash = "sha256:" + hashlib.sha256(authorized_bytes).hexdigest()
    if actual_hash != authorization_blob_hash:
        errors.append(f"{label} authorization ADR hash differs from authorized bytes")
    authorization_entry = git_tree_entry_at_revision(
        repository_root, authorization_commit_text, authorization_ref
    )
    if authorization_entry is None or authorization_entry not in {
        ("100644", "blob"),
        ("100755", "blob"),
    }:
        errors.append(f"{label} authorization ADR is not a regular Git file")
    current_authorization_entry = git_tree_entry_at_revision(
        repository_root, "HEAD", authorization_ref
    )
    if current_authorization_entry != authorization_entry:
        errors.append(f"{label} authorization ADR Git mode or type changed")
    if (
        authorization_entry is not None
        and worktree_regular_file_mode(authorization_path) != authorization_entry[0]
    ):
        errors.append(f"{label} authorization ADR worktree mode or type changed")
    if trusted_seam_base_commit is not None:
        base_authorization_bytes = git_file_bytes_at_revision(
            repository_root, trusted_seam_base_commit, authorization_ref
        )
        if base_authorization_bytes != authorized_bytes:
            errors.append(
                f"{label} authorization ADR was not preserved on protected seam base"
            )
        base_authorization_entry = git_tree_entry_at_revision(
            repository_root, trusted_seam_base_commit, authorization_ref
        )
        if base_authorization_entry != authorization_entry:
            errors.append(
                f"{label} authorization ADR mode or type was not preserved on protected seam base"
            )
    try:
        current_bytes = authorization_path.read_bytes()
    except OSError:
        errors.append(f"{label} authorization ADR cannot be read")
    else:
        if current_bytes != authorized_bytes:
            errors.append(f"{label} authorization ADR changed after authorization")

    protector_hashes = (
        authorization.get("protector_test_hashes")
        if isinstance(authorization, dict)
        else None
    )
    if isinstance(tests, list):
        if not isinstance(protector_hashes, dict) or set(protector_hashes) != set(
            test_ref for test_ref in tests if isinstance(test_ref, str)
        ):
            errors.append(f"{label} authorization ADR protector hashes are incomplete")
        for test_ref in tests:
            if not isinstance(test_ref, str):
                continue
            test_path_text, separator, selector = test_ref.partition("::")
            if not separator or not selector:
                continue
            authorized_test_bytes = git_file_bytes_at_revision(
                repository_root,
                authorization_commit_text,
                test_path_text,
            )
            if authorized_test_bytes is None:
                errors.append(
                    f"{label} protector test was absent at authorization_commit"
                )
                continue
            authorized_test_entry = git_tree_entry_at_revision(
                repository_root, authorization_commit_text, test_path_text
            )
            if authorized_test_entry is None or authorized_test_entry not in {
                ("100644", "blob"),
                ("100755", "blob"),
            }:
                errors.append(
                    f"{label} protector test was not a regular Git file at authorization_commit"
                )
            current_test_entry = git_tree_entry_at_revision(
                repository_root, "HEAD", test_path_text
            )
            if current_test_entry != authorized_test_entry:
                errors.append(f"{label} protector test Git mode or type changed")
            if trusted_seam_base_commit is not None:
                base_test_bytes = git_file_bytes_at_revision(
                    repository_root, trusted_seam_base_commit, test_path_text
                )
                if base_test_bytes != authorized_test_bytes:
                    errors.append(
                        f"{label} protector test was not preserved on protected seam base"
                    )
                base_test_entry = git_tree_entry_at_revision(
                    repository_root, trusted_seam_base_commit, test_path_text
                )
                if base_test_entry != authorized_test_entry:
                    errors.append(
                        f"{label} protector test mode or type was not preserved on protected seam base"
                    )
            expected_test_hash = (
                protector_hashes.get(test_ref)
                if isinstance(protector_hashes, dict)
                else None
            )
            authorized_test_hash = (
                "sha256:" + hashlib.sha256(authorized_test_bytes).hexdigest()
            )
            if not is_sha256(expected_test_hash):
                errors.append(f"{label} protector test authorization hash is invalid")
            elif expected_test_hash != authorized_test_hash:
                errors.append(
                    f"{label} protector test hash differs from authorized bytes"
                )
            try:
                current_test_path = resolve_policy_path(repository_root, test_path_text)
            except ValueError:
                errors.append(f"{label} protector test reference is unsafe")
                continue
            current_test_link_path = repository_root / Path(test_path_text)
            current_test_mode = worktree_regular_file_mode(current_test_link_path)
            if (
                authorized_test_entry is not None
                and current_test_mode != authorized_test_entry[0]
            ):
                errors.append(f"{label} protector test worktree mode or type changed")
            if current_test_mode is None:
                current_test_bytes = None
            else:
                try:
                    current_test_bytes = current_test_path.read_bytes()
                except OSError:
                    current_test_bytes = None
            if current_test_bytes != authorized_test_bytes:
                errors.append(f"{label} protector test changed after authorization")
            if trusted_repository_root is not None:
                try:
                    trusted_test_path = resolve_policy_path(
                        trusted_repository_root, test_path_text
                    )
                except ValueError:
                    errors.append(f"{label} trusted protector test reference is unsafe")
                else:
                    if worktree_regular_file_mode(trusted_test_path) is None:
                        errors.append(
                            f"{label} trusted protector test is not a regular file"
                        )
                    else:
                        try:
                            trusted_test_bytes = trusted_test_path.read_bytes()
                        except OSError:
                            errors.append(
                                f"{label} trusted protector test cannot be read"
                            )
                        else:
                            if trusted_test_bytes != authorized_test_bytes:
                                errors.append(
                                    f"{label} trusted protector test differs from authorized bytes"
                                )
            try:
                authorized_test_text = authorized_test_bytes.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(
                    f"{label} protector test was not UTF-8 at authorization_commit"
                )
                continue
            if not protector_selector_exists_in_text(
                Path(test_path_text).suffix, authorized_test_text, selector
            ):
                errors.append(
                    f"{label} protector test node was absent at authorization_commit"
                )
    return errors


def validate_successor_seam_binding(
    seam: dict[str, object],
    index: int,
    repository_root: Path,
    ownership_policy: dict[str, object] | None,
    trusted_repository_root: Path,
    protected_base_sha: str | None = None,
) -> list[str]:
    """Bind an active successor to the exact predecessor at its introduction parent."""

    errors: list[str] = []
    label = f"seam[{index}]"
    authorization = seam_successor_authorization_at_authorized_commit(
        repository_root, seam
    )
    if authorization is None:
        return errors
    seam_id = seam.get("seam_id")
    path = seam.get("path_pattern")
    supersedes = authorization.get("supersedes")
    if (
        not isinstance(seam_id, str)
        or not isinstance(path, str)
        or not isinstance(supersedes, dict)
    ):
        return [f"{label} successor identity cannot be established"]

    introduction_commit = first_seam_introduction_commit(repository_root, seam_id)
    if introduction_commit is None:
        return [f"{label} successor introduction commit cannot be established"]
    introduction_parent = subprocess.run(
        ["git", "rev-parse", f"{introduction_commit}^"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if introduction_parent.returncode != 0:
        return [f"{label} successor introduction parent cannot be established"]
    parent_commit = introduction_parent.stdout.strip()
    if seam.get("authorization_base_commit") != parent_commit:
        errors.append(
            f"{label} successor authorization base is not its introduction parent"
        )
    if protected_base_sha is not None and is_full_git_sha(protected_base_sha):
        base_seam = seam_at_revision(repository_root, protected_base_sha, seam_id)
        if base_seam is None and parent_commit != protected_base_sha:
            errors.append(
                f"{label} successor was not introduced atomically on protected PR base"
            )

    predecessor = seam_for_path_at_revision(repository_root, parent_commit, path)
    predecessor_id = supersedes.get("seam_id")
    if predecessor is None:
        errors.append(
            f"{label} successor has no exact active predecessor on its parent"
        )
        return errors
    if predecessor.get("seam_id") != predecessor_id:
        errors.append(f"{label} successor binds the wrong active predecessor")
    if predecessor.get("path_pattern") != path:
        errors.append(f"{label} successor changes predecessor path")
    if predecessor.get("allowed_classifications") != seam.get(
        "allowed_classifications"
    ):
        errors.append(f"{label} successor changes predecessor classifications")
    if predecessor.get("authorization_adr_ref") != supersedes.get(
        "authorization_adr_ref"
    ):
        errors.append(f"{label} successor binds the wrong predecessor ADR")
    if predecessor.get("authorization_blob_hash") != supersedes.get(
        "authorization_blob_hash"
    ):
        errors.append(f"{label} successor binds the wrong predecessor ADR hash")
    if (
        seam_at_revision(repository_root, introduction_commit, predecessor_id)
        is not None
    ):
        errors.append(f"{label} successor did not retire its predecessor atomically")

    predecessor_evidence_errors = validate_seam_authorization(
        predecessor,
        index,
        repository_root,
        ownership_policy,
        trusted_repository_root,
        parent_commit,
    )
    errors.extend(
        f"{label} predecessor evidence invalid: {error}"
        for error in predecessor_evidence_errors
    )
    return errors


def validate_seam_replacement_set(
    policy: dict[str, object],
    repository_root: Path,
    protected_base_sha: str | None,
) -> list[str]:
    """Reject retirement or same-path replacement without a pre-authorized successor."""

    if protected_base_sha is None or not is_full_git_sha(protected_base_sha):
        return []
    base_seams = seams_at_revision(repository_root, protected_base_sha)
    current_seams = policy.get("seams")
    if not isinstance(current_seams, list):
        return ["seam replacement set cannot be reconstructed from protected base"]
    if base_seams is None:
        base_seams = []
    current_objects = [
        cast(dict[str, object], seam)
        for seam in current_seams
        if isinstance(seam, dict)
    ]
    current_by_id = {
        cast(str, seam["seam_id"]): seam
        for seam in current_objects
        if isinstance(seam.get("seam_id"), str)
    }
    current_by_path = {
        cast(str, seam["path_pattern"]): seam
        for seam in current_objects
        if isinstance(seam.get("path_pattern"), str)
    }
    base_by_id = {
        cast(str, seam["seam_id"]): seam
        for seam in base_seams
        if isinstance(seam.get("seam_id"), str)
    }
    base_by_path = {
        cast(str, seam["path_pattern"]): seam
        for seam in base_seams
        if isinstance(seam.get("path_pattern"), str)
    }
    errors: list[str] = []

    for predecessor_id, predecessor in base_by_id.items():
        current_same_id = current_by_id.get(predecessor_id)
        if current_same_id is not None:
            if current_same_id != predecessor:
                errors.append(
                    f"existing seam is immutable on protected base: {predecessor_id}"
                )
            continue
        path = predecessor.get("path_pattern")
        successor = current_by_path.get(path) if isinstance(path, str) else None
        if successor is None:
            errors.append(
                f"active seam retirement requires an exact successor: {predecessor_id}"
            )
            continue
        authorization = seam_successor_authorization(repository_root, successor)
        supersedes = (
            authorization.get("supersedes") if isinstance(authorization, dict) else None
        )
        if not isinstance(supersedes, dict):
            errors.append(
                f"same-path seam replacement is not successor-authorized: {predecessor_id}"
            )
        elif supersedes.get("seam_id") != predecessor_id:
            errors.append(
                f"same-path seam replacement binds another predecessor: {predecessor_id}"
            )

    for seam_id, seam in current_by_id.items():
        if seam_id in base_by_id:
            continue
        path = seam.get("path_pattern")
        predecessor = base_by_path.get(path) if isinstance(path, str) else None
        is_successor = seam_successor_authorization(repository_root, seam) is not None
        if predecessor is not None and not is_successor:
            errors.append(
                f"new seam on occupied protected-base path requires successor authorization: {seam_id}"
            )
        if predecessor is None and is_successor:
            errors.append(
                f"successor seam has no predecessor on protected-base path: {seam_id}"
            )
    return errors


def validate_seam_history(
    policy: dict[str, object],
    repository_root: Path,
    ownership_policy: dict[str, object] | None,
    trusted_repository_root: Path,
) -> list[str]:
    """Reconstruct immutable seam generations and their preserved evidence."""

    errors: list[str] = []
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if shallow.returncode != 0:
        return ["seam history cannot be reconstructed"]
    if shallow.stdout.strip() == "true":
        return ["seam history requires a complete non-shallow repository"]
    history = subprocess.run(
        [
            "git",
            "rev-list",
            "--reverse",
            "--topo-order",
            "--full-history",
            "HEAD",
            "--",
            f":(literal){EXPECTED_SEAM_ALLOWLIST_REF}",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if history.returncode != 0 or not history.stdout.splitlines():
        return ["seam history cannot be reconstructed"]

    history_commits = history.stdout.splitlines()
    definitions: dict[str, dict[str, object]] = {}
    first_seen_order: dict[str, int] = {}
    first_seen_commit: dict[str, str] = {}
    seams_by_commit: dict[str, list[dict[str, object]]] = {}
    for order, commit in enumerate(history_commits):
        historical_seams = seams_at_revision(repository_root, commit)
        if historical_seams is None:
            errors.append(f"seam history is invalid at {commit}")
            continue
        seams_by_commit[commit] = historical_seams
        for seam in historical_seams:
            seam_id = seam.get("seam_id")
            if not isinstance(seam_id, str):
                continue
            existing = definitions.get(seam_id)
            if existing is not None and existing != seam:
                errors.append(f"historical seam definition mutated: {seam_id}")
            elif existing is None:
                definitions[seam_id] = seam
                first_seen_order[seam_id] = order
                first_seen_commit[seam_id] = commit

    for index, (seam_id, seam) in enumerate(
        sorted(definitions.items(), key=lambda item: first_seen_order[item[0]])
    ):
        historical_errors = validate_seam_authorization(
            seam,
            index,
            repository_root,
            ownership_policy,
            trusted_repository_root,
            first_seen_commit[seam_id],
        )
        errors.extend(
            f"historical seam {seam_id} evidence invalid: {error}"
            for error in historical_errors
        )
        evidence_history_errors = validate_seam_evidence_history(seam, repository_root)
        errors.extend(
            f"historical seam {seam_id} evidence invalid: {error}"
            for error in evidence_history_errors
        )
        errors.extend(
            validate_historical_seam_activation(
                seam,
                index,
                repository_root,
                ownership_policy,
                trusted_repository_root,
                first_seen_commit[seam_id],
            )
        )

    for commit in history_commits:
        current_generation = seams_by_commit.get(commit)
        if current_generation is None:
            continue
        current_by_id = {
            cast(str, seam["seam_id"]): seam
            for seam in current_generation
            if isinstance(seam.get("seam_id"), str)
        }
        current_paths = [
            cast(str, seam["path_pattern"])
            for seam in current_generation
            if isinstance(seam.get("path_pattern"), str)
        ]
        if len(current_by_id) != len(current_generation):
            errors.append(f"seam history has duplicate or invalid IDs at {commit}")
        if len(current_paths) != len(set(current_paths)):
            errors.append(f"seam history has duplicate paths at {commit}")
        parents = git_commit_parents(repository_root, commit)
        if parents is None:
            errors.append(f"seam history parents cannot be reconstructed at {commit}")
            continue
        parent_generations: list[tuple[str, list[dict[str, object]]]] = []
        for parent in parents:
            parent_bytes = git_file_bytes_at_revision(
                repository_root, parent, EXPECTED_SEAM_ALLOWLIST_REF
            )
            if parent_bytes is None:
                parent_generations.append((parent, []))
                continue
            parent_seams = seams_at_revision(repository_root, parent)
            if parent_seams is None:
                errors.append(f"seam history is invalid at parent {parent}")
                continue
            parent_generations.append((parent, parent_seams))

        transition_parents = parent_generations
        if len(parent_generations) > 1:
            if parent_generations[0][1] == current_generation:
                transition_parents = []
            else:
                transition_parents = parent_generations[:1]

        provenance_parent_id_union = {
            cast(str, seam["seam_id"])
            for _parent, parent_generation in parent_generations
            for seam in parent_generation
            if isinstance(seam.get("seam_id"), str)
        }
        for seam_id in set(current_by_id) - provenance_parent_id_union:
            if not transition_parents:
                continue
            introduction = first_seen_commit.get(seam_id)
            if introduction is None or introduction == commit:
                continue
            ancestor_parents = [
                parent
                for parent, _parent_generation in parent_generations
                if git_is_ancestor(repository_root, introduction, parent)
            ]
            if ancestor_parents:
                errors.append(f"historical seam ID resurrected at {commit}: {seam_id}")
            else:
                errors.append(
                    f"historical seam ID replayed on divergent history at {commit}: "
                    f"{seam_id}"
                )

        for parent, parent_generation in transition_parents:
            parent_by_id = {
                cast(str, seam["seam_id"]): seam
                for seam in parent_generation
                if isinstance(seam.get("seam_id"), str)
            }
            removed_ids = set(parent_by_id) - set(current_by_id)
            added_ids = set(current_by_id) - set(parent_by_id)
            added_successor_authorizations = {
                seam_id: seam_successor_authorization_at_authorized_commit(
                    repository_root, current_by_id[seam_id]
                )
                for seam_id in added_ids
            }
            for predecessor_id in removed_ids:
                successors = [
                    seam_id
                    for seam_id, authorization in added_successor_authorizations.items()
                    if isinstance(authorization, dict)
                    and isinstance(authorization.get("supersedes"), dict)
                    and cast(dict[str, object], authorization["supersedes"]).get(
                        "seam_id"
                    )
                    == predecessor_id
                ]
                if len(successors) != 1:
                    errors.append(
                        "historical seam retired without exact atomic successor "
                        f"at {commit} from parent {parent}: {predecessor_id}"
                    )
            for successor_id, authorization in added_successor_authorizations.items():
                if authorization is None:
                    continue
                supersedes = authorization.get("supersedes")
                predecessor_id = (
                    supersedes.get("seam_id") if isinstance(supersedes, dict) else None
                )
                if predecessor_id not in removed_ids:
                    errors.append(
                        "historical successor was not activated atomically with its "
                        f"predecessor at {commit} from parent {parent}: {successor_id}"
                    )

    edges: dict[str, list[str]] = {}
    transition_ids: dict[str, str] = {}
    target_hashes_by_path: dict[str, set[str]] = {}
    for seam_id, seam in sorted(
        definitions.items(), key=lambda item: first_seen_order[item[0]]
    ):
        authorization = seam_successor_authorization_at_authorized_commit(
            repository_root, seam
        )
        if authorization is None:
            continue
        transition_id = authorization.get("transition_id")
        if isinstance(transition_id, str):
            prior_transition_seam = transition_ids.get(transition_id)
            if prior_transition_seam is not None and prior_transition_seam != seam_id:
                errors.append(f"successor transition ID was replayed: {transition_id}")
            else:
                transition_ids[transition_id] = seam_id
        supersedes = authorization.get("supersedes")
        predecessor_id = (
            supersedes.get("seam_id") if isinstance(supersedes, dict) else None
        )
        if not isinstance(predecessor_id, str) or predecessor_id not in definitions:
            errors.append(
                f"successor seam has unknown historical predecessor: {seam_id}"
            )
            continue
        predecessor = definitions[predecessor_id]
        if predecessor.get("path_pattern") != seam.get("path_pattern"):
            errors.append(f"successor seam changes historical path: {seam_id}")
        if first_seen_commit[predecessor_id] == first_seen_commit[
            seam_id
        ] or not git_is_ancestor(
            repository_root,
            first_seen_commit[predecessor_id],
            first_seen_commit[seam_id],
        ):
            errors.append(
                f"successor seam precedes or resurrects its predecessor: {seam_id}"
            )
        edges.setdefault(predecessor_id, []).append(seam_id)
        path = seam.get("path_pattern")
        target_hash = authorization.get("target_blob_hash")
        predecessor_hash = (
            supersedes.get("patched_blob_hash")
            if isinstance(supersedes, dict)
            else None
        )
        if (
            isinstance(path, str)
            and isinstance(target_hash, str)
            and isinstance(predecessor_hash, str)
        ):
            prior_targets = target_hashes_by_path.setdefault(path, set())
            prior_targets.add(predecessor_hash)
            if target_hash in prior_targets:
                errors.append(f"successor seam replays historical bytes: {seam_id}")
            prior_targets.add(target_hash)

    for predecessor_id, successors in edges.items():
        if len(successors) != 1:
            errors.append(
                "historical seam has multiple successors: "
                + predecessor_id
                + " -> "
                + ", ".join(sorted(successors))
            )

    for seam_id, seam in definitions.items():
        errors.extend(
            validate_seam_generation_continuity(
                seam,
                repository_root,
                first_seen_commit[seam_id],
            )
        )

    for start in definitions:
        visited: set[str] = set()
        current = start
        while current in edges and len(edges[current]) == 1:
            if current in visited:
                errors.append(f"seam successor cycle detected at: {current}")
                break
            visited.add(current)
            current = edges[current][0]

    current_seams = policy.get("seams")
    current_ids = (
        {
            cast(str, seam["seam_id"])
            for seam in current_seams
            if isinstance(seam, dict) and isinstance(seam.get("seam_id"), str)
        }
        if isinstance(current_seams, list)
        else set()
    )
    for seam_id in definitions:
        successors = edges.get(seam_id, [])
        if seam_id not in current_ids and not successors:
            errors.append(f"historical seam retired without successor: {seam_id}")
        if seam_id in current_ids and successors:
            errors.append(f"non-terminal historical seam remains active: {seam_id}")
    return errors


def validate_seam_allowlist(
    policy: dict[str, object],
    repository_root: Path | None = None,
    ownership_policy: dict[str, object] | None = None,
    trusted_repository_root: Path | None = None,
    protected_base_sha: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if set(policy) != REQUIRED_SEAM_POLICY_KEYS:
        errors.append("seam allowlist has incomplete or unknown fields")
    if policy.get("schema_version") != EXPECTED_SEAM_POLICY_SCHEMA:
        errors.append("seam allowlist has unexpected schema version")
    if policy.get("admission_mode") != EXPECTED_POLICY_PHASE:
        errors.append("seam allowlist has unexpected admission mode")
    if policy.get("specification_commit") != EXPECTED_PMORG_SPEC_COMMIT:
        errors.append("seam allowlist has unexpected specification pin")
    if policy.get("default_decision") != "deny":
        errors.append("seam allowlist must default to deny")
    if policy.get("invariants") != EXPECTED_SEAM_INVARIANTS:
        errors.append("seam allowlist invariants are incomplete")
    seams = policy.get("seams")
    if not isinstance(seams, list):
        return errors + ["seam allowlist seams must be an array"]
    seam_ids: list[str] = []
    patterns: list[str] = []
    for index, seam in enumerate(seams):
        executable_protectors: list[tuple[str, str]] = []
        if not isinstance(seam, dict):
            errors.append(f"seam[{index}] is not an object")
            continue
        if set(seam) != REQUIRED_SEAM_KEYS:
            errors.append(f"seam[{index}] has incomplete or unknown fields")
        seam_id = seam.get("seam_id")
        pattern = seam.get("path_pattern")
        classifications = seam.get("allowed_classifications")
        tests = seam.get("required_protector_tests")
        reason = seam.get("reason")
        if isinstance(seam_id, str) and seam_id:
            seam_ids.append(seam_id)
        else:
            errors.append(f"seam[{index}] has no seam_id")
        if (
            isinstance(pattern, str)
            and pattern
            and not Path(pattern).is_absolute()
            and ".." not in Path(pattern).parts
            and "*" not in pattern
            and "?" not in pattern
        ):
            patterns.append(pattern)
        else:
            errors.append(f"seam[{index}] path_pattern must be a safe exact path")
        if (
            not isinstance(classifications, list)
            or not classifications
            or any(
                not isinstance(value, str)
                or value not in ALLOWED_CLASSIFICATIONS - {"PMORG-owned"}
                for value in classifications
            )
        ):
            errors.append(f"seam[{index}] has invalid allowed_classifications")
        elif len(classifications) != len(set(classifications)):
            errors.append(f"seam[{index}] has duplicate allowed_classifications")
        if (
            not isinstance(tests, list)
            or not tests
            or any(not isinstance(value, str) or not value for value in tests)
        ):
            errors.append(f"seam[{index}] has no protector tests")
        elif len(tests) != len(set(tests)):
            errors.append(f"seam[{index}] has duplicate protector tests")
        elif repository_root is not None:
            for test_ref in tests:
                test_path_text, separator, selector = test_ref.partition("::")
                if not separator or not selector:
                    errors.append(
                        f"seam[{index}] protector test is not an exact node reference"
                    )
                    continue
                if not is_governance_protector_path(test_path_text):
                    errors.append(
                        f"seam[{index}] protector test is outside governance discovery set"
                    )
                    continue
                try:
                    test_path = resolve_policy_path(repository_root, test_path_text)
                except ValueError:
                    errors.append(f"seam[{index}] protector test reference is unsafe")
                    continue
                candidate_test_path = repository_root / Path(test_path_text)
                if not candidate_test_path.exists():
                    errors.append(f"seam[{index}] protector test file does not exist")
                elif worktree_regular_file_mode(candidate_test_path) is None:
                    errors.append(
                        f"seam[{index}] protector test worktree mode or type changed"
                    )
                elif not test_path.is_file():
                    errors.append(f"seam[{index}] protector test file does not exist")
                elif not protector_selector_exists(test_path, selector):
                    errors.append(f"seam[{index}] protector test node does not exist")
                else:
                    executable_protectors.append((test_path_text, selector))
                if ownership_policy is not None:
                    test_owners = ownership_matches(test_path_text, ownership_policy)
                    if (
                        len(test_owners) != 1
                        or test_owners[0].get("ownership") != "pmorg_owned"
                    ):
                        errors.append(
                            f"seam[{index}] protector test is not PMORG-owned"
                        )
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"seam[{index}] has no reason")
        authorization_errors = validate_seam_authorization(
            seam,
            index,
            repository_root,
            ownership_policy,
            trusted_repository_root or repository_root,
            protected_base_sha,
        )
        errors.extend(authorization_errors)
        if repository_root is not None and not authorization_errors:
            errors.extend(
                validate_successor_seam_binding(
                    seam,
                    index,
                    repository_root,
                    ownership_policy,
                    trusted_repository_root or repository_root,
                    protected_base_sha,
                )
            )
            for test_path_text, selector in executable_protectors:
                if not protector_test_executes_exactly_once(
                    repository_root,
                    trusted_repository_root or repository_root,
                    test_path_text,
                    selector,
                ):
                    errors.append(
                        f"seam[{index}] protector test did not execute exactly once without skips"
                    )
    if len(seam_ids) != len(set(seam_ids)):
        errors.append("seam allowlist has duplicate seam_id values")
    if len(patterns) != len(set(patterns)):
        errors.append("seam allowlist has duplicate path patterns")
    if repository_root is not None:
        effective_protected_base_sha = (
            protected_base_sha
            if protected_base_sha is not None
            else os.environ.get("PMORG_PROTECTED_BASE_SHA")
        )
        errors.extend(
            validate_seam_replacement_set(
                policy, repository_root, effective_protected_base_sha
            )
        )
        errors.extend(
            validate_seam_history(
                policy,
                repository_root,
                ownership_policy,
                trusted_repository_root or repository_root,
            )
        )
    return errors


def ownership_matches(path: str, policy: dict[str, object]) -> list[dict[str, object]]:
    roots = policy.get("roots")
    if not isinstance(roots, list):
        return []
    return [
        cast(dict[str, object], root)
        for root in roots
        if isinstance(root, dict)
        and isinstance(root.get("path_pattern"), str)
        and path_matches_pattern(path, cast(str, root["path_pattern"]))
    ]


def seam_matches(path: str, policy: dict[str, object]) -> list[dict[str, object]]:
    seams = policy.get("seams")
    if not isinstance(seams, list):
        return []
    return [
        cast(dict[str, object], seam)
        for seam in seams
        if isinstance(seam, dict)
        and isinstance(seam.get("path_pattern"), str)
        and path_matches_pattern(path, cast(str, seam["path_pattern"]))
    ]


def is_pmorg_domain_path_under_upstream_root(path: str) -> bool:
    """Reject PMORG domain packages that bypass the bounded product roots."""

    return any(part.lower().startswith("pmorg") for part in Path(path).parts)


def validate_upstream_patch_record(
    record: dict[str, object],
    seam: dict[str, object],
    label: str,
    expected_upstream_commit: str | None = None,
    expected_upstream_tree_hash: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if set(record) != REQUIRED_UPSTREAM_PATCH_RECORD_KEYS:
        errors.append(f"{label} has incomplete or unknown fields")
    for key in (
        "id",
        "path",
        "seam_id",
        "classification",
        "reason",
        "owner",
        "last_revalidated_at",
        "conflict_notes",
    ):
        if not isinstance(record.get(key), str) or not cast(str, record[key]).strip():
            errors.append(f"{label} has no non-empty {key}")

    for key in (
        "requirement_refs",
        "capability_refs",
        "onyx_surfaces",
        "protector_tests",
    ):
        value = record.get(key)
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            errors.append(f"{label} has invalid {key} list")
        elif len(value) != len(set(value)):
            errors.append(f"{label} has duplicate {key}")

    requirement_refs = record.get("requirement_refs")
    capability_refs = record.get("capability_refs")
    if (
        isinstance(requirement_refs, list)
        and isinstance(capability_refs, list)
        and not requirement_refs
        and not capability_refs
    ):
        errors.append(f"{label} has no requirement or capability reference")
    if isinstance(requirement_refs, list) and "PLT-004" not in requirement_refs:
        errors.append(f"{label} does not trace PLT-004")

    classification = record.get("classification")
    allowed_classifications = seam.get("allowed_classifications")
    if (
        isinstance(allowed_classifications, list)
        and classification not in allowed_classifications
    ):
        errors.append(f"{label} classification is not allowed by its seam")
    if record.get("seam_id") != seam.get("seam_id"):
        errors.append(f"{label} seam_id does not match the allowlisted seam")

    source_ref = record.get("upstream_source_ref")
    if not isinstance(source_ref, dict):
        errors.append(f"{label} has no upstream_source_ref object")
    else:
        if set(source_ref) != REQUIRED_UPSTREAM_SOURCE_REF_KEYS:
            errors.append(f"{label} upstream_source_ref fields are incomplete")
        if source_ref.get("repository") != "https://github.com/onyx-dot-app/onyx.git":
            errors.append(
                f"{label} upstream_source_ref repository is not official Onyx"
            )
        source_commit = source_ref.get("commit")
        if (
            not isinstance(source_commit, str)
            or len(source_commit) != 40
            or any(character not in "0123456789abcdef" for character in source_commit)
        ):
            errors.append(f"{label} upstream_source_ref commit is not a full SHA")
        elif (
            expected_upstream_commit is not None
            and source_commit != expected_upstream_commit
        ):
            errors.append(f"{label} upstream_source_ref commit differs from baseline")
        if source_ref.get("path") != record.get("path"):
            errors.append(f"{label} upstream_source_ref path differs from record path")
        if not is_sha256(source_ref.get("tree_hash")):
            errors.append(f"{label} upstream_source_ref tree_hash is invalid")
        elif (
            expected_upstream_tree_hash is not None
            and source_ref.get("tree_hash") != expected_upstream_tree_hash
        ):
            errors.append(
                f"{label} upstream_source_ref tree_hash differs from pinned tree"
            )

    base_hash = record.get("base_blob_hash")
    patched_hash = record.get("patched_blob_hash")
    if base_hash is not None and not is_sha256(base_hash):
        errors.append(f"{label} base_blob_hash is not sha256 or null")
    if patched_hash is not None and not is_sha256(patched_hash):
        errors.append(f"{label} patched_blob_hash is not sha256 or null")
    if base_hash is None and patched_hash is None:
        errors.append(f"{label} cannot have both blob hashes null")
    if patched_hash is None:
        errors.append(f"{label} upstream seam patch cannot delete its path")

    official_url_patterns = {
        "upstream_issue_url": re.compile(
            r"^https://github\.com/onyx-dot-app/onyx/issues/[1-9]\d*$"
        ),
        "upstream_pr_url": re.compile(
            r"^https://github\.com/onyx-dot-app/onyx/pull/[1-9]\d*$"
        ),
    }
    for key, url_pattern in official_url_patterns.items():
        value = record.get(key)
        if value is not None and (
            not isinstance(value, str) or url_pattern.fullmatch(value) is None
        ):
            errors.append(f"{label} {key} must be an exact official Onyx URL or null")

    base_mode = record.get("base_git_mode")
    patched_mode = record.get("patched_git_mode")
    allowed_regular_modes = {"100644", "100755"}
    for field, mode, blob_hash in (
        ("base_git_mode", base_mode, base_hash),
        ("patched_git_mode", patched_mode, patched_hash),
    ):
        if mode is not None and mode not in allowed_regular_modes:
            errors.append(f"{label} {field} must be a regular-file mode or null")
        if (mode is None) != (blob_hash is None):
            errors.append(f"{label} {field} and its blob hash disagree on existence")

    ownership_class = record.get("ownership_class")
    license_class = record.get("license_class")
    surfaces = record.get("onyx_surfaces")
    record_path = record.get("path")
    is_enterprise_path = isinstance(record_path, str) and any(
        path_matches_pattern(record_path, pattern)
        for pattern in EXPECTED_ENTERPRISE_LICENSE_PATHS
    )
    if ownership_class == "upstream_ce_direct_patch":
        if is_enterprise_path:
            errors.append(f"{label} Enterprise path cannot claim CE patch ownership")
        if license_class != "mit-expat":
            errors.append(f"{label} CE direct patch must use mit-expat license_class")
        if not isinstance(surfaces, list) or tuple(surfaces) not in {
            ("ce",),
            ("ee",),
            ("ce", "ee"),
        }:
            errors.append(f"{label} CE direct patch has invalid Onyx surfaces")
    elif ownership_class == "upstream_ee_direct_patch":
        if not is_enterprise_path:
            errors.append(
                f"{label} EE patch ownership is outside declared Enterprise roots"
            )
        if license_class != "onyx-enterprise":
            errors.append(
                f"{label} EE direct patch must use onyx-enterprise license_class"
            )
        if surfaces != ["ee"]:
            errors.append(f"{label} EE direct patch is forbidden from CE surface")
    else:
        errors.append(f"{label} has invalid ownership_class")

    required_tests = seam.get("required_protector_tests")
    protector_tests = record.get("protector_tests")
    if (
        isinstance(required_tests, list)
        and isinstance(protector_tests, list)
        and all(isinstance(value, str) for value in required_tests)
        and all(isinstance(value, str) for value in protector_tests)
    ):
        if protector_tests != required_tests:
            errors.append(f"{label} protector tests differ from its seam")

    revalidated_at = record.get("last_revalidated_at")
    if isinstance(revalidated_at, str) and not is_rfc3339_utc(revalidated_at):
        errors.append(f"{label} last_revalidated_at must be RFC3339 UTC")

    removal_condition = record.get("removal_condition")
    if classification == "temporary":
        if not isinstance(removal_condition, str) or not removal_condition.strip():
            errors.append(f"{label} temporary patch requires a removal_condition")
    elif removal_condition is not None:
        errors.append(f"{label} non-temporary patch must keep removal_condition null")
    return errors


def blob_sha256_at_revision(
    repository_root: Path, revision: str, path: str
) -> str | None:
    completed = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        return None
    return "sha256:" + hashlib.sha256(completed.stdout).hexdigest()


def validate_atomic_seam_patch_introduction(
    repository_root: Path,
    seam: dict[str, object],
    record: dict[str, object],
    patch_entry: dict[str, object] | None,
    label: str,
) -> list[str]:
    errors: list[str] = []
    seam_id = seam.get("seam_id")
    path = record.get("path")
    if not isinstance(seam_id, str) or not isinstance(path, str):
        return [f"{label} atomic seam identity cannot be established"]
    introduction_commit = first_seam_introduction_commit(repository_root, seam_id)
    if introduction_commit is None:
        return [f"{label} atomic seam introduction commit cannot be established"]
    introduction_parent = subprocess.run(
        ["git", "rev-parse", f"{introduction_commit}^"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if introduction_parent.returncode != 0:
        return [f"{label} atomic seam introduction parent cannot be established"]
    parent_commit = introduction_parent.stdout.strip()
    successor_authorization = seam_successor_authorization_at_authorized_commit(
        repository_root, seam
    )
    supersedes = (
        successor_authorization.get("supersedes")
        if successor_authorization is not None
        else None
    )
    record_id = record.get("id")
    if isinstance(record_id, str) and ledger_identifier_seen_at_or_before(
        repository_root,
        parent_commit,
        "upstream_patch_records",
        record_id,
    ):
        errors.append(f"{label} patch record ID existed before atomic seam commit")

    introduction_ledger = json_object_at_revision(
        repository_root, introduction_commit, "pmorg/patch-ledger.json"
    )
    parent_ledger = json_object_at_revision(
        repository_root, parent_commit, "pmorg/patch-ledger.json"
    )
    introduction_records = (
        introduction_ledger.get("upstream_patch_records")
        if introduction_ledger is not None
        else None
    )
    exact_introduction_records = (
        [
            candidate
            for candidate in introduction_records
            if isinstance(candidate, dict)
            and candidate.get("seam_id") == seam_id
            and candidate.get("path") == path
        ]
        if isinstance(introduction_records, list)
        else []
    )
    if exact_introduction_records != [record]:
        errors.append(
            f"{label} exact patch record was not introduced atomically with seam"
        )

    parent_records = (
        parent_ledger.get("upstream_patch_records")
        if parent_ledger is not None
        else None
    )
    predecessor_record = record_for_path_at_revision(
        repository_root, parent_commit, path
    )
    if successor_authorization is None:
        if isinstance(parent_records, list) and any(
            isinstance(candidate, dict)
            and (candidate.get("seam_id") == seam_id or candidate.get("path") == path)
            for candidate in parent_records
        ):
            errors.append(f"{label} patch record existed before atomic seam commit")
    elif not isinstance(supersedes, dict):
        errors.append(f"{label} successor predecessor record cannot be established")
    elif predecessor_record is None:
        errors.append(f"{label} successor has no exact predecessor patch record")
    else:
        if predecessor_record.get("id") != supersedes.get("patch_record_id"):
            errors.append(f"{label} successor binds the wrong predecessor record")
        if predecessor_record.get("seam_id") != supersedes.get("seam_id"):
            errors.append(
                f"{label} predecessor record does not belong to predecessor seam"
            )
        if predecessor_record.get("patched_blob_hash") != supersedes.get(
            "patched_blob_hash"
        ):
            errors.append(f"{label} successor binds the wrong predecessor bytes")
        if predecessor_record.get("patched_git_mode") != supersedes.get(
            "patched_git_mode"
        ):
            errors.append(f"{label} successor binds the wrong predecessor mode")
        if record.get("id") != successor_authorization.get("successor_patch_record_id"):
            errors.append(f"{label} successor uses an unauthorized patch record ID")
        for field in (
            "path",
            "classification",
            "base_blob_hash",
            "base_git_mode",
            "upstream_source_ref",
            "ownership_class",
            "license_class",
            "onyx_surfaces",
        ):
            if record.get(field) != predecessor_record.get(field):
                errors.append(
                    f"{label} successor changes canonical predecessor field: {field}"
                )
        if record.get("patched_blob_hash") != successor_authorization.get(
            "target_blob_hash"
        ):
            errors.append(
                f"{label} successor patched bytes differ from authorized target"
            )
        if record.get("patched_git_mode") != successor_authorization.get(
            "target_git_mode"
        ):
            errors.append(
                f"{label} successor patched mode differs from authorized target"
            )

    entry_id = patch_entry.get("id") if patch_entry is not None else None
    if isinstance(entry_id, str) and ledger_identifier_seen_at_or_before(
        repository_root,
        parent_commit,
        "entries",
        entry_id,
    ):
        errors.append(f"{label} ledger owner ID existed before atomic seam commit")
    introduction_entries = (
        introduction_ledger.get("entries") if introduction_ledger is not None else None
    )
    introduction_entry = (
        next(
            (
                candidate
                for candidate in introduction_entries
                if isinstance(candidate, dict) and candidate.get("id") == entry_id
            ),
            None,
        )
        if isinstance(introduction_entries, list)
        else None
    )
    if patch_entry is None or introduction_entry != patch_entry:
        errors.append(
            f"{label} exact ledger owner was not introduced atomically with seam"
        )
    parent_entries = parent_ledger.get("entries") if parent_ledger is not None else None
    if successor_authorization is None:
        if isinstance(parent_entries, list) and any(
            isinstance(candidate, dict) and candidate.get("id") == entry_id
            for candidate in parent_entries
        ):
            errors.append(f"{label} ledger owner existed before atomic seam commit")
    elif isinstance(supersedes, dict):
        predecessor_owner = exact_patch_owner_for_path_at_revision(
            repository_root, parent_commit, path
        )
        if predecessor_owner is None:
            errors.append(f"{label} successor has no exact predecessor ledger owner")
        elif predecessor_owner.get("id") != supersedes.get("ledger_entry_id"):
            errors.append(f"{label} successor binds the wrong predecessor ledger owner")
        if entry_id != successor_authorization.get("successor_ledger_entry_id"):
            errors.append(f"{label} successor uses an unauthorized ledger owner ID")
        if isinstance(parent_entries, list) and any(
            isinstance(candidate, dict) and candidate.get("id") == entry_id
            for candidate in parent_entries
        ):
            errors.append(f"{label} successor ledger owner ID was reused")
        if isinstance(introduction_entries, list) and any(
            isinstance(candidate, dict)
            and candidate.get("id") == supersedes.get("ledger_entry_id")
            for candidate in introduction_entries
        ):
            errors.append(
                f"{label} successor did not retire predecessor ledger owner atomically"
            )

    introduction_blob = blob_sha256_at_revision(
        repository_root, introduction_commit, path
    )
    introduction_entry_state = git_tree_entry_at_revision(
        repository_root, introduction_commit, path
    )
    if introduction_blob != record.get("patched_blob_hash"):
        errors.append(f"{label} patched bytes were not introduced atomically with seam")
    if (
        introduction_entry_state is None
        or introduction_entry_state[1] != "blob"
        or introduction_entry_state[0] != record.get("patched_git_mode")
    ):
        errors.append(
            f"{label} patched Git mode/type was not introduced atomically with seam"
        )
    parent_blob = blob_sha256_at_revision(repository_root, parent_commit, path)
    parent_entry_state = git_tree_entry_at_revision(
        repository_root, parent_commit, path
    )
    expected_parent_mode = (
        parent_entry_state[0]
        if parent_entry_state is not None and parent_entry_state[1] == "blob"
        else None
    )
    if successor_authorization is None:
        if parent_blob != record.get("base_blob_hash"):
            errors.append(
                f"{label} seam parent bytes differ from recorded upstream base"
            )
        if expected_parent_mode != record.get("base_git_mode"):
            errors.append(
                f"{label} seam parent mode differs from recorded upstream base"
            )
    elif isinstance(supersedes, dict):
        if parent_blob != supersedes.get("patched_blob_hash"):
            errors.append(f"{label} seam parent bytes differ from predecessor record")
        if expected_parent_mode != supersedes.get("patched_git_mode"):
            errors.append(f"{label} seam parent mode differs from predecessor record")
        if introduction_blob == parent_blob:
            errors.append(f"{label} successor is a no-op")
    return errors


def validate_thin_fork_diff(
    changed_paths: list[str],
    patch_entries: list[object],
    upstream_patch_records: list[object],
    ownership_policy: dict[str, object],
    seam_policy: dict[str, object],
    repository_root: Path | None = None,
    upstream_commit: str | None = None,
) -> list[str]:
    errors: list[str] = []
    upstream_changed_paths: set[str] = set()
    records_by_path: dict[str, list[dict[str, object]]] = {}
    record_ids: list[str] = []
    for index, record in enumerate(upstream_patch_records):
        if not isinstance(record, dict):
            errors.append(f"upstream_patch_records[{index}] is not an object")
            continue
        record_id = record.get("id")
        if isinstance(record_id, str):
            record_ids.append(record_id)
        path = record.get("path")
        if isinstance(path, str):
            records_by_path.setdefault(path, []).append(record)
        else:
            errors.append(f"upstream_patch_records[{index}] has no string path")

    duplicate_record_ids = {
        record_id for record_id in record_ids if record_ids.count(record_id) > 1
    }
    if duplicate_record_ids:
        errors.append(
            "duplicate upstream patch record IDs: "
            + ", ".join(sorted(duplicate_record_ids))
        )

    patch_owners = find_path_owners(changed_paths, patch_entries)
    expected_upstream_tree_hash = (
        git_tree_sha256_at_revision(repository_root, upstream_commit)
        if repository_root is not None and upstream_commit is not None
        else None
    )
    governed_admission = (
        seam_policy.get("schema_version") == EXPECTED_SEAM_POLICY_SCHEMA
        and seam_policy.get("admission_mode") == EXPECTED_POLICY_PHASE
        and seam_policy.get("specification_commit") == EXPECTED_PMORG_SPEC_COMMIT
        and seam_policy.get("default_decision") == "deny"
        and seam_policy.get("invariants") == EXPECTED_SEAM_INVARIANTS
    )
    for path in changed_paths:
        roots = ownership_matches(path, ownership_policy)
        if len(roots) > 1:
            errors.append(f"path matches multiple ownership roots: {path}")
            continue
        ownership = (
            roots[0].get("ownership")
            if roots
            else ownership_policy.get("default_ownership")
        )
        records = records_by_path.get(path, [])

        if ownership == "pmorg_owned":
            if len(patch_owners[path]) == 0:
                errors.append(f"uncovered PMORG-owned fork path: {path}")
            elif len(patch_owners[path]) > 1:
                errors.append(
                    f"multiply-owned PMORG fork path: {path} ({', '.join(patch_owners[path])})"
                )
            else:
                matching_entry = next(
                    (
                        entry
                        for entry in patch_entries
                        if isinstance(entry, dict)
                        and isinstance(entry.get("paths"), list)
                        and any(
                            isinstance(pattern, str)
                            and path_matches_pattern(path, pattern)
                            for pattern in entry["paths"]
                        )
                    ),
                    None,
                )
                if (
                    matching_entry is not None
                    and matching_entry.get("classification") != "PMORG-owned"
                ):
                    errors.append(
                        f"PMORG-owned path must use PMORG-owned ledger classification: {path}"
                    )
            if records:
                errors.append(
                    f"PMORG-owned path cannot have an upstream patch record: {path}"
                )
            continue

        if ownership != "upstream_owned":
            errors.append(f"path has unknown ownership class: {path}")
            continue

        upstream_changed_paths.add(path)
        if not governed_admission:
            errors.append(
                f"upstream-owned changes require governed integration admission: {path}"
            )
        if is_pmorg_domain_path_under_upstream_root(path):
            errors.append(
                f"PMORG domain path is forbidden under an upstream-owned root: {path}"
            )

        owners = patch_owners[path]
        if len(owners) == 0:
            errors.append(f"uncovered upstream-owned fork path: {path}")
        elif len(owners) > 1:
            errors.append(
                f"multiply-owned upstream fork path: {path} ({', '.join(owners)})"
            )
        seams = seam_matches(path, seam_policy)
        if len(seams) != 1:
            errors.append(
                f"upstream-owned path requires exactly one allowlisted seam: {path}"
            )
            continue
        if len(records) != 1:
            errors.append(
                f"upstream-owned path requires exactly one upstream patch record: {path}"
            )
            continue
        record = records[0]
        label = (
            cast(str, record.get("id")) if isinstance(record.get("id"), str) else path
        )
        matching_entry = next(
            (
                entry
                for entry in patch_entries
                if isinstance(entry, dict)
                and isinstance(entry.get("paths"), list)
                and any(
                    isinstance(pattern, str) and path_matches_pattern(path, pattern)
                    for pattern in entry["paths"]
                )
            ),
            None,
        )
        if matching_entry is not None and matching_entry.get(
            "classification"
        ) != record.get("classification"):
            errors.append(f"{label} classification differs from its ledger owner")
        errors.extend(
            validate_upstream_patch_record(
                record,
                seams[0],
                label,
                expected_upstream_commit=upstream_commit,
                expected_upstream_tree_hash=expected_upstream_tree_hash,
            )
        )
        if repository_root is not None and upstream_commit is not None:
            errors.extend(
                validate_atomic_seam_patch_introduction(
                    repository_root,
                    seams[0],
                    record,
                    matching_entry,
                    label,
                )
            )
            expected_base = blob_sha256_at_revision(
                repository_root, upstream_commit, path
            )
            expected_patched = blob_sha256_at_revision(repository_root, "HEAD", path)
            base_entry = git_tree_entry_at_revision(
                repository_root, upstream_commit, path
            )
            patched_entry = git_tree_entry_at_revision(repository_root, "HEAD", path)
            expected_base_mode = base_entry[0] if base_entry is not None else None
            expected_patched_mode = (
                patched_entry[0] if patched_entry is not None else None
            )
            if record.get("base_blob_hash") != expected_base:
                errors.append(f"{label} base_blob_hash does not match upstream bytes")
            if record.get("patched_blob_hash") != expected_patched:
                errors.append(f"{label} patched_blob_hash does not match HEAD bytes")
            if record.get("base_git_mode") != expected_base_mode:
                errors.append(f"{label} base_git_mode does not match upstream tree")
            if record.get("patched_git_mode") != expected_patched_mode:
                errors.append(f"{label} patched_git_mode does not match HEAD tree")
            if base_entry is not None and base_entry[1] != "blob":
                errors.append(f"{label} upstream path is not a blob")
            if patched_entry is not None and patched_entry[1] != "blob":
                errors.append(f"{label} patched path is not a blob")

    for path, records in sorted(records_by_path.items()):
        if path not in upstream_changed_paths:
            errors.append(
                "upstream patch record does not name a changed upstream-owned "
                f"path: {path}"
            )
        if len(records) > 1:
            errors.append(f"duplicate upstream patch records for path: {path}")
    return errors


def validate_local_upstream(
    repository_root: Path, upstream: UpstreamManifest
) -> list[str]:
    errors: list[str] = []

    if upstream.get("release_tag") != "v4.3.9":
        errors.append("unexpected Onyx release tag")
    commit = upstream.get("commit")
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        errors.append("upstream commit is not a lowercase full SHA")
        return errors

    object_check = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if object_check.returncode != 0:
        errors.append("pinned upstream commit is absent from local history")
        return errors

    tag_check = subprocess.run(
        [
            "git",
            "show-ref",
            "--verify",
            "--quiet",
            f"refs/tags/{upstream['release_tag']}",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if tag_check.returncode == 0:
        release_commit = run_git(repository_root, "rev-parse", upstream["release_tag"])
        if release_commit != commit:
            errors.append(
                f"release tag resolves to {release_commit}, expected {commit}"
            )

    remote_names = run_git(repository_root, "remote").splitlines()
    checkout_remote = upstream.get("checkout_remote")
    if checkout_remote in remote_names:
        upstream_remote_url = run_git(
            repository_root, "remote", "get-url", checkout_remote
        )
        if upstream_remote_url != upstream.get("repository"):
            errors.append(
                f"upstream remote is {upstream_remote_url}, expected {upstream.get('repository')}"
            )

    return errors


def validate_specification_references(
    repository_root: Path, specification_commit: str
) -> list[str]:
    errors: list[str] = []
    for relative_path in ("PMORG.md", "plans/pmorg-v3-foundation.md"):
        content = (repository_root / relative_path).read_text(encoding="utf-8")
        if specification_commit not in content:
            errors.append(
                f"{relative_path} does not reference the pinned specification commit"
            )
    return errors


def verify(
    repository_root: Path,
    trusted_repository_root: Path = TRUSTED_REPOSITORY_ROOT,
    protected_base_sha: str | None = None,
) -> list[str]:
    errors: list[str] = []
    manifest = load_manifest(repository_root)
    patch_ledger = load_patch_ledger(repository_root)
    ownership_policy = load_ownership_roots(repository_root, patch_ledger)
    seam_policy = load_seam_allowlist(repository_root, patch_ledger)
    upstream = manifest["upstream"]
    specification = manifest["specification"]

    if run_git(repository_root, "status", "--porcelain"):
        errors.append("working tree is not clean")

    errors.extend(validate_local_upstream(repository_root, upstream))
    errors.extend(validate_patch_ledger_contract(patch_ledger))
    errors.extend(validate_ownership_roots(ownership_policy))
    errors.extend(
        validate_seam_allowlist(
            seam_policy,
            repository_root,
            ownership_policy,
            trusted_repository_root,
            protected_base_sha,
        )
    )

    if patch_ledger["upstream_commit"] != upstream["commit"]:
        errors.append("patch ledger and baseline manifest disagree on upstream commit")

    if specification["repository"] != "https://github.com/bmvv1995/PMORG.git":
        errors.append("unexpected PMORG specification repository")
    if specification["baseline"] != "RB-1/C2":
        errors.append("baseline manifest is not pinned to RB-1/C2")
    if len(specification["commit"]) != 40 or any(
        character not in "0123456789abcdef" for character in specification["commit"]
    ):
        errors.append("specification commit is not a lowercase full SHA")
    if patch_ledger["specification_commit"] != specification["commit"]:
        errors.append(
            "patch ledger and baseline manifest disagree on specification commit"
        )

    errors.extend(validate_surface_mode(manifest))
    errors.extend(validate_round_3_contract(manifest))
    errors.extend(validate_build_qualification_state(manifest))
    errors.extend(
        validate_specification_references(repository_root, specification["commit"])
    )

    ancestor_check = subprocess.run(
        ["git", "merge-base", "--is-ancestor", upstream["commit"], "HEAD"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if ancestor_check.returncode != 0:
        errors.append("pinned upstream commit is not an ancestor of HEAD")

    patch_entry_errors = validate_patch_entries(patch_ledger["entries"])
    errors.extend(patch_entry_errors)
    if patch_entry_errors:
        return errors

    ids = [entry["id"] for entry in patch_ledger["entries"] if "id" in entry]
    duplicate_ids = {entry_id for entry_id in ids if ids.count(entry_id) > 1}
    if duplicate_ids:
        errors.append(f"duplicate patch IDs: {', '.join(sorted(duplicate_ids))}")

    invalid_classifications = {
        cast(str, patch_entry.get("classification"))
        for patch_entry in patch_ledger["entries"]
        if patch_entry.get("classification") not in ALLOWED_CLASSIFICATIONS
    }
    if invalid_classifications:
        errors.append(
            "invalid patch classifications: "
            + ", ".join(sorted(invalid_classifications))
        )

    changed_paths = changed_paths_from_revision(repository_root, upstream["commit"])
    errors.extend(
        validate_thin_fork_diff(
            changed_paths,
            patch_ledger["entries"],
            patch_ledger["upstream_patch_records"],
            ownership_policy,
            seam_policy,
            repository_root,
            upstream["commit"],
        )
    )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a candidate PMORG fork using trusted governance code."
    )
    parser.add_argument(
        "--candidate-repository-root",
        type=Path,
        default=TRUSTED_REPOSITORY_ROOT,
        help="candidate repository root to inspect (default: verifier checkout)",
    )
    parser.add_argument(
        "--trusted-repository-root",
        type=Path,
        default=TRUSTED_REPOSITORY_ROOT,
        help="trusted checkout containing governance protector source",
    )
    parser.add_argument(
        "--protected-base-sha",
        help="trusted protected base for this candidate; overrides ambient PMORG_PROTECTED_BASE_SHA",
    )
    arguments = parser.parse_args()
    repository_root = arguments.candidate_repository_root.resolve()
    trusted_repository_root = arguments.trusted_repository_root.resolve()
    try:
        errors = verify(
            repository_root,
            trusted_repository_root,
            arguments.protected_base_sha,
        )
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print(
        "PASS: fork baseline, round-3 bootstrap and thin-fork policies are consistent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
