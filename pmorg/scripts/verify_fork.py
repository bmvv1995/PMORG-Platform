#!/usr/bin/env python3

from __future__ import annotations

import fnmatch
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import cast
from typing import TypedDict


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
        "root_id": "pmorg-plans",
        "path_pattern": "plans/**",
        "ownership": "pmorg_owned",
    },
    {
        "root_id": "pmorg-governance-and-product",
        "path_pattern": "pmorg/**",
        "ownership": "pmorg_owned",
    },
]
EXPECTED_OWNERSHIP_INVARIANTS = {
    "overlapping_roots_forbidden": True,
    "pmorg_domain_allowed_only_in_pmorg_owned_roots": True,
}
EXPECTED_SEAM_INVARIANTS = {
    "slice_zero_upstream_changes_forbidden": True,
    "upstream_owned_change_requires_exactly_one_allowlisted_seam": True,
    "upstream_owned_change_requires_exactly_one_patch_record": True,
    "pmorg_domain_in_upstream_owned_roots_forbidden": True,
}
REQUIRED_UPSTREAM_PATCH_RECORD_KEYS = {
    "id",
    "path",
    "seam_id",
    "classification",
    "base_blob_hash",
    "patched_blob_hash",
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
    "allowed_classifications",
    "required_protector_tests",
    "reason",
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
    if licensing.get("enterprise_license_paths") != [
        "backend/ee/**",
        "web/src/app/ee/**",
        "web/src/ee/**",
    ]:
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

        reason = patch_entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"{label} has no non-empty reason")

    return errors


def validate_patch_ledger_contract(patch_ledger: PatchLedger) -> list[str]:
    errors: list[str] = []
    if patch_ledger.get("schema_version") != "pmorg.platform.patch-ledger/v2":
        errors.append("patch ledger must use thin-fork schema v2")
    if patch_ledger.get("ownership_roots_ref") != EXPECTED_OWNERSHIP_ROOTS_REF:
        errors.append("patch ledger ownership_roots_ref is invalid")
    if patch_ledger.get("seam_allowlist_ref") != EXPECTED_SEAM_ALLOWLIST_REF:
        errors.append("patch ledger seam_allowlist_ref is invalid")
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
    if policy.get("schema_version") != "pmorg.platform.ownership-roots/v1":
        errors.append("ownership roots policy has unexpected schema version")
    if policy.get("default_ownership") != "upstream_owned":
        errors.append("ownership roots must default to upstream_owned")
    if policy.get("invariants") != EXPECTED_OWNERSHIP_INVARIANTS:
        errors.append("ownership roots invariants are incomplete")
    roots = policy.get("roots")
    if not isinstance(roots, list) or not roots:
        return errors + ["ownership roots policy has no roots"]
    if roots != EXPECTED_OWNERSHIP_ROOTS:
        errors.append(
            "ownership root set must remain the exact reviewed Slice 0 boundary"
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


def validate_seam_allowlist(policy: dict[str, object]) -> list[str]:
    errors: list[str] = []
    if policy.get("schema_version") != "pmorg.platform.seam-allowlist/v1":
        errors.append("seam allowlist has unexpected schema version")
    if policy.get("default_decision") != "deny":
        errors.append("seam allowlist must default to deny")
    if policy.get("invariants") != EXPECTED_SEAM_INVARIANTS:
        errors.append("seam allowlist invariants are incomplete")
    seams = policy.get("seams")
    if not isinstance(seams, list):
        return errors + ["seam allowlist seams must be an array"]
    if seams:
        errors.append("Slice 0 seam allowlist must remain empty")
    seam_ids: list[str] = []
    patterns: list[str] = []
    for index, seam in enumerate(seams):
        if not isinstance(seam, dict):
            errors.append(f"seam[{index}] is not an object")
            continue
        if set(seam) != REQUIRED_SEAM_KEYS:
            errors.append(f"seam[{index}] has incomplete or unknown fields")
        seam_id = seam.get("seam_id")
        pattern = seam.get("path_pattern")
        authorization_adr_ref = seam.get("authorization_adr_ref")
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
        ):
            patterns.append(pattern)
        else:
            errors.append(f"seam[{index}] has unsafe path_pattern")
        if (
            not isinstance(authorization_adr_ref, str)
            or not authorization_adr_ref.strip()
        ):
            errors.append(f"seam[{index}] has no authorization_adr_ref")
        if (
            not isinstance(classifications, list)
            or not classifications
            or any(
                value not in ALLOWED_CLASSIFICATIONS - {"PMORG-owned"}
                for value in classifications
            )
        ):
            errors.append(f"seam[{index}] has invalid allowed_classifications")
        if (
            not isinstance(tests, list)
            or not tests
            or any(not isinstance(value, str) or not value for value in tests)
        ):
            errors.append(f"seam[{index}] has no protector tests")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"seam[{index}] has no reason")
    if len(seam_ids) != len(set(seam_ids)):
        errors.append("seam allowlist has duplicate seam_id values")
    if len(patterns) != len(set(patterns)):
        errors.append("seam allowlist has duplicate path patterns")
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


def validate_upstream_patch_record(
    record: dict[str, object],
    seam: dict[str, object],
    label: str,
    expected_upstream_commit: str | None = None,
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

    base_hash = record.get("base_blob_hash")
    patched_hash = record.get("patched_blob_hash")
    if base_hash is not None and not is_sha256(base_hash):
        errors.append(f"{label} base_blob_hash is not sha256 or null")
    if patched_hash is not None and not is_sha256(patched_hash):
        errors.append(f"{label} patched_blob_hash is not sha256 or null")
    if base_hash is None and patched_hash is None:
        errors.append(f"{label} cannot have both blob hashes null")

    for key in ("upstream_issue_url", "upstream_pr_url"):
        value = record.get(key)
        if value is not None and (
            not isinstance(value, str)
            or not value.startswith("https://github.com/onyx-dot-app/onyx/")
        ):
            errors.append(f"{label} {key} must be an official Onyx URL or null")

    ownership_class = record.get("ownership_class")
    license_class = record.get("license_class")
    surfaces = record.get("onyx_surfaces")
    if ownership_class == "upstream_ce_direct_patch":
        if license_class != "mit-expat":
            errors.append(f"{label} CE direct patch must use mit-expat license_class")
        if not isinstance(surfaces, list) or tuple(surfaces) not in {
            ("ce",),
            ("ee",),
            ("ce", "ee"),
        }:
            errors.append(f"{label} CE direct patch has invalid Onyx surfaces")
    elif ownership_class == "upstream_ee_direct_patch":
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
    if isinstance(required_tests, list) and isinstance(protector_tests, list):
        missing_tests = sorted(set(required_tests) - set(protector_tests))
        if missing_tests:
            errors.append(
                f"{label} misses seam protector tests: {', '.join(missing_tests)}"
            )

    revalidated_at = record.get("last_revalidated_at")
    if isinstance(revalidated_at, str) and (
        "T" not in revalidated_at or not revalidated_at.endswith("Z")
    ):
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
        errors.append(
            "Slice 0 forbids upstream-owned changes until canonical boundary "
            f"evidence admission exists: {path}"
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
        errors.extend(
            validate_upstream_patch_record(
                record,
                seams[0],
                label,
                expected_upstream_commit=upstream_commit,
            )
        )
        if repository_root is not None and upstream_commit is not None:
            expected_base = blob_sha256_at_revision(
                repository_root, upstream_commit, path
            )
            expected_patched = blob_sha256_at_revision(repository_root, "HEAD", path)
            if record.get("base_blob_hash") != expected_base:
                errors.append(f"{label} base_blob_hash does not match upstream bytes")
            if record.get("patched_blob_hash") != expected_patched:
                errors.append(f"{label} patched_blob_hash does not match HEAD bytes")

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


def verify(repository_root: Path) -> list[str]:
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
    errors.extend(validate_seam_allowlist(seam_policy))

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

    changed_output = run_git(
        repository_root, "diff", "--name-only", f"{upstream['commit']}..HEAD"
    )
    changed_paths = changed_output.splitlines() if changed_output else []
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
    repository_root = Path(__file__).resolve().parents[2]
    try:
        errors = verify(repository_root)
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
