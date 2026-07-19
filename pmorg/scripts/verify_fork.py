#!/usr/bin/env python3

from __future__ import annotations

import fnmatch
import json
import subprocess
import sys
from pathlib import Path
from typing import TypedDict, cast


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
    ee_development_test_policy: str
    ee_production_policy: str
    capability_disposition_policy: str


class BuildManifest(TypedDict):
    mode: str
    onyx_surface: str | None
    usage_mode: str | None


class BaselineManifest(TypedDict):
    upstream: UpstreamManifest
    specification: SpecificationManifest
    licensing: LicensingManifest
    build: BuildManifest


class PatchEntry(TypedDict):
    id: str
    classification: str
    paths: list[str]
    requirements: list[str]
    reason: str
    verification: list[str]


class PatchLedger(TypedDict):
    upstream_commit: str
    specification_commit: str
    entries: list[PatchEntry]


ALLOWED_CLASSIFICATIONS = {
    "PMORG-owned",
    "integration",
    "upstream-candidate",
    "temporary",
}

EXPECTED_ONYX_SURFACES = ["ce", "ee"]
EXPECTED_USAGE_MODES = ["development_test", "production"]
EXPECTED_LICENSING_POLICIES = {
    "artifact_policy": "declared_onyx_surface_and_usage_mode",
    "qualification_status": "pending_surface_mode_selection",
    "ce_surface_policy": "exclude_onyx_ee_code",
    "ee_surface_policy": "complete_inventory_required_all_usage_modes",
    "ee_development_test_policy": (
        "signed_synthetic_admission_and_production_distribution_guard_required"
    ),
    "ee_production_policy": (
        "signed_commercial_authorization_bound_to_build_and_target_required_fail_closed"
    ),
    "capability_disposition_policy": (
        "versioned_catalog_complete_reuse_patch_pmorg_independent_report"
    ),
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


def load_manifest(repository_root: Path) -> BaselineManifest:
    value = read_json(repository_root / "pmorg" / "baseline-manifest.json")
    if not isinstance(value, dict) or not isinstance(value.get("upstream"), dict):
        raise ValueError("baseline manifest has no upstream object")
    if not isinstance(value.get("specification"), dict):
        raise ValueError("baseline manifest has no specification object")
    if not isinstance(value.get("licensing"), dict):
        raise ValueError("baseline manifest has no licensing object")
    if not isinstance(value.get("build"), dict):
        raise ValueError("baseline manifest has no build object")
    return cast(BaselineManifest, value)


def load_patch_ledger(repository_root: Path) -> PatchLedger:
    value = read_json(repository_root / "pmorg" / "patch-ledger.json")
    if not isinstance(value, dict) or not isinstance(value.get("entries"), list):
        raise ValueError("patch ledger has no entries array")
    return cast(PatchLedger, value)


def path_matches_pattern(path: str, pattern: str) -> bool:
    """Match ledger globs while treating brackets as literal path characters."""

    literal_bracket_pattern = pattern.replace("[", "[[]")
    return fnmatch.fnmatchcase(path, literal_bracket_pattern)


def find_path_owners(
    changed_paths: list[str], patch_entries: list[PatchEntry]
) -> dict[str, list[str]]:
    return {
        changed_path: [
            patch_entry["id"]
            for patch_entry in patch_entries
            if any(
                path_matches_pattern(changed_path, pattern)
                for pattern in patch_entry["paths"]
            )
        ]
        for changed_path in changed_paths
    }


def find_uncovered_paths(
    changed_paths: list[str], patch_entries: list[PatchEntry]
) -> list[str]:
    return [
        path
        for path, owners in find_path_owners(changed_paths, patch_entries).items()
        if not owners
    ]


def validate_surface_mode(manifest: BaselineManifest) -> list[str]:
    errors: list[str] = []
    licensing = manifest["licensing"]
    build = manifest["build"]

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


def validate_patch_entries(patch_entries: list[PatchEntry]) -> list[str]:
    errors: list[str] = []
    for index, patch_entry in enumerate(patch_entries):
        entry_id = patch_entry.get("id")
        label = entry_id if isinstance(entry_id, str) and entry_id else f"entry[{index}]"

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
        ["git", "show-ref", "--verify", "--quiet", f"refs/tags/{upstream['release_tag']}"],
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
                f"upstream remote is {upstream_remote_url}, "
                f"expected {upstream.get('repository')}"
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
    upstream = manifest["upstream"]
    specification = manifest["specification"]

    working_tree_status = run_git(repository_root, "status", "--porcelain")
    if working_tree_status:
        errors.append("working tree is not clean")

    errors.extend(validate_local_upstream(repository_root, upstream))

    if patch_ledger["upstream_commit"] != upstream["commit"]:
        errors.append("patch ledger and baseline manifest disagree on upstream commit")

    if specification["repository"] != "https://github.com/bmvv1995/PMORG.git":
        errors.append("unexpected PMORG specification repository")
    if specification["baseline"] != "RB-1/C2":
        errors.append("baseline manifest is not pinned to RB-1/C2")
    if (
        len(specification["commit"]) != 40
        or any(
            character not in "0123456789abcdef"
            for character in specification["commit"]
        )
    ):
        errors.append("specification commit is not a lowercase full SHA")
    if patch_ledger["specification_commit"] != specification["commit"]:
        errors.append(
            "patch ledger and baseline manifest disagree on specification commit"
        )

    errors.extend(validate_surface_mode(manifest))
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

    duplicate_ids = {
        patch_entry["id"]
        for patch_entry in patch_ledger["entries"]
        if sum(
            candidate["id"] == patch_entry["id"]
            for candidate in patch_ledger["entries"]
        )
        > 1
    }
    if duplicate_ids:
        errors.append(f"duplicate patch IDs: {', '.join(sorted(duplicate_ids))}")

    invalid_classifications = {
        patch_entry["classification"]
        for patch_entry in patch_ledger["entries"]
        if patch_entry["classification"] not in ALLOWED_CLASSIFICATIONS
    }
    if invalid_classifications:
        errors.append(
            "invalid patch classifications: "
            + ", ".join(sorted(invalid_classifications))
        )

    changed_output = run_git(
        repository_root,
        "diff",
        "--name-only",
        f"{upstream['commit']}..HEAD",
    )
    changed_paths = changed_output.splitlines() if changed_output else []
    uncovered_paths = find_uncovered_paths(changed_paths, patch_ledger["entries"])
    if uncovered_paths:
        errors.append("uncovered fork paths: " + ", ".join(uncovered_paths))

    multiply_owned_paths = {
        path: owners
        for path, owners in find_path_owners(
            changed_paths, patch_ledger["entries"]
        ).items()
        if len(owners) > 1
    }
    if multiply_owned_paths:
        rendered_paths = "; ".join(
            f"{path} ({', '.join(owners)})"
            for path, owners in sorted(multiply_owned_paths.items())
        )
        errors.append("multiply-owned fork paths: " + rendered_paths)

    return errors


def main() -> int:
    repository_root = Path(__file__).resolve().parents[2]
    errors = verify(repository_root)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("PASS: fork baseline and patch ledger are consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
