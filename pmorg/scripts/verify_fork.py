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


class BaselineManifest(TypedDict):
    upstream: UpstreamManifest
    specification: SpecificationManifest


class PatchEntry(TypedDict):
    id: str
    classification: str
    paths: list[str]


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


def verify(repository_root: Path) -> list[str]:
    errors: list[str] = []
    manifest = load_manifest(repository_root)
    patch_ledger = load_patch_ledger(repository_root)
    upstream = manifest["upstream"]
    specification = manifest["specification"]

    working_tree_status = run_git(repository_root, "status", "--porcelain")
    if working_tree_status:
        errors.append("working tree is not clean")

    release_commit = run_git(repository_root, "rev-parse", upstream["release_tag"])
    if release_commit != upstream["commit"]:
        errors.append(
            f"release tag resolves to {release_commit}, expected {upstream['commit']}"
        )

    upstream_remote_url = run_git(
        repository_root, "remote", "get-url", upstream["checkout_remote"]
    )
    if upstream_remote_url != upstream["repository"]:
        errors.append(
            f"upstream remote is {upstream_remote_url}, expected {upstream['repository']}"
        )

    if patch_ledger["upstream_commit"] != upstream["commit"]:
        errors.append("patch ledger and baseline manifest disagree on upstream commit")

    if specification["repository"] != "https://github.com/bmvv1995/PMORG.git":
        errors.append("unexpected PMORG specification repository")
    if specification["baseline"] != "RB-1/C2":
        errors.append("baseline manifest is not pinned to RB-1/C2")
    if (
        len(specification["commit"]) != 40
        or any(character not in "0123456789abcdef" for character in specification["commit"])
    ):
        errors.append("specification commit is not a lowercase full SHA")
    if patch_ledger["specification_commit"] != specification["commit"]:
        errors.append(
            "patch ledger and baseline manifest disagree on specification commit"
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
