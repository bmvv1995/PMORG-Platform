#!/usr/bin/env python3
"""Verify CE boundary, egress, and independent source-artifact rebuilds."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPOSITORY_ROOT))

from pmorg.build.artifact import _read_json_object
from pmorg.build.artifact import build_artifact
from pmorg.build.artifact import REPOSITORY_ROOT
from pmorg.build.artifact import scan_pmorg_worktree
from pmorg.build.artifact import SPEC_PATH
from pmorg.build.artifact import validate_spec
from pmorg.build.artifact import verify_egress


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--revision", default="HEAD")
    arguments = parser.parse_args()
    repository_root = arguments.repository_root.resolve()
    spec = _read_json_object(repository_root / SPEC_PATH.relative_to(REPOSITORY_ROOT))
    validate_spec(spec, repository_root)
    violations = [
        *scan_pmorg_worktree(repository_root, spec),
        *verify_egress(
            repository_root,
            repository_root / "pmorg/build/ce-build-egress.json",
        ),
    ]
    if violations:
        for violation in sorted(set(violations)):
            print(violation.render())
        return 1

    with tempfile.TemporaryDirectory(prefix="pmorg-ce-rebuild-") as temp_dir:
        first = build_artifact(
            repository_root,
            Path(temp_dir) / "first.tar",
            revision=arguments.revision,
            spec_path=repository_root / "pmorg/build/ce-artifact-spec.json",
        )
        second = build_artifact(
            repository_root,
            Path(temp_dir) / "second.tar",
            revision=arguments.revision,
            spec_path=repository_root / "pmorg/build/ce-artifact-spec.json",
        )
    if first.artifact_sha256 != second.artifact_sha256:
        print("REPRODUCIBILITY artifact digests differ across independent rebuilds")
        return 1
    print(
        "PMORG CE source build PASS "
        f"commit={first.commit} files={first.file_count} "
        f"sha256={first.artifact_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
