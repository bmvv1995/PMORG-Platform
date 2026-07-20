#!/usr/bin/env python3
"""Build deterministic PMORG CE backend and web context bundles."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPOSITORY_ROOT))

from pmorg.build.artifact import build_artifact
from pmorg.build.image_context import build_contexts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--repository-root", type=Path, default=_REPOSITORY_ROOT)
    parser.add_argument("--revision", default="HEAD")
    arguments = parser.parse_args()
    repository_root = arguments.repository_root.resolve()
    with tempfile.TemporaryDirectory(prefix="pmorg-ce-source-") as temporary:
        source = Path(temporary) / "source.tar"
        build_artifact(
            repository_root,
            source,
            revision=arguments.revision,
            spec_path=repository_root / "pmorg/build/ce-artifact-spec.json",
        )
        results = build_contexts(
            source,
            arguments.output_directory.resolve(),
        )
    for result in results:
        print(
            f"{result.name} files={result.file_count} bytes={result.size} "
            f"sha256={result.sha256} path={result.path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
