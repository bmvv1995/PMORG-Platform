#!/usr/bin/env python3
"""Build the canonical, offline PMORG CE source artifact."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPOSITORY_ROOT))

from pmorg.build.artifact import build_artifact
from pmorg.build.artifact import REPOSITORY_ROOT


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    result = build_artifact(
        arguments.repository_root.resolve(),
        arguments.output.resolve(),
        revision=arguments.revision,
    )
    print(
        json.dumps(
            {
                "artifact": str(result.artifact_path),
                "artifact_sha256": result.artifact_sha256,
                "artifact_size": result.artifact_size,
                "commit": result.commit,
                "file_count": result.file_count,
                "manifest_sha256": result.manifest_sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
