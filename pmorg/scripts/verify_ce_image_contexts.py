#!/usr/bin/env python3
"""Verify two independent CE image-context generations are byte-identical."""

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
    parser.add_argument("--repository-root", type=Path, default=_REPOSITORY_ROOT)
    parser.add_argument("--revision", default="HEAD")
    arguments = parser.parse_args()
    repository_root = arguments.repository_root.resolve()
    with tempfile.TemporaryDirectory(prefix="pmorg-ce-contexts-") as temporary:
        root = Path(temporary)
        source = root / "source.tar"
        build_artifact(
            repository_root,
            source,
            revision=arguments.revision,
            spec_path=repository_root / "pmorg/build/ce-artifact-spec.json",
        )
        first = build_contexts(
            source,
            root / "first",
        )
        second = build_contexts(
            source,
            root / "second",
        )
        if [(item.name, item.sha256) for item in first] != [
            (item.name, item.sha256) for item in second
        ]:
            print("REPRODUCIBILITY CE image context digests differ")
            return 1
        if any(
            left.path.read_bytes() != right.path.read_bytes()
            for left, right in zip(first, second, strict=True)
        ):
            print("REPRODUCIBILITY CE image context bytes differ")
            return 1
    print(
        "PMORG CE image contexts PASS "
        + " ".join(f"{item.name}={item.sha256}" for item in first)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
