#!/usr/bin/env python3
"""Build or verify the terminal catalog-completion aggregate."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))
sys.path.insert(0, str(REPOSITORY_ROOT))

from pmorg.application.catalog_completion_aggregate import (
    validate_catalog_completion_aggregate,
)
from pmorg.application.catalog_completion_aggregate import (
    write_catalog_completion_aggregate,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if not arguments.check:
        write_catalog_completion_aggregate(REPOSITORY_ROOT)
    validate_catalog_completion_aggregate(REPOSITORY_ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
