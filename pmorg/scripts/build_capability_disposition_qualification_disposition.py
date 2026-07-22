#!/usr/bin/env python3
"""Build or verify the bounded Q7e capability disposition record."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))
sys.path.insert(0, str(REPOSITORY_ROOT))

from pmorg.application.capability_disposition_qualification_disposition import (
    validate_capability_disposition_qualification_disposition,
)
from pmorg.application.capability_disposition_qualification_disposition import (
    write_capability_disposition_qualification_disposition,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if not arguments.check:
        write_capability_disposition_qualification_disposition(REPOSITORY_ROOT)
    validate_capability_disposition_qualification_disposition(REPOSITORY_ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
