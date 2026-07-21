#!/usr/bin/env python3
"""Build or verify bounded admission capability dispositions."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))
sys.path.insert(0, str(REPOSITORY_ROOT))

from pmorg.application.capability_dispositions import validate_capability_dispositions
from pmorg.application.capability_dispositions import (
    validate_thin_fork_capability_disposition,
)
from pmorg.application.capability_dispositions import write_capability_dispositions
from pmorg.application.capability_dispositions import (
    write_thin_fork_capability_disposition,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--thin-fork", action="store_true")
    arguments = parser.parse_args()
    if arguments.thin_fork:
        if not arguments.check:
            write_thin_fork_capability_disposition(REPOSITORY_ROOT)
        validate_thin_fork_capability_disposition(REPOSITORY_ROOT)
        return 0
    if arguments.check:
        validate_capability_dispositions(REPOSITORY_ROOT)
        return 0
    write_capability_dispositions(REPOSITORY_ROOT)
    validate_capability_dispositions(REPOSITORY_ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
