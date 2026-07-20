#!/usr/bin/env python3
"""Write or verify the closed PMORG release capability catalog."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPOSITORY_ROOT / "backend"))

from pmorg.application.capabilities import check_capability_catalog
from pmorg.application.capabilities import write_capability_catalog


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--repository-root", type=Path, default=_REPOSITORY_ROOT)
    arguments = parser.parse_args()
    repository_root = arguments.repository_root.resolve()
    if arguments.write:
        write_capability_catalog(repository_root)
    else:
        check_capability_catalog(repository_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
