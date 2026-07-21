#!/usr/bin/env python3
"""Write or verify content-addressed candidate qualification interfaces."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPOSITORY_ROOT / "backend"))

from pmorg.application.qualification_interfaces import check_qualification_interfaces
from pmorg.application.qualification_interfaces import write_qualification_interfaces


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--repository-root", type=Path, default=_REPOSITORY_ROOT)
    arguments = parser.parse_args()
    if arguments.write:
        write_qualification_interfaces(arguments.repository_root)
    else:
        check_qualification_interfaces(arguments.repository_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
