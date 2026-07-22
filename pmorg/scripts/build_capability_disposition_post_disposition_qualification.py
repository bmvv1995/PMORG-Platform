#!/usr/bin/env python3
"""Build or verify Capability Disposition post-disposition qualification evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from pmorg.application.capability_disposition_post_disposition_qualification import (  # noqa: E402
    check_capability_disposition_post_disposition_qualification,
)
from pmorg.application.capability_disposition_post_disposition_qualification import (  # noqa: E402
    write_capability_disposition_post_disposition_qualification,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_capability_disposition_post_disposition_qualification(REPOSITORY_ROOT)
        return 0
    write_capability_disposition_post_disposition_qualification(REPOSITORY_ROOT)
    check_capability_disposition_post_disposition_qualification(REPOSITORY_ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
