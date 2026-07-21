#!/usr/bin/env python3
"""Generate or verify qualified-build Q6a vectors and screening evidence."""

from __future__ import annotations

import argparse

from pmorg.application.qualified_build_qualification_setup import (
    check_qualified_build_qualification_setup,
)
from pmorg.application.qualified_build_qualification_setup import (
    write_qualified_build_qualification_setup,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_qualified_build_qualification_setup()
    else:
        write_qualified_build_qualification_setup()


if __name__ == "__main__":
    main()
