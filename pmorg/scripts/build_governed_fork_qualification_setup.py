#!/usr/bin/env python3
"""Generate or verify governed-fork Q5a vectors and screening evidence."""

from __future__ import annotations

import argparse

from pmorg.application.governed_fork_qualification_setup import (
    check_governed_fork_qualification_setup,
)
from pmorg.application.governed_fork_qualification_setup import (
    write_governed_fork_qualification_setup,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_governed_fork_qualification_setup()
    else:
        write_governed_fork_qualification_setup()


if __name__ == "__main__":
    main()
