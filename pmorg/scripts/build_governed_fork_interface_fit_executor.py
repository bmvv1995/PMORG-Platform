#!/usr/bin/env python3
"""Generate or verify the governed-fork candidate-aware oracle extension."""

from __future__ import annotations

import argparse

from pmorg.application.governed_fork_interface_fit_executor import (
    check_governed_fork_oracle_extension,
)
from pmorg.application.governed_fork_interface_fit_executor import (
    write_governed_fork_oracle_extension,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_governed_fork_oracle_extension()
    else:
        write_governed_fork_oracle_extension()


if __name__ == "__main__":
    main()
