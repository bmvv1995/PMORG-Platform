#!/usr/bin/env python3
"""Generate or verify the Thin Fork candidate-aware oracle extension."""

from __future__ import annotations

import argparse

from pmorg.application.thin_fork_interface_fit_executor import (
    check_thin_fork_oracle_extension,
)
from pmorg.application.thin_fork_interface_fit_executor import (
    write_thin_fork_oracle_extension,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_thin_fork_oracle_extension()
    else:
        write_thin_fork_oracle_extension()


if __name__ == "__main__":
    main()
