#!/usr/bin/env python3
"""Generate or verify exhaustive Thin Fork interface-fit screening evidence."""

from __future__ import annotations

import argparse

from pmorg.application.thin_fork_interface_fit import (
    check_thin_fork_interface_fit_evidence,
)
from pmorg.application.thin_fork_interface_fit import (
    write_thin_fork_interface_fit_evidence,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_thin_fork_interface_fit_evidence()
    else:
        write_thin_fork_interface_fit_evidence()


if __name__ == "__main__":
    main()
