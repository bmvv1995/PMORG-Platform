#!/usr/bin/env python3
"""Generate or verify all Governed Fork candidate qualification reports."""

from __future__ import annotations

import argparse

from pmorg.application.governed_fork_candidate_qualification_reports import (
    check_governed_fork_candidate_qualification_reports,
)
from pmorg.application.governed_fork_candidate_qualification_reports import (
    write_governed_fork_candidate_qualification_reports,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_governed_fork_candidate_qualification_reports()
    else:
        write_governed_fork_candidate_qualification_reports()


if __name__ == "__main__":
    main()
