#!/usr/bin/env python3
"""Execute or verify complete admission candidate qualification reports."""

from __future__ import annotations

import argparse

from pmorg.application.candidate_qualification_reports import (
    check_candidate_qualification_reports,
)
from pmorg.application.candidate_qualification_reports import (
    write_candidate_qualification_reports,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_candidate_qualification_reports()
    else:
        write_candidate_qualification_reports()


if __name__ == "__main__":
    main()
