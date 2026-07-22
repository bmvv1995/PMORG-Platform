#!/usr/bin/env python3
"""Generate or verify all Capability Disposition Qualification candidate qualification reports."""

from __future__ import annotations

import argparse

from pmorg.application.capability_disposition_qualification_candidate_qualification_reports import (
    check_capability_disposition_qualification_candidate_qualification_reports,
)
from pmorg.application.capability_disposition_qualification_candidate_qualification_reports import (
    write_capability_disposition_qualification_candidate_qualification_reports,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_capability_disposition_qualification_candidate_qualification_reports()
    else:
        write_capability_disposition_qualification_candidate_qualification_reports()


if __name__ == "__main__":
    main()
