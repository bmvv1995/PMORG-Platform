#!/usr/bin/env python3
"""Generate or verify exhaustive admission candidate interface-fit evidence."""

from __future__ import annotations

import argparse

from pmorg.application.candidate_interface_fit_denominator import (
    check_candidate_interface_fit_denominator_evidence,
)
from pmorg.application.candidate_interface_fit_denominator import (
    write_candidate_interface_fit_denominator_evidence,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_candidate_interface_fit_denominator_evidence()
    else:
        write_candidate_interface_fit_denominator_evidence()


if __name__ == "__main__":
    main()
