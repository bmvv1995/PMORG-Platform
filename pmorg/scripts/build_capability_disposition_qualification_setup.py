#!/usr/bin/env python3
"""Generate or verify capability-disposition-qualification Q7a vectors and screening evidence."""

from __future__ import annotations

import argparse

from pmorg.application.capability_disposition_qualification_setup import (
    check_capability_disposition_qualification_setup,
)
from pmorg.application.capability_disposition_qualification_setup import (
    write_capability_disposition_qualification_setup,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check_capability_disposition_qualification_setup()
    else:
        write_capability_disposition_qualification_setup()


if __name__ == "__main__":
    main()
