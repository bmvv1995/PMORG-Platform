"""Expose the nested CE boundary suite to repository-level unittest discovery."""

from __future__ import annotations

import unittest
from pathlib import Path


def load_tests(
    loader: unittest.TestLoader,
    standard_tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    suite_directory = Path(__file__).resolve().parent / "ce_boundary"
    nested_tests = loader.discover(
        start_dir=str(suite_directory),
        pattern=pattern or "test_*.py",
        top_level_dir=str(suite_directory),
    )
    standard_tests.addTests(nested_tests)
    return standard_tests
