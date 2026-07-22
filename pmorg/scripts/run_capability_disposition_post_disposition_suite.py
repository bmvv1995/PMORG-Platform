#!/usr/bin/env python3
"""Execute the exact Capability Disposition verifier test module and emit a closed receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
SUITE_NAMES = (
    "pmorg.tests.test_qualification_oracles",
    "pmorg.tests.test_qualification_signing",
)
EXPECTED_TEST_COUNT = 12
BASE_PLATFORM_COMMIT = "d3cb3ceee627024404af0588103168367c0f5faa"


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _flatten(suite: unittest.TestSuite) -> list[unittest.TestCase]:
    tests: list[unittest.TestCase] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            tests.extend(_flatten(item))
        elif isinstance(item, unittest.TestCase):
            tests.append(item)
        else:
            raise TypeError(f"unsupported unittest node: {type(item).__name__}")
    return tests


class _RecordingResult(unittest.TestResult):
    def __init__(self) -> None:
        super().__init__()
        self.status_by_id: dict[str, str] = {}

    def startTest(self, test: unittest.TestCase) -> None:  # noqa: N802
        self.status_by_id[test.id()] = "pass"
        super().startTest(test)

    def addFailure(self, test: unittest.TestCase, err: Any) -> None:  # noqa: N802
        self.status_by_id[test.id()] = "fail"
        super().addFailure(test, err)

    def addError(self, test: unittest.TestCase, err: Any) -> None:  # noqa: N802
        self.status_by_id[test.id()] = "error"
        super().addError(test, err)

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:  # noqa: N802
        self.status_by_id[test.id()] = "skipped"
        super().addSkip(test, reason)

    def addExpectedFailure(  # noqa: N802
        self, test: unittest.TestCase, err: Any
    ) -> None:
        self.status_by_id[test.id()] = "expected_failure"
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:  # noqa: N802
        self.status_by_id[test.id()] = "unexpected_success"
        super().addUnexpectedSuccess(test)

    def addSubTest(  # noqa: N802
        self,
        test: unittest.TestCase,
        subtest: unittest.TestCase,
        err: Any,
    ) -> None:
        if err is not None:
            self.status_by_id[test.id()] = "fail"
        super().addSubTest(test, subtest, err)


def _load_suite() -> tuple[unittest.TestSuite, list[str]]:
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromName(name) for name in SUITE_NAMES
    )
    tests = _flatten(suite)
    identities = [test.id() for test in tests]
    if len(identities) != EXPECTED_TEST_COUNT:
        raise RuntimeError(
            f"Capability Disposition verifier suite drifted: {len(identities)} tests"
        )
    if identities != sorted(set(identities)):
        raise RuntimeError(
            "Capability Disposition verifier suite identities are not unique/sorted"
        )
    return suite, identities


def _receipt() -> dict[str, Any]:
    suite, identities = _load_suite()
    result = _RecordingResult()
    suite.run(result)
    records = [
        {"fully_qualified_name": identity, "status": result.status_by_id[identity]}
        for identity in identities
    ]
    if result.testsRun != EXPECTED_TEST_COUNT or any(
        record["status"] != "pass" for record in records
    ):
        raise RuntimeError(
            "Capability Disposition qualification suites did not pass exactly 12/12"
        )
    interpreter = Path(sys.executable).resolve()
    return {
        "schema_version": "pmorg.capability-disposition-post-disposition-suite-receipt/v1",
        "pmorg_platform_commit": BASE_PLATFORM_COMMIT,
        "suites": list(SUITE_NAMES),
        "test_count": EXPECTED_TEST_COUNT,
        "tests": records,
        "interpreter_binary": {
            "digest": _sha256(interpreter.read_bytes()),
            "relative_path": "@runtime/executed-python-interpreter",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.chdir(REPOSITORY_ROOT)
    if args.list:
        _, identities = _load_suite()
        print(json.dumps(identities, sort_keys=True))
        return
    if args.output is None:
        parser.error("--output is required unless --list is used")
    payload = json.dumps(_receipt(), indent=2, sort_keys=True) + "\n"
    args.output.write_text(payload, encoding="utf-8")


if __name__ == "__main__":
    main()
