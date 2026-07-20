from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = Path(".github/workflows/pr-helm-chart-testing.yml")
BASELINE_FIXTURE_PATH = Path("pmorg/tests/fixtures/ci-seams/pr-helm-chart-testing.yml")
STATIC_LANE_FIXTURE_PATH = Path(
    "pmorg/tests/fixtures/ci-seams/pr-helm-chart-testing-static-lane.yml"
)
BASELINE_SHA256 = "08a7ecc5d55a97ef1ec895ad3fa0862b0e0fb79cb6cbe62ca40808a7e1722070"
STATIC_LANE_SHA256 = "49b0a6bc14679eec0780792935a84032504e4c69f068e48a486d1dbf978eeae5"


def repository_bytes(path: Path) -> bytes:
    return (REPOSITORY_ROOT / path).read_bytes()


def assert_one_byte_drift_rejected(
    test_case: unittest.TestCase,
    content: bytes,
    expected_sha256: str,
) -> None:
    if not content:
        raise AssertionError("cannot drift empty content")
    drifted = bytearray(content)
    drifted[len(drifted) // 2] ^= 0x01
    test_case.assertEqual(
        sum(before != after for before, after in zip(content, drifted)),
        1,
    )
    test_case.assertNotEqual(
        hashlib.sha256(drifted).hexdigest(),
        expected_sha256,
    )


class TestHelmStaticRunnerAdmissionSeam(unittest.TestCase):
    def test_static_ephemeral_lane_replaces_only_runner_selector(self) -> None:
        baseline = repository_bytes(BASELINE_FIXTURE_PATH)
        fixture = repository_bytes(STATIC_LANE_FIXTURE_PATH)

        self.assertEqual(hashlib.sha256(baseline).hexdigest(), BASELINE_SHA256)
        self.assertEqual(hashlib.sha256(fixture).hexdigest(), STATIC_LANE_SHA256)
        assert_one_byte_drift_rejected(self, fixture, STATIC_LANE_SHA256)

        dynamic_selector = (
            b"    runs-on:\n"
            b"      - runs-on\n"
            b"      - runner=8cpu-linux-x64\n"
            b'      - "run-id=${{ github.run_id }}-helm-chart-check"\n'
        )
        static_selector = (
            b"    runs-on:\n"
            b"      - self-hosted\n"
            b"      - Linux\n"
            b"      - X64\n"
            b"      - helm-lane\n"
        )
        self.assertEqual(baseline.count(dynamic_selector), 1)
        self.assertEqual(fixture.count(static_selector), 1)
        self.assertEqual(
            fixture,
            baseline.replace(dynamic_selector, static_selector),
        )
        self.assertEqual(repository_bytes(WORKFLOW_PATH), fixture)


if __name__ == "__main__":
    unittest.main()
