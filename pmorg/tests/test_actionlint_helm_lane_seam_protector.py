from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = Path(".github/actionlint.yml")
FIXTURE_PATH = Path("pmorg/tests/fixtures/ci-seams/actionlint-static-helm-lane.yml")
BASELINE_SHA256 = "2490770896ca822f2958c84f7ff79c067eb5bca288316a19763b62d698aae195"
STATIC_LANE_SHA256 = "4301dbacaf4e7ee2e3b6e88a18c7600a2d716728b16e5c412521c6641daf77e7"


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


class TestActionlintHelmLaneAdmissionSeam(unittest.TestCase):
    def test_helm_lane_is_only_runner_catalog_change(self) -> None:
        fixture = repository_bytes(FIXTURE_PATH)
        self.assertEqual(hashlib.sha256(fixture).hexdigest(), STATIC_LANE_SHA256)
        assert_one_byte_drift_rejected(self, fixture, STATIC_LANE_SHA256)

        static_catalog = b"    - helm-lane\n    - runs-on\n"
        baseline_catalog = b"    - runs-on\n"
        self.assertEqual(fixture.count(static_catalog), 1)
        baseline = fixture.replace(static_catalog, baseline_catalog)
        self.assertEqual(hashlib.sha256(baseline).hexdigest(), BASELINE_SHA256)
        self.assertEqual(repository_bytes(CONFIG_PATH), fixture)


if __name__ == "__main__":
    unittest.main()
