from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = Path(".github/workflows/zizmor.yml")
FIXTURE_PATH = Path("pmorg/tests/fixtures/ci-seams/zizmor.yml")
FIXTURE_SHA256 = "53c56f34546a7672bf87d2beda1e1c1dd04ddefd86e8f7a71c1df6061bfe88be"
JOB_HEADER = re.compile(r"^  [A-Za-z0-9_-]+:$")


def repository_bytes(path: Path) -> bytes:
    return (REPOSITORY_ROOT / path).read_bytes()


def active_lines(path: Path) -> list[str]:
    lines: list[str] = []
    for raw_line in (REPOSITORY_ROOT / path).read_text(encoding="utf-8").splitlines():
        if raw_line.lstrip().startswith("#"):
            continue
        line = raw_line.split(" #", 1)[0].rstrip()
        if line.strip():
            lines.append(line)
    return lines


def job_block(lines: list[str], job_id: str) -> list[str]:
    marker = f"  {job_id}:"
    if lines.count(marker) != 1:
        raise AssertionError(f"expected exactly one active job marker: {marker}")
    start = lines.index(marker)
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if JOB_HEADER.match(lines[index])
        ),
        len(lines),
    )
    return lines[start:end]


def step_block(job: list[str], step_name: str) -> list[str]:
    marker = f"      - name: {step_name}"
    if job.count(marker) != 1:
        raise AssertionError(f"expected exactly one active step marker: {marker}")
    start = job.index(marker)
    end = next(
        (
            index
            for index in range(start + 1, len(job))
            if job[index].startswith("      - name:")
            or job[index].startswith("      - uses:")
        ),
        len(job),
    )
    return job[start:end]


class TestZizmorPrivateRepositorySeam(unittest.TestCase):
    def test_sarif_upload_is_explicitly_opt_in(self) -> None:
        fixture = repository_bytes(FIXTURE_PATH)
        self.assertEqual(hashlib.sha256(fixture).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(repository_bytes(WORKFLOW_PATH), fixture)

        lines = active_lines(FIXTURE_PATH)
        job = job_block(lines, "zizmor")
        scan = step_block(job, "Run zizmor")
        upload = step_block(job, "Upload SARIF file")
        permissions_start = job.index("    permissions:")
        steps_start = job.index("    steps:")

        self.assertEqual(job.count("    permissions:"), 1)
        self.assertEqual(job.count("    steps:"), 1)
        self.assertEqual(
            job[permissions_start:steps_start],
            [
                "    permissions:",
                "      actions: read",
                "      contents: read",
                "      security-events: write",
            ],
        )
        self.assertEqual(
            scan,
            [
                "      - name: Run zizmor",
                "        run: uv run --no-sync zizmor --format=sarif . > results.sarif",
                "        env:",
                "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            ],
        )
        self.assertEqual(
            upload,
            [
                "      - name: Upload SARIF file",
                "        if: >-",
                "          ${{",
                "            !cancelled() &&",
                "            vars.PMORG_ENABLE_ZIZMOR_SARIF == 'true' &&",
                "            hashFiles('results.sarif') != '' &&",
                "            (",
                "              github.event_name == 'push' ||",
                "              github.event.pull_request.head.repo.full_name == github.repository",
                "            )",
                "          }}",
                "        uses: github/codeql-action/upload-sarif@ba454b8ab46733eb6145342877cd148270bb77ab",
                "        with:",
                "          sarif_file: results.sarif",
                "          category: zizmor",
            ],
        )
        self.assertFalse(any("continue-on-error:" in line for line in job))
        self.assertFalse(any("|| true" in line for line in job))


if __name__ == "__main__":
    unittest.main()
