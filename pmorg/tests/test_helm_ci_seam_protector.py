from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = Path(".github/workflows/pr-helm-chart-testing.yml")
FIXTURE_PATH = Path("pmorg/tests/fixtures/ci-seams/pr-helm-chart-testing.yml")
FIXTURE_SHA256 = "08a7ecc5d55a97ef1ec895ad3fa0862b0e0fb79cb6cbe62ca40808a7e1722070"
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


class TestHelmRunnerAdmissionSeam(unittest.TestCase):
    def test_non_helm_change_does_not_require_runs_on(self) -> None:
        fixture = repository_bytes(FIXTURE_PATH)

        self.assertEqual(hashlib.sha256(fixture).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(repository_bytes(WORKFLOW_PATH), fixture)

        lines = active_lines(FIXTURE_PATH)
        jobs_start = lines.index("jobs:")
        detector = job_block(lines, "detect_helm_inputs")
        validation = job_block(lines, "helm_validation")
        required = job_block(lines, "helm-chart-check")
        validation_steps = validation.index("    steps:")

        self.assertEqual(
            [line for line in lines[jobs_start + 1 :] if JOB_HEADER.match(line)],
            [
                "  detect_helm_inputs:",
                "  helm_validation:",
                "  helm-chart-check:",
            ],
        )
        self.assertEqual(
            lines[:jobs_start],
            [
                "name: Helm - Lint and Test Charts",
                "concurrency:",
                "  group: Helm-Lint-and-Test-Charts-${{ github.workflow }}-${{ github.head_ref || github.event.workflow_run.head_branch || github.run_id }}",
                "  cancel-in-progress: true",
                "on:",
                "  merge_group:",
                "    types: [checks_requested]",
                "  pull_request:",
                "    branches: [main]",
                "  push:",
                '    tags: ["v*.*.*"]',
                "  workflow_dispatch:",
                "permissions:",
                "  contents: read",
            ],
        )
        self.assertEqual(
            detector,
            [
                "  detect_helm_inputs:",
                "    name: Detect Helm inputs",
                "    runs-on: ubuntu-latest",
                "    timeout-minutes: 5",
                "    outputs:",
                "      relevant: ${{ steps.detect.outputs.relevant }}",
                "    steps:",
                "      - name: Check out complete history",
                "        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
                "        with:",
                "          fetch-depth: 0",
                "          persist-credentials: false",
                "      - name: Detect relevant Helm inputs",
                "        id: detect",
                "        shell: bash",
                "        run: |",
                "          set -euo pipefail",
                '          case "$GITHUB_EVENT_NAME" in',
                "            pull_request)",
                '              base_sha="$(jq -er \'.pull_request.base.sha\' "$GITHUB_EVENT_PATH")"',
                '              head_sha="$GITHUB_SHA"',
                "              ;;",
                "            merge_group)",
                '              base_sha="$(jq -er \'.merge_group.base_sha\' "$GITHUB_EVENT_PATH")"',
                '              head_sha="$GITHUB_SHA"',
                "              ;;",
                "            push|workflow_dispatch)",
                '              echo "relevant=true" >> "$GITHUB_OUTPUT"',
                "              exit 0",
                "              ;;",
                "            *)",
                '              echo "Unsupported event: $GITHUB_EVENT_NAME" >&2',
                "              exit 1",
                "              ;;",
                "          esac",
                '          git rev-parse --verify "${base_sha}^{commit}" >/dev/null',
                '          git rev-parse --verify "${head_sha}^{commit}" >/dev/null',
                '          git merge-base --is-ancestor "$base_sha" "$head_sha"',
                '          changed="$RUNNER_TEMP/helm-changed-paths"',
                "          git diff --no-renames --name-only -z \\",
                '            "$base_sha" "$head_sha" -- > "$changed"',
                "          relevant=false",
                "          while IFS= read -r -d '' path; do",
                '            case "$path" in',
                "              deployment/helm/*|ct.yaml|.github/workflows/pr-helm-chart-testing.yml)",
                "                relevant=true",
                "                ;;",
                "            esac",
                '          done < "$changed"',
                '          echo "relevant=$relevant" >> "$GITHUB_OUTPUT"',
            ],
        )
        self.assertEqual(
            validation[: validation_steps + 1],
            [
                "  helm_validation:",
                "    name: Helm validation",
                "    needs: detect_helm_inputs",
                "    if: >-",
                "      ${{",
                "        needs.detect_helm_inputs.result == 'success' &&",
                "        needs.detect_helm_inputs.outputs.relevant == 'true' &&",
                "        (",
                "          github.event_name != 'pull_request' ||",
                "          github.event.pull_request.head.repo.full_name == github.repository",
                "        )",
                "      }}",
                "    runs-on:",
                "      - runs-on",
                "      - runner=8cpu-linux-x64",
                '      - "run-id=${{ github.run_id }}-helm-chart-check"',
                "    timeout-minutes: 45",
                "    steps:",
            ],
        )
        self.assertEqual(
            [
                line.removeprefix("      - name: ")
                for line in validation
                if line.startswith("      - name: ")
            ],
            [
                "Checkout code",
                "Set up Helm",
                "Set up chart-testing",
                "Run chart-testing (lint)",
                "Create kind cluster",
                "Pre-install cluster status check",
                "Add Helm repositories and update",
                "Verify CNPG CRDs are in sync",
                "Pre-pull required images",
                "Validate chart dependencies",
                "Run chart-testing (install) with enhanced monitoring",
                "Post-install verification",
                "Cleanup on failure",
            ],
        )
        self.assertEqual(
            [line for line in validation if line.lstrip().startswith("if:")],
            ["    if: >-", "        if: ${{ failure() }}"],
        )
        for required_line in [
            "        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
            "        uses: azure/setup-helm@dda3372f752e03dde6b3237bc9431cdc2f7a02a2",
            "        uses: helm/chart-testing-action@2e2940618cb426dce2999631d543b53cdcfc8527",
            "        run: ct lint --config ct.yaml --all",
            "        uses: helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc",
            "          deployment/helm/charts/onyx/scripts/check-cnpg-crds.sh",
            "          helm lint . \\",
            "          ct install --all \\",
            "      - name: Post-install verification",
        ]:
            self.assertIn(required_line, validation)
        self.assertEqual(
            required,
            [
                "  helm-chart-check:",
                "    name: helm-chart-check",
                "    needs: [detect_helm_inputs, helm_validation]",
                "    if: ${{ always() }}",
                "    runs-on: ubuntu-latest",
                "    timeout-minutes: 5",
                "    steps:",
                "      - name: Resolve Helm gate",
                "        env:",
                "          DETECT_RESULT: ${{ needs.detect_helm_inputs.result }}",
                "          RELEVANT: ${{ needs.detect_helm_inputs.outputs.relevant }}",
                "          VALIDATION_RESULT: ${{ needs.helm_validation.result }}",
                "        shell: bash",
                "        run: |",
                "          set -euo pipefail",
                '          if [[ "$DETECT_RESULT" != "success" ]]; then',
                '            echo "Helm input detection failed: $DETECT_RESULT" >&2',
                "            exit 1",
                "          fi",
                '          case "$RELEVANT:$VALIDATION_RESULT" in',
                "            false:skipped)",
                '              echo "Helm validation not applicable; RunsOn was not requested."',
                "              ;;",
                "            true:success)",
                '              echo "Applicable Helm validation passed."',
                "              ;;",
                "            *)",
                '              echo "Invalid Helm gate state: relevant=$RELEVANT validation=$VALIDATION_RESULT" >&2',
                "              exit 1",
                "              ;;",
                "          esac",
            ],
        )
        self.assertEqual(sum("runner=8cpu-linux-x64" in line for line in lines), 1)
        self.assertNotIn("ct list-changed", "\n".join(lines))
        self.assertNotIn("steps.list-changed.outputs.changed", "\n".join(lines))
        self.assertNotIn("id: list-changed", "\n".join(lines))
        self.assertFalse(any("continue-on-error:" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
