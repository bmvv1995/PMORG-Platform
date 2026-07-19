from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from verify_fork import PatchEntry  # noqa: E402
from verify_fork import find_path_owners  # noqa: E402
from verify_fork import load_manifest  # noqa: E402
from verify_fork import load_patch_ledger  # noqa: E402
from verify_fork import validate_local_upstream  # noqa: E402
from verify_fork import validate_patch_entries  # noqa: E402
from verify_fork import validate_specification_references  # noqa: E402
from verify_fork import validate_surface_mode  # noqa: E402


class ForkLedgerTest(unittest.TestCase):
    def test_dynamic_route_brackets_are_literal(self) -> None:
        route = "web/src/app/admin/bots/[bot-id]/channels/[id]/page.tsx"
        entries: list[PatchEntry] = [
            {
                "id": "PL-TEST",
                "classification": "integration",
                "paths": [route],
            }
        ]

        owners = find_path_owners(
            [route, "web/src/app/admin/bots/b/channels/i/page.tsx"], entries
        )

        self.assertEqual(owners[route], ["PL-TEST"])
        self.assertEqual(
            owners["web/src/app/admin/bots/b/channels/i/page.tsx"], []
        )

    def test_overlapping_entries_are_reported_as_multiple_owners(self) -> None:
        path = "pmorg/scripts/verify_fork.py"
        entries: list[PatchEntry] = [
            {
                "id": "PL-BROAD",
                "classification": "PMORG-owned",
                "paths": ["pmorg/**"],
            },
            {
                "id": "PL-NARROW",
                "classification": "PMORG-owned",
                "paths": [path],
            },
        ]

        self.assertEqual(
            find_path_owners([path], entries)[path],
            ["PL-BROAD", "PL-NARROW"],
        )

    def test_current_foundation_paths_have_one_owner(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        ledger = load_patch_ledger(repository_root)
        paths = [
            "PMORG.md",
            ".codex/agents/pmorg-mapper.toml",
            "plans/pmorg-v3-foundation.md",
            "pmorg/CE-BOUNDARY.md",
            "pmorg/scripts/verify_fork.py",
            "pmorg/tests/test_verify_fork.py",
        ]

        self.assertEqual(
            find_path_owners(paths, ledger["entries"]),
            {
                paths[0]: ["PL-000"],
                paths[1]: ["PL-001"],
                paths[2]: ["PL-002"],
                paths[3]: ["PL-000"],
                paths[4]: ["PL-000"],
                paths[5]: ["PL-000"],
            },
        )

    def test_specification_pin_is_cross_recorded(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = load_manifest(repository_root)
        ledger = load_patch_ledger(repository_root)

        self.assertEqual(manifest["specification"]["baseline"], "RB-1/C2")
        self.assertEqual(
            manifest["specification"]["commit"],
            ledger["specification_commit"],
        )
        self.assertEqual(
            validate_specification_references(
                repository_root, manifest["specification"]["commit"]
            ),
            [],
        )

    def test_current_surface_mode_policy_is_valid(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = load_manifest(repository_root)

        self.assertEqual(validate_surface_mode(manifest), [])

    def test_surface_and_mode_must_be_declared_together(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = copy.deepcopy(load_manifest(repository_root))
        manifest["build"]["onyx_surface"] = "ee"

        self.assertIn(
            "onyx_surface and usage_mode must be declared together",
            validate_surface_mode(manifest),
        )

    def test_legacy_licensed_ee_value_is_rejected(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = copy.deepcopy(load_manifest(repository_root))
        manifest["build"]["onyx_surface"] = "licensed-ee"
        manifest["build"]["usage_mode"] = "production"

        errors = validate_surface_mode(manifest)

        self.assertIn("invalid onyx_surface: licensed-ee", errors)
        self.assertIn("legacy delivery-profile terminology is forbidden", errors)

    def test_unknown_usage_mode_is_rejected(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = copy.deepcopy(load_manifest(repository_root))
        manifest["build"]["onyx_surface"] = "ce"
        manifest["build"]["usage_mode"] = "client"

        self.assertIn(
            "invalid usage_mode: client",
            validate_surface_mode(manifest),
        )

    def test_patch_entry_requires_traceability_fields(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        ledger = load_patch_ledger(repository_root)
        broken_entry = copy.deepcopy(ledger["entries"][0])
        broken_entry.pop("requirements")

        self.assertIn(
            "PL-000 has no non-empty requirements list",
            validate_patch_entries([broken_entry]),
        )

    def test_patch_entry_rejects_empty_reason_and_verification(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        ledger = load_patch_ledger(repository_root)
        broken_entry = copy.deepcopy(ledger["entries"][0])
        broken_entry["reason"] = " "
        broken_entry["verification"] = []

        errors = validate_patch_entries([broken_entry])

        self.assertIn("PL-000 has no non-empty reason", errors)
        self.assertIn("PL-000 has no non-empty verification list", errors)

    def test_upstream_check_allows_clean_origin_only_clone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            subprocess.run(
                ["git", "init", "-q"],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "test@pmorg.invalid"],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "PMORG Test"],
                cwd=repository_root,
                check=True,
            )
            (repository_root / "fixture.txt").write_text("fixture\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "fixture.txt"],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-q", "-m", "fixture"],
                cwd=repository_root,
                check=True,
            )
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            upstream = {
                "repository": "https://github.com/onyx-dot-app/onyx.git",
                "release_tag": "v4.3.9",
                "commit": commit,
                "checkout_remote": "upstream",
            }

            self.assertEqual(validate_local_upstream(repository_root, upstream), [])

    def test_upstream_check_reports_missing_commit_without_traceback(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        upstream = {
            "repository": "https://github.com/onyx-dot-app/onyx.git",
            "release_tag": "v4.3.9",
            "commit": "0" * 40,
            "checkout_remote": "upstream",
        }

        self.assertIn(
            "pinned upstream commit is absent from local history",
            validate_local_upstream(repository_root, upstream),
        )


if __name__ == "__main__":
    unittest.main()
