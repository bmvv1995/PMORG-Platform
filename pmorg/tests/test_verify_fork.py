from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from verify_fork import PatchEntry  # noqa: E402
from verify_fork import find_path_owners  # noqa: E402
from verify_fork import load_manifest  # noqa: E402
from verify_fork import load_patch_ledger  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
