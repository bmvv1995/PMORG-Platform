from __future__ import annotations

import sys
import unittest
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from verify_fork import PatchEntry  # noqa: E402
from verify_fork import find_path_owners  # noqa: E402
from verify_fork import load_patch_ledger  # noqa: E402


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
        path = "pmorg/scripts/verify_ce_boundary.py"
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
            find_path_owners([path], entries)[path], ["PL-BROAD", "PL-NARROW"]
        )

    def test_real_ledger_has_one_owner_for_gate_a_paths(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        ledger = load_patch_ledger(repository_root)
        paths = [
            "pmorg/scripts/verify_ce_boundary.py",
            "pmorg/scripts/ce_boundary/source.py",
            "pmorg/tests/ce_boundary/test_source_and_docker.py",
            "pmorg/tests/test_ce_boundary_suite.py",
            "web/src/providers/QueryControllerProvider.pmorg-ce.test.tsx",
        ]

        self.assertEqual(
            find_path_owners(paths, ledger["entries"]),
            {
                paths[0]: ["PL-003"],
                paths[1]: ["PL-003"],
                paths[2]: ["PL-003"],
                paths[3]: ["PL-003"],
                paths[4]: ["PL-004"],
            },
        )


if __name__ == "__main__":
    unittest.main()
